#include "forensicator/json.hpp"

#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <string>

namespace forensicator::json {

static const Value kNull;

const Value& Value::at(std::string_view key) const {
    if (!is_object()) return kNull;
    auto it = obj_->find(std::string(key));
    if (it == obj_->end()) return kNull;
    return it->second;
}

bool Value::contains(std::string_view key) const {
    if (!is_object()) return false;
    return obj_->find(std::string(key)) != obj_->end();
}

// ---- Parser ----

namespace {

struct Parser {
    std::string_view s;
    std::size_t i = 0;

    [[noreturn]] void err(const std::string& msg) const {
        throw ParseError("json parse error at offset " + std::to_string(i) + ": " + msg);
    }

    void skip_ws() {
        while (i < s.size() &&
               (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) {
            ++i;
        }
    }

    char peek() {
        if (i >= s.size()) err("unexpected eof");
        return s[i];
    }

    void expect(char c) {
        if (i >= s.size() || s[i] != c) err(std::string("expected '") + c + "'");
        ++i;
    }

    bool match_literal(const char* lit) {
        std::size_t n = std::strlen(lit);
        if (i + n > s.size()) return false;
        if (s.compare(i, n, lit) != 0) return false;
        i += n;
        return true;
    }

    Value parse_value() {
        skip_ws();
        if (i >= s.size()) err("unexpected eof");
        char c = s[i];
        if (c == '{') return parse_object();
        if (c == '[') return parse_array();
        if (c == '"') return parse_string_value();
        if (c == 't' || c == 'f') return parse_bool();
        if (c == 'n') return parse_null();
        return parse_number();
    }

    Value parse_object() {
        Object o;
        ++i;  // '{'
        skip_ws();
        if (i < s.size() && s[i] == '}') { ++i; return Value(std::move(o)); }
        while (true) {
            skip_ws();
            if (i >= s.size() || s[i] != '"') err("expected string key");
            std::string key = parse_string();
            skip_ws();
            expect(':');
            Value v = parse_value();
            o.emplace(std::move(key), std::move(v));
            skip_ws();
            if (i < s.size() && s[i] == ',') { ++i; continue; }
            if (i < s.size() && s[i] == '}') { ++i; break; }
            err("expected ',' or '}'");
        }
        return Value(std::move(o));
    }

    Value parse_array() {
        Array a;
        ++i;  // '['
        skip_ws();
        if (i < s.size() && s[i] == ']') { ++i; return Value(std::move(a)); }
        while (true) {
            a.push_back(parse_value());
            skip_ws();
            if (i < s.size() && s[i] == ',') { ++i; continue; }
            if (i < s.size() && s[i] == ']') { ++i; break; }
            err("expected ',' or ']'");
        }
        return Value(std::move(a));
    }

    std::string parse_string() {
        expect('"');
        std::string out;
        while (i < s.size()) {
            char c = s[i++];
            if (c == '"') return out;
            if (c == '\\') {
                if (i >= s.size()) err("bad escape");
                char e = s[i++];
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        if (i + 4 > s.size()) err("bad \\u escape");
                        unsigned cp = 0;
                        for (int k = 0; k < 4; ++k) {
                            char h = s[i++];
                            cp <<= 4;
                            if (h >= '0' && h <= '9') cp |= (h - '0');
                            else if (h >= 'a' && h <= 'f') cp |= (h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') cp |= (h - 'A' + 10);
                            else err("bad hex in \\u");
                        }
                        // Handle surrogate pair
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            if (i + 6 > s.size() || s[i] != '\\' || s[i + 1] != 'u') {
                                err("expected low surrogate");
                            }
                            i += 2;
                            unsigned low = 0;
                            for (int k = 0; k < 4; ++k) {
                                char h = s[i++];
                                low <<= 4;
                                if (h >= '0' && h <= '9') low |= (h - '0');
                                else if (h >= 'a' && h <= 'f') low |= (h - 'a' + 10);
                                else if (h >= 'A' && h <= 'F') low |= (h - 'A' + 10);
                                else err("bad hex in low surrogate");
                            }
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                        }
                        // UTF-8 encode
                        if (cp < 0x80) {
                            out.push_back(static_cast<char>(cp));
                        } else if (cp < 0x800) {
                            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        } else if (cp < 0x10000) {
                            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        } else {
                            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
                            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        }
                        break;
                    }
                    default: err("bad escape");
                }
            } else {
                out.push_back(c);
            }
        }
        err("unterminated string");
        return {};
    }

    Value parse_string_value() { return Value(parse_string()); }

    Value parse_bool() {
        if (match_literal("true")) return Value(true);
        if (match_literal("false")) return Value(false);
        err("expected true/false");
        return {};
    }

    Value parse_null() {
        if (match_literal("null")) return Value();
        err("expected null");
        return {};
    }

    Value parse_number() {
        std::size_t start = i;
        bool is_float = false;
        if (i < s.size() && s[i] == '-') ++i;
        while (i < s.size() && (std::isdigit(static_cast<unsigned char>(s[i])))) ++i;
        if (i < s.size() && s[i] == '.') {
            is_float = true; ++i;
            while (i < s.size() && (std::isdigit(static_cast<unsigned char>(s[i])))) ++i;
        }
        if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
            is_float = true; ++i;
            if (i < s.size() && (s[i] == '+' || s[i] == '-')) ++i;
            while (i < s.size() && (std::isdigit(static_cast<unsigned char>(s[i])))) ++i;
        }
        std::string tok(s.substr(start, i - start));
        if (tok.empty()) err("bad number");
        if (is_float) {
            return Value(std::stod(tok));
        }
        try {
            return Value(static_cast<std::int64_t>(std::stoll(tok)));
        } catch (...) {
            return Value(std::stod(tok));
        }
    }
};

}  // namespace

Value parse(std::string_view text) {
    Parser p{text, 0};
    Value v = p.parse_value();
    p.skip_ws();
    if (p.i != text.size()) {
        // Trailing data is permitted only when whitespace; otherwise fail.
        // Many JSONL paths feed line-by-line so callers should split first.
    }
    return v;
}

// ---- Encoder ----

static void encode_string(std::string& out, const std::string& s) {
    out.push_back('"');
    for (std::size_t i = 0; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
}

static void encode_value(std::string& out, const Value& v) {
    switch (v.type()) {
        case Value::Type::Null: out += "null"; break;
        case Value::Type::Bool: out += v.as_bool() ? "true" : "false"; break;
        case Value::Type::Int: {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%lld",
                          static_cast<long long>(v.as_int()));
            out += buf;
            break;
        }
        case Value::Type::Double: {
            double d = v.as_double();
            if (std::isnan(d) || std::isinf(d)) { out += "null"; break; }
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.17g", d);
            out += buf;
            break;
        }
        case Value::Type::String: encode_string(out, v.as_string()); break;
        case Value::Type::ArrayT: {
            out.push_back('[');
            bool first = true;
            for (const auto& el : v.as_array()) {
                if (!first) out.push_back(',');
                first = false;
                encode_value(out, el);
            }
            out.push_back(']');
            break;
        }
        case Value::Type::ObjectT: {
            out.push_back('{');
            bool first = true;
            // std::map is already key-sorted (lexicographic on raw bytes),
            // matching JSON::PP->canonical for ASCII keys.
            for (const auto& kv : v.as_object()) {
                if (!first) out.push_back(',');
                first = false;
                encode_string(out, kv.first);
                out.push_back(':');
                encode_value(out, kv.second);
            }
            out.push_back('}');
            break;
        }
    }
}

std::string encode(const Value& v) {
    std::string out;
    encode_value(out, v);
    return out;
}

}  // namespace forensicator::json
