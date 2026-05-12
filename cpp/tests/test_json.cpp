#include "forensicator/json.hpp"

#include <cassert>
#include <iostream>
#include <string>

using namespace forensicator::json;

int main() {
    {
        Value v = parse(R"({"b":1,"a":2})");
        assert(v.is_object());
        assert(v.at("a").as_int() == 2);
        // Canonical encode sorts keys alphabetically.
        assert(encode(v) == "{\"a\":2,\"b\":1}");
    }
    {
        Object o;
        o["hostname"] = Value("h");
        o["sha512"] = Value();  // null
        o["size"] = Value(static_cast<long long>(123));
        std::string s = encode(Value(std::move(o)));
        assert(s == "{\"hostname\":\"h\",\"sha512\":null,\"size\":123}");
    }
    {
        Value v = parse("[1,2,3]");
        assert(v.is_array() && v.as_array().size() == 3);
    }
    {
        // string with escapes
        Value v = parse("\"a\\nb\"");
        assert(v.is_string() && v.as_string() == "a\nb");
        assert(encode(v) == "\"a\\nb\"");
    }
    {
        // unicode escape
        Value v = parse("\"\\u00e9\"");
        // U+00E9 = c3 a9 in UTF-8
        assert(v.as_string() == "\xc3\xa9");
    }
    std::cout << "test_json ok\n";
    return 0;
}
