#include "forensicator/catalog.hpp"
#include "forensicator/hashlog.hpp"
#include "forensicator/json.hpp"
#include "forensicator/pathnorm.hpp"
#include "forensicator/util.hpp"

#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace forensicator {

struct MergeOpts {
    std::string output;
    std::string rehash_list;
    std::string dataset;
    bool quiet = false;
    std::vector<std::string> inputs;
};

static void merge_usage() {
    std::cout <<
        "forensicator merge: combine multiple catalogs/JSONL into one\n\n"
        "Usage:\n"
        "  forensicator merge --output FILE --inputs A [B ...]\n\n"
        "Options:\n"
        "  --output FILE        Output catalog (.sqlite) or export (.jsonl)\n"
        "  --inputs FILE...     One or more inputs (.sqlite or .jsonl)\n"
        "  --rehash-list FILE   Write JSONL of size-collision rows missing sha512\n"
        "  --dataset NAME       Dataset label for output catalog\n"
        "  --quiet, -q          Suppress progress output\n"
        "  --help, -h           This message\n";
}

namespace {

struct Row {
    std::string hostname;
    std::string volume;
    std::string mount_point;
    std::string os;
    std::string path;
    std::string path_norm;
    std::int64_t size = 0;
    std::int64_t mtime = 0;
    std::optional<std::string> sha512;
    std::int64_t scanned_at = 0;
};

static bool ends_with_ci(const std::string& s, const std::string& suf) {
    if (s.size() < suf.size()) return false;
    for (std::size_t i = 0; i < suf.size(); ++i) {
        char a = s[s.size() - suf.size() + i];
        char b = suf[i];
        if (std::tolower(static_cast<unsigned char>(a)) !=
            std::tolower(static_cast<unsigned char>(b))) return false;
    }
    return true;
}

}  // namespace

int cmd_merge(int argc, char** argv, const std::string& exe_path) {
    MergeOpts opt;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") { merge_usage(); return 0; }
        else if (a == "--output") { if (i + 1 >= argc) { std::cerr << "--output needs value\n"; return 2; } opt.output = argv[++i]; }
        else if (a == "--inputs") {
            // gobble until next --flag or end
            while (i + 1 < argc) {
                std::string v = argv[i + 1];
                if (v.size() >= 2 && v[0] == '-' && v[1] == '-') break;
                opt.inputs.push_back(v);
                ++i;
            }
        }
        else if (a == "--rehash-list") { if (i + 1 >= argc) { std::cerr << "--rehash-list needs value\n"; return 2; } opt.rehash_list = argv[++i]; }
        else if (a == "--dataset") { if (i + 1 >= argc) { std::cerr << "--dataset needs value\n"; return 2; } opt.dataset = argv[++i]; }
        else if (a == "--quiet" || a == "-q") opt.quiet = true;
        else { std::cerr << "unknown option: " << a << "\n"; return 2; }
    }
    if (opt.output.empty())  { std::cerr << "missing --output\n"; return 2; }
    if (opt.inputs.empty())  { std::cerr << "missing --inputs\n"; return 2; }

    std::string schema = find_schema_file(exe_path);
    if (schema.empty()) { std::cerr << "cannot locate schema/forensicator.sql\n"; return 2; }

    bool out_jsonl = ends_with_ci(opt.output, ".jsonl");

    if (!out_jsonl && std::filesystem::exists(opt.output)) {
        std::cerr << "refusing to overwrite existing output: " << opt.output << "\n";
        return 2;
    }

    auto log = [&](const std::string& m) {
        if (!opt.quiet) std::cerr << "[merge] " << m << "\n";
    };

    std::unique_ptr<Catalog> out_cat;
    std::unique_ptr<std::ofstream> jsonl_out;

    if (out_jsonl) {
        jsonl_out = std::make_unique<std::ofstream>(opt.output, std::ios::out | std::ios::binary);
        if (!*jsonl_out) { std::cerr << opt.output << ": cannot open\n"; return 2; }
    } else {
        out_cat = std::make_unique<Catalog>();
        std::optional<std::string> ds;
        if (!opt.dataset.empty()) ds = opt.dataset;
        try { out_cat->open(opt.output, schema, false, ds); }
        catch (const std::exception& e) { std::cerr << e.what() << "\n"; return 2; }
    }

    std::int64_t total_rows = 0, total_conflicts = 0, total_hash_disagreements = 0;

    std::unordered_map<std::string, std::int64_t> vol_id_cache;
    auto volume_id = [&](const std::string& host, const std::string& vol,
                         const std::string& mount, const std::string& os) -> std::int64_t {
        std::string k = host + std::string(1, '\0') + vol;
        auto it = vol_id_cache.find(k);
        if (it != vol_id_cache.end()) return it->second;
        Volume v = out_cat->upsert_volume(host, vol, mount, os);
        vol_id_cache[k] = v.volume_id;
        return v.volume_id;
    };

    std::unique_ptr<Statement> upsert_sth;
    std::unique_ptr<Statement> check_sth;
    if (out_cat) {
        upsert_sth = std::make_unique<Statement>(out_cat->raw(),
            "INSERT INTO files(volume_id, path, path_norm, size, mtime, sha512, scanned_at) "
            "VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(volume_id, path_norm) DO UPDATE SET "
            "  path = CASE WHEN excluded.scanned_at >= files.scanned_at "
            "             THEN excluded.path ELSE files.path END, "
            "  size = CASE WHEN excluded.scanned_at >= files.scanned_at "
            "             THEN excluded.size ELSE files.size END, "
            "  mtime = CASE WHEN excluded.scanned_at >= files.scanned_at "
            "              THEN excluded.mtime ELSE files.mtime END, "
            "  sha512 = CASE "
            "             WHEN excluded.scanned_at >= files.scanned_at AND excluded.sha512 IS NOT NULL "
            "               THEN excluded.sha512 "
            "             WHEN files.sha512 IS NULL "
            "               THEN excluded.sha512 "
            "             ELSE files.sha512 "
            "           END, "
            "  scanned_at = MAX(excluded.scanned_at, files.scanned_at)");
        check_sth = std::make_unique<Statement>(out_cat->raw(),
            "SELECT size, sha512, scanned_at FROM files WHERE volume_id = ? AND path_norm = ?");
    }

    auto ingest_row = [&](const Row& row) {
        ++total_rows;
        if (out_cat) {
            std::int64_t vid = volume_id(row.hostname, row.volume, row.mount_point, row.os);
            check_sth->reset();
            check_sth->clear_bindings();
            check_sth->bind(1, vid);
            check_sth->bind(2, row.path_norm);
            if (check_sth->step()) {
                ++total_conflicts;
                auto existing_sha = check_sth->col_text_optional(1);
                if (existing_sha.has_value() && row.sha512.has_value() && *existing_sha != *row.sha512) {
                    ++total_hash_disagreements;
                    if (!opt.quiet) {
                        std::cerr << "[merge] hash disagreement on "
                                  << row.hostname << ":" << row.volume << ":" << row.path << "\n";
                    }
                }
            }
            check_sth->reset();
            upsert_sth->reset();
            upsert_sth->clear_bindings();
            upsert_sth->bind(1, vid);
            upsert_sth->bind(2, row.path);
            upsert_sth->bind(3, row.path_norm);
            upsert_sth->bind(4, row.size);
            upsert_sth->bind(5, row.mtime);
            upsert_sth->bind_optional(6, row.sha512);
            upsert_sth->bind(7, row.scanned_at);
            upsert_sth->step();
        } else {
            json::Object o;
            o["hostname"]    = json::Value(row.hostname);
            o["volume"]      = json::Value(row.volume);
            o["mount_point"] = json::Value(row.mount_point);
            o["os"]          = json::Value(row.os);
            o["path"]        = json::Value(row.path);
            o["path_norm"]   = json::Value(row.path_norm);
            o["size"]        = json::Value(row.size);
            o["mtime"]       = json::Value(row.mtime);
            if (row.sha512.has_value()) o["sha512"] = json::Value(*row.sha512);
            else o["sha512"] = json::Value();
            o["scanned_at"]  = json::Value(row.scanned_at);
            *jsonl_out << json::encode(json::Value(std::move(o))) << "\n";
        }
    };

    auto ingest_sqlite = [&](const std::string& path) {
        log("ingesting sqlite: " + path);
        Catalog in;
        in.open(path, schema, true);
        auto vols = in.volumes();
        std::int64_t count = 0;
        for (const auto& v : vols) {
            Statement st(in.raw(),
                "SELECT path, path_norm, size, mtime, sha512, scanned_at FROM files WHERE volume_id = ?");
            st.bind(1, v.volume_id);
            while (st.step()) {
                Row r;
                r.hostname = v.hostname;
                r.volume = v.volume;
                r.mount_point = v.mount_point;
                r.os = v.os;
                r.path = st.col_text(0);
                r.path_norm = st.col_text(1);
                r.size = st.col_int64(2);
                r.mtime = st.col_int64(3);
                r.sha512 = st.col_text_optional(4);
                r.scanned_at = st.col_int64(5);
                ingest_row(r);
                ++count;
                if (out_cat && count % 5000 == 0) {
                    out_cat->commit();
                    out_cat->begin();
                }
            }
        }
        log("  " + std::to_string(count) + " rows from " + path);
    };

    auto ingest_jsonl = [&](const std::string& path) {
        log("ingesting jsonl: " + path);
        std::ifstream ifs(path);
        if (!ifs) { std::cerr << path << ": cannot open\n"; return; }
        std::string line;
        std::int64_t count = 0;
        while (std::getline(ifs, line)) {
            if (line.empty()) continue;
            json::Value v;
            try { v = json::parse(line); } catch (...) { continue; }
            if (!v.is_object()) continue;
            Row r;
            if (!v.contains("hostname") || !v.contains("volume") || !v.contains("path")) continue;
            r.hostname = v.at("hostname").as_string();
            r.volume = v.at("volume").as_string();
            r.path = v.at("path").as_string();
            r.mount_point = v.contains("mount_point") && v.at("mount_point").is_string()
                ? v.at("mount_point").as_string() : "";
            r.os = v.contains("os") && v.at("os").is_string() ? v.at("os").as_string() : "";
            r.path_norm = (v.contains("path_norm") && v.at("path_norm").is_string())
                ? v.at("path_norm").as_string()
                : normalize_path(r.path, r.os);
            r.scanned_at = v.contains("scanned_at") && v.at("scanned_at").is_number()
                ? v.at("scanned_at").as_int() : now_epoch();
            r.mtime = v.contains("mtime") && v.at("mtime").is_number() ? v.at("mtime").as_int() : 0;
            r.size = v.contains("size") && v.at("size").is_number() ? v.at("size").as_int() : 0;
            if (v.contains("sha512") && v.at("sha512").is_string()) r.sha512 = v.at("sha512").as_string();
            ingest_row(r);
            ++count;
            if (out_cat && count % 5000 == 0) {
                out_cat->commit();
                out_cat->begin();
            }
        }
        log("  " + std::to_string(count) + " rows from " + path);
    };

    if (out_cat) out_cat->begin();

    for (const auto& input : opt.inputs) {
        if (ends_with_ci(input, ".jsonl")) {
            ingest_jsonl(input);
        } else if (ends_with_ci(input, ".sqlite") || ends_with_ci(input, ".db")) {
            ingest_sqlite(input);
        } else {
            // Sniff first 16 bytes.
            std::ifstream ifs(input, std::ios::binary);
            if (!ifs) { std::cerr << "no such input: " << input << "\n"; return 2; }
            char head[16] = {0};
            ifs.read(head, 15);
            std::string sniff(head, head + 15);
            if (sniff.rfind("SQLite format 3", 0) == 0) ingest_sqlite(input);
            else ingest_jsonl(input);
        }
    }

    if (out_cat) out_cat->commit();
    if (jsonl_out) jsonl_out->close();

    log("merged " + std::to_string(total_rows) + " rows from "
        + std::to_string(opt.inputs.size()) + " inputs");
    if (total_conflicts)
        log(std::to_string(total_conflicts) + " duplicate (host,volume,path) rows reconciled");
    if (total_hash_disagreements)
        log(std::to_string(total_hash_disagreements) + " rows had disagreeing SHA512 (newest scan kept)");

    if (!opt.rehash_list.empty() && out_cat) {
        log("writing rehash list: " + opt.rehash_list);
        std::ofstream rfs(opt.rehash_list, std::ios::out | std::ios::binary);
        if (!rfs) { std::cerr << opt.rehash_list << ": cannot open\n"; return 2; }
        Statement st(out_cat->raw(),
            "SELECT v.hostname, v.volume, v.mount_point, f.path, f.path_norm, f.size "
            "FROM files f JOIN volumes v ON v.volume_id = f.volume_id "
            "WHERE f.sha512 IS NULL AND f.size IN "
            "  (SELECT size FROM files GROUP BY size HAVING COUNT(*) > 1) "
            "ORDER BY v.hostname, v.volume, f.path_norm");
        std::int64_t n = 0;
        while (st.step()) {
            json::Object o;
            o["hostname"]    = json::Value(st.col_text(0));
            o["volume"]      = json::Value(st.col_text(1));
            o["mount_point"] = json::Value(st.col_text(2));
            o["path"]        = json::Value(st.col_text(3));
            o["path_norm"]   = json::Value(st.col_text(4));
            o["size"]        = json::Value(st.col_int64(5));
            rfs << json::encode(json::Value(std::move(o))) << "\n";
            ++n;
        }
        rfs.close();
        log("rehash list: " + std::to_string(n) + " entries");
    }
    return 0;
}

}  // namespace forensicator
