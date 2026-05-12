#include "forensicator/catalog.hpp"
#include "forensicator/hashlog.hpp"
#include "forensicator/json.hpp"
#include "forensicator/pathnorm.hpp"
#include "forensicator/pipeline.hpp"
#include "forensicator/sha512.hpp"
#include "forensicator/util.hpp"
#include "forensicator/walker.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace forensicator {

struct ScanOpts {
    std::string catalog;
    std::string volume;
    std::string root;
    std::string hostname;
    std::string mount_point;
    std::string dataset;
    std::string hashlog_path;
    std::string rehash_list;
    bool full_hash = false;
    bool rehash = false;
    bool quiet = false;
    bool no_hashlog = false;
    int progress_every = 1000;
    int commit_every = 500;
    int hash_threads = 0;
    int queue_capacity = 4096;
};

static void scan_usage() {
    std::cout <<
        "forensicator scan: walk a volume and record files in a catalog\n\n"
        "Usage:\n"
        "  forensicator scan --catalog FILE --volume NAME --root DIR [opts]\n"
        "  forensicator scan --catalog FILE --rehash --volume NAME --root DIR\n"
        "  forensicator scan --catalog FILE --rehash-list FILE --volume NAME --root DIR\n\n"
        "Options:\n"
        "  --catalog FILE        SQLite catalog (created if missing)\n"
        "  --volume NAME         Logical volume name (sticks with the data)\n"
        "  --root DIR            Directory to scan / mount point for rehash\n"
        "  --hostname NAME       Override hostname (default: short hostname)\n"
        "  --mount-point DIR     Record mount point (default: --root)\n"
        "  --full-hash           Hash every file (default: only size collisions)\n"
        "  --rehash              Hash files in this catalog with NULL sha512 (no walk)\n"
        "  --rehash-list FILE    JSONL of {hostname,volume,path} entries to hash\n"
        "  --dataset NAME        Dataset label (stored in catalog metadata)\n"
        "  --progress-every N    Log progress every N files (default 1000)\n"
        "  --commit-every N      Commit transaction every N rows (default 500)\n"
        "  --hash-threads N      Hasher threads (default: hardware concurrency)\n"
        "  --quiet               Suppress progress output\n"
        "  --hashlog FILE        Append-only JSONL recovery log\n"
        "  --no-hashlog          Disable the hashlog\n"
        "  --help, -h            This message\n";
}

static void log_progress(const ScanOpts& o, const std::string& msg) {
    if (o.quiet) return;
    std::cerr << "[scan] " << msg << "\n";
}

static std::string take_value(int& i, int argc, char** argv, const char* flag) {
    if (i + 1 >= argc) throw std::runtime_error(std::string(flag) + " requires a value");
    return argv[++i];
}

static int parse_scan_args(int argc, char** argv, ScanOpts& o) {
    o.hostname = default_hostname();
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") { scan_usage(); return 1; }
        else if (a == "--catalog") o.catalog = take_value(i, argc, argv, "--catalog");
        else if (a == "--volume")  o.volume  = take_value(i, argc, argv, "--volume");
        else if (a == "--root")    o.root    = take_value(i, argc, argv, "--root");
        else if (a == "--hostname") o.hostname = take_value(i, argc, argv, "--hostname");
        else if (a == "--mount-point") o.mount_point = take_value(i, argc, argv, "--mount-point");
        else if (a == "--dataset") o.dataset = take_value(i, argc, argv, "--dataset");
        else if (a == "--hashlog") o.hashlog_path = take_value(i, argc, argv, "--hashlog");
        else if (a == "--rehash-list") o.rehash_list = take_value(i, argc, argv, "--rehash-list");
        else if (a == "--full-hash") o.full_hash = true;
        else if (a == "--rehash") o.rehash = true;
        else if (a == "--no-hashlog") o.no_hashlog = true;
        else if (a == "--quiet" || a == "-q") o.quiet = true;
        else if (a == "--progress-every") o.progress_every = std::stoi(take_value(i, argc, argv, "--progress-every"));
        else if (a == "--commit-every")   o.commit_every   = std::stoi(take_value(i, argc, argv, "--commit-every"));
        else if (a == "--hash-threads")   o.hash_threads   = std::stoi(take_value(i, argc, argv, "--hash-threads"));
        else throw std::runtime_error("unknown option: " + a);
    }
    return 0;
}

// ---- Pipeline records ----

namespace {

struct WalkMsg {
    std::filesystem::path absolute;
    std::string rel_path;
    std::string path_norm;
    std::int64_t size = 0;
    std::int64_t mtime = 0;
};

struct HashTask {
    std::int64_t file_id = 0;
    std::filesystem::path absolute;
    std::string rel_path;
    std::string path_norm;
    std::int64_t size = 0;
    std::int64_t mtime = 0;
};

struct HashResult {
    std::int64_t file_id = 0;
    std::string rel_path;
    std::string path_norm;
    std::int64_t size = 0;
    std::int64_t mtime = 0;
    std::optional<std::string> sha512;
    bool error = false;
};

// One queue feeds the recorder; messages are tagged.
struct RecorderEvent {
    enum class Kind { Walk, Hash };
    Kind kind;
    WalkMsg walk;
    HashResult hash;
};

}  // namespace

static int do_scan(const ScanOpts& opt,
                   const std::filesystem::path& schema_sql_path) {
    namespace fs = std::filesystem;
    if (opt.catalog.empty()) { std::cerr << "missing --catalog\n"; return 2; }
    if (opt.volume.empty())  { std::cerr << "missing --volume\n";  return 2; }
    if (opt.root.empty())    { std::cerr << "missing --root\n";    return 2; }
    if (!fs::is_directory(opt.root)) {
        std::cerr << "root not a directory: " << opt.root << "\n";
        return 2;
    }

    Catalog cat;
    std::optional<std::string> dataset;
    if (!opt.dataset.empty()) dataset = opt.dataset;
    cat.open(opt.catalog, schema_sql_path, false, dataset);

    std::string mount = opt.mount_point.empty() ? opt.root : opt.mount_point;
    Volume vol = cat.upsert_volume(opt.hostname, opt.volume, mount, os_name());
    std::int64_t vid = vol.volume_id;

    std::string hashlog_path;
    if (!opt.no_hashlog) {
        hashlog_path = opt.hashlog_path.empty()
            ? (opt.catalog + ".hashlog.jsonl")
            : opt.hashlog_path;
    }
    Hashlog hashlog(hashlog_path);
    if (!opt.quiet && hashlog.enabled()) {
        std::cerr << "[scan] hashlog: " << hashlog_path << "\n";
    }

    int n_hash = opt.hash_threads > 0
                    ? opt.hash_threads
                    : static_cast<int>(std::max(1u, std::thread::hardware_concurrency()));

    // Queues:
    //   walk_q: walker -> walk_forwarder. This is the only back-pressure point
    //           in the system; bound it so memory stays in check.
    //   hash_q: recorder -> hashers. Effectively unbounded because the
    //           producer (recorder) is already rate-limited by walk_q.
    //   events: feeders -> recorder. Effectively unbounded because the
    //           producers are rate-limited by walk_q and by the hashers'
    //           CPU speed, and avoiding back-pressure here is required to
    //           prevent a deadlock between events and hash_q.
    BoundedQueue<WalkMsg>        walk_q(static_cast<std::size_t>(opt.queue_capacity));
    BoundedQueue<HashTask>       hash_q(static_cast<std::size_t>(-1));
    BoundedQueue<RecorderEvent>  events(static_cast<std::size_t>(-1));

    std::atomic<std::uint64_t> n_seen{0};
    std::atomic<std::uint64_t> n_hashed{0};
    std::atomic<std::uint64_t> n_skipped{0};
    std::atomic<std::uint64_t> n_errors{0};
    std::int64_t started = now_epoch();

    // ---- Walker thread ----
    std::thread walker_thr([&] {
        WalkStats ws = walk_tree(opt.root, os_name(), [&](WalkedFile wf) {
            WalkMsg m{wf.absolute, wf.rel_path, wf.path_norm, wf.size, wf.mtime};
            walk_q.push(std::move(m));
        });
        n_skipped += ws.skipped;
        n_errors  += ws.errors;
        walk_q.close();
    });

    // ---- Walk forwarder ----
    std::thread walk_fwd([&] {
        while (true) {
            auto m = walk_q.pop();
            if (!m) break;
            RecorderEvent ev;
            ev.kind = RecorderEvent::Kind::Walk;
            ev.walk = std::move(*m);
            events.push(std::move(ev));
        }
    });

    // When the walker finishes and the forwarder has drained walk_q, push a
    // sentinel into the events stream so the recorder can run the final
    // size-collision sweep and then close hash_q.
    std::thread walk_done_setter([&] {
        walker_thr.join();
        walk_fwd.join();
        RecorderEvent sentinel;
        sentinel.kind = RecorderEvent::Kind::Walk;
        sentinel.walk.size = -1;  // sentinel marker (real files are size > 0)
        events.push(std::move(sentinel));
    });

    // ---- Hasher pool ----
    std::atomic<int> active_hashers{n_hash};
    std::vector<std::thread> hashers;
    hashers.reserve(static_cast<std::size_t>(n_hash));
    for (int i = 0; i < n_hash; ++i) {
        hashers.emplace_back([&] {
            while (true) {
                auto maybe = hash_q.pop();
                if (!maybe) break;
                HashTask t = std::move(*maybe);
                auto sha = sha512_file(t.absolute);
                RecorderEvent ev;
                ev.kind = RecorderEvent::Kind::Hash;
                ev.hash.file_id = t.file_id;
                ev.hash.rel_path = std::move(t.rel_path);
                ev.hash.path_norm = std::move(t.path_norm);
                ev.hash.size = t.size;
                ev.hash.mtime = t.mtime;
                if (sha.has_value()) {
                    ev.hash.sha512 = std::move(*sha);
                    n_hashed.fetch_add(1, std::memory_order_relaxed);
                } else {
                    ev.hash.error = true;
                    n_errors.fetch_add(1, std::memory_order_relaxed);
                }
                events.push(std::move(ev));
            }
            if (active_hashers.fetch_sub(1) == 1) {
                // last hasher to exit: signal recorder via events.close()
                events.close();
            }
        });
    }

    // ---- Recorder thread (single, owns SQLite) ----
    std::thread recorder_thr([&] {
        Statement ins(cat.raw(),
            "INSERT INTO files(volume_id, path, path_norm, size, mtime, sha512, scanned_at) "
            "VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(volume_id, path_norm) DO UPDATE SET "
            "path=excluded.path, size=excluded.size, mtime=excluded.mtime, "
            "sha512=COALESCE(excluded.sha512, files.sha512), "
            "scanned_at=excluded.scanned_at");
        Statement get_existing(cat.raw(),
            "SELECT file_id, size, mtime, sha512 FROM files WHERE volume_id = ? AND path_norm = ?");
        Statement get_id(cat.raw(),
            "SELECT file_id FROM files WHERE volume_id = ? AND path_norm = ?");
        Statement upd_sha(cat.raw(),
            "UPDATE files SET sha512 = ? WHERE file_id = ?");

        std::unordered_map<std::int64_t, std::vector<HashTask>> by_size_pending;
        std::unordered_map<std::int64_t, bool> size_already_hashed;

        cat.begin();
        std::uint64_t since_commit = 0;

        auto maybe_commit = [&] {
            if (since_commit >= static_cast<std::uint64_t>(opt.commit_every)) {
                cat.commit();
                cat.begin();
                since_commit = 0;
            }
        };

        bool sweep_done = false;
        bool hash_q_closed = false;

        while (true) {
            auto ev_opt = events.pop();
            if (!ev_opt) {
                // events closed -> all hashers drained -> done.
                break;
            }
            RecorderEvent ev = std::move(*ev_opt);

            if (ev.kind == RecorderEvent::Kind::Hash) {
                const HashResult& r = ev.hash;
                if (!r.error && r.sha512.has_value()) {
                    upd_sha.reset();
                    upd_sha.clear_bindings();
                    upd_sha.bind(1, *r.sha512);
                    upd_sha.bind(2, r.file_id);
                    upd_sha.step();
                    HashlogRecord rec;
                    rec.hostname = opt.hostname;
                    rec.volume = opt.volume;
                    rec.mount_point = mount;
                    rec.os = os_name();
                    rec.path = r.rel_path;
                    rec.path_norm = r.path_norm;
                    rec.size = r.size;
                    rec.mtime = r.mtime;
                    rec.sha512 = r.sha512;
                    rec.scanned_at = now_epoch();
                    hashlog.write(rec);
                    ++since_commit;
                    maybe_commit();
                }
                continue;
            }

            // Walk event.
            // Sentinel: size == -1 means "walker finished, time to consider
            // the post-walk sweep". Real files always have size > 0 (we skip
            // zero-byte files in the walker).
            if (ev.walk.size < 0) {
                if (sweep_done) continue;
                sweep_done = true;
                // Final sweep: any rows with NULL sha512 whose size collides
                // with another row still need hashing (covers prior runs).
                Statement sweep(cat.raw(),
                    "SELECT f.file_id, f.path, f.path_norm, f.size, f.mtime, v.mount_point "
                    "FROM files f JOIN volumes v ON v.volume_id = f.volume_id "
                    "WHERE f.sha512 IS NULL AND f.size IN "
                    "  (SELECT size FROM files GROUP BY size HAVING COUNT(*) > 1)");
                std::vector<HashTask> todo;
                while (sweep.step()) {
                    HashTask t;
                    t.file_id = sweep.col_int64(0);
                    t.rel_path = sweep.col_text(1);
                    t.path_norm = sweep.col_text(2);
                    t.size = sweep.col_int64(3);
                    t.mtime = sweep.col_int64(4);
                    std::string mp = sweep.col_text(5);
                    if (mp.empty()) continue;
                    std::filesystem::path abs = std::filesystem::path(mp) / t.rel_path;
                    std::error_code ec;
                    if (!std::filesystem::is_regular_file(abs, ec)) continue;
                    t.absolute = std::move(abs);
                    todo.push_back(std::move(t));
                }
                if (!todo.empty()) {
                    log_progress(opt, "hashing " + std::to_string(todo.size()) +
                                 " size-collision files across all reachable volumes...");
                }
                for (auto& t : todo) hash_q.push(std::move(t));
                hash_q.close();
                hash_q_closed = true;
                continue;
            }

            const WalkMsg& m = ev.walk;
            std::optional<std::string> existing_sha;
            std::int64_t existing_size = -1;
            std::int64_t existing_mtime = -1;
            bool had_existing = false;
            get_existing.reset();
            get_existing.clear_bindings();
            get_existing.bind(1, vid);
            get_existing.bind(2, m.path_norm);
            if (get_existing.step()) {
                had_existing = true;
                existing_size = get_existing.col_int64(1);
                existing_mtime = get_existing.col_int64(2);
                existing_sha = get_existing.col_text_optional(3);
            }
            get_existing.reset();

            bool unchanged = had_existing &&
                             existing_size == m.size &&
                             existing_mtime == m.mtime;
            std::optional<std::string> initial_sha;
            if (unchanged && existing_sha.has_value()) {
                initial_sha = existing_sha;
            }

            std::int64_t scanned = now_epoch();
            HashlogRecord rec;
            rec.hostname = opt.hostname;
            rec.volume = opt.volume;
            rec.mount_point = mount;
            rec.os = os_name();
            rec.path = m.rel_path;
            rec.path_norm = m.path_norm;
            rec.size = m.size;
            rec.mtime = m.mtime;
            rec.sha512 = initial_sha;
            rec.scanned_at = scanned;
            hashlog.write(rec);

            ins.reset();
            ins.clear_bindings();
            ins.bind(1, vid);
            ins.bind(2, m.rel_path);
            ins.bind(3, m.path_norm);
            ins.bind(4, m.size);
            ins.bind(5, m.mtime);
            ins.bind_optional(6, initial_sha);
            ins.bind(7, scanned);
            ins.step();

            std::int64_t fid = 0;
            get_id.reset();
            get_id.clear_bindings();
            get_id.bind(1, vid);
            get_id.bind(2, m.path_norm);
            if (get_id.step()) fid = get_id.col_int64(0);
            get_id.reset();

            ++since_commit;
            maybe_commit();
            std::uint64_t seen = n_seen.fetch_add(1, std::memory_order_relaxed) + 1;
            if (seen % static_cast<std::uint64_t>(opt.progress_every) == 0) {
                std::int64_t el = now_epoch() - started;
                if (el <= 0) el = 1;
                double rate = static_cast<double>(seen) / static_cast<double>(el);
                char buf[256];
                if (opt.full_hash) {
                    std::snprintf(buf, sizeof(buf),
                        "walk: %llu files, %llu hashed, %llu skipped, %llu errors, %s elapsed (%.0f/s)",
                        (unsigned long long)seen,
                        (unsigned long long)n_hashed.load(),
                        (unsigned long long)n_skipped.load(),
                        (unsigned long long)n_errors.load(),
                        fmt_duration(el).c_str(), rate);
                } else {
                    std::snprintf(buf, sizeof(buf),
                        "walk: %llu files cataloged, %llu skipped, %llu errors, %s elapsed (%.0f/s) -- hashing happens after walk",
                        (unsigned long long)seen,
                        (unsigned long long)n_skipped.load(),
                        (unsigned long long)n_errors.load(),
                        fmt_duration(el).c_str(), rate);
                }
                log_progress(opt, buf);
            }

            if (initial_sha.has_value()) {
                // Already hashed, nothing to do.
                continue;
            }

            HashTask t;
            t.file_id = fid;
            t.absolute = m.absolute;
            t.rel_path = m.rel_path;
            t.path_norm = m.path_norm;
            t.size = m.size;
            t.mtime = m.mtime;

            if (opt.full_hash) {
                hash_q.push(std::move(t));
            } else {
                auto& vec = by_size_pending[m.size];
                if (size_already_hashed[m.size]) {
                    hash_q.push(std::move(t));
                } else {
                    vec.push_back(std::move(t));
                    if (vec.size() >= 2) {
                        for (auto& q : vec) hash_q.push(std::move(q));
                        vec.clear();
                        size_already_hashed[m.size] = true;
                    }
                }
            }
        }

        // Defensive: if we somehow exit before closing hash_q (e.g. events
        // closed while sweep was never reached), close now so hashers exit.
        if (!hash_q_closed) hash_q.close();
        cat.commit();
    });

    walk_done_setter.join();
    for (auto& t : hashers) t.join();
    recorder_thr.join();

    std::int64_t el = now_epoch() - started;
    char buf[256];
    std::snprintf(buf, sizeof(buf),
        "FINAL: %llu files, %llu hashed, %llu skipped, %llu errors, %lds",
        (unsigned long long)n_seen.load(),
        (unsigned long long)n_hashed.load(),
        (unsigned long long)n_skipped.load(),
        (unsigned long long)n_errors.load(),
        (long)el);
    log_progress(opt, buf);
    return 0;
}

// ---- Rehash path (single-threaded) ----

static int do_rehash(const ScanOpts& opt,
                     const std::filesystem::path& schema_sql_path) {
    namespace fs = std::filesystem;
    if (opt.volume.empty()) { std::cerr << "rehash needs --volume\n"; return 2; }
    if (opt.root.empty())   { std::cerr << "rehash needs --root\n";   return 2; }
    if (!fs::is_directory(opt.root)) {
        std::cerr << "root not a directory: " << opt.root << "\n";
        return 2;
    }

    Catalog cat;
    cat.open(opt.catalog, schema_sql_path, false);
    auto vol = cat.get_volume(opt.hostname, opt.volume);
    if (!vol) {
        std::cerr << "volume not in catalog: " << opt.hostname << ":" << opt.volume << "\n";
        return 2;
    }
    if (!opt.mount_point.empty() && opt.mount_point != vol->mount_point) {
        Statement st(cat.raw(), "UPDATE volumes SET mount_point = ? WHERE volume_id = ?");
        st.bind(1, opt.mount_point);
        st.bind(2, vol->volume_id);
        st.step();
    }

    std::string hashlog_path;
    if (!opt.no_hashlog) {
        hashlog_path = opt.hashlog_path.empty()
            ? (opt.catalog + ".hashlog.jsonl")
            : opt.hashlog_path;
    }
    Hashlog hashlog(hashlog_path);

    struct Row {
        std::int64_t file_id;
        std::string path;
        std::string path_norm;
        std::int64_t size;
        std::int64_t mtime;
    };
    std::vector<Row> rows;

    if (!opt.rehash_list.empty()) {
        std::ifstream ifs(opt.rehash_list);
        if (!ifs) { std::cerr << opt.rehash_list << ": cannot open\n"; return 2; }
        std::string line;
        Statement st(cat.raw(),
            "SELECT file_id, path, path_norm, size, mtime FROM files "
            "WHERE volume_id = ? AND path_norm = ? AND sha512 IS NULL");
        while (std::getline(ifs, line)) {
            if (line.empty()) continue;
            json::Value v;
            try { v = json::parse(line); } catch (...) { continue; }
            if (!v.is_object()) continue;
            if (v.at("hostname").as_string() != opt.hostname) continue;
            if (v.at("volume").as_string() != opt.volume) continue;
            std::string norm = normalize_path(v.at("path").as_string(), os_name());
            st.reset();
            st.clear_bindings();
            st.bind(1, vol->volume_id);
            st.bind(2, norm);
            while (st.step()) {
                Row r;
                r.file_id = st.col_int64(0);
                r.path = st.col_text(1);
                r.path_norm = st.col_text(2);
                r.size = st.col_int64(3);
                r.mtime = st.col_int64(4);
                rows.push_back(std::move(r));
            }
        }
    } else {
        Statement st(cat.raw(),
            "SELECT file_id, path, path_norm, size, mtime FROM files "
            "WHERE volume_id = ? AND sha512 IS NULL");
        st.bind(1, vol->volume_id);
        while (st.step()) {
            Row r;
            r.file_id = st.col_int64(0);
            r.path = st.col_text(1);
            r.path_norm = st.col_text(2);
            r.size = st.col_int64(3);
            r.mtime = st.col_int64(4);
            rows.push_back(std::move(r));
        }
    }

    std::uint64_t total_bytes = 0;
    for (const auto& r : rows) total_bytes += static_cast<std::uint64_t>(r.size);
    if (!opt.quiet) {
        std::cerr << "[scan] " << rows.size() << " files to rehash ("
                  << fmt_bytes(total_bytes) << ")\n";
    }

    Statement upd(cat.raw(), "UPDATE files SET sha512 = ? WHERE file_id = ?");
    std::uint64_t hashed = 0, errors = 0, i = 0;
    std::int64_t started = now_epoch();
    cat.begin();
    for (const auto& r : rows) {
        ++i;
        std::filesystem::path abs = std::filesystem::path(opt.root) / r.path;
        std::error_code ec;
        if (!std::filesystem::is_regular_file(abs, ec)) {
            if (!opt.quiet) std::cerr << "[rehash] missing: " << abs.string() << "\n";
            ++errors;
            continue;
        }
        auto sha = sha512_file(abs);
        if (!sha) { ++errors; continue; }
        HashlogRecord rec;
        rec.hostname = opt.hostname;
        rec.volume = opt.volume;
        rec.mount_point = opt.root;
        rec.os = os_name();
        rec.path = r.path;
        rec.path_norm = r.path_norm;
        rec.size = r.size;
        rec.mtime = r.mtime;
        rec.sha512 = *sha;
        rec.scanned_at = now_epoch();
        hashlog.write(rec);

        upd.reset();
        upd.clear_bindings();
        upd.bind(1, *sha);
        upd.bind(2, r.file_id);
        upd.step();
        ++hashed;
        if (i % static_cast<std::uint64_t>(opt.commit_every) == 0) {
            cat.commit(); cat.begin();
        }
        if (i % static_cast<std::uint64_t>(opt.progress_every) == 0) {
            log_progress(opt, fmt_eta("rehash", i, rows.size(), started));
        }
    }
    cat.commit();
    if (!opt.quiet) {
        std::cerr << "[scan] rehash done: " << hashed << " hashed, "
                  << errors << " errors, " << fmt_duration(now_epoch() - started) << "\n";
    }
    return 0;
}

int cmd_scan(int argc, char** argv, const std::string& exe_path) {
    ScanOpts opt;
    try {
        if (int rc = parse_scan_args(argc, argv, opt); rc) return rc == 1 ? 0 : rc;
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\nsee --help\n";
        return 2;
    }
    std::string schema = find_schema_file(exe_path);
    if (schema.empty()) {
        std::cerr << "cannot locate schema/forensicator.sql; set FORENSICATOR_SCHEMA\n";
        return 2;
    }
    try {
        if (opt.rehash || !opt.rehash_list.empty()) {
            return do_rehash(opt, schema);
        }
        return do_scan(opt, schema);
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 2;
    }
}

}  // namespace forensicator
