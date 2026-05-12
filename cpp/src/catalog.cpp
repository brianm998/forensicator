#include "forensicator/catalog.hpp"

#include "forensicator/util.hpp"

#include <sqlite3.h>

#include <cstring>
#include <fstream>
#include <sstream>

namespace forensicator {

Statement::Statement(sqlite3* db, const std::string& sql) : db_(db) {
    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt_, nullptr);
    if (rc != SQLITE_OK) {
        throw CatalogError(std::string("prepare failed: ") +
                           sqlite3_errmsg(db) + " for: " + sql);
    }
}

Statement::~Statement() {
    if (stmt_) sqlite3_finalize(stmt_);
}

Statement::Statement(Statement&& o) noexcept
    : db_(o.db_), stmt_(o.stmt_) { o.db_ = nullptr; o.stmt_ = nullptr; }

Statement& Statement::operator=(Statement&& o) noexcept {
    if (this != &o) {
        if (stmt_) sqlite3_finalize(stmt_);
        db_ = o.db_;
        stmt_ = o.stmt_;
        o.db_ = nullptr;
        o.stmt_ = nullptr;
    }
    return *this;
}

void Statement::bind_null(int idx) {
    sqlite3_bind_null(stmt_, idx);
}

void Statement::bind(int idx, std::int64_t v) {
    sqlite3_bind_int64(stmt_, idx, v);
}

void Statement::bind(int idx, const std::string& v) {
    sqlite3_bind_text(stmt_, idx, v.data(),
                      static_cast<int>(v.size()), SQLITE_TRANSIENT);
}

void Statement::bind(int idx, std::string_view v) {
    sqlite3_bind_text(stmt_, idx, v.data(),
                      static_cast<int>(v.size()), SQLITE_TRANSIENT);
}

void Statement::bind(int idx, const char* v) {
    sqlite3_bind_text(stmt_, idx, v, -1, SQLITE_TRANSIENT);
}

void Statement::bind_optional(int idx, const std::optional<std::string>& v) {
    if (v.has_value()) bind(idx, *v);
    else bind_null(idx);
}

bool Statement::step() {
    int rc = sqlite3_step(stmt_);
    if (rc == SQLITE_ROW) return true;
    if (rc == SQLITE_DONE) return false;
    throw CatalogError(std::string("step failed: ") + sqlite3_errmsg(db_));
}

void Statement::reset() {
    sqlite3_reset(stmt_);
}

void Statement::clear_bindings() {
    sqlite3_clear_bindings(stmt_);
}

int Statement::col_int(int idx) const {
    return sqlite3_column_int(stmt_, idx);
}

std::int64_t Statement::col_int64(int idx) const {
    return sqlite3_column_int64(stmt_, idx);
}

std::string Statement::col_text(int idx) const {
    const unsigned char* s = sqlite3_column_text(stmt_, idx);
    if (!s) return {};
    int n = sqlite3_column_bytes(stmt_, idx);
    return std::string(reinterpret_cast<const char*>(s), n);
}

std::optional<std::string> Statement::col_text_optional(int idx) const {
    if (sqlite3_column_type(stmt_, idx) == SQLITE_NULL) return std::nullopt;
    return col_text(idx);
}

bool Statement::col_is_null(int idx) const {
    return sqlite3_column_type(stmt_, idx) == SQLITE_NULL;
}

// ---- Catalog ----

Catalog::Catalog() = default;

Catalog::~Catalog() { close(); }

void Catalog::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

void Catalog::probe_locking(const std::filesystem::path& dbpath) {
    // A trivial query to surface broken-locking failures up front.
    char* errmsg = nullptr;
    int rc = sqlite3_exec(db_, "SELECT 1 FROM sqlite_master LIMIT 1;",
                          nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        std::string msg = errmsg ? errmsg : "unknown";
        if (errmsg) sqlite3_free(errmsg);
        if (rc == SQLITE_IOERR || rc == SQLITE_BUSY || rc == SQLITE_LOCKED ||
            rc == SQLITE_PROTOCOL || rc == SQLITE_IOERR_LOCK) {
            std::ostringstream oss;
            oss << "cannot open catalog " << dbpath.string() << ": " << msg << "\n"
                << "This filesystem appears to have broken POSIX locking (SMB / NFS / exFAT /\n"
                << "some FUSE mounts). forensicator refuses to operate on such filesystems\n"
                << "because long-running scans corrupt SQLite there (\"database disk image is\n"
                << "malformed\"), and the previous nolock fallback caused real data loss.\n\n"
                << "Move the catalog to a local SSD/HDD with a normal filesystem (APFS / ext4\n"
                << "/ NTFS / HFS+) and re-run. The catalog records mount_point separately so\n"
                << "it can still find files on the original data volume, regardless of where\n"
                << "the SQLite file lives.\n";
            throw CatalogError(oss.str());
        }
        throw CatalogError("cannot open catalog " + dbpath.string() + ": " + msg);
    }
}

void Catalog::open(const std::filesystem::path& path,
                   const std::filesystem::path& schema_sql_path,
                   bool readonly,
                   std::optional<std::string> dataset) {
    int flags = readonly ? SQLITE_OPEN_READONLY
                         : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    int rc = sqlite3_open_v2(path.string().c_str(), &db_, flags, nullptr);
    if (rc != SQLITE_OK) {
        std::string err = db_ ? sqlite3_errmsg(db_) : "open failed";
        if (db_) { sqlite3_close(db_); db_ = nullptr; }
        throw CatalogError("cannot open catalog " + path.string() + ": " + err);
    }

    probe_locking(path);

    // Pragmas.
    if (!readonly) {
        char* err = nullptr;
        sqlite3_exec(db_, "PRAGMA journal_mode = WAL;", nullptr, nullptr, &err);
        if (err) { sqlite3_free(err); err = nullptr; }
        sqlite3_exec(db_, "PRAGMA synchronous = NORMAL;", nullptr, nullptr, &err);
        if (err) { sqlite3_free(err); err = nullptr; }
    }
    {
        char* err = nullptr;
        sqlite3_exec(db_, "PRAGMA foreign_keys = ON;", nullptr, nullptr, &err);
        if (err) sqlite3_free(err);
    }
    {
        char* err = nullptr;
        sqlite3_exec(db_, "PRAGMA cache_size = -200000;", nullptr, nullptr, &err);
        if (err) sqlite3_free(err);
    }

    // Check schema_version if meta exists.
    {
        sqlite3_stmt* st = nullptr;
        sqlite3_prepare_v2(db_,
            "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'",
            -1, &st, nullptr);
        bool has_meta = false;
        if (st && sqlite3_step(st) == SQLITE_ROW) has_meta = true;
        if (st) sqlite3_finalize(st);
        if (has_meta) {
            auto sv = get_meta("schema_version");
            int v = sv ? std::stoi(*sv) : 0;
            if (v != SCHEMA_VERSION) {
                throw CatalogError("catalog " + path.string() +
                                   " has schema version " + std::to_string(v) +
                                   ", expected " + std::to_string(SCHEMA_VERSION));
            }
        }
    }

    if (!readonly) {
        init_schema(schema_sql_path, dataset);
    }
}

void Catalog::init_schema(const std::filesystem::path& schema_sql_path,
                          std::optional<std::string> dataset) {
    std::string sql = read_schema_sql(schema_sql_path);
    for (const auto& stmt : split_sql(sql)) {
        if (stmt.find_first_not_of(" \t\r\n") == std::string::npos) continue;
        exec(stmt);
    }
    set_meta("schema_version", std::to_string(SCHEMA_VERSION));
    set_meta("created_at", std::to_string(now_epoch()));
    if (dataset.has_value()) set_meta("dataset_name", *dataset);
}

void Catalog::exec(const std::string& sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::string msg = err ? err : "exec failed";
        if (err) sqlite3_free(err);
        throw CatalogError("sql failed: " + msg + " for: " + sql);
    }
}

void Catalog::begin() { exec("BEGIN"); }
void Catalog::commit() { exec("COMMIT"); }
void Catalog::rollback() { exec("ROLLBACK"); }

std::optional<std::string> Catalog::get_meta(const std::string& key) {
    Statement st(db_, "SELECT value FROM meta WHERE key = ?");
    st.bind(1, key);
    if (!st.step()) return std::nullopt;
    return st.col_text_optional(0);
}

void Catalog::set_meta(const std::string& key, const std::string& value) {
    Statement st(db_, "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)");
    st.bind(1, key);
    st.bind(2, value);
    st.step();
}

Volume Catalog::upsert_volume(const std::string& hostname,
                              const std::string& volume,
                              const std::string& mount_point,
                              const std::string& os_n) {
    Statement st(db_,
        "INSERT INTO volumes(hostname, volume, mount_point, os, scanned_at) "
        "VALUES(?,?,?,?,?) "
        "ON CONFLICT(hostname, volume) DO UPDATE SET "
        "mount_point = excluded.mount_point, "
        "os = excluded.os, scanned_at = excluded.scanned_at");
    st.bind(1, hostname);
    st.bind(2, volume);
    st.bind(3, mount_point);
    st.bind(4, os_n);
    st.bind(5, now_epoch());
    st.step();
    auto v = get_volume(hostname, volume);
    if (!v) throw CatalogError("upsert_volume: volume not found after insert");
    return *v;
}

std::optional<Volume> Catalog::get_volume(const std::string& hostname,
                                          const std::string& volume) {
    Statement st(db_,
        "SELECT volume_id, hostname, volume, mount_point, os, scanned_at "
        "FROM volumes WHERE hostname = ? AND volume = ?");
    st.bind(1, hostname);
    st.bind(2, volume);
    if (!st.step()) return std::nullopt;
    Volume v;
    v.volume_id = st.col_int64(0);
    v.hostname = st.col_text(1);
    v.volume = st.col_text(2);
    v.mount_point = st.col_text(3);
    v.os = st.col_text(4);
    v.scanned_at = st.col_int64(5);
    return v;
}

std::vector<Volume> Catalog::volumes() {
    std::vector<Volume> out;
    Statement st(db_,
        "SELECT volume_id, hostname, volume, mount_point, os, scanned_at "
        "FROM volumes ORDER BY hostname, volume");
    while (st.step()) {
        Volume v;
        v.volume_id = st.col_int64(0);
        v.hostname = st.col_text(1);
        v.volume = st.col_text(2);
        v.mount_point = st.col_text(3);
        v.os = st.col_text(4);
        v.scanned_at = st.col_int64(5);
        out.push_back(std::move(v));
    }
    return out;
}

// ---- Schema helpers ----

std::string read_schema_sql(const std::filesystem::path& schema_sql_path) {
    std::ifstream ifs(schema_sql_path, std::ios::binary);
    if (!ifs) {
        throw CatalogError("schema file " + schema_sql_path.string() +
                           ": cannot open");
    }
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

std::vector<std::string> split_sql(const std::string& sql) {
    // Strip line comments (-- ... \n), then split on ';\n'.
    std::string clean;
    clean.reserve(sql.size());
    for (std::size_t i = 0; i < sql.size(); ++i) {
        if (sql[i] == '-' && i + 1 < sql.size() && sql[i + 1] == '-') {
            while (i < sql.size() && sql[i] != '\n') ++i;
            if (i < sql.size()) clean.push_back(sql[i]);  // keep the \n
        } else {
            clean.push_back(sql[i]);
        }
    }
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < clean.size(); ++i) {
        if (clean[i] == ';') {
            // Trim trailing whitespace, then check it's followed by EOL/eof
            std::size_t j = i + 1;
            while (j < clean.size() && (clean[j] == ' ' || clean[j] == '\t')) ++j;
            if (j >= clean.size() || clean[j] == '\n') {
                if (cur.find_first_not_of(" \t\r\n") != std::string::npos) {
                    out.push_back(cur);
                }
                cur.clear();
                i = j;
                continue;
            }
        }
        cur.push_back(clean[i]);
    }
    if (cur.find_first_not_of(" \t\r\n") != std::string::npos) {
        out.push_back(cur);
    }
    return out;
}

}  // namespace forensicator
