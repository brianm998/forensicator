#include "forensicator/walker.hpp"

#include "forensicator/pathnorm.hpp"

#include <chrono>
#include <filesystem>
#include <string>
#include <system_error>
#include <unordered_set>

namespace forensicator {

namespace fs = std::filesystem;

static const std::unordered_set<std::string>& skip_dirs() {
    static const std::unordered_set<std::string> s = {
        ".git", ".Spotlight-V100", ".Trashes", ".fseventsd", ".TemporaryItems",
        "$RECYCLE.BIN", "System Volume Information", ".DocumentRevisions-V100",
    };
    return s;
}

static const std::unordered_set<std::string>& skip_files() {
    static const std::unordered_set<std::string> s = {
        ".DS_Store", "Thumbs.db", "desktop.ini", ".localized",
    };
    return s;
}

bool is_skipped_dir(const std::string& basename) {
    return skip_dirs().count(basename) > 0;
}

bool is_skipped_file(const std::string& basename) {
    return skip_files().count(basename) > 0;
}

static std::int64_t to_epoch(fs::file_time_type ft) {
    using namespace std::chrono;
    auto sys = time_point_cast<system_clock::duration>(
        ft - fs::file_time_type::clock::now() + system_clock::now());
    return duration_cast<seconds>(sys.time_since_epoch()).count();
}

static std::string make_rel(const fs::path& root, const fs::path& p) {
    std::error_code ec;
    fs::path rel = fs::relative(p, root, ec);
    if (ec) return p.string();
    return rel.generic_string();
}

WalkStats walk_tree(const fs::path& root,
                    const std::string& os_n,
                    const std::function<void(WalkedFile)>& on_file) {
    WalkStats stats;
    std::error_code ec;
    auto opts = fs::directory_options::skip_permission_denied;

    fs::recursive_directory_iterator it(root, opts, ec);
    if (ec) { stats.errors++; return stats; }
    fs::recursive_directory_iterator end;

    while (it != end) {
        const fs::directory_entry& entry = *it;
        std::error_code lec;
        auto status = entry.symlink_status(lec);
        if (lec) {
            stats.errors++;
            it.increment(ec); if (ec) break;
            continue;
        }

        // Skip symlinks (do not follow, do not record).
        if (fs::is_symlink(status)) {
            stats.skipped++;
            it.disable_recursion_pending();
            it.increment(ec); if (ec) break;
            continue;
        }

        if (fs::is_directory(status)) {
            std::string base = entry.path().filename().string();
            if (is_skipped_dir(base)) {
                stats.skipped++;
                it.disable_recursion_pending();
            }
            it.increment(ec); if (ec) break;
            continue;
        }

        if (!fs::is_regular_file(status)) {
            it.increment(ec); if (ec) break;
            continue;
        }

        std::string base = entry.path().filename().string();
        if (is_skipped_file(base)) {
            stats.skipped++;
            it.increment(ec); if (ec) break;
            continue;
        }

        std::error_code sec;
        auto sz = entry.file_size(sec);
        if (sec) { stats.errors++; it.increment(ec); if (ec) break; continue; }
        if (sz == 0) {
            stats.skipped++;
            it.increment(ec); if (ec) break;
            continue;
        }

        auto mt = entry.last_write_time(sec);
        std::int64_t mtime_epoch = sec ? 0 : to_epoch(mt);

        WalkedFile w;
        w.absolute = entry.path();
        w.rel_path = make_rel(root, entry.path());
        w.path_norm = normalize_path(w.rel_path, os_n);
        w.size = static_cast<std::int64_t>(sz);
        w.mtime = mtime_epoch;

        on_file(std::move(w));
        stats.files++;
        it.increment(ec); if (ec) break;
    }
    return stats;
}

}  // namespace forensicator
