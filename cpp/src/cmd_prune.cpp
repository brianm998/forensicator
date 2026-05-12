#include "forensicator/catalog.hpp"
#include "forensicator/json.hpp"
#include "forensicator/util.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace forensicator {

struct PruneOpts {
    std::string catalog;
    std::string plan;
    bool apply = false;
    std::string keep_rule;
    bool interactive = true;
    std::string hostname;
    bool file_level = false;
    bool yes = false;
};

static void prune_usage() {
    std::cout <<
        "forensicator prune: act on a dedupe plan to remove duplicates and update catalog\n\n"
        "Usage:\n"
        "  forensicator prune --catalog FILE --plan FILE.json [--apply] [opts]\n\n"
        "Options:\n"
        "  --catalog FILE       Local SQLite catalog\n"
        "  --plan FILE          JSON output from forensicator dedupe --format json\n"
        "  --apply              Actually delete files (default: dry-run)\n"
        "  --keep-rule RULE     first | host=NAME | volume=NAME | shortest-path\n"
        "  --no-interactive     Skip groups without a rule match\n"
        "  --file-level         For dir-level dups, prompt per-file\n"
        "  --hostname NAME      Override hostname (default: short hostname)\n"
        "  --yes, -y            Skip the final confirmation when --apply is set\n"
        "  --help, -h           This message\n";
}

namespace {

struct Member {
    std::string hostname;
    std::string volume;
    std::string path;
    std::string orig_path;
    std::optional<std::int64_t> file_id;
    std::optional<std::string> sha512;
    bool covered = false;
    std::int64_t size_each = 0;
};

struct Group {
    std::string sig;
    std::string kind;
    std::int64_t size_each = 0;
    std::int64_t file_count_each = 0;
    std::vector<Member> members;
};

static std::string key_of(const Member& m) {
    std::string p = m.path.empty() ? "<root>" : m.path;
    return m.hostname + ":" + m.volume + ":" + p;
}

struct Action {
    Group* group;
    Member keep;
    std::vector<Member> del;
};

static std::vector<Member> pick_by_rule(const std::vector<Member>& ms,
                                        const std::string& rule) {
    if (rule == "first") return {ms.front()};
    if (rule.rfind("host=", 0) == 0) {
        std::string h = rule.substr(5);
        std::vector<Member> matches;
        for (const auto& m : ms) if (m.hostname == h) matches.push_back(m);
        if (matches.size() == 1) return matches;
        return {};
    }
    if (rule.rfind("volume=", 0) == 0) {
        std::string v = rule.substr(7);
        std::vector<Member> matches;
        for (const auto& m : ms) if (m.volume == v) matches.push_back(m);
        if (matches.size() == 1) return matches;
        return {};
    }
    if (rule == "shortest-path") {
        auto best = ms.front();
        for (const auto& m : ms) {
            if (m.path.size() < best.path.size()) best = m;
        }
        return {best};
    }
    return {};
}

struct SubtreeInfo { std::int64_t count = 0; std::int64_t bytes = 0; };

static SubtreeInfo subtree_info(Catalog& cat, const std::string& host,
                                const std::string& volume, const std::string& path) {
    auto v = cat.get_volume(host, volume);
    if (!v) return {};
    Statement st(cat.raw(),
        "SELECT COUNT(*), COALESCE(SUM(size),0) FROM files "
        "WHERE volume_id = ? AND (path_norm = ? OR path_norm LIKE ?)");
    st.bind(1, v->volume_id);
    st.bind(2, path);
    st.bind(3, path.empty() ? "%" : (path + "/%"));
    if (st.step()) {
        SubtreeInfo info;
        info.count = st.col_int64(0);
        info.bytes = st.col_int64(1);
        return info;
    }
    return {};
}

static Member node_from_file_row(const std::string& host, const std::string& volume,
                                 const std::string& path_norm, std::int64_t file_id,
                                 std::int64_t size) {
    Member m;
    m.hostname = host;
    m.volume = volume;
    m.path = path_norm;
    m.file_id = file_id;
    m.size_each = size;
    return m;
}

static std::vector<Action> expand_dir_group(Group& g, const Member& keep,
                                            const std::vector<Member>& del,
                                            Catalog& cat,
                                            const std::string& host) {
    std::vector<Action> out;
    auto keep_vol = cat.get_volume(keep.hostname, keep.volume);
    if (!keep_vol) return out;
    std::vector<std::tuple<std::int64_t, std::string, std::string, std::int64_t>> keep_files;
    {
        Statement st(cat.raw(),
            "SELECT file_id, path, path_norm, size FROM files "
            "WHERE volume_id = ? AND (path_norm = ? OR path_norm LIKE ?) "
            "ORDER BY path_norm");
        st.bind(1, keep_vol->volume_id);
        st.bind(2, keep.path);
        st.bind(3, keep.path.empty() ? "%" : (keep.path + "/%"));
        while (st.step()) {
            keep_files.emplace_back(st.col_int64(0), st.col_text(1),
                                    st.col_text(2), st.col_int64(3));
        }
    }
    for (const auto& d : del) {
        if (d.hostname != host) continue;
        auto dvol = cat.get_volume(d.hostname, d.volume);
        if (!dvol) continue;
        std::vector<std::tuple<std::int64_t, std::string, std::string, std::int64_t>> del_files;
        Statement st(cat.raw(),
            "SELECT file_id, path, path_norm, size FROM files "
            "WHERE volume_id = ? AND (path_norm = ? OR path_norm LIKE ?) "
            "ORDER BY path_norm");
        st.bind(1, dvol->volume_id);
        st.bind(2, d.path);
        st.bind(3, d.path.empty() ? "%" : (d.path + "/%"));
        while (st.step()) {
            del_files.emplace_back(st.col_int64(0), st.col_text(1),
                                   st.col_text(2), st.col_int64(3));
        }
        std::size_t base = keep.path.empty() ? 0 : keep.path.size() + 1;
        std::unordered_map<std::string, std::tuple<std::int64_t, std::string, std::int64_t>> by_rel;
        for (const auto& [fid, p, pn, sz] : keep_files) {
            std::string rel = pn.size() >= base ? pn.substr(base) : "";
            by_rel[rel] = {fid, pn, sz};
        }
        std::size_t dbase = d.path.empty() ? 0 : d.path.size() + 1;
        for (const auto& [fid, p, pn, sz] : del_files) {
            std::string rel = pn.size() >= dbase ? pn.substr(dbase) : "";
            auto it = by_rel.find(rel);
            if (it == by_rel.end()) continue;
            Action a;
            a.group = &g;
            auto& kt = it->second;
            a.keep = node_from_file_row(keep.hostname, keep.volume,
                                        std::get<1>(kt), std::get<0>(kt), std::get<2>(kt));
            Member dm = node_from_file_row(d.hostname, d.volume, pn, fid, sz);
            dm.size_each = sz;
            a.del.push_back(dm);
            out.push_back(std::move(a));
        }
    }
    return out;
}

struct DelResult { std::int64_t files = 0; std::int64_t bytes = 0; std::int64_t errors = 0; };

static DelResult delete_file_member(Catalog& cat, const std::string& host, const Member& m) {
    DelResult r;
    if (m.hostname != host) return r;
    auto vol = cat.get_volume(m.hostname, m.volume);
    if (!vol) {
        std::cerr << "[prune] volume not in catalog: " << m.hostname << ":" << m.volume << "\n";
        r.errors = 1; return r;
    }
    if (vol->mount_point.empty()) {
        std::cerr << "[prune] no mount_point for " << m.hostname << ":" << m.volume << "\n";
        r.errors = 1; return r;
    }
    std::int64_t file_id = 0;
    std::string orig_path;
    std::int64_t size = 0;
    if (m.file_id.has_value()) {
        Statement st(cat.raw(), "SELECT file_id, path, size FROM files WHERE file_id = ?");
        st.bind(1, *m.file_id);
        if (st.step()) {
            file_id = st.col_int64(0);
            orig_path = st.col_text(1);
            size = st.col_int64(2);
        }
    }
    if (!file_id) {
        Statement st(cat.raw(),
            "SELECT file_id, path, size FROM files WHERE volume_id = ? AND path_norm = ?");
        st.bind(1, vol->volume_id);
        st.bind(2, m.path);
        if (st.step()) {
            file_id = st.col_int64(0);
            orig_path = st.col_text(1);
            size = st.col_int64(2);
        }
    }
    if (!file_id) {
        std::cerr << "[prune] no catalog entry for " << key_of(m) << "\n";
        r.errors = 1; return r;
    }
    std::filesystem::path abs = std::filesystem::path(vol->mount_point) / orig_path;
    std::error_code ec;
    if (!std::filesystem::is_regular_file(abs, ec)) {
        std::cerr << "[prune] file already missing: " << abs.string()
                  << " (removing catalog entry)\n";
        Statement del(cat.raw(), "DELETE FROM files WHERE file_id = ?");
        del.bind(1, file_id);
        del.step();
        r.errors = 1; return r;
    }
    auto sz = std::filesystem::file_size(abs, ec);
    if (!ec && static_cast<std::int64_t>(sz) != size) {
        std::cerr << "[prune] size mismatch for " << abs.string()
                  << " (catalog: " << size << ", disk: " << sz << "); skipping\n";
        r.errors = 1; return r;
    }
    if (std::filesystem::remove(abs, ec) && !ec) {
        Statement del(cat.raw(), "DELETE FROM files WHERE file_id = ?");
        del.bind(1, file_id);
        del.step();
        r.files = 1;
        r.bytes = size;
    } else {
        std::cerr << "[prune] unlink failed: " << abs.string() << "\n";
        r.errors = 1;
    }
    return r;
}

static DelResult delete_subtree(Catalog& cat, const std::string& host,
                                const std::string& volume, const std::string& path) {
    DelResult r;
    auto vol = cat.get_volume(host, volume);
    if (!vol) {
        std::cerr << "[prune] volume not in catalog: " << host << ":" << volume << "\n";
        r.errors = 1; return r;
    }
    if (vol->mount_point.empty()) {
        std::cerr << "[prune] no mount_point for " << host << ":" << volume << "\n";
        r.errors = 1; return r;
    }
    struct Row { std::int64_t file_id; std::string path; std::int64_t size; };
    std::vector<Row> rows;
    {
        Statement st(cat.raw(),
            "SELECT file_id, path, size FROM files "
            "WHERE volume_id = ? AND (path_norm = ? OR path_norm LIKE ?) "
            "ORDER BY length(path_norm) DESC");
        st.bind(1, vol->volume_id);
        st.bind(2, path);
        st.bind(3, path.empty() ? "%" : (path + "/%"));
        while (st.step()) {
            rows.push_back({st.col_int64(0), st.col_text(1), st.col_int64(2)});
        }
    }
    std::set<std::string> dirs_seen;
    for (const auto& row : rows) {
        std::filesystem::path abs = std::filesystem::path(vol->mount_point) / row.path;
        std::error_code ec;
        if (std::filesystem::is_regular_file(abs, ec)) {
            if (std::filesystem::remove(abs, ec) && !ec) {
                r.files++;
                r.bytes += row.size;
                Statement del(cat.raw(), "DELETE FROM files WHERE file_id = ?");
                del.bind(1, row.file_id);
                del.step();
                auto parent = abs.parent_path();
                while (!parent.empty()) {
                    dirs_seen.insert(parent.string());
                    auto up = parent.parent_path();
                    if (up == parent) break;
                    parent = up;
                }
            } else {
                std::cerr << "[prune] unlink failed: " << abs.string() << "\n";
                r.errors++;
            }
        } else {
            std::cerr << "[prune] file missing: " << abs.string()
                      << " (removing catalog entry)\n";
            Statement del(cat.raw(), "DELETE FROM files WHERE file_id = ?");
            del.bind(1, row.file_id);
            del.step();
            r.errors++;
        }
    }
    // Try to rmdir empty dirs deepest-first.
    std::vector<std::string> sorted(dirs_seen.begin(), dirs_seen.end());
    std::sort(sorted.begin(), sorted.end(),
              [](const std::string& a, const std::string& b) {
                  return a.size() > b.size();
              });
    for (const auto& d : sorted) {
        std::error_code ec;
        std::filesystem::remove(d, ec);  // succeeds only if empty
    }
    return r;
}

static std::optional<std::pair<Member, std::vector<Member>>>
prompt_group(Group& g, const std::string& host, std::string& last_response) {
    std::cerr << "\n=== ";
    std::string kind_uc = g.kind;
    for (auto& c : kind_uc) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    std::cerr << kind_uc << " duplicate, " << fmt_bytes(static_cast<std::uint64_t>(g.size_each));
    if (g.kind == "dir") std::cerr << " (" << g.file_count_each << " files each)";
    std::cerr << " ===\n";
    int idx = 0;
    for (const auto& m : g.members) {
        ++idx;
        std::string tag;
        std::vector<std::string> tags;
        if (m.hostname == host) tags.push_back("LOCAL");
        if (m.covered) tags.push_back("covered");
        if (!tags.empty()) {
            tag = " [";
            for (std::size_t i = 0; i < tags.size(); ++i) {
                if (i) tag += ",";
                tag += tags[i];
            }
            tag += "]";
        }
        std::cerr << "  " << idx << ". " << key_of(m) << tag << "\n";
    }
    std::cerr << "Keep which? (number to keep / a=keep all (skip) / s=skip / q=quit): ";
    std::string resp;
    if (!std::getline(std::cin, resp)) { last_response = ""; return std::nullopt; }
    last_response = resp;
    if (resp == "s" || resp == "a" || resp.empty()) return std::nullopt;
    if (resp == "q") return std::nullopt;
    try {
        int n = std::stoi(resp);
        if (n < 1 || n > static_cast<int>(g.members.size())) return std::nullopt;
        Member keep = g.members[n - 1];
        std::vector<Member> del;
        for (const auto& m : g.members) {
            if (m.hostname == host && !(m.hostname == keep.hostname &&
                                        m.volume == keep.volume &&
                                        m.path == keep.path)) {
                del.push_back(m);
            }
        }
        return std::make_pair(keep, del);
    } catch (...) { return std::nullopt; }
}

}  // namespace

int cmd_prune(int argc, char** argv, const std::string& exe_path) {
    PruneOpts opt;
    opt.hostname = default_hostname();
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") { prune_usage(); return 0; }
        else if (a == "--catalog") { if (i + 1 >= argc) { std::cerr << "--catalog needs value\n"; return 2; } opt.catalog = argv[++i]; }
        else if (a == "--plan")    { if (i + 1 >= argc) { std::cerr << "--plan needs value\n"; return 2; }    opt.plan = argv[++i]; }
        else if (a == "--apply") opt.apply = true;
        else if (a == "--keep-rule") { if (i + 1 >= argc) { std::cerr << "--keep-rule needs value\n"; return 2; } opt.keep_rule = argv[++i]; }
        else if (a == "--no-interactive") opt.interactive = false;
        else if (a == "--interactive") opt.interactive = true;
        else if (a == "--hostname") { if (i + 1 >= argc) { std::cerr << "--hostname needs value\n"; return 2; } opt.hostname = argv[++i]; }
        else if (a == "--file-level") opt.file_level = true;
        else if (a == "--yes" || a == "-y") opt.yes = true;
        else { std::cerr << "unknown option: " << a << "\n"; return 2; }
    }
    if (opt.catalog.empty()) { std::cerr << "missing --catalog\n"; return 2; }
    if (opt.plan.empty())    { std::cerr << "missing --plan\n";    return 2; }

    std::string schema = find_schema_file(exe_path);
    if (schema.empty()) { std::cerr << "cannot locate schema/forensicator.sql\n"; return 2; }

    Catalog cat;
    try { cat.open(opt.catalog, schema, false); }
    catch (const std::exception& e) { std::cerr << e.what() << "\n"; return 2; }

    std::ifstream pfs(opt.plan, std::ios::binary);
    if (!pfs) { std::cerr << opt.plan << ": cannot open\n"; return 2; }
    std::ostringstream oss;
    oss << pfs.rdbuf();
    json::Value plan;
    try { plan = json::parse(oss.str()); }
    catch (const std::exception& e) { std::cerr << opt.plan << ": " << e.what() << "\n"; return 2; }
    if (!plan.is_object() || plan.at("forensicator").as_string() != "dedupe") {
        std::cerr << "plan does not look like a forensicator-dedupe document\n";
        return 2;
    }

    std::vector<Group> groups;
    if (plan.contains("duplicate_groups")) {
        for (const auto& gv : plan.at("duplicate_groups").as_array()) {
            Group g;
            g.sig = gv.at("sig").as_string();
            g.kind = gv.at("kind").as_string();
            g.size_each = gv.at("size_each").as_int();
            g.file_count_each = gv.at("file_count_each").as_int();
            for (const auto& mv : gv.at("members").as_array()) {
                Member m;
                m.hostname = mv.at("hostname").as_string();
                m.volume = mv.at("volume").as_string();
                m.path = mv.at("path").as_string();
                if (mv.contains("file_id") && mv.at("file_id").is_int()) {
                    m.file_id = mv.at("file_id").as_int();
                }
                if (mv.contains("sha512") && mv.at("sha512").is_string()) {
                    m.sha512 = mv.at("sha512").as_string();
                }
                if (mv.contains("orig_path") && mv.at("orig_path").is_string()) {
                    m.orig_path = mv.at("orig_path").as_string();
                }
                if (mv.contains("covered_by_ancestor")) {
                    m.covered = mv.at("covered_by_ancestor").as_bool();
                }
                m.size_each = g.size_each;
                g.members.push_back(std::move(m));
            }
            groups.push_back(std::move(g));
        }
    }

    std::vector<Action> actions;
    std::string last_response;
    int skipped = 0, no_local = 0;
    for (auto& g : groups) {
        std::vector<Member> local;
        for (const auto& m : g.members) if (m.hostname == opt.hostname) local.push_back(m);
        if (local.empty()) { ++no_local; continue; }

        std::vector<Member> keepers;
        if (!opt.keep_rule.empty()) keepers = pick_by_rule(g.members, opt.keep_rule);

        std::optional<Member> keep;
        std::vector<Member> del;

        if (keepers.size() == 1) {
            keep = keepers.front();
            for (const auto& m : g.members) {
                if (m.hostname == opt.hostname) {
                    if (!(m.hostname == keep->hostname && m.volume == keep->volume && m.path == keep->path)) {
                        del.push_back(m);
                    }
                }
            }
        } else if (opt.interactive) {
            auto pr = prompt_group(g, opt.hostname, last_response);
            if (last_response == "q") break;
            if (!pr) { ++skipped; continue; }
            keep = pr->first;
            del = pr->second;
        } else {
            ++skipped; continue;
        }

        if (opt.file_level && g.kind == "dir") {
            auto expanded = expand_dir_group(g, *keep, del, cat, opt.hostname);
            for (auto& a : expanded) actions.push_back(std::move(a));
        } else {
            Action a;
            a.group = &g;
            a.keep = *keep;
            a.del = std::move(del);
            actions.push_back(std::move(a));
        }
    }

    if (no_local) std::cerr << "[prune] " << no_local << " groups had no members on this host (skipped silently)\n";
    if (skipped)  std::cerr << "[prune] " << skipped << " groups skipped by user/rule\n";
    if (actions.empty()) {
        std::cerr << "[prune] nothing to do\n";
        return 0;
    }

    std::cerr << "\n[prune] planned actions:\n";
    std::int64_t total_files = 0, total_bytes = 0;
    for (const auto& a : actions) {
        std::cerr << "  KEEP   " << key_of(a.keep) << "\n";
        if (a.group->kind == "dir" && !opt.file_level) {
            for (const auto& d : a.del) {
                auto info = subtree_info(cat, opt.hostname, d.volume, d.path);
                total_files += info.count;
                total_bytes += info.bytes;
                std::cerr << "  DELETE " << key_of(d) << "  (" << info.count
                          << " files, " << fmt_bytes(static_cast<std::uint64_t>(info.bytes)) << ")\n";
            }
        } else {
            for (const auto& d : a.del) {
                total_files++;
                total_bytes += d.size_each;
                std::cerr << "  DELETE " << key_of(d) << "  ("
                          << fmt_bytes(static_cast<std::uint64_t>(d.size_each)) << ")\n";
            }
        }
    }
    std::cerr << "\n[prune] total: " << total_files << " files, "
              << fmt_bytes(static_cast<std::uint64_t>(total_bytes)) << "\n";

    if (!opt.apply) {
        std::cerr << "[prune] DRY RUN -- pass --apply to actually delete\n";
        return 0;
    }

    if (!opt.yes) {
        std::cerr << "[prune] proceed with deletion? type 'yes' to continue: ";
        std::string r;
        if (!std::getline(std::cin, r) || r != "yes") {
            std::cerr << "[prune] aborted\n";
            return 1;
        }
    }

    DelResult totals;
    for (const auto& a : actions) {
        for (const auto& d : a.del) {
            DelResult r;
            if (a.group->kind == "dir" && !opt.file_level) {
                r = delete_subtree(cat, opt.hostname, d.volume, d.path);
            } else {
                r = delete_file_member(cat, opt.hostname, d);
            }
            totals.files += r.files;
            totals.bytes += r.bytes;
            totals.errors += r.errors;
        }
    }
    std::cerr << "[prune] DONE: " << totals.files << " files removed, "
              << fmt_bytes(static_cast<std::uint64_t>(totals.bytes))
              << " freed, " << totals.errors << " errors\n";
    return totals.errors ? 2 : 0;
}

}  // namespace forensicator
