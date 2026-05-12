#include "forensicator/catalog.hpp"
#include "forensicator/json.hpp"
#include "forensicator/sha512.hpp"
#include "forensicator/util.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace forensicator {

struct DedupeOpts {
    std::string catalog;
    std::string format = "human";
    std::string output;
    std::int64_t min_size = 0;
};

static void dedupe_usage() {
    std::cout <<
        "forensicator dedupe: find duplicate files and directory trees\n\n"
        "Usage:\n"
        "  forensicator dedupe --catalog FILE [--format human|json] [--output FILE]\n\n"
        "Options:\n"
        "  --catalog FILE    SQLite catalog\n"
        "  --format FORMAT   \"human\" or \"json\" (default human)\n"
        "  --output FILE     Write to FILE (default stdout)\n"
        "  --min-size BYTES  Ignore single-file dups smaller than this\n"
        "  --help, -h        This message\n";
}

namespace {

struct FileRec {
    std::int64_t file_id;
    std::string path;
    std::string path_norm;
    std::int64_t size;
    std::optional<std::string> sha512;
    std::string hostname;
    std::string volume;
};

struct Node;
using NodePtr = std::shared_ptr<Node>;

struct Node {
    std::string kind;       // "dir" or "file"
    std::string path;       // path within tree (normalized, like path_norm without leading slash)
    std::string hostname;
    std::string volume;
    // For dirs:
    std::map<std::string, NodePtr> dirs;
    // For dirs we keep file entries here:
    std::vector<NodePtr> files;
    // For files:
    std::string name;
    std::string orig_path;
    std::int64_t size = 0;
    std::optional<std::string> sha512;
    std::int64_t file_id = 0;
    // Computed:
    std::string sig;
    std::int64_t size_total = 0;
    std::int64_t count = 0;
};

NodePtr make_dir(const std::string& path,
                 const std::string& host,
                 const std::string& vol) {
    auto n = std::make_shared<Node>();
    n->kind = "dir";
    n->path = path;
    n->hostname = host;
    n->volume = vol;
    return n;
}

static void insert_file(NodePtr tree, const FileRec& f) {
    std::vector<std::string> parts;
    {
        std::string cur;
        for (char c : f.path_norm) {
            if (c == '/') {
                parts.push_back(cur);
                cur.clear();
            } else cur.push_back(c);
        }
        parts.push_back(cur);
    }
    std::string name = parts.back();
    parts.pop_back();
    auto node = tree;
    for (const auto& p : parts) {
        if (p.empty()) continue;
        std::string sub = node->path.empty() ? p : (node->path + "/" + p);
        auto it = node->dirs.find(p);
        if (it == node->dirs.end()) {
            auto child = make_dir(sub, f.hostname, f.volume);
            node->dirs[p] = child;
            node = child;
        } else {
            node = it->second;
        }
    }
    auto leaf = std::make_shared<Node>();
    leaf->kind = "file";
    leaf->name = name;
    leaf->path = node->path.empty() ? name : (node->path + "/" + name);
    leaf->orig_path = f.path;
    leaf->hostname = f.hostname;
    leaf->volume = f.volume;
    leaf->size = f.size;
    leaf->sha512 = f.sha512;
    leaf->file_id = f.file_id;
    node->files.push_back(leaf);
}

static void walk_compute(NodePtr node,
                         std::vector<NodePtr>& all,
                         const std::unordered_map<std::int64_t, std::int64_t>& size_count) {
    std::vector<std::pair<std::string, std::string>> entries;
    std::int64_t size_total = 0;
    std::int64_t count = 0;

    for (auto& f : node->files) {
        std::string sig;
        if (f->sha512.has_value()) {
            sig = "F:" + *f->sha512;
        } else {
            auto it = size_count.find(f->size);
            if (it == size_count.end() || it->second <= 1) {
                sig = "U:" + std::to_string(f->file_id);
            } else {
                sig = "X:" + std::to_string(f->file_id);
            }
        }
        f->sig = sig;
        entries.emplace_back(f->name, sig);
        size_total += f->size;
        ++count;
        all.push_back(f);
    }

    // Sort directories by name (std::map already iterates in order)
    for (auto& [name, d] : node->dirs) {
        walk_compute(d, all, size_count);
        entries.emplace_back(name, d->sig);
        size_total += d->size_total;
        count += d->count;
    }

    node->size_total = size_total;
    node->count = count;

    if (entries.empty()) {
        node->sig = "D:empty";
    } else {
        std::sort(entries.begin(), entries.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        Sha512 h;
        for (const auto& e : entries) {
            h.update(e.first.data(), e.first.size());
            h.update("\0", 1);
            h.update(e.second.data(), e.second.size());
            h.update("\0", 1);
        }
        node->sig = "D:" + h.hex_digest();
    }
    all.push_back(node);
}

static int depth_of(const NodePtr& n) {
    if (n->path.empty()) return 0;
    int c = 0;
    for (char ch : n->path) if (ch == '/') ++c;
    return c + 1;
}

static std::int64_t group_size(const std::vector<NodePtr>& g) {
    const auto& n = g.front();
    return n->kind == "file" ? n->size : n->size_total;
}

static std::string node_key(const NodePtr& n) {
    return n->hostname + std::string(1, '\0') + n->volume + std::string(1, '\0') + n->path;
}

static bool is_covered(const NodePtr& n,
                       const std::unordered_map<std::string, bool>& covered) {
    std::string hv = n->hostname + std::string(1, '\0') + n->volume + std::string(1, '\0');
    std::string p = n->path;
    while (true) {
        auto pos = p.rfind('/');
        if (pos == std::string::npos) break;
        p = p.substr(0, pos);
        if (covered.count(hv + p)) return true;
    }
    if (covered.count(hv)) return true;
    return false;
}

static std::string key_str(const NodePtr& n) {
    std::string p = n->path.empty() ? "<root>" : n->path;
    return n->hostname + ":" + n->volume + ":" + p;
}

struct Member {
    NodePtr node;
    bool covered;
};

struct ReportedGroup {
    std::string sig;
    std::string kind;
    std::int64_t size;
    std::int64_t count;
    std::vector<Member> members;
};

}  // namespace

int cmd_dedupe(int argc, char** argv, const std::string& exe_path) {
    DedupeOpts opt;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") { dedupe_usage(); return 0; }
        else if (a == "--catalog") { if (i + 1 >= argc) { std::cerr << "--catalog needs value\n"; return 2; } opt.catalog = argv[++i]; }
        else if (a == "--format")  { if (i + 1 >= argc) { std::cerr << "--format needs value\n"; return 2; }  opt.format = argv[++i]; }
        else if (a == "--output")  { if (i + 1 >= argc) { std::cerr << "--output needs value\n"; return 2; }  opt.output = argv[++i]; }
        else if (a == "--min-size") { if (i + 1 >= argc) { std::cerr << "--min-size needs value\n"; return 2; } opt.min_size = std::stoll(argv[++i]); }
        else { std::cerr << "unknown option: " << a << "\n"; return 2; }
    }
    if (opt.catalog.empty()) { std::cerr << "missing --catalog\n"; return 2; }
    if (opt.format != "human" && opt.format != "json") {
        std::cerr << "format must be 'human' or 'json'\n"; return 2;
    }

    std::string schema = find_schema_file(exe_path);
    if (schema.empty()) {
        std::cerr << "cannot locate schema/forensicator.sql\n"; return 2;
    }

    Catalog cat;
    try {
        cat.open(opt.catalog, schema, true);
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 2;
    }

    // Load all files joined with volumes, ordered by host/volume/path_norm.
    std::vector<FileRec> files;
    {
        Statement st(cat.raw(),
            "SELECT f.file_id, f.path, f.path_norm, f.size, f.sha512, v.hostname, v.volume "
            "FROM files f JOIN volumes v ON v.volume_id = f.volume_id "
            "ORDER BY v.hostname, v.volume, f.path_norm");
        while (st.step()) {
            FileRec r;
            r.file_id = st.col_int64(0);
            r.path = st.col_text(1);
            r.path_norm = st.col_text(2);
            r.size = st.col_int64(3);
            r.sha512 = st.col_text_optional(4);
            r.hostname = st.col_text(5);
            r.volume = st.col_text(6);
            files.push_back(std::move(r));
        }
    }

    std::unordered_map<std::int64_t, std::int64_t> size_count;
    for (const auto& f : files) size_count[f.size]++;

    int missing_collisions = 0;
    std::vector<std::string> missing_examples;
    for (const auto& f : files) {
        if (!f.sha512.has_value() && size_count[f.size] > 1) {
            ++missing_collisions;
            if (missing_examples.size() < 5) {
                missing_examples.push_back(f.hostname + ":" + f.volume + ":" + f.path);
            }
        }
    }

    std::vector<std::string> warnings;
    if (missing_collisions) {
        std::string w = std::to_string(missing_collisions) +
            " files have size collisions but no SHA512 hash; "
            "run forensicator-scan --rehash on each host. Examples: ";
        for (std::size_t i = 0; i < missing_examples.size(); ++i) {
            if (i) w += ", ";
            w += missing_examples[i];
        }
        warnings.push_back(std::move(w));
    }

    // Build per-(host,volume) trees.
    std::map<std::string, NodePtr> trees;
    for (const auto& f : files) {
        std::string key = f.hostname + std::string(1, '\0') + f.volume;
        auto it = trees.find(key);
        if (it == trees.end()) {
            trees[key] = make_dir("", f.hostname, f.volume);
            it = trees.find(key);
        }
        insert_file(it->second, f);
    }

    std::vector<NodePtr> all_nodes;
    for (auto& [k, tree] : trees) {
        walk_compute(tree, all_nodes, size_count);
    }

    // Group by sig (skip U:/X: and empty).
    std::map<std::string, std::vector<NodePtr>> groups;
    for (auto& n : all_nodes) {
        if (n->sig.size() >= 2 && (n->sig[0] == 'U' || n->sig[0] == 'X') && n->sig[1] == ':') continue;
        if (n->sig == "D:empty") continue;
        groups[n->sig].push_back(n);
    }

    std::vector<std::vector<NodePtr>> dup_groups;
    for (auto& [sig, g] : groups) {
        if (g.size() < 2) continue;
        const auto& first = g.front();
        if (first->kind == "file" && first->size < opt.min_size) continue;
        dup_groups.push_back(g);
    }

    std::sort(dup_groups.begin(), dup_groups.end(),
              [](const auto& a, const auto& b) {
                  int da = depth_of(a.front());
                  int db = depth_of(b.front());
                  if (da != db) return da < db;
                  return group_size(b) < group_size(a);  // larger first
              });

    std::unordered_map<std::string, bool> covered;
    std::vector<ReportedGroup> reported;
    for (auto& g : dup_groups) {
        std::vector<Member> members;
        bool any_uncovered = false;
        for (auto& n : g) {
            bool cov = is_covered(n, covered);
            if (!cov) any_uncovered = true;
            members.push_back({n, cov});
        }
        if (!any_uncovered) continue;
        ReportedGroup rg;
        rg.sig = g.front()->sig;
        rg.kind = g.front()->kind;
        rg.size = rg.kind == "file" ? g.front()->size : g.front()->size_total;
        rg.count = rg.kind == "file" ? 1 : g.front()->count;
        rg.members = std::move(members);
        reported.push_back(std::move(rg));
        for (auto& m : reported.back().members) {
            covered[node_key(m.node)] = true;
        }
    }

    std::sort(reported.begin(), reported.end(),
              [](const auto& a, const auto& b) {
                  if (a.size != b.size) return a.size > b.size;
                  return a.count > b.count;
              });

    std::ostream* out = &std::cout;
    std::ofstream ofs;
    if (!opt.output.empty()) {
        ofs.open(opt.output, std::ios::out | std::ios::binary);
        if (!ofs) { std::cerr << opt.output << ": cannot open\n"; return 2; }
        out = &ofs;
    }

    if (opt.format == "json") {
        json::Array groups_arr;
        for (const auto& g : reported) {
            json::Array mems;
            for (const auto& m : g.members) {
                json::Object e;
                e["hostname"] = json::Value(m.node->hostname);
                e["volume"]   = json::Value(m.node->volume);
                e["path"]     = json::Value(m.node->path);
                e["key"]      = json::Value(key_str(m.node));
                e["covered_by_ancestor"] = json::Value(m.covered);
                if (m.node->kind == "file") {
                    e["file_id"]   = json::Value(m.node->file_id);
                    if (m.node->sha512.has_value()) e["sha512"] = json::Value(*m.node->sha512);
                    else e["sha512"] = json::Value();
                    e["orig_path"] = json::Value(m.node->orig_path);
                }
                mems.push_back(json::Value(std::move(e)));
            }
            json::Object go;
            go["sig"] = json::Value(g.sig);
            go["kind"] = json::Value(g.kind);
            go["size_each"] = json::Value(g.size);
            go["file_count_each"] = json::Value(g.count);
            go["members"] = json::Value(std::move(mems));
            groups_arr.push_back(json::Value(std::move(go)));
        }
        json::Object doc;
        doc["forensicator"] = json::Value("dedupe");
        doc["version"] = json::Value(1);
        doc["generated_at"] = json::Value(now_epoch());
        doc["catalog"] = json::Value(opt.catalog);
        auto ds = cat.get_meta("dataset_name");
        if (ds.has_value()) doc["dataset"] = json::Value(*ds);
        else doc["dataset"] = json::Value();
        json::Array warr;
        for (const auto& w : warnings) warr.push_back(json::Value(w));
        doc["warnings"] = json::Value(std::move(warr));
        doc["duplicate_groups"] = json::Value(std::move(groups_arr));
        (*out) << json::encode(json::Value(std::move(doc))) << "\n";
    } else {
        (*out) << "# forensicator-dedupe report (" << local_timestamp(now_epoch()) << ")\n";
        (*out) << "# catalog: " << opt.catalog << "\n";
        auto ds = cat.get_meta("dataset_name");
        if (ds.has_value()) (*out) << "# dataset: " << *ds << "\n";
        (*out) << "# duplicate groups: " << reported.size() << "\n";
        if (!warnings.empty()) {
            (*out) << "\n";
            for (const auto& w : warnings) (*out) << "WARNING: " << w << "\n";
        }
        (*out) << "\n";
        std::size_t idx = 0;
        for (const auto& g : reported) {
            ++idx;
            std::string kind_uc = g.kind;
            for (auto& c : kind_uc) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            char head[256];
            if (g.kind == "file") {
                std::snprintf(head, sizeof(head), "[%zu] %s  %s  %zu copies",
                              idx, kind_uc.c_str(), fmt_bytes(static_cast<std::uint64_t>(g.size)).c_str(),
                              g.members.size());
            } else {
                std::snprintf(head, sizeof(head), "[%zu] %s  %s  (%lld files each)  %zu copies",
                              idx, kind_uc.c_str(), fmt_bytes(static_cast<std::uint64_t>(g.size)).c_str(),
                              static_cast<long long>(g.count), g.members.size());
            }
            (*out) << head << "\n";
            bool first = true;
            for (const auto& m : g.members) {
                const char* tag = first ? "KEEP-CANDIDATE:" : "DUPLICATE:     ";
                first = false;
                std::string note = m.covered ? "   (covered by ancestor dup)" : "";
                (*out) << "  " << tag << " " << key_str(m.node) << note << "\n";
            }
            (*out) << "\n";
        }
    }
    if (ofs.is_open()) ofs.close();
    return 0;
}

}  // namespace forensicator
