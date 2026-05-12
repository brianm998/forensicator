#include "forensicator/hashlog.hpp"

#include "forensicator/json.hpp"

#include <ios>

namespace forensicator {

Hashlog::Hashlog(const std::filesystem::path& path) {
    if (path.empty()) return;
    ofs_.open(path, std::ios::out | std::ios::app | std::ios::binary);
    if (!ofs_) {
        throw std::runtime_error("hashlog " + path.string() + ": open failed");
    }
}

Hashlog::~Hashlog() = default;

void Hashlog::write(const HashlogRecord& rec) {
    if (!ofs_.is_open()) return;
    json::Object o;
    o["hostname"]    = json::Value(rec.hostname);
    o["volume"]      = json::Value(rec.volume);
    o["mount_point"] = json::Value(rec.mount_point);
    o["os"]          = json::Value(rec.os);
    o["path"]        = json::Value(rec.path);
    o["path_norm"]   = json::Value(rec.path_norm);
    o["size"]        = json::Value(rec.size);
    o["mtime"]       = json::Value(rec.mtime);
    if (rec.sha512.has_value()) {
        o["sha512"]  = json::Value(*rec.sha512);
    } else {
        o["sha512"]  = json::Value();  // null
    }
    o["scanned_at"]  = json::Value(rec.scanned_at);
    std::string line = json::encode(json::Value(std::move(o)));
    line.push_back('\n');
    std::lock_guard<std::mutex> lk(mu_);
    ofs_.write(line.data(), static_cast<std::streamsize>(line.size()));
    ofs_.flush();
}

}  // namespace forensicator
