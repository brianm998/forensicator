#include "forensicator/util.hpp"

#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <windows.h>
#else
#  include <unistd.h>
#  include <sys/types.h>
#endif

#ifndef FORENSICATOR_INSTALL_DATAROOT
#  define FORENSICATOR_INSTALL_DATAROOT ""
#endif

namespace forensicator {

std::string os_name() {
#if defined(__APPLE__)
    return "darwin";
#elif defined(_WIN32)
    return "MSWin32";
#elif defined(__CYGWIN__)
    return "cygwin";
#elif defined(__linux__)
    return "linux";
#elif defined(__FreeBSD__)
    return "freebsd";
#elif defined(__OpenBSD__)
    return "openbsd";
#elif defined(__NetBSD__)
    return "netbsd";
#else
    return "unknown";
#endif
}

std::string default_hostname() {
#if defined(_WIN32)
    char buf[256] = {0};
    DWORD sz = sizeof(buf);
    if (GetComputerNameA(buf, &sz)) {
        std::string h(buf, sz);
        auto p = h.find('.');
        if (p != std::string::npos) h.erase(p);
        return h;
    }
    return "localhost";
#else
    char buf[256] = {0};
    if (gethostname(buf, sizeof(buf) - 1) != 0) return "localhost";
    std::string h(buf);
    auto p = h.find('.');
    if (p != std::string::npos) h.erase(p);
    return h;
#endif
}

std::int64_t now_epoch() {
    return static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string fmt_duration(std::int64_t secs) {
    if (secs < 0) secs = 0;
    if (secs < 60) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%lds", static_cast<long>(secs));
        return buf;
    }
    long h = static_cast<long>(secs / 3600);
    long m = static_cast<long>((secs % 3600) / 60);
    long s = static_cast<long>(secs % 60);
    char buf[64];
    if (h) {
        std::snprintf(buf, sizeof(buf), "%ldh%02ldm", h, m);
    } else {
        std::snprintf(buf, sizeof(buf), "%ldm%02lds", m, s);
    }
    return buf;
}

std::string fmt_bytes(std::uint64_t b) {
    static const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    double v = static_cast<double>(b);
    int i = 0;
    while (v >= 1024.0 && i < 5) { v /= 1024.0; ++i; }
    char buf[64];
    if (i == 0) {
        std::snprintf(buf, sizeof(buf), "%llu %s",
                      static_cast<unsigned long long>(b), units[i]);
    } else {
        std::snprintf(buf, sizeof(buf), "%.2f %s", v, units[i]);
    }
    return buf;
}

std::string fmt_eta(std::string_view label,
                    std::uint64_t done,
                    std::uint64_t total,
                    std::int64_t started_epoch) {
    std::int64_t el = now_epoch() - started_epoch;
    if (el <= 0) el = 1;
    double rate = static_cast<double>(done) / static_cast<double>(el);
    double pct = total ? (100.0 * static_cast<double>(done) / static_cast<double>(total)) : 0.0;
    std::int64_t eta_s = 0;
    if (rate > 0.0 && done < total) {
        eta_s = static_cast<std::int64_t>(
            static_cast<double>(total - done) / rate);
    }
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "%.*s: %llu / %llu done (%.1f%%, %.0f/s, %s elapsed, ETA %s)",
                  static_cast<int>(label.size()), label.data(),
                  static_cast<unsigned long long>(done),
                  static_cast<unsigned long long>(total),
                  pct, rate,
                  fmt_duration(el).c_str(),
                  fmt_duration(eta_s).c_str());
    return buf;
}

bool is_case_insensitive_os(std::string_view os) {
    return os == "MSWin32" || os == "darwin" || os == "cygwin" || os == "msys";
}

void ascii_lower_inplace(std::string& s) {
    for (char& c : s) {
        if (static_cast<unsigned char>(c) < 128) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
    }
}

std::string local_timestamp(std::int64_t epoch) {
    std::time_t t = static_cast<std::time_t>(epoch);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[64];
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %Z", &tm) == 0) {
        return "";
    }
    return buf;
}

static bool exists_file(const std::filesystem::path& p) {
    std::error_code ec;
    return std::filesystem::is_regular_file(p, ec);
}

std::string find_schema_file(std::string_view exe_path) {
    namespace fs = std::filesystem;
    if (const char* env = std::getenv("FORENSICATOR_SCHEMA")) {
        if (env[0] && exists_file(env)) return env;
    }
    if (!exe_path.empty()) {
        fs::path exe(exe_path);
        std::error_code ec;
        fs::path exe_dir = exe.parent_path();
        // same-dir-as-binary schema/forensicator.sql
        fs::path c1 = exe_dir / "schema" / "forensicator.sql";
        if (exists_file(c1)) return c1.string();
        // ../schema/forensicator.sql
        fs::path c2 = exe_dir / ".." / "schema" / "forensicator.sql";
        c2 = fs::weakly_canonical(c2, ec);
        if (!ec && exists_file(c2)) return c2.string();
        // ../share/forensicator/forensicator.sql (install layout)
        fs::path c3 = exe_dir / ".." / "share" / "forensicator" / "forensicator.sql";
        c3 = fs::weakly_canonical(c3, ec);
        if (!ec && exists_file(c3)) return c3.string();
    }
    // Walk up from the current working dir looking for schema/forensicator.sql
    {
        std::error_code ec;
        fs::path cwd = fs::current_path(ec);
        for (int i = 0; !ec && i < 6 && !cwd.empty(); ++i) {
            fs::path c = cwd / "schema" / "forensicator.sql";
            if (exists_file(c)) return c.string();
            fs::path parent = cwd.parent_path();
            if (parent == cwd) break;
            cwd = parent;
        }
    }
    // Compile-time install prefix.
    if (std::string(FORENSICATOR_INSTALL_DATAROOT).size() > 0) {
        fs::path c = fs::path(FORENSICATOR_INSTALL_DATAROOT) / "forensicator" / "forensicator.sql";
        if (exists_file(c)) return c.string();
    }
    return {};
}

}  // namespace forensicator
