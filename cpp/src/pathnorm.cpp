#include "forensicator/pathnorm.hpp"

#include "forensicator/util.hpp"

namespace forensicator {

std::string normalize_path(std::string_view path, std::string_view os) {
    // Empty os string -> default to host OS to match Perl `$os //= os_name()`.
    std::string host_os;
    if (os.empty()) {
        host_os = os_name();
        os = host_os;
    }
    std::string n;
    n.reserve(path.size());
    for (char c : path) {
        n.push_back(c == '\\' ? '/' : c);
    }
    // Collapse repeated slashes.
    if (!n.empty()) {
        std::string out;
        out.reserve(n.size());
        char prev = 0;
        for (char c : n) {
            if (c == '/' && prev == '/') continue;
            out.push_back(c);
            prev = c;
        }
        n.swap(out);
    }
    // Strip any number of leading "./" segments.
    while (n.size() >= 2 && n[0] == '.' && n[1] == '/') {
        n.erase(0, 2);
    }
    // Strip trailing slash unless the whole string is "/".
    if (n.size() > 1 && n.back() == '/') {
        n.pop_back();
    }
    if (is_case_insensitive_os(os)) {
        ascii_lower_inplace(n);
    }
    return n;
}

std::string normalize_path(std::string_view path) {
    return normalize_path(path, os_name());
}

}  // namespace forensicator
