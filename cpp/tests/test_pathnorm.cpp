#include "forensicator/pathnorm.hpp"

#include <cassert>
#include <iostream>
#include <string>

using forensicator::normalize_path;

static void eq(const std::string& got, const std::string& expected, const char* msg) {
    if (got != expected) {
        std::cerr << "FAIL " << msg << ": got \"" << got << "\" expected \"" << expected << "\"\n";
        std::abort();
    }
}

int main() {
    // Slash collapsing
    eq(normalize_path("a//b///c", "linux"), "a/b/c", "collapse slashes");
    // Backslash conversion
    eq(normalize_path("a\\b\\c", "linux"), "a/b/c", "backslashes");
    // Trailing slash
    eq(normalize_path("foo/bar/", "linux"), "foo/bar", "trailing slash");
    // Root preserved
    eq(normalize_path("/", "linux"), "/", "root");
    // Leading ./
    eq(normalize_path("./a/b", "linux"), "a/b", "leading ./");
    // Case-insensitive on darwin
    eq(normalize_path("Foo/BAR.TXT", "darwin"), "foo/bar.txt", "darwin lowercase");
    // Case-sensitive on linux
    eq(normalize_path("Foo/BAR.TXT", "linux"), "Foo/BAR.TXT", "linux case-sensitive");
    // Windows case-insensitive
    eq(normalize_path("C:\\Users\\Bob", "MSWin32"), "c:/users/bob", "windows");
    // Combination
    eq(normalize_path("././/a//B/c\\d/", "darwin"), "a/b/c/d", "combo");
    std::cout << "test_pathnorm ok\n";
    return 0;
}
