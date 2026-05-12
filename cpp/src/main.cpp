#include <cstring>
#include <iostream>
#include <string>

#if defined(__APPLE__)
#  include <mach-o/dyld.h>
#  include <vector>
#elif defined(__linux__)
#  include <unistd.h>
#  include <limits.h>
#elif defined(_WIN32)
#  include <windows.h>
#endif

namespace forensicator {
int cmd_scan  (int argc, char** argv, const std::string& exe_path);
int cmd_dedupe(int argc, char** argv, const std::string& exe_path);
int cmd_prune (int argc, char** argv, const std::string& exe_path);
int cmd_merge (int argc, char** argv, const std::string& exe_path);
}

static std::string self_exe_path() {
#if defined(__APPLE__)
    std::vector<char> buf(1024);
    std::uint32_t sz = static_cast<std::uint32_t>(buf.size());
    if (_NSGetExecutablePath(buf.data(), &sz) != 0) {
        buf.resize(sz);
        _NSGetExecutablePath(buf.data(), &sz);
    }
    return std::string(buf.data());
#elif defined(__linux__)
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    buf[n] = 0;
    return buf;
#elif defined(_WIN32)
    char buf[MAX_PATH];
    DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (n == 0) return {};
    return std::string(buf, n);
#else
    return {};
#endif
}

static void top_usage() {
    std::cout <<
        "forensicator: catalog and deduplicate digital archives\n\n"
        "Usage:\n"
        "  forensicator <command> [args...]\n\n"
        "Commands:\n"
        "  scan       Walk a volume and catalog files\n"
        "  dedupe     Find duplicate files and directory trees\n"
        "  prune      Delete duplicates per a dedupe plan\n"
        "  merge      Combine multiple catalogs/JSONL into one\n\n"
        "Run 'forensicator <command> --help' for command-specific options.\n";
}

int main(int argc, char** argv) {
    if (argc < 2) { top_usage(); return 0; }
    std::string cmd = argv[1];
    std::string exe = self_exe_path();
    int rc = 0;
    int sub_argc = argc - 2;
    char** sub_argv = argv + 2;
    if (cmd == "-h" || cmd == "--help" || cmd == "help") { top_usage(); return 0; }
    else if (cmd == "scan")   rc = forensicator::cmd_scan(sub_argc, sub_argv, exe);
    else if (cmd == "dedupe") rc = forensicator::cmd_dedupe(sub_argc, sub_argv, exe);
    else if (cmd == "prune")  rc = forensicator::cmd_prune(sub_argc, sub_argv, exe);
    else if (cmd == "merge")  rc = forensicator::cmd_merge(sub_argc, sub_argv, exe);
    else {
        std::cerr << "unknown command: " << cmd << "\n";
        top_usage();
        return 2;
    }
    return rc;
}
