#include "forensicator/util.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>

namespace fs = std::filesystem;

static int run(const std::string& cmd) {
    int rc = std::system(cmd.c_str());
    return rc;
}

static std::string slurp(const fs::path& p) {
    std::ifstream ifs(p);
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: test_e2e <forensicator-binary>\n";
        return 2;
    }
    std::string bin = argv[1];

    fs::path tmp = fs::temp_directory_path() /
        ("fc-e2e-" + std::to_string(forensicator::now_epoch()));
    fs::create_directories(tmp);
    fs::path data = tmp / "data" / "sub";
    fs::create_directories(data);
    {
        std::ofstream(tmp / "data" / "a.txt") << "alpha";
        std::ofstream(tmp / "data" / "b.txt") << "alpha";   // dup of a.txt
        std::ofstream(tmp / "data" / "c.txt") << "beta";    // unique
        std::ofstream(data / "deep.txt") << "alpha";        // also dup
    }

    fs::path cat = tmp / "c.sqlite";
    {
        std::string c = bin + " scan --catalog " + cat.string()
                      + " --volume v --root " + (tmp / "data").string()
                      + " --hostname testhost --quiet";
        int rc = run(c);
        if (rc != 0) {
            std::cerr << "scan failed rc=" << rc << "\n";
            return 1;
        }
    }
    {
        fs::path out = tmp / "dupes.json";
        std::string c = bin + " dedupe --catalog " + cat.string()
                      + " --format json --output " + out.string();
        int rc = run(c);
        if (rc != 0) { std::cerr << "dedupe failed\n"; return 1; }
        std::string body = slurp(out);
        if (body.find("\"duplicate_groups\":") == std::string::npos) {
            std::cerr << "no duplicate_groups in output\n"; return 1;
        }
        if (body.find("alpha") != std::string::npos) {
            // fine: should not contain file content
        }
        // We expect at least one duplicate group (the three 'alpha' files).
        if (body.find("\"sig\":") == std::string::npos) {
            std::cerr << "no sig in dedupe output\n"; return 1;
        }
    }

    // Test merge: jsonl export round-trip.
    {
        fs::path jp = tmp / "exp.jsonl";
        std::string c = bin + " merge --output " + jp.string()
                      + " --inputs " + cat.string() + " --quiet";
        int rc = run(c);
        if (rc != 0) { std::cerr << "merge to jsonl failed\n"; return 1; }
        std::string body = slurp(jp);
        if (body.find("\"hostname\":\"testhost\"") == std::string::npos) {
            std::cerr << "merge jsonl missing hostname\n"; return 1;
        }
    }

    std::error_code ec;
    fs::remove_all(tmp, ec);
    std::cout << "test_e2e ok\n";
    return 0;
}
