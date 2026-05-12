#include "forensicator/catalog.hpp"
#include "forensicator/util.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>

using namespace forensicator;

int main() {
    namespace fs = std::filesystem;
    auto tmp = fs::temp_directory_path() / ("fc-test-cat-" + std::to_string(now_epoch()));
    fs::create_directories(tmp);
    auto db = tmp / "c.sqlite";

    std::string schema = find_schema_file({});
    if (schema.empty()) {
        std::cerr << "schema not found via search; FORENSICATOR_SCHEMA env should be set\n";
        return 2;
    }

    {
        Catalog cat;
        cat.open(db, schema, false);
        auto v = cat.upsert_volume("h1", "v1", "/mnt", os_name());
        assert(v.volume_id == 1);
        assert(v.hostname == "h1");
        assert(v.volume == "v1");
        auto got = cat.get_volume("h1", "v1");
        assert(got.has_value());
        assert(got->volume_id == 1);
        auto vs = cat.volumes();
        assert(vs.size() == 1);
        cat.set_meta("dataset_name", "test-ds");
        auto sv = cat.get_meta("schema_version");
        assert(sv.has_value() && *sv == "1");
    }

    // Re-open
    {
        Catalog cat;
        cat.open(db, schema, true);
        auto v = cat.get_volume("h1", "v1");
        assert(v.has_value());
        assert(*cat.get_meta("dataset_name") == "test-ds");
    }

    std::error_code ec;
    fs::remove_all(tmp, ec);
    std::cout << "test_catalog ok\n";
    return 0;
}
