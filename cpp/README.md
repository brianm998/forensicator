# forensicator - C++ implementation

A multi-threaded port of the forensicator catalog/dedupe tool. Reads and
writes the same SQLite schema and JSONL records as the Perl and Python
implementations, so a catalog produced here is consumable by either of
the others.

## Why C++?

For multi-TB archives or many-million-file scans, the scan pipeline is
the bottleneck. The C++ implementation uses a producer/consumer
architecture so the walker, hashers, and SQLite recorder run
concurrently and a fast hash routine (OpenSSL with hardware
acceleration where available) keeps all CPU cores busy.

```
   walker thread  --[(path, size, mtime)]-->  recorder thread
                                                |  ^
                                                v  |
                                            hash queue
                                                |
                                                v
                                    K hasher threads (default = cores)
                                                |
                                                v
                                       hash result queue --> recorder
```

All catalog writes go through the single recorder thread so SQLite sees
no contention. Queues are bounded so producers block under back-pressure.

## Requirements

- CMake >= 3.20
- A C++20 compiler (GCC 11+, Clang 13+, MSVC 2022+, Apple clang from
  Xcode 14+)
- libsqlite3 (system or Homebrew)
- OpenSSL >= 1.1 (optional; falls back to a vendored SHA-512
  implementation if not found)

## Build

```
cd cpp
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/forensicator --help
```

If CMake cannot find OpenSSL on macOS:

```
cmake -S . -B build -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3) -DCMAKE_BUILD_TYPE=Release
```

## Install

```
cmake --install build --prefix /usr/local
```

This installs:

- `bin/forensicator`
- `share/forensicator/forensicator.sql` (canonical schema)

The binary searches the schema in this order:

1. `$FORENSICATOR_SCHEMA` env var
2. `<exe-dir>/schema/forensicator.sql`
3. `<exe-dir>/../schema/forensicator.sql`
4. `<exe-dir>/../share/forensicator/forensicator.sql`
5. The compiled-in install prefix (`CMAKE_INSTALL_DATAROOTDIR`)
6. A walk up from CWD looking for `schema/forensicator.sql`

## Usage

Same surface as the Perl version:

```
forensicator scan    --catalog FILE --volume NAME --root DIR [--hash-threads N] [opts]
forensicator dedupe  --catalog FILE [--format human|json] [--output FILE]
forensicator prune   --catalog FILE --plan FILE.json [--apply] [opts]
forensicator merge   --output FILE  --inputs A.sqlite B.sqlite ...
```

See `forensicator <cmd> --help` for full option lists.

The only C++-specific option is `--hash-threads N` on `scan`; defaults
to `std::thread::hardware_concurrency()`.

## Layout

```
include/forensicator/   public headers
src/                    library + subcommand implementations
tests/                  CTest-driven unit and end-to-end tests
scripts/                release packaging and dep installers
cmake/                  extra CMake helpers (currently unused)
third_party/            optional vendored deps (currently empty)
```

## Compatibility

A catalog written by this binary is byte-compatible with the Perl
implementation. Cross-check with:

```
./build/forensicator scan --catalog c.sqlite --volume v --root /some/path --hostname me
/usr/bin/perl -I../perl/lib ../perl/bin/forensicator-dedupe --catalog c.sqlite
```
