#!/usr/bin/env bash
# Install build prerequisites on macOS using Homebrew.
set -euo pipefail

if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew not found. Install from https://brew.sh first." >&2
    exit 1
fi

brew update
brew install cmake sqlite3 openssl@3

cat <<EOF

If CMake cannot find OpenSSL automatically, configure with:
  cmake -S . -B build -DOPENSSL_ROOT_DIR=\$(brew --prefix openssl@3)

If CMake cannot find SQLite (macOS bundles sqlite3 but not always its
pkg-config), you can hint with:
  cmake -S . -B build -DSQLite3_INCLUDE_DIR=\$(brew --prefix sqlite)/include \\
                     -DSQLite3_LIBRARY=\$(brew --prefix sqlite)/lib/libsqlite3.dylib
EOF
