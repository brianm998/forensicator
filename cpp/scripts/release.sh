#!/usr/bin/env bash
# Build a release tarball for the host platform.
#
# Usage:
#   scripts/release.sh [--version VERSION] [--static]
#
# Produces cpp/dist/forensicator-<os>-<arch>-<version>.tar.gz
set -euo pipefail

VERSION=""
STATIC=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2;;
        --static)  STATIC=1; shift;;
        -h|--help)
            echo "usage: $0 [--version VERSION] [--static]"; exit 0;;
        *) echo "unknown option: $1" >&2; exit 2;;
    esac
done

cd "$(dirname "$0")/.."

if [[ -z "$VERSION" ]]; then
    if [[ -f VERSION ]]; then
        VERSION="$(cat VERSION)"
    else
        VERSION="dev"
    fi
fi

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
    darwin) OS=darwin;;
    linux)  OS=linux;;
    *) echo "unsupported os: $OS" >&2; exit 2;;
esac
ARCH="$(uname -m)"

BUILD_DIR="build-release"
DIST_DIR="dist"
mkdir -p "$DIST_DIR"

EXTRA_FLAGS=()
if [[ "$STATIC" -eq 1 ]]; then
    EXTRA_FLAGS+=("-DCMAKE_EXE_LINKER_FLAGS=-static-libstdc++")
fi
# Allow callers to point at non-system OpenSSL / SQLite.
if [[ -n "${OPENSSL_ROOT_DIR:-}" ]]; then
    EXTRA_FLAGS+=("-DOPENSSL_ROOT_DIR=$OPENSSL_ROOT_DIR")
fi
if [[ -n "${SQLITE3_ROOT:-}" ]]; then
    EXTRA_FLAGS+=("-DSQLite3_INCLUDE_DIR=$SQLITE3_ROOT/include")
    EXTRA_FLAGS+=("-DSQLite3_LIBRARY=$SQLITE3_ROOT/lib/libsqlite3.dylib")
fi

# Bash 3.2 (macOS) chokes on ${ARR[@]} with set -u when the array is empty;
# use the safe expansion.
cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release ${EXTRA_FLAGS[@]+"${EXTRA_FLAGS[@]}"}
cmake --build "$BUILD_DIR" --parallel

PKG="forensicator-${OS}-${ARCH}-${VERSION}"
STAGE="$BUILD_DIR/$PKG"
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/share/forensicator"
cp "$BUILD_DIR/forensicator" "$STAGE/bin/"
cp ../schema/forensicator.sql "$STAGE/share/forensicator/"
cp README.md "$STAGE/" 2>/dev/null || true

tar -C "$BUILD_DIR" -czf "$DIST_DIR/$PKG.tar.gz" "$PKG"
echo "wrote $DIST_DIR/$PKG.tar.gz"
