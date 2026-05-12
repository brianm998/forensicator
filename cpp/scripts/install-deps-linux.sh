#!/usr/bin/env bash
# Install build prerequisites on Linux.
set -euo pipefail

if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y cmake g++ pkg-config libsqlite3-dev libssl-dev
elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y cmake gcc-c++ pkgconf sqlite-devel openssl-devel
elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Sy --noconfirm cmake gcc pkgconf sqlite openssl
elif command -v zypper >/dev/null 2>&1; then
    sudo zypper install -y cmake gcc-c++ pkg-config sqlite3-devel libopenssl-devel
else
    echo "Unknown distro. Install: cmake, a C++20 compiler, libsqlite3-dev, libssl-dev." >&2
    exit 1
fi
