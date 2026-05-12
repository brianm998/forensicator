#!/usr/bin/env bash
# Zero-byte files and symlinks should be skipped, NOT cataloged.
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

mkdir -p "$FC_WORK/data"
echo "real content" > "$FC_WORK/data/real.txt"
: > "$FC_WORK/data/empty.txt"                       # zero-byte
ln -s real.txt "$FC_WORK/data/link.txt"             # symlink
ln -s does-not-exist "$FC_WORK/data/broken.txt"     # broken symlink

fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK/data" --hostname test >/dev/null

count=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files")
fc_assert_eq "only real.txt cataloged" "1" "$count"

path=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT path FROM files")
fc_assert_eq "the cataloged file is real.txt" "real.txt" "$path"

fc_finish
