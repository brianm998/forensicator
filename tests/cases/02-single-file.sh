#!/usr/bin/env bash
# A unique-size file (no collisions) should be cataloged with NULL sha512.
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

mkdir -p "$FC_WORK/data"
echo "uniqueness 7654321" > "$FC_WORK/data/only.txt"

fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK/data" --hostname test >/dev/null

count=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files")
fc_assert_eq "one file row" "1" "$count"

hashed=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(sha512) FROM files")
fc_assert_eq "unique-size files not hashed in quick mode" "0" "$hashed"

path=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT path FROM files")
fc_assert_eq "relative path stored" "only.txt" "$path"

fc_finish
