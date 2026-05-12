#!/usr/bin/env bash
# Re-running scan against the same tree should be idempotent: same row count,
# unchanged files retain their sha512 without re-hashing.
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

mkdir -p "$FC_WORK/data"
echo "content one" > "$FC_WORK/data/one.txt"
echo "content two" > "$FC_WORK/data/two.txt"
echo "content one" > "$FC_WORK/data/one-copy.txt"

# First scan
fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK/data" --hostname test >/dev/null
n1=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files")
h1=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files WHERE sha512 IS NOT NULL")

# Second scan, no fs changes
fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK/data" --hostname test >/dev/null
n2=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files")
h2=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files WHERE sha512 IS NOT NULL")

fc_assert_eq "file count unchanged" "$n1" "$n2"
fc_assert_eq "hashed count unchanged" "$h1" "$h2"

fc_finish
