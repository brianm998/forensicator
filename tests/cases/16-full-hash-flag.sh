#!/usr/bin/env bash
# --full-hash should hash every file, even those with unique sizes.
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

mkdir -p "$FC_WORK/data"
echo "a"        > "$FC_WORK/data/one.txt"          # 2 bytes
echo "bb"       > "$FC_WORK/data/two.txt"          # 3 bytes
echo "ccc"      > "$FC_WORK/data/three.txt"        # 4 bytes — all unique sizes

fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK/data" \
       --hostname test --full-hash >/dev/null

hashed=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files WHERE sha512 IS NOT NULL")
fc_assert_eq "all three unique-size files were hashed (full-hash mode)" "3" "$hashed"

fc_finish
