#!/usr/bin/env bash
# Default skip lists: .git dirs and OS junk files must not appear in catalog.
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

mkdir -p "$FC_WORK/data/.git/objects" "$FC_WORK/data/.Trashes" "$FC_WORK/data/real"
echo "keep me" > "$FC_WORK/data/real/real.txt"
echo "git junk" > "$FC_WORK/data/.git/objects/abc"
echo "trash"    > "$FC_WORK/data/.Trashes/junk"
echo "ds_store" > "$FC_WORK/data/.DS_Store"
echo "thumbs"   > "$FC_WORK/data/Thumbs.db"

fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK/data" --hostname test >/dev/null

count=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files")
fc_assert_eq "only real.txt cataloged (junk skipped)" "1" "$count"

fc_finish
