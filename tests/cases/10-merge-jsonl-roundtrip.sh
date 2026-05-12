#!/usr/bin/env bash
# Round-trip: scan -> export JSONL via merge -> import JSONL back into a fresh
# sqlite via merge. The resulting catalogs must contain the same rows.
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

mkdir -p "$FC_WORK/data"
echo "alpha" > "$FC_WORK/data/a.txt"
echo "alpha" > "$FC_WORK/data/b.txt"
echo "beta"  > "$FC_WORK/data/c.txt"

fc scan --catalog "$FC_WORK/orig.sqlite" --volume v --root "$FC_WORK/data" --hostname test >/dev/null

fc merge --output "$FC_WORK/export.jsonl" --inputs "$FC_WORK/orig.sqlite" --quiet
fc_assert_file_exists "jsonl export created" "$FC_WORK/export.jsonl"

fc merge --output "$FC_WORK/round.sqlite" --inputs "$FC_WORK/export.jsonl" --quiet

orig_count=$(fc_sqlite_count "$FC_WORK/orig.sqlite" "SELECT COUNT(*) FROM files")
round_count=$(fc_sqlite_count "$FC_WORK/round.sqlite" "SELECT COUNT(*) FROM files")
fc_assert_eq "row counts match" "$orig_count" "$round_count"

# Hashes survived the round trip.
orig_hashes=$(sqlite3 "$FC_WORK/orig.sqlite" "SELECT path,sha512 FROM files WHERE sha512 IS NOT NULL ORDER BY path")
round_hashes=$(sqlite3 "$FC_WORK/round.sqlite" "SELECT path,sha512 FROM files WHERE sha512 IS NOT NULL ORDER BY path")
fc_assert_eq "hashes preserved" "$orig_hashes" "$round_hashes"

fc_finish
