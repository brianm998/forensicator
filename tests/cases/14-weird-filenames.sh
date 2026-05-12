#!/usr/bin/env bash
# Filenames with spaces, unicode, and quotes must be cataloged and queryable.
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

mkdir -p "$FC_WORK/data"
echo "spaces"  > "$FC_WORK/data/file with spaces.txt"
echo "unicode" > "$FC_WORK/data/photo café.jpg"
echo "dash-prefix" > "$FC_WORK/data/-leading-dash.txt"
echo "deeply"  > "$FC_WORK/data/a name with 'quotes' and dollar \$signs.txt"

fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK/data" --hostname test >/dev/null

count=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files")
fc_assert_eq "all four weird-named files cataloged" "4" "$count"

# Path with spaces should round-trip through sqlite.
spaces=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files WHERE path = 'file with spaces.txt'")
fc_assert_eq "spaces preserved" "1" "$spaces"

# Unicode preserved.
unicode=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files WHERE path = 'photo café.jpg'")
fc_assert_eq "unicode preserved" "1" "$unicode"

fc_finish
