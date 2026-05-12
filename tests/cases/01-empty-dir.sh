#!/usr/bin/env bash
# Scanning an empty directory should succeed and produce a valid empty catalog.
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

mkdir -p "$FC_WORK/data"

fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK/data" --hostname test >/dev/null

fc_assert_file_exists "catalog created" "$FC_WORK/c.sqlite"
files=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files")
fc_assert_eq "no files in catalog" "0" "$files"

vols=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM volumes")
fc_assert_eq "one volume row" "1" "$vols"

sv=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT value FROM meta WHERE key='schema_version'")
fc_assert_eq "schema_version is 1" "1" "$sv"

fc_finish
