#!/usr/bin/env bash
# Prune without --apply should NOT delete anything and NOT modify the catalog.
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

mkdir -p "$FC_WORK/data"
echo "shared" > "$FC_WORK/data/a.txt"
echo "shared" > "$FC_WORK/data/b.txt"

fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK/data" --hostname test >/dev/null
fc dedupe --catalog "$FC_WORK/c.sqlite" --format json --output "$FC_WORK/plan.json" >/dev/null

before=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files")

fc prune --catalog "$FC_WORK/c.sqlite" --plan "$FC_WORK/plan.json" \
    --keep-rule first --no-interactive --hostname test >/dev/null

fc_assert_file_exists "a.txt still present (dry-run)" "$FC_WORK/data/a.txt"
fc_assert_file_exists "b.txt still present (dry-run)" "$FC_WORK/data/b.txt"

after=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files")
fc_assert_eq "catalog unchanged after dry run" "$before" "$after"

fc_finish
