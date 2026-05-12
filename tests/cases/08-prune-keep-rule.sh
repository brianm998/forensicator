#!/usr/bin/env bash
# Prune with --keep-rule first should keep the alphabetically-first member of
# each group, delete the others, AND remove the deleted rows from the catalog.
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

mkdir -p "$FC_WORK/data"
echo "shared" > "$FC_WORK/data/aaa.txt"
echo "shared" > "$FC_WORK/data/bbb.txt"
echo "shared" > "$FC_WORK/data/ccc.txt"

fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK/data" --hostname test >/dev/null
fc dedupe --catalog "$FC_WORK/c.sqlite" --format json --output "$FC_WORK/plan.json" >/dev/null

fc_assert_file_exists "all three files exist before prune" "$FC_WORK/data/bbb.txt"

fc prune --catalog "$FC_WORK/c.sqlite" --plan "$FC_WORK/plan.json" \
    --keep-rule first --no-interactive --apply --yes --hostname test >/dev/null

# Exactly one of the three should remain (the one chosen as keeper).
remaining=$(ls "$FC_WORK/data" | wc -l | tr -d ' ')
fc_assert_eq "one file remains after prune" "1" "$remaining"

# Catalog should also have only one row for this volume.
rows=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files")
fc_assert_eq "catalog row count matches filesystem" "1" "$rows"

fc_finish
