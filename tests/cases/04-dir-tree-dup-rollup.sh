#!/usr/bin/env bash
# Identical directory trees should be rolled up — reported as one dir-level
# duplicate, NOT as N separate file-level duplicates.
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

mkdir -p "$FC_WORK/data/photos/2024" "$FC_WORK/data/backup/photos/2024"
for n in x y z; do
    echo "content of $n" > "$FC_WORK/data/photos/2024/$n.jpg"
    echo "content of $n" > "$FC_WORK/data/backup/photos/2024/$n.jpg"
done

fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK/data" --hostname test >/dev/null
fc dedupe --catalog "$FC_WORK/c.sqlite" --format json --output "$FC_WORK/dupes.json" >/dev/null

# Expect: one DIR-level dup at the photos/2024 level (NOT three FILE-level).
groups=$(python3 -c "import json; d=json.load(open('$FC_WORK/dupes.json')); print(len(d['duplicate_groups']))")
fc_assert_eq "exactly one duplicate group (rolled up)" "1" "$groups"

kind=$(python3 -c "import json; d=json.load(open('$FC_WORK/dupes.json')); print(d['duplicate_groups'][0]['kind'])")
fc_assert_eq "rolled up to dir level" "dir" "$kind"

count=$(python3 -c "import json; d=json.load(open('$FC_WORK/dupes.json')); print(d['duplicate_groups'][0]['file_count_each'])")
fc_assert_eq "three files per dir member" "3" "$count"

fc_finish
