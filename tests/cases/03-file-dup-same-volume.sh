#!/usr/bin/env bash
# Two files with identical content on the same volume should be detected as duplicates.
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

mkdir -p "$FC_WORK/data/sub"
echo "duplicate content alpha" > "$FC_WORK/data/a.txt"             # 24 bytes
echo "duplicate content alpha" > "$FC_WORK/data/sub/a-copy.txt"    # 24 bytes
echo "completely different unique-length content" > "$FC_WORK/data/b.txt"  # 43 bytes (unique size)

fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK/data" --hostname test >/dev/null

# Both colliding files should now be hashed
hashed=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files WHERE sha512 IS NOT NULL")
fc_assert_eq "both size-colliders are hashed" "2" "$hashed"

# Dedupe in JSON format should produce exactly one group of 2
fc dedupe --catalog "$FC_WORK/c.sqlite" --format json --output "$FC_WORK/dupes.json" >/dev/null

groups=$(python3 -c "import json,sys; d=json.load(open('$FC_WORK/dupes.json')); print(len(d['duplicate_groups']))")
fc_assert_eq "one duplicate group" "1" "$groups"

members=$(python3 -c "import json,sys; d=json.load(open('$FC_WORK/dupes.json')); print(len(d['duplicate_groups'][0]['members']))")
fc_assert_eq "two members in the group" "2" "$members"

kind=$(python3 -c "import json,sys; d=json.load(open('$FC_WORK/dupes.json')); print(d['duplicate_groups'][0]['kind'])")
fc_assert_eq "kind is file" "file" "$kind"

fc_finish
