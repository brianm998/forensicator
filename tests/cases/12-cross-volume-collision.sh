#!/usr/bin/env bash
# Files with same size on different volumes (same host, same catalog) must be
# resolved by the post-walk reachable-volumes pass.
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

mkdir -p "$FC_WORK/volA" "$FC_WORK/volB"
echo "12345" > "$FC_WORK/volA/x.txt"
echo "67890" > "$FC_WORK/volB/y.txt"

# Same size (6 bytes incl newline), different content — both should end up hashed.
fc scan --catalog "$FC_WORK/c.sqlite" --volume volA --root "$FC_WORK/volA" --hostname test >/dev/null
fc scan --catalog "$FC_WORK/c.sqlite" --volume volB --root "$FC_WORK/volB" --hostname test >/dev/null

null_hashes=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files WHERE sha512 IS NULL")
fc_assert_eq "all colliding files are hashed across volumes" "0" "$null_hashes"

# Different content, so no duplicates.
fc dedupe --catalog "$FC_WORK/c.sqlite" --format json --output "$FC_WORK/dupes.json" >/dev/null
groups=$(python3 -c "import json; d=json.load(open('$FC_WORK/dupes.json')); print(len(d['duplicate_groups']))")
fc_assert_eq "no duplicate groups (different content)" "0" "$groups"

fc_finish
