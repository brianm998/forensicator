#!/usr/bin/env bash
# The hashlog must capture every catalog write. Replaying it through merge
# should reproduce a byte-equivalent catalog (same paths, same hashes).
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

mkdir -p "$FC_WORK/data"
echo "duplicate" > "$FC_WORK/data/a.txt"
echo "duplicate" > "$FC_WORK/data/b.txt"
echo "unique"    > "$FC_WORK/data/c.txt"

fc scan --catalog "$FC_WORK/orig.sqlite" \
       --hashlog "$FC_WORK/hash.jsonl" \
       --volume v --root "$FC_WORK/data" --hostname test >/dev/null

fc_assert_file_exists "hashlog created" "$FC_WORK/hash.jsonl"

lines=$(wc -l < "$FC_WORK/hash.jsonl" | tr -d ' ')
fc_assert "hashlog has at least one record per file" [ "$lines" -ge "3" ]

# Replay hashlog into a fresh sqlite via merge.
fc merge --output "$FC_WORK/replay.sqlite" --inputs "$FC_WORK/hash.jsonl" --quiet

orig_hashes=$(sqlite3 "$FC_WORK/orig.sqlite" "SELECT path,sha512 FROM files ORDER BY path")
replay_hashes=$(sqlite3 "$FC_WORK/replay.sqlite" "SELECT path,sha512 FROM files ORDER BY path")
fc_assert_eq "replay produces matching catalog" "$orig_hashes" "$replay_hashes"

fc_finish
