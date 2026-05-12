#!/usr/bin/env bash
# A catalog produced by implementation X must be fully readable and usable
# by ALL OTHER implementations (schema and JSONL compatibility check).
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

# Skip if this is the only implementation available.
others=()
for impl in perl python cpp; do
    [ "$impl" = "$FC_IMPL" ] && continue
    fc_impl_available "$impl" && others+=("$impl")
done
if [ "${#others[@]}" -eq 0 ]; then
    fc_log "SKIP  no other implementations available to cross-check"
    exit 77
fi

mkdir -p "$FC_WORK/data"
echo "alpha"      > "$FC_WORK/data/a.txt"
echo "alpha"      > "$FC_WORK/data/b.txt"
echo "different"  > "$FC_WORK/data/c.txt"

# Build catalog with the implementation under test.
fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK/data" --hostname test >/dev/null

# Have every other implementation run dedupe against it and check the group count.
for other in "${others[@]}"; do
    FC_IMPL="$other" fc dedupe --catalog "$FC_WORK/c.sqlite" --format json \
        --output "$FC_WORK/dupes-${other}.json" >/dev/null

    groups=$(python3 -c "import json; d=json.load(open('$FC_WORK/dupes-${other}.json')); print(len(d['duplicate_groups']))")
    fc_assert_eq "$other reads the $FC_IMPL catalog (1 dup group)" "1" "$groups"
done

fc_finish
