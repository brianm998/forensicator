#!/usr/bin/env bash
# Run the forensicator cross-language test suite.
#
# Usage:
#   tests/run-all.sh                     # all implementations, all cases
#   tests/run-all.sh --only perl         # one implementation
#   tests/run-all.sh --only python --only cpp
#   tests/run-all.sh --case 03           # run only case scripts matching '03'
#   tests/run-all.sh --case dedupe       # run only case scripts matching 'dedupe'
#
# Exit code 0 means all selected cases passed on all selected implementations.

set -u
set -o pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TESTS_DIR="$REPO/tests"
. "$TESTS_DIR/lib/harness.sh"

IMPLS=()
PATTERN=""

while [ $# -gt 0 ]; do
    case "$1" in
        --only)        IMPLS+=("$2"); shift 2 ;;
        --case)        PATTERN="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,11p' "$0"
            exit 0
            ;;
        *)
            echo "unknown arg: $1" >&2
            exit 2
            ;;
    esac
done

if [ "${#IMPLS[@]}" -eq 0 ]; then
    IMPLS=(perl python cpp)
fi

case_scripts=()
for f in "$TESTS_DIR"/cases/*.sh; do
    [ -f "$f" ] || continue
    base="$(basename "$f")"
    if [ -n "$PATTERN" ] && [[ "$base" != *"$PATTERN"* ]]; then
        continue
    fi
    case_scripts+=("$f")
done

if [ "${#case_scripts[@]}" -eq 0 ]; then
    echo "no matching case scripts" >&2
    exit 2
fi

declare -i total=0 passed=0 failed=0 skipped=0
failed_list=()

for impl in "${IMPLS[@]}"; do
    if ! fc_impl_available "$impl"; then
        printf '== SKIP impl=%s (not available) ==\n' "$impl"
        skipped=$((skipped + 1))
        continue
    fi
    printf '\n== impl=%s ==\n' "$impl"
    for case_script in "${case_scripts[@]}"; do
        total=$((total + 1))
        out="$(FC_IMPL="$impl" bash "$case_script" 2>&1)"
        rc=$?
        if [ "$rc" -eq 0 ]; then
            passed=$((passed + 1))
            printf '  PASS  %s\n' "$(basename "$case_script" .sh)"
        elif [ "$rc" -eq 77 ]; then
            skipped=$((skipped + 1))
            printf '  SKIP  %s\n' "$(basename "$case_script" .sh)"
        else
            failed=$((failed + 1))
            failed_list+=("$impl:$(basename "$case_script" .sh)")
            printf '  FAIL  %s\n' "$(basename "$case_script" .sh)"
            echo "$out" | sed 's/^/        /'
        fi
    done
done

echo
echo "== summary =="
echo "  total:   $total"
echo "  passed:  $passed"
echo "  failed:  $failed"
echo "  skipped: $skipped"

if [ "$failed" -gt 0 ]; then
    echo
    echo "failed cases:"
    for f in "${failed_list[@]}"; do
        echo "  $f"
    done
    exit 1
fi
exit 0
