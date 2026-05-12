#!/usr/bin/env bash
# Cross-language test harness shared helpers.
#
# Each case script sources this file and then runs:
#   fc_setup
#   ... build fixture ...
#   fc scan/dedupe/prune/merge ...
#   fc_assert ...
#   fc_teardown
#
# `fc` is a wrapper that dispatches to whichever implementation is being
# tested (FC_IMPL=perl|python|cpp). The CLI surface is identical across all
# three (single entry point + subcommand).

set -u
set -o pipefail

FC_IMPL="${FC_IMPL:-perl}"
# Repo root = two levels up from harness.sh itself (tests/lib/harness.sh).
_FC_HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FC_REPO="${FC_REPO:-$(cd "$_FC_HARNESS_DIR/../.." && pwd)}"

# Pick a python3 whose bundled SQLite supports UPSERT (>= 3.24, June 2018).
# macOS often ships a Python whose sqlite3 module is statically linked
# against an old SQLite; we don't want to test the Python implementation
# against that — that's the user's environment problem, not ours.
fc_pick_python3() {
    if [ -n "${FC_PYTHON3:-}" ]; then
        echo "$FC_PYTHON3"; return
    fi
    for p in /usr/local/bin/python3 /opt/homebrew/bin/python3 /usr/bin/python3 python3; do
        if command -v "$p" >/dev/null 2>&1; then
            if "$p" -c 'import sqlite3,sys; sys.exit(0 if sqlite3.sqlite_version_info >= (3,24) else 1)' 2>/dev/null; then
                echo "$p"; return
            fi
        fi
    done
    echo ""  # none found
}
FC_PYTHON3="$(fc_pick_python3)"
export FC_PYTHON3
FC_WORK="${FC_WORK:-}"
FC_FAILS=0
FC_CASE_NAME="${0##*/}"
FC_CASE_NAME="${FC_CASE_NAME%.sh}"

fc_log() { printf '[%s/%s] %s\n' "$FC_IMPL" "$FC_CASE_NAME" "$*" >&2; }

# Set up a temp workdir for this case.
fc_setup() {
    FC_WORK="$(mktemp -d "/tmp/fc-test-${FC_CASE_NAME}.XXXXXX")"
    export FC_WORK
    trap 'fc_teardown' EXIT
}

fc_teardown() {
    if [ -n "${FC_WORK:-}" ] && [ -d "$FC_WORK" ]; then
        rm -rf "$FC_WORK"
    fi
}

# Dispatch to the implementation under test.
fc() {
    case "$FC_IMPL" in
        perl)
            /usr/bin/perl -I"$FC_REPO/perl/lib" "$FC_REPO/perl/bin/forensicator" "$@"
            ;;
        python)
            if [ -z "$FC_PYTHON3" ]; then
                fc_log "SKIP: no python3 with SQLite >= 3.24 found"
                exit 77
            fi
            PYTHONPATH="$FC_REPO/python" "$FC_PYTHON3" -m forensicator "$@"
            ;;
        cpp)
            local bin="$FC_REPO/cpp/build/forensicator"
            if [ ! -x "$bin" ]; then
                bin="$FC_REPO/cpp/build-release/forensicator"
            fi
            if [ ! -x "$bin" ]; then
                fc_log "SKIP: cpp binary not built"
                exit 77
            fi
            "$bin" "$@"
            ;;
        *)
            fc_log "unknown FC_IMPL: $FC_IMPL"
            exit 2
            ;;
    esac
}

# Is the given implementation available right now?
fc_impl_available() {
    case "$1" in
        perl)
            /usr/bin/perl -I"$FC_REPO/perl/lib" -e 'use Forensicator;' 2>/dev/null
            ;;
        python)
            [ -n "$FC_PYTHON3" ] || return 1
            "$FC_PYTHON3" -c "import sys; sys.path.insert(0, '$FC_REPO/python'); from forensicator.cli import main" 2>/dev/null
            ;;
        cpp)
            [ -x "$FC_REPO/cpp/build/forensicator" ] || [ -x "$FC_REPO/cpp/build-release/forensicator" ]
            ;;
        *) return 1 ;;
    esac
}

# Assert helpers.
fc_assert() {
    local desc="$1"; shift
    if "$@"; then
        fc_log "PASS  $desc"
    else
        fc_log "FAIL  $desc (cmd: $*)"
        FC_FAILS=$((FC_FAILS + 1))
    fi
}

fc_assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        fc_log "PASS  $desc"
    else
        fc_log "FAIL  $desc"
        fc_log "      expected: $expected"
        fc_log "      actual:   $actual"
        FC_FAILS=$((FC_FAILS + 1))
    fi
}

fc_assert_file_exists() {
    local desc="$1" path="$2"
    if [ -e "$path" ]; then
        fc_log "PASS  $desc"
    else
        fc_log "FAIL  $desc (missing: $path)"
        FC_FAILS=$((FC_FAILS + 1))
    fi
}

fc_assert_file_absent() {
    local desc="$1" path="$2"
    if [ ! -e "$path" ]; then
        fc_log "PASS  $desc"
    else
        fc_log "FAIL  $desc (still present: $path)"
        FC_FAILS=$((FC_FAILS + 1))
    fi
}

fc_finish() {
    if [ "$FC_FAILS" -eq 0 ]; then
        fc_log "OK"
        exit 0
    else
        fc_log "$FC_FAILS assertion(s) failed"
        exit 1
    fi
}

# Helper: count rows in a table.
fc_sqlite_count() {
    local catalog="$1" sql="$2"
    sqlite3 "$catalog" "$sql"
}

# Helper: list files under a path, relative, sorted.
fc_ls_rel() {
    local root="$1"
    (cd "$root" && find . -type f | sort)
}
