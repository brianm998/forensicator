#!/usr/bin/env bash
# Missing/invalid arguments should produce a clear error (non-zero exit)
# without creating a catalog file.
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

# 1. Missing --catalog
if fc scan --volume v --root "$FC_WORK" --hostname test >/dev/null 2>&1; then
    fc_log "FAIL  scan accepted missing --catalog"
    FC_FAILS=$((FC_FAILS+1))
else
    fc_log "PASS  scan rejects missing --catalog"
fi

# 2. Missing --volume
if fc scan --catalog "$FC_WORK/c.sqlite" --root "$FC_WORK" --hostname test >/dev/null 2>&1; then
    fc_log "FAIL  scan accepted missing --volume"
    FC_FAILS=$((FC_FAILS+1))
else
    fc_log "PASS  scan rejects missing --volume"
fi

# 3. Root that doesn't exist
if fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK/nope" --hostname test >/dev/null 2>&1; then
    fc_log "FAIL  scan accepted missing --root"
    FC_FAILS=$((FC_FAILS+1))
else
    fc_log "PASS  scan rejects missing --root"
fi

# 4. Positional after flags (should reject — only flags allowed)
if fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK" extra_garbage >/dev/null 2>&1; then
    fc_log "FAIL  scan accepted stray positional arg"
    FC_FAILS=$((FC_FAILS+1))
else
    fc_log "PASS  scan rejects stray positional arg"
fi

fc_finish
