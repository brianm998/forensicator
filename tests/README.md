# forensicator cross-language test harness

The same suite of corner-case tests runs against every implementation
(Perl, Python, C++). Each test script invokes `forensicator` using the
implementation under test (selected by `FC_IMPL=perl|python|cpp`) and
asserts on the resulting catalog, filesystem, or output.

This guards against:
- Regressions when any implementation is modified
- Schema or JSONL drift between implementations
- Algorithmic divergence in dedupe rollup, path normalization, etc.

## Layout

```
tests/
  run-all.sh           Main entry point. Runs cases × implementations.
  lib/harness.sh       Shared helpers sourced by every case script.
  cases/               Numbered test scripts. Each is self-contained.
```

## Run

```
tests/run-all.sh                        # all impls × all cases
tests/run-all.sh --only perl            # one impl
tests/run-all.sh --only python --only cpp
tests/run-all.sh --case 03              # only case scripts matching '03'
tests/run-all.sh --case dedupe          # only case scripts matching 'dedupe'
```

Implementations that aren't installed/built are reported as `SKIP`
rather than failures, so you can iterate on one language at a time.

## Conventions

- Each case sources `lib/harness.sh`, then calls `fc_setup` to make a
  temp workdir (auto-cleaned on exit).
- The `fc` shell function dispatches to whichever implementation
  `$FC_IMPL` points at. Test code stays language-agnostic.
- Assertions: `fc_assert_eq`, `fc_assert_file_exists`,
  `fc_assert_file_absent`, `fc_assert <desc> <command...>`.
- End each case with `fc_finish` — it exits 0 if all asserts passed,
  1 otherwise. Exit 77 = skipped.

## Adding a new case

```bash
cat > tests/cases/17-my-new-case.sh <<'EOF'
#!/usr/bin/env bash
. "$(dirname "$0")/../lib/harness.sh"
fc_setup

# build fixture
mkdir -p "$FC_WORK/data"
echo content > "$FC_WORK/data/x.txt"

# exercise
fc scan --catalog "$FC_WORK/c.sqlite" --volume v --root "$FC_WORK/data" --hostname test >/dev/null

# assert
count=$(fc_sqlite_count "$FC_WORK/c.sqlite" "SELECT COUNT(*) FROM files")
fc_assert_eq "one file" "1" "$count"

fc_finish
EOF
chmod +x tests/cases/17-my-new-case.sh
```

## Cases covered

| #  | Case                              | What it verifies                                                   |
|----|-----------------------------------|--------------------------------------------------------------------|
| 01 | empty-dir                         | Empty tree produces a valid empty catalog                          |
| 02 | single-file                       | Unique-size files are recorded with NULL sha512 in quick-scan mode |
| 03 | file-dup-same-volume              | Same-volume duplicates detected; both hashed                       |
| 04 | dir-tree-dup-rollup               | Identical trees collapse to one dir-level dup, not N file-level    |
| 05 | zero-byte-and-symlinks            | Both are skipped, not cataloged                                    |
| 06 | default-skip-list                 | `.git`, `.DS_Store`, `Thumbs.db`, `.Trashes` etc. all skipped      |
| 07 | rerun-idempotent                  | Second run skips unchanged files                                   |
| 08 | prune-keep-rule                   | `--keep-rule first --apply` deletes files AND removes catalog rows |
| 09 | prune-dry-run                     | Without `--apply`, nothing is touched                              |
| 10 | merge-jsonl-roundtrip             | sqlite → jsonl → sqlite preserves rows and hashes                  |
| 11 | hashlog-replay                    | Hashlog → merge reconstructs a byte-equivalent catalog             |
| 12 | cross-volume-collision            | Cross-volume same-host size collisions get hashed in post-walk pass|
| 13 | bad-args                          | Missing/invalid flags fail clearly; no catalog leaked              |
| 14 | weird-filenames                   | Spaces, unicode, quotes, leading dashes survive round-trip         |
| 15 | cross-impl-catalog                | Catalogs are interchangeable between implementations               |
| 16 | full-hash-flag                    | `--full-hash` hashes unique-size files too                         |

## Requirements on the host

- `bash`, `sqlite3`, `python3` (for JSON parsing in some asserts).
- For each implementation: its own installation prerequisites
  (Perl + DBI/DBD::SQLite, Python 3.10+, a built C++ binary).
