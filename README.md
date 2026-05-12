# forensicator

Catalog and deduplicate large digital archives that span multiple volumes
and multiple machines. Available in three implementations that share a
common SQLite schema and JSONL interchange format — pick whichever fits
your platform and workload.

| Implementation | Best for | README |
|---|---|---|
| **Perl** | the reference implementation; portable, mature | [perl/README.md](perl/README.md) |
| **Python** | scriptability, easy install, rich library ecosystem | [python/README.md](python/README.md) |
| **C++** | maximum throughput, multi-threaded scanning, single binary | [cpp/README.md](cpp/README.md) |

All three are compatible: a catalog produced by one can be read,
extended, merged, or pruned by any other. They load the same on-disk
schema from [`schema/forensicator.sql`](schema/forensicator.sql) and
emit/consume the same JSONL records.

## What it does

```
forensicator scan     Walk a volume, record every file's (size, sha512)
forensicator dedupe   Find duplicate files and rolled-up duplicate directory trees
forensicator prune    Interactively (or rule-driven) delete duplicates and update the catalog
forensicator merge    Combine per-host catalogs and emit a cross-host rehash worklist
```

By default scan only hashes files whose size collides with another file's
size (quick-scan mode) — much faster on multi-TB archives with the same
dedupe results. `--full-hash` hashes everything.

## Repository layout

```
schema/forensicator.sql       Canonical SQLite schema (single source of truth)
perl/                         Perl implementation
python/                       Python implementation
cpp/                          C++ implementation (CMake)
tests/                        Cross-language test harness
```

## Picking an implementation

- **Have a Mac or Linux box with Perl already installed?** Use Perl. It's
  the reference, the most thoroughly battle-tested, and needs only
  `DBI` + `DBD::SQLite`.
- **Want pip-installable or easy embedding in larger Python pipelines?**
  Use Python. Same behavior, same catalogs, friendlier to extend.
- **Scanning tens of millions of files where every CPU cycle matters?**
  Use C++. The threaded pipeline (walker → recorder → hasher pool) keeps
  every core saturated and the executable has no runtime dependencies
  beyond `libsqlite3`.

## Compatibility guarantee

A catalog or JSONL produced by any implementation is consumable by all
others. The schema version is stored in the `meta` table; if it does not
match what the implementation expects, the program refuses to open the
file rather than corrupt it.

## Tests

The cross-language test harness lives in [`tests/`](tests/) and exercises
every implementation against the same fixtures. Run:

```
tests/run-all.sh                 # all implementations
tests/run-all.sh --only perl     # one implementation
tests/run-all.sh --only python
tests/run-all.sh --only cpp
```

See [`tests/README.md`](tests/README.md) for details.
