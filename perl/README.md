# forensicator — Perl implementation

Catalog and deduplicate large digital archives that span multiple volumes
and multiple machines. One Perl entry point with four subcommands, backed
by a single-file SQLite catalog per dataset. The on-disk schema lives in
[`../schema/forensicator.sql`](../schema/forensicator.sql) and is shared
verbatim with the Python and C++ implementations — any catalog produced
by one can be read by the others.

```
forensicator scan     Walk a volume, record (hostname, volume, path) -> (size, sha512)
forensicator dedupe   Find duplicate files and directory trees
forensicator prune    Interactively delete duplicates and update the catalog
forensicator merge    Combine catalogs and emit a per-host rehash worklist
```

The legacy hyphenated forms (`forensicator-scan`, `forensicator-dedupe`,
...) remain available — `forensicator scan` is just a thin dispatcher
that execs the matching hyphenated script.

The catalog is a single SQLite file. Each dataset gets its own file
(e.g. `photos.sqlite`, `archive-2024.sqlite`) — easy to sync read-only via
Dropbox or copy between machines. JSONL is supported as an interchange
format on input and output of `forensicator merge`.

## Layout

```
bin/forensicator              # dispatcher
bin/forensicator-scan
bin/forensicator-dedupe
bin/forensicator-prune
bin/forensicator-merge
lib/Forensicator.pm
cpanfile
```

## Why Perl?

- Ships on most Unix systems
- Mature `DBI` / `DBD::SQLite` and `Digest::SHA`
- File::Find handles edge cases (broken symlinks, permission errors, deep
  trees) without surprises
- The original implementation; the reference for the schema and the
  JSONL interchange format

## Requirements

- Perl 5.14 or newer
- `DBI` and `DBD::SQLite`
- Everything else (`Digest::SHA`, `JSON::PP`, `File::Find`, `Sys::Hostname`, `Getopt::Long`) is core

## Install — macOS

Pick one Perl. The scripts use `#!/usr/bin/env perl`, so whichever Perl is
first in `PATH` will be used.

### Option 1: system Perl (recommended for most users)

macOS ships with `/usr/bin/perl`. On recent macOS (Sonoma/Sequoia) it
already includes `DBI` and `DBD::SQLite`. Verify:

```
/usr/bin/perl -MDBI -MDBD::SQLite -e 'print "ok\n"'
```

If that prints `ok`, you're done — just put `bin/` on your `PATH`:

```
export PATH="$HOME/git/forensicator/bin:$PATH"
```

### Option 2: MacPorts

```
sudo port install perl5 p5-dbi p5-dbd-sqlite
```

### Option 3: Homebrew

```
brew install perl cpanminus
cpanm --installdeps /path/to/forensicator
```

(`cpanm` reads [cpanfile](cpanfile) and installs `DBI` + `DBD::SQLite`.)

### Verify

```
forensicator-scan --help
```

## Install — Windows

### Option 1: Strawberry Perl (recommended)

[Strawberry Perl](https://strawberryperl.com/) ships with `DBI` and
`DBD::SQLite` already installed and a working C toolchain.

1. Install Strawberry Perl (the MSI installer adds Perl to your `PATH`).
2. Clone or copy this repo somewhere, e.g. `C:\tools\forensicator`.
3. Add the `bin` directory to `PATH`:

   PowerShell (one-shot for the current session):
   ```
   $env:PATH = "C:\tools\forensicator\bin;" + $env:PATH
   ```

   Permanent (User scope):
   ```
   [Environment]::SetEnvironmentVariable(
     "PATH",
     "C:\tools\forensicator\bin;" + [Environment]::GetEnvironmentVariable("PATH","User"),
     "User")
   ```

4. Verify:
   ```
   perl -MDBI -MDBD::SQLite -e "print 'ok',\"\n\""
   forensicator-scan --help
   ```

If the scripts don't run directly by name, invoke them through Perl:
```
perl C:\tools\forensicator\bin\forensicator-scan --help
```
Or set up a `.pl` association, or add a thin `forensicator-scan.bat`
wrapper.

### Option 2: WSL

Install WSL (Ubuntu) and follow the Linux instructions:
```
sudo apt install perl libdbi-perl libdbd-sqlite3-perl
```

### Option 3: ActivePerl

ActivePerl works too. Use its `ppm` or `cpan` to install dependencies:
```
cpan DBI DBD::SQLite
```

## Install — Linux

```
sudo apt install perl libdbi-perl libdbd-sqlite3-perl   # Debian/Ubuntu
sudo dnf install perl perl-DBI perl-DBD-SQLite          # Fedora/RHEL
```

Then add `bin/` to `PATH`.

## Quick start (single host)

```
# Scan a volume. The catalog is created on first use.
forensicator scan --catalog photos.sqlite --volume bigdrive --root /Volumes/bigdrive/photos

# Find duplicates (human-readable report).
forensicator dedupe --catalog photos.sqlite

# Find duplicates (machine-readable plan for prune).
forensicator dedupe --catalog photos.sqlite --format json --output dupes.json

# Dry-run prune. Interactive prompts for each duplicate group.
forensicator prune --catalog photos.sqlite --plan dupes.json

# Apply for real (use --keep-rule for non-interactive).
forensicator prune --catalog photos.sqlite --plan dupes.json \
    --keep-rule volume=bigdrive --apply
```

By default scan only hashes files whose size collides with another file's
size — much faster on multi-TB archives, with the same dedupe results.
Use `--full-hash` to hash every file.

## Where to put the catalog

**The catalog must live on a filesystem with working POSIX locking** —
APFS, ext4, NTFS, HFS+, etc. SMB, NFS, exFAT, and some FUSE mounts have
broken or absent fcntl locking, and forensicator will refuse to run on
them. Long-running SQLite writes on those filesystems silently corrupt
the database (`database disk image is malformed`).

The catalog stores `mount_point` separately from the SQLite file's
location, so the SQLite catalog can live on your local SSD even when the
data being cataloged is on an external/networked volume. That's the
recommended setup.

If you really need the catalog to follow the data on a removable drive,
format the drive APFS (macOS) or ext4 (Linux). exFAT will not work.

## Hashlog and recovery

Every file written to the catalog is also appended to a plain-text JSONL
hashlog **before** the SQLite write, with autoflush enabled. Default
path is `<catalog>.hashlog.jsonl`; override with `--hashlog FILE`. Use
`--no-hashlog` to disable.

If the SQLite catalog ever corrupts mid-scan, you can recover without
re-walking the volume:

```
# 1. Salvage what's still readable from the corrupt catalog.
cp /path/to/corrupt.sqlite /tmp/corrupt.sqlite
sqlite3 /tmp/corrupt.sqlite ".recover" > /tmp/recover.sql
sqlite3 ~/recovered.sqlite < /tmp/recover.sql

# 2. Replay the hashlog on top to fill in anything the recover missed.
forensicator-merge --output ~/recovered.sqlite --inputs ~/recovered.sqlite.hashlog.jsonl
# (merge takes the latest scanned_at, so re-applying old records is safe)

# 3. Or, if .recover fails entirely, rebuild from the hashlog alone:
forensicator-merge --output ~/rebuilt.sqlite --inputs ~/recovered.sqlite.hashlog.jsonl
```

By default the hashlog sits next to the catalog. Since the catalog
itself must be on a reliable local filesystem (see above), the default
is fine for most uses. Override with `--hashlog FILE` if you want to
keep the recovery log somewhere else (e.g., on a different physical
disk for extra durability).

## Cross-machine workflow

Each machine maintains its own SQLite catalog. The merge phase produces a
combined view and a rehash worklist for any cross-machine size collisions
that quick-scan couldn't resolve locally.

```
# On each host (laptop, NAS, server, ...):
forensicator scan --catalog ~/Dropbox/forensicator/$(hostname).sqlite \
                  --volume bigdrive --root /Volumes/bigdrive

# On one machine, build the combined catalog and a rehash worklist:
forensicator merge \
    --output combined.sqlite \
    --inputs ~/Dropbox/forensicator/*.sqlite \
    --rehash-list rehash.jsonl

# Distribute rehash.jsonl to every host (Dropbox is fine), then on each host:
forensicator scan --catalog ~/Dropbox/forensicator/$(hostname).sqlite \
                  --volume bigdrive --root /Volumes/bigdrive \
                  --rehash-list rehash.jsonl

# Re-merge — the rehash list should now be empty:
forensicator merge --output combined.sqlite --inputs ~/Dropbox/forensicator/*.sqlite

# Find duplicates across all hosts:
forensicator dedupe --catalog combined.sqlite --format json --output dupes.json

# Run prune on each host where you want to delete (the script only touches
# files belonging to its own --hostname):
forensicator prune --catalog ~/Dropbox/forensicator/$(hostname).sqlite \
                   --plan dupes.json --apply
```

The Dropbox-shared SQLite files are intended to be **read-only when
shared** — each host writes to its own catalog locally. The combined
`combined.sqlite` is a derived artifact you regenerate as needed.

## Reference

### `forensicator-scan`

```
forensicator-scan --catalog FILE --volume NAME --root DIR [opts]
forensicator-scan --catalog FILE --rehash --volume NAME --root DIR
forensicator-scan --catalog FILE --rehash-list FILE --volume NAME --root DIR
```

| flag | meaning |
| --- | --- |
| `--catalog FILE` | SQLite catalog (created if missing) |
| `--volume NAME` | Logical volume name; sticks with the data even if the disk moves |
| `--root DIR` | Directory to walk; recorded as the volume's `mount_point` |
| `--hostname NAME` | Override hostname (default: short hostname) |
| `--mount-point DIR` | Override mount_point (defaults to `--root`) |
| `--full-hash` | Hash every file (default: only size collisions) |
| `--rehash` | No walk; hash any catalog rows with NULL sha512 on this volume |
| `--rehash-list FILE` | Hash specific files listed in a merge-produced JSONL |
| `--dataset NAME` | Dataset label, stored in catalog metadata |
| `--quiet` | Suppress progress output |
| `--hashlog FILE` | Append-only JSONL recovery log; default `<catalog>.hashlog.jsonl` |
| `--no-hashlog` | Disable the hashlog (lose recovery insurance) |

### `forensicator-dedupe`

```
forensicator-dedupe --catalog FILE [--format human|json] [--output FILE]
                    [--min-size BYTES]
```

The output rolls up identical directory trees: descendants of an
already-reported duplicate dir are suppressed unless they appear in
additional uncovered locations elsewhere.

The `--format json` output is the input format for `forensicator-prune`.

### `forensicator-prune`

```
forensicator-prune --catalog FILE --plan FILE.json [--apply] [opts]
```

| flag | meaning |
| --- | --- |
| `--catalog FILE` | This host's SQLite catalog |
| `--plan FILE` | JSON output from `forensicator-dedupe --format json` |
| `--apply` | Actually delete files (default: dry-run) |
| `--keep-rule RULE` | Auto-pick keeper: `first`, `host=NAME`, `volume=NAME`, `shortest-path` |
| `--no-interactive` | Skip groups where the rule didn't match (don't prompt) |
| `--file-level` | For dir-level dups, prompt per-file instead of per-tree |
| `--hostname NAME` | Override hostname (default: short hostname) |
| `--yes` / `-y` | Skip the final confirmation when `--apply` is set |

Only files belonging to the local host are eligible for deletion. Members
on other hosts are shown for context but never touched. Catalog rows for
deleted files are removed in the same transaction.

### `forensicator-merge`

```
forensicator-merge --output FILE --inputs FILE [FILE ...]
                   [--rehash-list FILE] [--dataset NAME]
```

Inputs may be `.sqlite` or `.jsonl` (autodetected). Output format is
inferred from the extension of `--output`. When `(hostname, volume, path)`
appears in multiple inputs the row with the latest `scanned_at` wins; if
hashes disagree, the latest-scanned one wins and a warning is emitted.

`--rehash-list` writes JSONL of `(hostname, volume, path)` triples whose
size collides with another file in the merged set but whose `sha512` is
still NULL. Feed that file to `forensicator-scan --rehash-list` on each
host, then re-merge.

## Files skipped by `forensicator-scan`

By default:

- Symlinks (not followed, not recorded)
- Zero-byte files
- OS junk: `.DS_Store`, `Thumbs.db`, `desktop.ini`, `.localized`,
  `.Spotlight-V100`, `.Trashes`, `.fseventsd`, `.TemporaryItems`,
  `.DocumentRevisions-V100`, `$RECYCLE.BIN`, `System Volume Information`
- `.git` directories (objects are already content-hashed; recording them
  inflates the catalog with no signal)

Archives (`.zip`, `.tar.gz`, ...) are treated as opaque files: the
archive itself is hashed, not its contents.
