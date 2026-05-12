"""Top-level CLI: `forensicator <subcommand> [opts]`."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import scan as scan_mod
from . import dedupe as dedupe_mod
from . import prune as prune_mod
from . import merge as merge_mod


_USAGE = """\
forensicator: catalog and deduplicate large digital archives

Usage:
  forensicator <command> [options...]

Commands:
  scan      Walk a volume and record files in a catalog
  dedupe    Find duplicate files and directory trees
  prune     Interactively remove duplicates and update the catalog
  merge     Combine catalogs (sqlite/jsonl) and emit a rehash worklist

Run any command with --help for its own options:
  forensicator scan --help
"""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="forensicator",
        add_help=False,
        description="catalog and deduplicate large digital archives",
    )
    sub = p.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", add_help=False)
    scan_mod.add_arguments(scan_p)
    scan_p.add_argument("-h", "--help", action="store_true", dest="help")

    dedupe_p = sub.add_parser("dedupe", add_help=False)
    dedupe_mod.add_arguments(dedupe_p)
    dedupe_p.add_argument("-h", "--help", action="store_true", dest="help")

    prune_p = sub.add_parser("prune", add_help=False)
    prune_mod.add_arguments(prune_p)
    prune_p.add_argument("-h", "--help", action="store_true", dest="help")

    merge_p = sub.add_parser("merge", add_help=False)
    merge_mod.add_arguments(merge_p)
    merge_p.add_argument("-h", "--help", action="store_true", dest="help")

    return p


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)

    if not argv or argv[0] in ("-h", "--help"):
        sys.stdout.write(_USAGE)
        return 0

    cmd = argv[0]
    rest = argv[1:]
    if cmd not in {"scan", "dedupe", "prune", "merge"}:
        sys.stderr.write(f"forensicator: unknown command '{cmd}'\n\n")
        sys.stderr.write(_USAGE)
        return 2

    parser = _build_parser()
    # Parse args under the subcommand. We use parse_known_args to detect
    # stray positionals and reject them (matches Perl's Getopt::Long behavior).
    args, extra = parser.parse_known_args([cmd] + rest)
    if getattr(args, "help", False):
        _print_subcommand_help(cmd)
        return 0
    if extra:
        sys.stderr.write(
            f"unexpected positional argument(s): {' '.join(extra)}\n"
            "run with --help for usage\n"
        )
        return 2

    try:
        if cmd == "scan":
            return scan_mod.cmd_scan(args)
        if cmd == "dedupe":
            return dedupe_mod.cmd_dedupe(args)
        if cmd == "prune":
            return prune_mod.cmd_prune(args)
        if cmd == "merge":
            return merge_mod.cmd_merge(args)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        return 130
    return 0


_SUBCMD_HELP = {
    "scan": """\
forensicator scan: walk a volume and record files in a catalog

Modes:
  scan      forensicator scan --catalog FILE --volume NAME --root DIR [opts]
  rehash    forensicator scan --catalog FILE --rehash --volume NAME --root DIR
            forensicator scan --catalog FILE --rehash-list FILE --volume NAME --root DIR

Options:
  --catalog FILE        SQLite catalog (created if missing)
  --volume NAME         Logical volume name (sticks with the data)
  --root DIR            Directory to scan / mount point for rehash
  --hostname NAME       Override hostname (default: short hostname)
  --mount-point DIR     Record mount point (default: --root)
  --full-hash           Hash every file (default: only size collisions)
  --rehash              Hash files in this catalog with NULL sha512 (no walk)
  --rehash-list FILE    JSONL of {hostname, volume, path} entries to hash
  --dataset NAME        Dataset label (stored in catalog metadata)
  --progress-every N    Log progress every N files (default 1000)
  --commit-every N      Commit DB transaction every N files (default 500)
  --quiet               Suppress progress output
  --hashlog FILE        Append-only JSONL recovery log. Default <catalog>.hashlog.jsonl
  --no-hashlog          Disable the hashlog (lose recovery insurance).
""",
    "dedupe": """\
forensicator dedupe: find duplicate files and directory trees

Usage:
  forensicator dedupe --catalog FILE [--format human|json] [--output FILE]

Options:
  --catalog FILE    SQLite catalog (from forensicator scan / merge)
  --format FORMAT   "human" or "json" (default human)
  --output FILE     Write to FILE (default stdout)
  --min-size BYTES  Ignore single-file dups smaller than this (default 0)
""",
    "prune": """\
forensicator prune: act on a dedupe plan to remove duplicates and update catalog

Usage:
  forensicator prune --catalog FILE --plan FILE.json [--apply] [opts]

Options:
  --catalog FILE       Local SQLite catalog (this host's files)
  --plan FILE          JSON output from forensicator dedupe --format json
  --apply              Actually delete files (default: dry-run)
  --keep-rule RULE     first | host=NAME | volume=NAME | shortest-path
  --no-interactive     Skip groups without a rule match (don't prompt)
  --file-level         For dir-level dups, prompt per-file instead of per-tree
  --hostname NAME      Override hostname (default: short hostname)
  --yes, -y            Skip the final confirmation when --apply is set
""",
    "merge": """\
forensicator merge: combine catalogs/JSONL into one catalog or JSONL

Usage:
  forensicator merge --output combined.sqlite --inputs a.sqlite b.sqlite ...
  forensicator merge --output export.jsonl    --inputs combined.sqlite
  forensicator merge --output combined.sqlite --inputs *.sqlite --rehash-list r.jsonl

Options:
  --output FILE        Output catalog (.sqlite) or export (.jsonl)
  --inputs FILE...     One or more inputs (.sqlite or .jsonl)
  --rehash-list FILE   When merging, write JSONL of files that need hashes
  --dataset NAME       Dataset label for output catalog metadata
  --quiet              Suppress progress output
""",
}


def _print_subcommand_help(cmd: str) -> None:
    sys.stdout.write(_SUBCMD_HELP.get(cmd, ""))


if __name__ == "__main__":
    sys.exit(main())
