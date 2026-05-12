"""forensicator scan: walk a volume and record files in a catalog."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
from pathlib import Path
from typing import Iterator

from .catalog import (
    open_catalog,
    upsert_volume,
    get_volume,
)
from .hashlog import HashLog, jsonl_reader
from .pathnorm import default_hostname, normalize_path, os_name


SKIP_DIRS = {
    ".git",
    ".Spotlight-V100",
    ".Trashes",
    ".fseventsd",
    ".TemporaryItems",
    "$RECYCLE.BIN",
    "System Volume Information",
    ".DocumentRevisions-V100",
}
SKIP_FILES = {
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    ".localized",
}


def sha512_file(path: str) -> str | None:
    try:
        h = hashlib.sha512()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def fmt_dur(s: float) -> str:
    s = int(s or 0)
    if s < 60:
        return f"{s}s"
    h = s // 3600
    m = (s % 3600) // 60
    sec = s % 60
    if h:
        return f"{h}h{m:02d}m"
    return f"{m}m{sec:02d}s"


def fmt_bytes(b: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    while b >= 1024 and i < len(units) - 1:
        b /= 1024
        i += 1
    if i == 0:
        return f"{int(b)} {units[i]}"
    return f"{b:.2f} {units[i]}"


def fmt_eta(label: str, i: int, total: int, started: float) -> str:
    el = max(1.0, time.time() - started)
    rate = i / el
    pct = (i / total * 100) if total else 0.0
    eta_s = ((total - i) / rate) if (rate > 0 and i < total) else 0
    return (
        f"{label}: {i} / {total} done ({pct:.1f}%, {rate:.0f}/s, "
        f"{fmt_dur(el)} elapsed, ETA {fmt_dur(eta_s)})"
    )


def log_progress(quiet: bool, msg: str) -> None:
    if not quiet:
        sys.stderr.write(f"[scan] {msg}\n")


def _walk(root: str) -> Iterator[tuple[str, list[os.DirEntry], list[os.DirEntry], int]]:
    """Yield (dirpath, subdirs, files, skipped_here) using os.scandir.
    Skips symlinks; honors SKIP_DIRS by not recursing into them."""
    try:
        with os.scandir(root) as it:
            entries = list(it)
    except OSError:
        return
    subdirs: list[os.DirEntry] = []
    files: list[os.DirEntry] = []
    skipped_here = 0
    for e in entries:
        try:
            if e.is_symlink():
                skipped_here += 1
                continue
            if e.is_dir(follow_symlinks=False):
                if e.name in SKIP_DIRS:
                    skipped_here += 1
                    continue
                subdirs.append(e)
            elif e.is_file(follow_symlinks=False):
                files.append(e)
        except OSError:
            continue
    yield root, subdirs, files, skipped_here
    for d in subdirs:
        yield from _walk(d.path)


def _rel_path(abs_path: str, root: str) -> str:
    """Relative path with forward slashes, matching how Perl's File::Spec->abs2rel
    produces them, but normalized to forward slashes for storage."""
    rel = os.path.relpath(abs_path, root)
    if os.sep != "/":
        rel = rel.replace(os.sep, "/")
    return rel


def cmd_scan(args: argparse.Namespace) -> int:
    if not args.catalog:
        raise SystemExit("missing --catalog")
    rehash_mode = bool(args.rehash or args.rehash_list)
    if rehash_mode:
        if not args.volume:
            raise SystemExit("rehash needs --volume")
        if not args.root:
            raise SystemExit("rehash needs --root")
    else:
        if not args.volume:
            raise SystemExit("missing --volume")
        if not args.root:
            raise SystemExit("missing --root")
    if not args.root or not os.path.isdir(args.root):
        raise SystemExit(f"root not a directory: {args.root}")

    conn = open_catalog(args.catalog, dataset=args.dataset)
    hashlog = HashLog.open(
        args.catalog,
        override=args.hashlog,
        disabled=args.no_hashlog,
        quiet=args.quiet,
    )
    try:
        if rehash_mode:
            do_rehash(args, conn, hashlog)
        else:
            do_scan(args, conn, hashlog)
    finally:
        hashlog.close()
        conn.close()
    return 0


def do_scan(args: argparse.Namespace, conn, hashlog: HashLog) -> None:
    mount = args.mount_point if args.mount_point else args.root
    vol = upsert_volume(
        conn,
        hostname=args.hostname,
        volume=args.volume,
        mount_point=mount,
        os=os_name(),
    )
    vid = vol["volume_id"]

    sel_sql = (
        "SELECT file_id, size, mtime, sha512 FROM files "
        "WHERE volume_id = ? AND path_norm = ?"
    )
    ins_sql = """
INSERT INTO files(volume_id, path, path_norm, size, mtime, sha512, scanned_at)
VALUES(?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(volume_id, path_norm) DO UPDATE SET
  path       = excluded.path,
  size       = excluded.size,
  mtime      = excluded.mtime,
  sha512     = COALESCE(excluded.sha512, files.sha512),
  scanned_at = excluded.scanned_at
"""

    count = 0
    hashed = 0
    errors = 0
    skipped = 0
    started = time.time()

    conn.execute("BEGIN")

    for dirpath, _subdirs, files, skipped_here in _walk(args.root):
        skipped += skipped_here
        for ent in files:
            if ent.name in SKIP_FILES:
                skipped += 1
                continue
            try:
                st = ent.stat(follow_symlinks=False)
            except OSError:
                errors += 1
                continue
            size = st.st_size
            mtime = int(st.st_mtime)
            if size == 0:
                skipped += 1
                continue

            rel = _rel_path(ent.path, args.root)
            norm = normalize_path(rel)

            row = conn.execute(sel_sql, (vid, norm)).fetchone()
            unchanged = (
                row is not None
                and row["size"] == size
                and row["mtime"] == mtime
            )
            sha: str | None
            if unchanged:
                sha = row["sha512"]
                if args.full_hash and not sha:
                    sha = sha512_file(ent.path)
                    if sha:
                        hashed += 1
                    else:
                        errors += 1
            else:
                if args.full_hash:
                    sha = sha512_file(ent.path)
                    if sha:
                        hashed += 1
                    else:
                        errors += 1
                else:
                    sha = None

            now = int(time.time())
            hashlog.write({
                "hostname": args.hostname,
                "volume": args.volume,
                "mount_point": mount,
                "os": os_name(),
                "path": rel,
                "path_norm": norm,
                "size": int(size),
                "mtime": int(mtime),
                "sha512": sha,
                "scanned_at": now,
            })
            conn.execute(ins_sql, (vid, rel, norm, size, mtime, sha, now))

            count += 1
            if count % args.commit_every == 0:
                conn.execute("COMMIT")
                conn.execute("BEGIN")
            if count % args.progress_every == 0:
                el = max(1.0, time.time() - started)
                rate = count / el
                if args.full_hash:
                    log_progress(
                        args.quiet,
                        f"walk: {count} files, {hashed} hashed, {skipped} skipped, "
                        f"{errors} errors, {fmt_dur(el)} elapsed ({rate:.0f}/s)",
                    )
                else:
                    log_progress(
                        args.quiet,
                        f"walk: {count} files cataloged, {skipped} skipped, "
                        f"{errors} errors, {fmt_dur(el)} elapsed ({rate:.0f}/s) "
                        "-- hashing happens after walk",
                    )

    conn.execute("COMMIT")
    log_progress(
        args.quiet,
        f"walk done: {count} files cataloged, {hashed} hashed, "
        f"{skipped} skipped, {errors} errors, {int(time.time() - started)}s",
    )

    if not args.full_hash:
        rows = list(conn.execute(
            """
            SELECT f.file_id, f.path, f.path_norm, f.size, f.mtime,
                   v.mount_point, v.hostname, v.volume, v.os
            FROM files f
            JOIN volumes v ON v.volume_id = f.volume_id
            WHERE f.sha512 IS NULL
              AND f.size IN (
                SELECT size FROM files GROUP BY size HAVING COUNT(*) > 1
              )
            """
        ))
        total = len(rows)
        total_bytes = sum(r["size"] for r in rows)
        log_progress(
            args.quiet,
            f"hashing {total} size-collision files ({fmt_bytes(total_bytes)}) "
            "across all reachable volumes...",
        )
        local_hashed = 0
        unreachable = 0
        hash_started = time.time()
        conn.execute("BEGIN")
        i = 0
        for r in rows:
            i += 1
            mount_pt = r["mount_point"]
            if not mount_pt or not os.path.isdir(mount_pt):
                unreachable += 1
                continue
            abs_path = os.path.join(mount_pt, r["path"])
            if not os.path.isfile(abs_path):
                unreachable += 1
                continue
            sha = sha512_file(abs_path)
            if not sha:
                errors += 1
                continue
            now = int(time.time())
            hashlog.write({
                "hostname": r["hostname"],
                "volume": r["volume"],
                "mount_point": r["mount_point"],
                "os": r["os"],
                "path": r["path"],
                "path_norm": r["path_norm"],
                "size": int(r["size"]),
                "mtime": int(r["mtime"] or 0),
                "sha512": sha,
                "scanned_at": now,
            })
            conn.execute(
                "UPDATE files SET sha512 = ? WHERE file_id = ?",
                (sha, r["file_id"]),
            )
            local_hashed += 1
            if i % args.commit_every == 0:
                conn.execute("COMMIT")
                conn.execute("BEGIN")
            if i % args.progress_every == 0:
                log_progress(args.quiet, fmt_eta("collision-hashes", i, total, hash_started))
        conn.execute("COMMIT")
        hashed += local_hashed
        log_progress(
            args.quiet,
            f"collision-hash done: {local_hashed} hashed, {unreachable} unreachable, "
            f"{fmt_dur(time.time() - hash_started)}",
        )

    log_progress(
        args.quiet,
        f"FINAL: {count} files, {hashed} hashed, {skipped} skipped, "
        f"{errors} errors, {int(time.time() - started)}s",
    )


def do_rehash(args: argparse.Namespace, conn, hashlog: HashLog) -> None:
    vol = get_volume(conn, args.hostname, args.volume)
    if not vol:
        raise SystemExit(f"volume not in catalog: {args.hostname}:{args.volume}")

    if args.mount_point and (not vol["mount_point"] or vol["mount_point"] != args.mount_point):
        conn.execute(
            "UPDATE volumes SET mount_point = ? WHERE volume_id = ?",
            (args.mount_point, vol["volume_id"]),
        )

    rows: list = []
    if args.rehash_list:
        sel = (
            "SELECT file_id, path, path_norm, size, mtime FROM files "
            "WHERE volume_id = ? AND path_norm = ? AND sha512 IS NULL"
        )
        for task in jsonl_reader(args.rehash_list):
            if not task:
                continue
            if task.get("hostname", "") != args.hostname:
                continue
            if task.get("volume", "") != args.volume:
                continue
            norm = normalize_path(task.get("path", ""))
            for r in conn.execute(sel, (vol["volume_id"], norm)):
                rows.append(r)
    else:
        rows = list(conn.execute(
            "SELECT file_id, path, path_norm, size, mtime FROM files "
            "WHERE volume_id = ? AND sha512 IS NULL",
            (vol["volume_id"],),
        ))

    total = len(rows)
    total_bytes = sum(r["size"] for r in rows)
    log_progress(args.quiet, f"{total} files to rehash ({fmt_bytes(total_bytes)})")

    hashed = 0
    errors = 0
    started = time.time()
    conn.execute("BEGIN")
    for i, r in enumerate(rows, start=1):
        abs_path = os.path.join(args.root, r["path"])
        if not os.path.isfile(abs_path):
            if not args.quiet:
                sys.stderr.write(f"[rehash] missing: {abs_path}\n")
            errors += 1
            continue
        sha = sha512_file(abs_path)
        if not sha:
            errors += 1
            continue
        now = int(time.time())
        hashlog.write({
            "hostname": args.hostname,
            "volume": args.volume,
            "mount_point": args.root,
            "os": os_name(),
            "path": r["path"],
            "path_norm": r["path_norm"],
            "size": int(r["size"]),
            "mtime": int(r["mtime"] or 0),
            "sha512": sha,
            "scanned_at": now,
        })
        conn.execute(
            "UPDATE files SET sha512 = ? WHERE file_id = ?",
            (sha, r["file_id"]),
        )
        hashed += 1
        if i % args.commit_every == 0:
            conn.execute("COMMIT")
            conn.execute("BEGIN")
        if i % args.progress_every == 0:
            log_progress(args.quiet, fmt_eta("rehash", i, total, started))
    conn.execute("COMMIT")

    log_progress(
        args.quiet,
        f"rehash done: {hashed} hashed, {errors} errors, "
        f"{fmt_dur(time.time() - started)}",
    )


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--catalog", required=False)
    p.add_argument("--volume")
    p.add_argument("--root")
    p.add_argument("--hostname", default=default_hostname())
    p.add_argument("--mount-point", dest="mount_point")
    p.add_argument("--full-hash", action="store_true", dest="full_hash")
    p.add_argument("--rehash", action="store_true")
    p.add_argument("--rehash-list", dest="rehash_list")
    p.add_argument("--dataset")
    p.add_argument("--progress-every", type=int, default=1000, dest="progress_every")
    p.add_argument("--commit-every", type=int, default=500, dest="commit_every")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--hashlog")
    p.add_argument("--no-hashlog", action="store_true", dest="no_hashlog")
