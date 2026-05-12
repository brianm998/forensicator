"""forensicator merge: combine catalogs/JSONL into one catalog or JSONL."""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Any

from .catalog import open_catalog, upsert_volume, volumes
from .hashlog import jsonl_reader, jsonl_writer
from .pathnorm import normalize_path


def cmd_merge(args: argparse.Namespace) -> int:
    if not args.output:
        raise SystemExit("missing --output")
    if not args.inputs:
        raise SystemExit("missing --inputs")

    out = args.output
    out_kind = "jsonl" if out.lower().endswith(".jsonl") else "sqlite"

    if out_kind == "jsonl" and args.rehash_list:
        sys.stderr.write("[merge] note: --rehash-list with JSONL output uses an in-memory pass\n")

    if out_kind == "sqlite" and os.path.exists(out):
        raise SystemExit(f"refusing to overwrite existing output: {out}")

    def log(msg: str) -> None:
        if not args.quiet:
            sys.stderr.write(f"[merge] {msg}\n")

    out_conn = None
    jsonl_emit = None
    jsonl_close = None

    if out_kind == "sqlite":
        out_conn = open_catalog(out, dataset=args.dataset)
    else:
        jsonl_emit, jsonl_close = jsonl_writer(out)

    vol_id_cache: dict[tuple[str, str], int] = {}

    def get_vid(hostname: str, volume: str, mount: str | None, osname: str | None) -> int:
        k = (hostname, volume)
        if k in vol_id_cache:
            return vol_id_cache[k]
        v = upsert_volume(
            out_conn,
            hostname=hostname,
            volume=volume,
            mount_point=mount,
            os=osname,
        )
        vol_id_cache[k] = v["volume_id"]
        return v["volume_id"]

    state = {"total": 0, "conflicts": 0, "hash_disagreements": 0}

    upsert_sth = None
    check_sth = None
    if out_conn is not None:
        upsert_sth = """
INSERT INTO files(volume_id, path, path_norm, size, mtime, sha512, scanned_at)
VALUES(?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(volume_id, path_norm) DO UPDATE SET
  path       = CASE WHEN excluded.scanned_at >= files.scanned_at
                    THEN excluded.path ELSE files.path END,
  size       = CASE WHEN excluded.scanned_at >= files.scanned_at
                    THEN excluded.size ELSE files.size END,
  mtime      = CASE WHEN excluded.scanned_at >= files.scanned_at
                    THEN excluded.mtime ELSE files.mtime END,
  sha512     = CASE
                 WHEN excluded.scanned_at >= files.scanned_at AND excluded.sha512 IS NOT NULL
                   THEN excluded.sha512
                 WHEN files.sha512 IS NULL
                   THEN excluded.sha512
                 ELSE files.sha512
               END,
  scanned_at = MAX(excluded.scanned_at, files.scanned_at)
"""
        check_sth = (
            "SELECT size, sha512, scanned_at FROM files "
            "WHERE volume_id = ? AND path_norm = ?"
        )

    def ingest_row(row: dict[str, Any]) -> None:
        state["total"] += 1
        if out_conn is not None:
            vid = get_vid(row["hostname"], row["volume"], row.get("mount_point"), row.get("os"))
            existing = out_conn.execute(check_sth, (vid, row["path_norm"])).fetchone()
            if existing is not None:
                state["conflicts"] += 1
                if existing["sha512"] is not None and row.get("sha512") is not None \
                        and existing["sha512"] != row["sha512"]:
                    state["hash_disagreements"] += 1
                    if not args.quiet:
                        sys.stderr.write(
                            f"[merge] hash disagreement on "
                            f"{row['hostname']}:{row['volume']}:{row['path']}\n"
                        )
            out_conn.execute(upsert_sth, (
                vid,
                row["path"], row["path_norm"],
                row["size"], row["mtime"],
                row.get("sha512"), row["scanned_at"],
            ))
        else:
            jsonl_emit({
                "hostname": row["hostname"],
                "volume": row["volume"],
                "mount_point": row.get("mount_point"),
                "os": row.get("os"),
                "path": row["path"],
                "path_norm": row["path_norm"],
                "size": int(row["size"]),
                "mtime": int(row["mtime"]),
                "sha512": row.get("sha512"),
                "scanned_at": int(row["scanned_at"]),
            })

    def ingest_sqlite(path: str) -> None:
        log(f"ingesting sqlite: {path}")
        in_conn = open_catalog(path, readonly=True)
        try:
            vols = volumes(in_conn)
            count = 0
            for v in vols:
                sth = in_conn.execute(
                    "SELECT path, path_norm, size, mtime, sha512, scanned_at "
                    "FROM files WHERE volume_id = ?",
                    (v["volume_id"],),
                )
                for row in sth:
                    ingest_row({
                        "hostname": v["hostname"],
                        "volume": v["volume"],
                        "mount_point": v["mount_point"],
                        "os": v["os"],
                        "path": row["path"],
                        "path_norm": row["path_norm"],
                        "size": row["size"],
                        "mtime": row["mtime"],
                        "sha512": row["sha512"],
                        "scanned_at": row["scanned_at"],
                    })
                    count += 1
                    if out_conn is not None and count % 5000 == 0:
                        out_conn.execute("COMMIT")
                        out_conn.execute("BEGIN")
            log(f"  {count} rows from {path}")
        finally:
            in_conn.close()

    def ingest_jsonl_file(path: str) -> None:
        log(f"ingesting jsonl: {path}")
        count = 0
        for row in jsonl_reader(path):
            if not row:
                continue
            if not isinstance(row, dict):
                continue
            if row.get("hostname") is None or row.get("volume") is None or row.get("path") is None:
                continue
            if "path_norm" not in row or row["path_norm"] is None:
                row["path_norm"] = normalize_path(row["path"], row.get("os"))
            if "scanned_at" not in row or row["scanned_at"] is None:
                row["scanned_at"] = int(time.time())
            if "mtime" not in row or row["mtime"] is None:
                row["mtime"] = 0
            if "size" not in row or row["size"] is None:
                row["size"] = 0
            ingest_row(row)
            count += 1
            if out_conn is not None and count % 5000 == 0:
                out_conn.execute("COMMIT")
                out_conn.execute("BEGIN")
        log(f"  {count} rows from {path}")

    def autodetect_and_ingest(path: str) -> None:
        low = path.lower()
        if low.endswith(".jsonl"):
            ingest_jsonl_file(path)
        elif low.endswith(".sqlite") or low.endswith(".db"):
            ingest_sqlite(path)
        else:
            if not os.path.exists(path):
                raise SystemExit(f"no such input: {path}")
            with open(path, "rb") as fh:
                head = fh.read(16)
            if head.startswith(b"SQLite format 3"):
                ingest_sqlite(path)
            else:
                ingest_jsonl_file(path)

    if out_conn is not None:
        out_conn.execute("BEGIN")

    try:
        for inp in args.inputs:
            autodetect_and_ingest(inp)
        if out_conn is not None:
            out_conn.execute("COMMIT")
    finally:
        if jsonl_close is not None:
            jsonl_close()

    log(f"merged {state['total']} rows from {len(args.inputs)} inputs")
    if state["conflicts"]:
        log(f"{state['conflicts']} duplicate (host,volume,path) rows reconciled")
    if state["hash_disagreements"]:
        log(f"{state['hash_disagreements']} rows had disagreeing SHA512 (newest scan kept)")

    if args.rehash_list and out_conn is not None:
        _write_rehash_list(out_conn, args.rehash_list, log)

    if out_conn is not None:
        out_conn.close()
    return 0


def _write_rehash_list(conn, path: str, log) -> None:
    log(f"writing rehash list: {path}")
    rows = list(conn.execute(
        """
        SELECT v.hostname, v.volume, v.mount_point, f.path, f.path_norm, f.size
        FROM files f
        JOIN volumes v ON v.volume_id = f.volume_id
        WHERE f.sha512 IS NULL
          AND f.size IN (
            SELECT size FROM files GROUP BY size HAVING COUNT(*) > 1
          )
        ORDER BY v.hostname, v.volume, f.path_norm
        """
    ))
    emit, close = jsonl_writer(path)
    n = 0
    try:
        for r in rows:
            emit({
                "hostname": r["hostname"],
                "volume": r["volume"],
                "mount_point": r["mount_point"],
                "path": r["path"],
                "path_norm": r["path_norm"],
                "size": int(r["size"]),
            })
            n += 1
    finally:
        close()
    log(f"rehash list: {n} entries")


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--output")
    p.add_argument("--inputs", nargs="+", default=[])
    p.add_argument("--rehash-list", dest="rehash_list")
    p.add_argument("--dataset")
    p.add_argument("-q", "--quiet", action="store_true")
