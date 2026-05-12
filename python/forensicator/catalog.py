"""SQLite catalog open/init/upsert helpers."""

from __future__ import annotations

import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Iterable

from . import SCHEMA_VERSION

_LOCKING_ERROR_PATTERNS = re.compile(
    r"disk I/O error|database is locked|locking protocol", re.IGNORECASE
)


def _find_schema_file() -> Path:
    """Walk up from this file to find schema/forensicator.sql.

    Layout: python/forensicator/catalog.py -> ../../schema/forensicator.sql
    """
    here = Path(__file__).resolve()
    # python/forensicator/catalog.py -> python/forensicator -> python -> repo root
    candidate = here.parent.parent.parent / "schema" / "forensicator.sql"
    if candidate.is_file():
        return candidate
    # Walk further up just in case
    for ancestor in here.parents:
        c = ancestor / "schema" / "forensicator.sql"
        if c.is_file():
            return c
    env = os.environ.get("FORENSICATOR_SCHEMA")
    if env and Path(env).is_file():
        return Path(env)
    raise RuntimeError(
        f"cannot locate schema/forensicator.sql (tried {candidate})"
    )


def schema_sql() -> str:
    return _find_schema_file().read_text(encoding="utf-8")


def _split_sql_statements(sql: str) -> list[str]:
    # Strip line comments
    sql = re.sub(r"--[^\n]*", "", sql)
    parts = re.split(r";\s*(?:\n|$)", sql)
    return [p for p in parts if p.strip()]


def _locking_error_message(path: str, err: str) -> str:
    return (
        f"cannot open catalog {path}: {err}\n"
        "This filesystem appears to have broken POSIX locking (SMB / NFS / exFAT /\n"
        "some FUSE mounts). forensicator refuses to operate on such filesystems\n"
        "because long-running scans corrupt SQLite there (\"database disk image is\n"
        "malformed\"), and the previous nolock fallback caused real data loss.\n"
        "\n"
        "Move the catalog to a local SSD/HDD with a normal filesystem (APFS / ext4\n"
        "/ NTFS / HFS+) and re-run. The catalog records mount_point separately so\n"
        "it can still find files on the original data volume, regardless of where\n"
        "the SQLite file lives.\n"
    )


def open_catalog(
    path: str | os.PathLike,
    *,
    readonly: bool = False,
    dataset: str | None = None,
) -> sqlite3.Connection:
    path = str(path)
    conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.text_factory = str

    if not readonly:
        try:
            conn.execute("PRAGMA journal_mode = WAL")
        except sqlite3.DatabaseError:
            sys.stderr.write(
                f"[forensicator] WAL journal mode unavailable on this filesystem ({path}); using rollback journal\n"
            )
        try:
            conn.execute("PRAGMA synchronous = NORMAL")
        except sqlite3.DatabaseError:
            pass
    try:
        conn.execute("PRAGMA foreign_keys = ON")
    except sqlite3.DatabaseError:
        pass
    try:
        conn.execute("PRAGMA cache_size = -200000")
    except sqlite3.DatabaseError:
        pass

    try:
        has_meta = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'"
        ).fetchone()
        if has_meta:
            sv_raw = catalog_meta(conn, "schema_version")
            sv = int(sv_raw) if sv_raw is not None else 0
            if sv != SCHEMA_VERSION:
                raise RuntimeError(
                    f"catalog {path} has schema version {sv}, expected {SCHEMA_VERSION}"
                )
        if not readonly:
            init_catalog(conn, dataset=dataset)
    except sqlite3.DatabaseError as e:
        try:
            conn.close()
        except Exception:
            pass
        msg = str(e)
        if _LOCKING_ERROR_PATTERNS.search(msg):
            raise RuntimeError(_locking_error_message(path, msg)) from e
        raise RuntimeError(f"cannot open catalog {path}: {msg}") from e
    except Exception as e:
        try:
            conn.close()
        except Exception:
            pass
        msg = str(e)
        if _LOCKING_ERROR_PATTERNS.search(msg):
            raise RuntimeError(_locking_error_message(path, msg)) from e
        raise

    return conn


def init_catalog(conn: sqlite3.Connection, *, dataset: str | None = None) -> None:
    sql = schema_sql()
    for stmt in _split_sql_statements(sql):
        conn.execute(stmt)
    set_catalog_meta(conn, "schema_version", str(SCHEMA_VERSION))
    set_catalog_meta(conn, "created_at", str(int(time.time())))
    if dataset is not None:
        set_catalog_meta(conn, "dataset_name", dataset)


def catalog_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    if row is None:
        return None
    return row[0]


def set_catalog_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value)
    )


def upsert_volume(
    conn: sqlite3.Connection,
    *,
    hostname: str,
    volume: str,
    mount_point: str | None,
    os: str | None,
) -> sqlite3.Row:
    now = int(time.time())
    conn.execute(
        """
        INSERT INTO volumes(hostname, volume, mount_point, os, scanned_at)
        VALUES(?, ?, ?, ?, ?)
        ON CONFLICT(hostname, volume) DO UPDATE SET
          mount_point = excluded.mount_point,
          os          = excluded.os,
          scanned_at  = excluded.scanned_at
        """,
        (hostname, volume, mount_point, os, now),
    )
    return get_volume(conn, hostname, volume)


def get_volume(
    conn: sqlite3.Connection, hostname: str, volume: str
) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM volumes WHERE hostname = ? AND volume = ?",
        (hostname, volume),
    ).fetchone()


def volumes(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(
        conn.execute("SELECT * FROM volumes ORDER BY hostname, volume")
    )


def begin(conn: sqlite3.Connection) -> None:
    conn.execute("BEGIN")


def commit(conn: sqlite3.Connection) -> None:
    conn.execute("COMMIT")
