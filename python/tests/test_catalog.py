import sqlite3

from forensicator.catalog import (
    catalog_meta,
    get_volume,
    open_catalog,
    set_catalog_meta,
    upsert_volume,
    volumes,
)


def test_open_creates_catalog(tmp_path):
    p = tmp_path / "c.sqlite"
    conn = open_catalog(str(p))
    try:
        assert p.exists()
        sv = catalog_meta(conn, "schema_version")
        assert sv == "1"
    finally:
        conn.close()


def test_meta_roundtrip(tmp_path):
    conn = open_catalog(str(tmp_path / "c.sqlite"))
    try:
        set_catalog_meta(conn, "k", "v")
        assert catalog_meta(conn, "k") == "v"
        set_catalog_meta(conn, "k", "v2")
        assert catalog_meta(conn, "k") == "v2"
    finally:
        conn.close()


def test_upsert_volume_idempotent(tmp_path):
    conn = open_catalog(str(tmp_path / "c.sqlite"))
    try:
        v1 = upsert_volume(conn, hostname="h", volume="v", mount_point="/m", os="darwin")
        v2 = upsert_volume(conn, hostname="h", volume="v", mount_point="/m2", os="darwin")
        assert v1["volume_id"] == v2["volume_id"]
        got = get_volume(conn, "h", "v")
        assert got["mount_point"] == "/m2"
        all_vols = volumes(conn)
        assert len(all_vols) == 1
    finally:
        conn.close()


def test_schema_tables_created(tmp_path):
    conn = open_catalog(str(tmp_path / "c.sqlite"))
    try:
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert "files" in tables
        assert "volumes" in tables
        assert "meta" in tables
    finally:
        conn.close()
