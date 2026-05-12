"""End-to-end: scan a small tree, then dedupe and check group count."""

import json
import sqlite3

from forensicator.cli import main


def test_scan_then_dedupe(tmp_path):
    data = tmp_path / "data"
    sub = data / "sub"
    sub.mkdir(parents=True)
    (data / "a.txt").write_text("duplicate content alpha\n")
    (sub / "a-copy.txt").write_text("duplicate content alpha\n")
    (data / "b.txt").write_text("unique-length content different\n")

    catalog = tmp_path / "c.sqlite"
    rc = main([
        "scan",
        "--catalog", str(catalog),
        "--volume", "v",
        "--root", str(data),
        "--hostname", "test",
        "--quiet",
    ])
    assert rc == 0
    assert catalog.exists()

    conn = sqlite3.connect(str(catalog))
    try:
        (count,) = conn.execute("SELECT COUNT(*) FROM files").fetchone()
        assert count == 3
        (hashed,) = conn.execute(
            "SELECT COUNT(*) FROM files WHERE sha512 IS NOT NULL"
        ).fetchone()
        assert hashed == 2
    finally:
        conn.close()

    out = tmp_path / "dupes.json"
    rc = main([
        "dedupe",
        "--catalog", str(catalog),
        "--format", "json",
        "--output", str(out),
    ])
    assert rc == 0
    doc = json.loads(out.read_text())
    assert doc["forensicator"] == "dedupe"
    assert len(doc["duplicate_groups"]) == 1
    g = doc["duplicate_groups"][0]
    assert g["kind"] == "file"
    assert len(g["members"]) == 2


def test_full_hash_flag(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "one.txt").write_text("a\n")
    (data / "two.txt").write_text("bb\n")
    (data / "three.txt").write_text("ccc\n")
    catalog = tmp_path / "c.sqlite"
    rc = main([
        "scan",
        "--catalog", str(catalog),
        "--volume", "v",
        "--root", str(data),
        "--hostname", "test",
        "--full-hash",
        "--quiet",
    ])
    assert rc == 0
    conn = sqlite3.connect(str(catalog))
    try:
        (hashed,) = conn.execute(
            "SELECT COUNT(*) FROM files WHERE sha512 IS NOT NULL"
        ).fetchone()
        assert hashed == 3
    finally:
        conn.close()


def test_jsonl_roundtrip(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "a.txt").write_text("alpha\n")
    (data / "b.txt").write_text("alpha\n")
    (data / "c.txt").write_text("beta\n")

    orig = tmp_path / "orig.sqlite"
    rc = main([
        "scan", "--catalog", str(orig), "--volume", "v",
        "--root", str(data), "--hostname", "test", "--quiet",
    ])
    assert rc == 0

    export = tmp_path / "export.jsonl"
    rc = main([
        "merge", "--output", str(export), "--inputs", str(orig), "--quiet",
    ])
    assert rc == 0
    assert export.exists()

    rebuilt = tmp_path / "round.sqlite"
    rc = main([
        "merge", "--output", str(rebuilt), "--inputs", str(export), "--quiet",
    ])
    assert rc == 0

    def fetch(p):
        c = sqlite3.connect(str(p))
        try:
            return c.execute(
                "SELECT path, sha512 FROM files ORDER BY path"
            ).fetchall()
        finally:
            c.close()

    assert fetch(orig) == fetch(rebuilt)
