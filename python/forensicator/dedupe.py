"""forensicator dedupe: find duplicate files and directory trees."""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from typing import Any

from .catalog import catalog_meta, open_catalog
from .hashlog import json_encode


def cmd_dedupe(args: argparse.Namespace) -> int:
    if not args.catalog:
        raise SystemExit("missing --catalog")
    if args.format not in ("human", "json"):
        raise SystemExit("format must be 'human' or 'json'")

    conn = open_catalog(args.catalog, readonly=True)
    try:
        files = list(conn.execute(
            """
            SELECT f.file_id, f.path, f.path_norm, f.size, f.sha512,
                   v.hostname, v.volume
            FROM files f
            JOIN volumes v ON v.volume_id = f.volume_id
            ORDER BY v.hostname, v.volume, f.path_norm
            """
        ))

        size_count: dict[int, int] = {}
        for f in files:
            size_count[f["size"]] = size_count.get(f["size"], 0) + 1

        missing_collisions = 0
        missing_examples: list[str] = []
        for f in files:
            if not f["sha512"] and size_count.get(f["size"], 0) > 1:
                missing_collisions += 1
                if len(missing_examples) < 5:
                    missing_examples.append(
                        f"{f['hostname']}:{f['volume']}:{f['path']}"
                    )

        warnings: list[str] = []
        if missing_collisions:
            warnings.append(
                f"{missing_collisions} files have size collisions but no SHA512 hash; "
                "run forensicator-scan --rehash on each host. Examples: "
                + ", ".join(missing_examples)
            )

        trees: dict[tuple[str, str], dict[str, Any]] = {}
        for f in files:
            key = (f["hostname"], f["volume"])
            tree = trees.get(key)
            if tree is None:
                tree = _make_dir("", f["hostname"], f["volume"])
                trees[key] = tree
            _insert_file(tree, f)

        all_nodes: list[dict[str, Any]] = []
        for tree in trees.values():
            _walk_compute(tree, all_nodes, size_count)

        groups: dict[str, list[dict[str, Any]]] = {}
        for n in all_nodes:
            sig = n["sig"]
            if sig.startswith("U:") or sig.startswith("X:"):
                continue
            if sig == "D:empty":
                continue
            groups.setdefault(sig, []).append(n)

        dup_groups: list[list[dict[str, Any]]] = []
        for sig, g in groups.items():
            if len(g) < 2:
                continue
            first = g[0]
            if first["kind"] == "file" and first["size"] < args.min_size:
                continue
            dup_groups.append(g)

        dup_groups.sort(key=lambda g: (_depth(g[0]), -_group_size(g)))

        covered: set[str] = set()
        reported: list[dict[str, Any]] = []
        for g in dup_groups:
            members = []
            any_uncovered = False
            for n in g:
                cov = _is_covered(n, covered)
                if not cov:
                    any_uncovered = True
                members.append({"node": n, "covered": cov})
            if not any_uncovered:
                continue
            first = g[0]
            reported.append({
                "sig": first["sig"],
                "kind": first["kind"],
                "size": first["size"] if first["kind"] == "file" else first["size_total"],
                "count": 1 if first["kind"] == "file" else first["count"],
                "members": members,
            })
            for m in members:
                covered.add(_node_key(m["node"]))

        reported.sort(key=lambda r: (-r["size"], -r["count"]))

        if args.output:
            out_fh = open(args.output, "wb")
            close_out = True
        else:
            out_fh = sys.stdout.buffer
            close_out = False

        try:
            if args.format == "json":
                _emit_json(out_fh, reported, warnings, args.catalog, conn)
            else:
                _emit_human(out_fh, reported, warnings, args.catalog, conn)
        finally:
            if close_out:
                out_fh.close()
    finally:
        conn.close()
    return 0


# --- helpers ---

def _make_dir(path: str, hostname: str, volume: str) -> dict[str, Any]:
    return {
        "kind": "dir",
        "path": path,
        "hostname": hostname,
        "volume": volume,
        "dirs": {},
        "files": [],
    }


def _insert_file(tree: dict[str, Any], f) -> None:
    parts = f["path_norm"].split("/")
    name = parts.pop()
    node = tree
    for p in parts:
        if not p:
            continue
        sub_path = f"{node['path']}/{p}" if node["path"] else p
        if p not in node["dirs"]:
            node["dirs"][p] = _make_dir(sub_path, f["hostname"], f["volume"])
        node = node["dirs"][p]
    fpath = f"{node['path']}/{name}" if node["path"] else name
    node["files"].append({
        "kind": "file",
        "name": name,
        "path": fpath,
        "orig_path": f["path"],
        "hostname": f["hostname"],
        "volume": f["volume"],
        "size": f["size"],
        "sha512": f["sha512"],
        "file_id": f["file_id"],
    })


def _walk_compute(node: dict[str, Any], all_nodes: list, size_count: dict[int, int]) -> None:
    entries: list[tuple[str, str]] = []
    size_total = 0
    count = 0
    for fl in node["files"]:
        if fl["sha512"]:
            sig = f"F:{fl['sha512']}"
        elif size_count.get(fl["size"], 0) <= 1:
            sig = f"U:{fl['file_id']}"
        else:
            sig = f"X:{fl['file_id']}"
        fl["sig"] = sig
        entries.append((fl["name"], sig))
        size_total += fl["size"]
        count += 1
        all_nodes.append(fl)
    for name in sorted(node["dirs"].keys()):
        d = node["dirs"][name]
        _walk_compute(d, all_nodes, size_count)
        entries.append((name, d["sig"]))
        size_total += d["size_total"]
        count += d["count"]
    node["size_total"] = size_total
    node["count"] = count
    if not entries:
        node["sig"] = "D:empty"
    else:
        h = hashlib.sha512()
        for e_name, e_sig in sorted(entries, key=lambda e: e[0]):
            h.update(e_name.encode("utf-8"))
            h.update(b"\0")
            h.update(e_sig.encode("utf-8"))
            h.update(b"\0")
        node["sig"] = "D:" + h.hexdigest()
    all_nodes.append(node)


def _depth(n: dict[str, Any]) -> int:
    if not n["path"]:
        return 0
    return n["path"].count("/") + 1


def _group_size(g: list[dict[str, Any]]) -> int:
    n = g[0]
    return n["size"] if n["kind"] == "file" else n["size_total"]


def _node_key(n: dict[str, Any]) -> str:
    return f"{n['hostname']}\0{n['volume']}\0{n['path']}"


def _is_covered(n: dict[str, Any], covered: set[str]) -> bool:
    hv = f"{n['hostname']}\0{n['volume']}\0"
    p = n["path"]
    while "/" in p:
        p = p.rsplit("/", 1)[0]
        if (hv + p) in covered:
            return True
    if hv in covered:
        return True
    return False


def _key_str(n: dict[str, Any]) -> str:
    p = n["path"] if n["path"] else "<root>"
    return f"{n['hostname']}:{n['volume']}:{p}"


def _fmt_bytes(b: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    while b >= 1024 and i < len(units) - 1:
        b /= 1024
        i += 1
    if i == 0:
        return f"{int(b)} {units[i]}"
    return f"{b:.2f} {units[i]}"


def _emit_human(fh, reported: list[dict], warnings: list[str], catalog_path: str, conn) -> None:
    def w(s: str) -> None:
        fh.write(s.encode("utf-8"))
    now = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime())
    w(f"# forensicator-dedupe report ({now})\n")
    w(f"# catalog: {catalog_path}\n")
    name = catalog_meta(conn, "dataset_name")
    if name:
        w(f"# dataset: {name}\n")
    w(f"# duplicate groups: {len(reported)}\n")
    if warnings:
        w("\n")
        for wn in warnings:
            w(f"WARNING: {wn}\n")
    w("\n")
    for i, g in enumerate(reported, start=1):
        kind = g["kind"].upper()
        size = _fmt_bytes(g["size"])
        count = g["count"]
        copies = len(g["members"])
        if g["kind"] == "file":
            head = f"[{i}] {kind}  {size}  {copies} copies"
        else:
            head = f"[{i}] {kind}  {size}  ({count} files each)  {copies} copies"
        w(head + "\n")
        first = True
        for m in g["members"]:
            tag = "KEEP-CANDIDATE:" if first else "DUPLICATE:     "
            first = False
            note = "   (covered by ancestor dup)" if m["covered"] else ""
            w(f"  {tag} {_key_str(m['node'])}{note}\n")
        w("\n")


def _emit_json(fh, reported: list[dict], warnings: list[str], catalog_path: str, conn) -> None:
    groups_out = []
    for g in reported:
        mems = []
        for m in g["members"]:
            n = m["node"]
            entry: dict[str, Any] = {
                "hostname": n["hostname"],
                "volume": n["volume"],
                "path": n["path"],
                "key": _key_str(n),
                "covered_by_ancestor": bool(m["covered"]),
            }
            if n["kind"] == "file":
                entry["file_id"] = n["file_id"]
                entry["sha512"] = n["sha512"]
                entry["orig_path"] = n["orig_path"]
            mems.append(entry)
        groups_out.append({
            "sig": g["sig"],
            "kind": g["kind"],
            "size_each": g["size"],
            "file_count_each": g["count"],
            "members": mems,
        })
    doc = {
        "forensicator": "dedupe",
        "version": 1,
        "generated_at": int(time.time()),
        "catalog": catalog_path,
        "dataset": catalog_meta(conn, "dataset_name"),
        "warnings": warnings,
        "duplicate_groups": groups_out,
    }
    fh.write((json_encode(doc) + "\n").encode("utf-8"))


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--catalog")
    p.add_argument("--format", default="human")
    p.add_argument("--output")
    p.add_argument("--min-size", type=int, default=0, dest="min_size")
