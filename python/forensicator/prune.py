"""forensicator prune: act on a dedupe plan to remove duplicates."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from .catalog import get_volume, open_catalog
from .hashlog import json_decode
from .pathnorm import default_hostname


def cmd_prune(args: argparse.Namespace) -> int:
    if not args.catalog:
        raise SystemExit("missing --catalog")
    if not args.plan:
        raise SystemExit("missing --plan")

    conn = open_catalog(args.catalog)
    try:
        with open(args.plan, "rb") as fh:
            plan_str = fh.read().decode("utf-8")
        plan = json_decode(plan_str)
        if not isinstance(plan, dict) or plan.get("forensicator") != "dedupe":
            raise SystemExit("plan does not look like a forensicator-dedupe document")

        actions: list[dict[str, Any]] = []
        skipped = 0
        no_local = 0

        last_response: list[str] = [""]

        for g in plan.get("duplicate_groups", []) or []:
            local = [m for m in g["members"] if m["hostname"] == args.hostname]
            if not local:
                no_local += 1
                continue

            keepers: list[dict[str, Any]] = []
            if args.keep_rule:
                keepers = _pick_by_rule(g["members"], args.keep_rule)

            keep: dict[str, Any] | None
            delete: list[dict[str, Any]]

            if len(keepers) == 1:
                keep = keepers[0]
                delete = [m for m in g["members"] if m is not keep and m["hostname"] == args.hostname]
            elif args.interactive:
                keep, delete = _prompt_group(g, args.hostname, last_response)
                if keep is None and not delete and last_response[0] == "q":
                    break
                if keep is None:
                    skipped += 1
                    continue
            else:
                skipped += 1
                continue

            if args.file_level and g["kind"] == "dir":
                actions.extend(_expand_dir_group(g, keep, delete, conn, args.hostname))
            else:
                actions.append({"group": g, "keep": keep, "delete": delete})

        if no_local:
            sys.stderr.write(f"[prune] {no_local} groups had no members on this host (skipped silently)\n")
        if skipped:
            sys.stderr.write(f"[prune] {skipped} groups skipped by user/rule\n")

        if not actions:
            sys.stderr.write("[prune] nothing to do\n")
            return 0

        sys.stderr.write("\n[prune] planned actions:\n")
        total_files = 0
        total_bytes = 0
        for a in actions:
            g = a["group"]
            keep_key = _key_of(a["keep"])
            sys.stderr.write(f"  KEEP   {keep_key}\n")
            if g["kind"] == "dir" and not args.file_level:
                for d in a["delete"]:
                    info = _subtree_info(conn, args.hostname, d["volume"], d["path"])
                    total_files += info["count"]
                    total_bytes += info["bytes"]
                    sys.stderr.write(
                        f"  DELETE {_key_of(d)}  ({info['count']} files, {_fmt_bytes(info['bytes'])})\n"
                    )
            else:
                for d in a["delete"]:
                    total_files += 1
                    sz = d.get("size_each") or g.get("size_each") or 0
                    total_bytes += sz
                    sys.stderr.write(f"  DELETE {_key_of(d)}  ({_fmt_bytes(sz)})\n")
        sys.stderr.write(f"\n[prune] total: {total_files} files, {_fmt_bytes(total_bytes)}\n")

        if not args.apply:
            sys.stderr.write("[prune] DRY RUN -- pass --apply to actually delete\n")
            return 0

        if not args.yes:
            sys.stderr.write("[prune] proceed with deletion? type 'yes' to continue: ")
            sys.stderr.flush()
            try:
                r = input()
            except EOFError:
                r = ""
            if r != "yes":
                sys.stderr.write("[prune] aborted\n")
                return 1

        deleted_files = 0
        deleted_bytes = 0
        errors = 0

        conn.execute("BEGIN")
        for a in actions:
            g = a["group"]
            for d in a["delete"]:
                if g["kind"] == "dir" and not args.file_level:
                    df, db, err = _delete_subtree(conn, args.hostname, d["volume"], d["path"])
                else:
                    df, db, err = _delete_file_member(conn, args.hostname, d)
                deleted_files += df
                deleted_bytes += db
                errors += err
        conn.execute("COMMIT")

        sys.stderr.write(
            f"[prune] DONE: {deleted_files} files removed, "
            f"{_fmt_bytes(deleted_bytes)} freed, {errors} errors\n"
        )
        return 2 if errors else 0
    finally:
        conn.close()


def _key_of(m: dict[str, Any]) -> str:
    p = m["path"] if m["path"] else "<root>"
    return f"{m['hostname']}:{m['volume']}:{p}"


def _pick_by_rule(members: list[dict[str, Any]], rule: str) -> list[dict[str, Any]]:
    local = list(members)
    if rule == "first":
        return [local[0]] if local else []
    if rule.startswith("host="):
        h = rule[len("host="):]
        match = [m for m in local if m["hostname"] == h]
        return match if len(match) == 1 else []
    if rule.startswith("volume="):
        v = rule[len("volume="):]
        match = [m for m in local if m["volume"] == v]
        return match if len(match) == 1 else []
    if rule == "shortest-path":
        if not local:
            return []
        srt = sorted(local, key=lambda m: len(m["path"]))
        return [srt[0]]
    return []


def _prompt_group(g: dict[str, Any], host: str, last_response: list[str]) -> tuple[dict | None, list[dict]]:
    sz = _fmt_bytes(g.get("size_each", 0))
    extra = f" ({g.get('file_count_each', 0)} files each)" if g["kind"] == "dir" else ""
    sys.stderr.write(f"\n=== {g['kind'].upper()} duplicate, {sz}{extra} ===\n")
    for i, m in enumerate(g["members"], start=1):
        tags = []
        if m["hostname"] == host:
            tags.append("LOCAL")
        if m.get("covered_by_ancestor"):
            tags.append("covered")
        tag = f" [{','.join(tags)}]" if tags else ""
        sys.stderr.write(f"  {i}. {_key_of(m)}{tag}\n")
    sys.stderr.write("Keep which? (number to keep / a=keep all (skip) / s=skip / q=quit): ")
    sys.stderr.flush()
    try:
        resp = input()
    except EOFError:
        last_response[0] = ""
        return (None, [])
    last_response[0] = resp
    if resp in ("s", "a", "", "q"):
        return (None, [])
    if resp.isdigit():
        idx = int(resp) - 1
        if idx < 0 or idx >= len(g["members"]):
            return (None, [])
        keep = g["members"][idx]
        delete = [m for m in g["members"] if m is not keep and m["hostname"] == host]
        return (keep, delete)
    return (None, [])


def _subtree_info(conn, host: str, volume: str, path: str) -> dict[str, int]:
    vol = get_volume(conn, host, volume)
    if not vol:
        return {"count": 0, "bytes": 0}
    like = f"{path}/%" if path else "%"
    row = conn.execute(
        "SELECT COUNT(*), COALESCE(SUM(size),0) FROM files "
        "WHERE volume_id = ? AND (path_norm = ? OR path_norm LIKE ?)",
        (vol["volume_id"], path, like),
    ).fetchone()
    return {"count": row[0] or 0, "bytes": row[1] or 0}


def _expand_dir_group(g, keep, delete, conn, host) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    keep_vol = get_volume(conn, keep["hostname"], keep["volume"])
    if not keep_vol:
        return []
    like = f"{keep['path']}/%" if keep["path"] else "%"
    keep_files = list(conn.execute(
        "SELECT file_id, path, path_norm, size, sha512 FROM files "
        "WHERE volume_id = ? AND (path_norm = ? OR path_norm LIKE ?) "
        "ORDER BY path_norm",
        (keep_vol["volume_id"], keep["path"], like),
    ))
    for d in delete:
        vol = get_volume(conn, d["hostname"], d["volume"])
        if not vol:
            continue
        dlike = f"{d['path']}/%" if d["path"] else "%"
        del_files = list(conn.execute(
            "SELECT file_id, path, path_norm, size, sha512 FROM files "
            "WHERE volume_id = ? AND (path_norm = ? OR path_norm LIKE ?) "
            "ORDER BY path_norm",
            (vol["volume_id"], d["path"], dlike),
        ))
        base = len(keep["path"]) + 1 if keep["path"] else 0
        by_rel: dict[str, Any] = {}
        for kf in keep_files:
            rel = kf["path_norm"][base:]
            by_rel[rel] = kf
        dbase = len(d["path"]) + 1 if d["path"] else 0
        for df in del_files:
            rel = df["path_norm"][dbase:]
            kf = by_rel.get(rel)
            if not kf:
                continue
            actions.append({
                "group": {"kind": "file", "size_each": df["size"]},
                "keep": {
                    "hostname": keep["hostname"],
                    "volume": keep["volume"],
                    "path": kf["path_norm"],
                    "file_id": kf["file_id"],
                },
                "delete": [{
                    "hostname": d["hostname"],
                    "volume": d["volume"],
                    "path": df["path_norm"],
                    "file_id": df["file_id"],
                    "size_each": df["size"],
                }],
            })
    return actions


def _delete_file_member(conn, host, m) -> tuple[int, int, int]:
    if m["hostname"] != host:
        return (0, 0, 0)
    vol = get_volume(conn, m["hostname"], m["volume"])
    if not vol:
        sys.stderr.write(f"[prune] volume not in catalog: {m['hostname']}:{m['volume']}\n")
        return (0, 0, 1)
    mount = vol["mount_point"]
    if not mount:
        sys.stderr.write(
            f"[prune] no mount_point for {m['hostname']}:{m['volume']}; cannot locate file\n"
        )
        return (0, 0, 1)

    file_id = None
    orig_path = None
    size = None
    if m.get("file_id"):
        row = conn.execute(
            "SELECT file_id, path, size FROM files WHERE file_id = ?",
            (m["file_id"],),
        ).fetchone()
        if row:
            file_id, orig_path, size = row[0], row[1], row[2]
    if not file_id:
        row = conn.execute(
            "SELECT file_id, path, size FROM files WHERE volume_id = ? AND path_norm = ?",
            (vol["volume_id"], m["path"]),
        ).fetchone()
        if row:
            file_id, orig_path, size = row[0], row[1], row[2]
    if not file_id:
        sys.stderr.write(f"[prune] no catalog entry for {_key_of(m)}\n")
        return (0, 0, 1)

    abs_path = os.path.join(mount, orig_path)
    if not os.path.isfile(abs_path):
        sys.stderr.write(f"[prune] file already missing: {abs_path} (removing catalog entry)\n")
        conn.execute("DELETE FROM files WHERE file_id = ?", (file_id,))
        return (0, 0, 1)

    try:
        st = os.stat(abs_path)
        if st.st_size != size:
            sys.stderr.write(
                f"[prune] size mismatch for {abs_path} (catalog: {size}, disk: {st.st_size}); skipping\n"
            )
            return (0, 0, 1)
    except OSError:
        pass

    try:
        os.unlink(abs_path)
    except OSError as e:
        sys.stderr.write(f"[prune] unlink failed: {abs_path}: {e}\n")
        return (0, 0, 1)
    conn.execute("DELETE FROM files WHERE file_id = ?", (file_id,))
    return (1, size, 0)


def _delete_subtree(conn, host, volume, path) -> tuple[int, int, int]:
    vol = get_volume(conn, host, volume)
    if not vol:
        sys.stderr.write(f"[prune] volume not in catalog: {host}:{volume}\n")
        return (0, 0, 1)
    mount = vol["mount_point"]
    if not mount:
        sys.stderr.write(f"[prune] no mount_point for {host}:{volume}; cannot delete subtree\n")
        return (0, 0, 1)
    like = f"{path}/%" if path else "%"
    rows = list(conn.execute(
        "SELECT file_id, path, path_norm, size FROM files "
        "WHERE volume_id = ? AND (path_norm = ? OR path_norm LIKE ?) "
        "ORDER BY length(path_norm) DESC",
        (vol["volume_id"], path, like),
    ))
    df = 0
    db = 0
    err = 0
    dirs_seen: set[str] = set()
    for r in rows:
        abs_path = os.path.join(mount, r["path"])
        if os.path.isfile(abs_path):
            try:
                os.unlink(abs_path)
            except OSError as e:
                sys.stderr.write(f"[prune] unlink failed: {abs_path}: {e}\n")
                err += 1
                continue
            df += 1
            db += r["size"]
            conn.execute("DELETE FROM files WHERE file_id = ?", (r["file_id"],))
            d = os.path.dirname(abs_path)
            while d and d != os.path.sep:
                dirs_seen.add(d)
                parent = os.path.dirname(d)
                if parent == d:
                    break
                d = parent
        else:
            sys.stderr.write(f"[prune] file missing: {abs_path} (removing catalog entry)\n")
            conn.execute("DELETE FROM files WHERE file_id = ?", (r["file_id"],))
            err += 1
    for d in sorted(dirs_seen, key=lambda x: -len(x)):
        if os.path.isdir(d):
            try:
                os.rmdir(d)
            except OSError:
                pass
    return (df, db, err)


def _fmt_bytes(b: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    while b >= 1024 and i < len(units) - 1:
        b /= 1024
        i += 1
    if i == 0:
        return f"{int(b)} {units[i]}"
    return f"{b:.2f} {units[i]}"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--catalog")
    p.add_argument("--plan")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--keep-rule", dest="keep_rule")
    # --interactive is on by default; --no-interactive turns it off.
    p.add_argument(
        "--no-interactive",
        action="store_false",
        dest="interactive",
        default=True,
    )
    p.add_argument("--hostname", default=default_hostname())
    p.add_argument("--file-level", action="store_true", dest="file_level")
    p.add_argument("-y", "--yes", action="store_true")
