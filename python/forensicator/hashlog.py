"""Append-only JSONL recovery log and shared JSONL helpers."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, IO, Iterator


def json_encode(obj: Any) -> str:
    """Match Perl's JSON::PP->canonical: sorted keys, compact separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def json_decode(s: str) -> Any:
    return json.loads(s)


def jsonl_writer(path: str | os.PathLike):
    fh = open(path, "wb")

    def emit(obj: dict[str, Any]) -> None:
        line = json_encode(obj) + "\n"
        fh.write(line.encode("utf-8"))

    def close() -> None:
        fh.close()

    return emit, close


def jsonl_reader(path: str | os.PathLike) -> Iterator[dict[str, Any]]:
    with open(path, "rb") as fh:
        for raw in fh:
            line = raw.decode("utf-8").rstrip("\n").rstrip("\r")
            if not line:
                yield {}
                continue
            yield json_decode(line)


class HashLog:
    """Append-only JSONL writer with autoflush. Each write is flushed before
    returning so a downstream SQLite write can crash without losing the log."""

    def __init__(self, fh: IO[bytes] | None, path: str | None = None):
        self._fh = fh
        self.path = path

    @classmethod
    def open(cls, catalog_path: str, *, override: str | None = None,
             disabled: bool = False, quiet: bool = False) -> "HashLog":
        if disabled:
            return cls(None)
        path = override if override is not None else f"{catalog_path}.hashlog.jsonl"
        fh = open(path, "ab", buffering=0)
        if not quiet:
            sys.stderr.write(f"[scan] hashlog: {path}\n")
        return cls(fh, path)

    def write(self, record: dict[str, Any]) -> None:
        if self._fh is None:
            return
        line = json_encode(record) + "\n"
        self._fh.write(line.encode("utf-8"))

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None
