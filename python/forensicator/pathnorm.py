"""Path normalization that matches the Perl reference implementation."""

from __future__ import annotations

import socket
import sys


def os_name() -> str:
    """Return the OS literal as recorded in catalogs (matches sys.platform)."""
    return sys.platform


# OS strings (from either Perl's $^O or Python's sys.platform) that imply a
# case-insensitive filesystem and therefore case-folded path_norm.
_CASE_INSENSITIVE = {
    "darwin",
    "mswin32",
    "win32",
    "cygwin",
    "msys",
}


def is_case_insensitive_os(os: str | None = None) -> bool:
    if os is None:
        os = os_name()
    return os.lower() in _CASE_INSENSITIVE


def normalize_path(path: str, os: str | None = None) -> str:
    """Normalize a path the same way the Perl reference does.

    - Backslashes -> forward slashes.
    - Collapse runs of slashes.
    - Strip leading "./".
    - Strip trailing "/" (unless the path is exactly "/").
    - Lowercase on case-insensitive OSes.
    """
    if os is None:
        os = os_name()
    n = path.replace("\\", "/")
    # Collapse multiple slashes
    while "//" in n:
        n = n.replace("//", "/")
    if n.startswith("./"):
        n = n[2:]
    if n != "/" and n.endswith("/"):
        n = n[:-1]
    if is_case_insensitive_os(os):
        n = n.lower()
    return n


def default_hostname() -> str:
    h = socket.gethostname()
    return h.split(".", 1)[0]
