"""Make sure the in-tree forensicator package is importable when pytest runs
without an install. Adds the repository's python/ directory to sys.path."""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PKG_DIR = os.path.dirname(_HERE)
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)
