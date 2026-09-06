#!/usr/bin/env python3
"""Compatibility entry point for the packaged offline identifier generator."""
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sudetect.idgen import *  # Preserve the public Python API used by operator scripts.

if __name__ == "__main__":
    raise SystemExit(main())
