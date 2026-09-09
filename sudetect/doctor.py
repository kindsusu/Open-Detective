"""Read-only runtime/source parity checks; never installs or changes settings."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

RUNTIME_DIRS = ("sudetect", "tools", "ops", "ko", "schemas", "examples", "assets", "surfaces")
ROOT_FILES = ("SKILL.md", "README.md", "README.ko.md", "IMPLEMENTATION.ko.md",
              "CHANGELOG.md", "pyproject.toml", "LICENSE")


def runtime_files(root):
    root = Path(root)
    files = [root / name for name in ROOT_FILES]
    for folder in RUNTIME_DIRS:
        files.extend(p for p in (root / folder).rglob("*") if p.is_file()
                     and "__pycache__" not in p.parts and p.suffix not in (".pyc", ".pyo"))
    return sorted(set(files))


def check(skill_root=None, reference=None, require_browser=False):
    from . import __version__
    runtime = Path(__file__).resolve().parents[1]
    root = Path(skill_root).resolve() if skill_root else runtime
    failures = []
    required = ("SKILL.md", "sudetect/__main__.py", "sudetect/search_plan.py",
                "sudetect/identifiers.py", "sudetect/idgen.py", "sudetect/locators.py",
                "tools/idgen.py", "ops/scope.md", "ops/forensics.md", "ko/ops/forensics.md",
                "ops/discovery-optimization.md", "ko/ops/discovery-optimization.md",
                "sudetect/forensic_cli.py", "sudetect/discovery_channels.py",
                "sudetect/discovery_eval.py", "sudetect/asset_graph.py",
                "sudetect/asset_profile.py", "sudetect/asset_locations.py",
                "sudetect/asset_trace.py", "ops/asset-profile.md", "ops/asset-trace.md",
                "sudetect/github_code_search.py", "ops/github-code-search.md")
    missing = [name for name in required if not (root / name).is_file()]
    if missing:
        failures.append("RUNTIME_FILES_MISSING")
    if runtime != root:
        failures.append("RUNTIME_ROOT_MISMATCH")
    mismatches = []
    if reference:
        source = Path(reference).resolve()
        if not (source / "sudetect/__main__.py").is_file():
            failures.append("REFERENCE_INVALID")
        else:
            for path in runtime_files(source):
                relative = path.relative_to(source)
                target = root / relative
                if not path.is_file() or not target.is_file() or hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(target.read_bytes()).digest():
                    mismatches.append(relative.as_posix())
            if mismatches:
                failures.append("SOURCE_PARITY_FAILED")
    browser_ready = False
    if importlib.util.find_spec("playwright"):
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser_ready = Path(p.chromium.executable_path).is_file()
        except Exception:
            pass
    if require_browser and not browser_ready:
        failures.append("BROWSER_RUNTIME_UNAVAILABLE")
    return {"status": "PASS" if not failures else "FAIL", "version": __version__,
            "python": sys.version.split()[0], "runtime_root": str(runtime), "skill_root": str(root),
            "browser_ready": browser_ready, "missing": missing, "mismatched": mismatches,
            "errors": failures}


def main(argv=None):
    p = argparse.ArgumentParser(description="Verify the actual runtime and optionally compare a reviewed source tree")
    p.add_argument("--skill-root")
    p.add_argument("--reference")
    p.add_argument("--require-browser", action="store_true")
    args = p.parse_args(argv)
    try:
        result = check(args.skill_root, args.reference, args.require_browser)
    except (OSError, ValueError):
        result = {"status": "FAIL", "errors": ["RUNTIME_CHECK_FAILED"]}
    print(json.dumps(result))
    return 0 if result["status"] == "PASS" else 2
