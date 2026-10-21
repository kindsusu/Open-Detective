"""Private local manifest entry point for captured original-JavaScript review."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os
import sqlite3
from pathlib import Path

from .dom_replay import _read_bounded, _reject_symlink_path
from . import strict_json


def main(argv=None):
    from .runtime_review import (MAX_RESOURCES, MAX_SOURCE_BYTES, MAX_RESOURCE_BYTES,
                                 MAX_TOTAL_BYTES, review_runtime_source)
    parser = argparse.ArgumentParser(description="Execute a hash-authorized captured local application.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--case", help="existing case directory for append-only evidence")
    args = parser.parse_args(argv)
    try:
        manifest_path = _reject_symlink_path(Path(args.manifest))
        manifest = strict_json.loads(_read_bounded(manifest_path, 1_048_576,
                                                  invalid="invalid_manifest"))
        if not isinstance(manifest, dict) or not isinstance(manifest.get("resources", {}), dict):
            raise ValueError("invalid_manifest")
        output = _reject_symlink_path(Path(args.output))
        if output.exists() or not output.parent.is_dir():
            raise ValueError("invalid_output")

        def read_local(value, limit):
            if not isinstance(value, str) or not value or limit < 1:
                raise ValueError("invalid_input")
            path = Path(value)
            if not path.is_absolute():
                path = manifest_path.parent / path
            return _read_bounded(path, limit, invalid="invalid_input")

        body = read_local(manifest["input"], MAX_SOURCE_BYTES)
        resource_rows = manifest.get("resources", {})
        if len(resource_rows) > MAX_RESOURCES:
            raise ValueError("resource_limit")
        resources = {}
        total = len(body)
        for synthetic_path, row in resource_rows.items():
            if not isinstance(row, dict):
                raise ValueError("invalid_resource")
            data = read_local(row["input"], min(MAX_RESOURCE_BYTES, MAX_TOTAL_BYTES - total))
            total += len(data)
            resources[synthetic_path] = {"body": data, "content_type": row["content_type"]}
        with ExitStack() as stack:
            case = None
            if args.case:
                from .audit import Case
                case_path = _reject_symlink_path(Path(args.case))
                case = stack.enter_context(Case(case_path))
                if case.meta["case_id"] != manifest["authorization"]["case_id"]:
                    raise ValueError("case_mismatch")
            result = review_runtime_source(body, manifest["content_type"],
                authorization=manifest["authorization"], resources=resources,
                reveal_client_ui=manifest.get("reveal_client_ui", True),
                max_seconds=manifest.get("max_seconds", 30))
            if case is not None:
                case.ledger._event("CAPTURED_RUNTIME_REVIEW", result["source_sha256"], result)
                case.ledger.db.commit()
        with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                       "w", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=True, indent=2)
            stream.write("\n")
        return 0 if result.get("runtime_observation_complete") is True else 3
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, sqlite3.Error):
        print('{"error":"invalid_local_runtime_input"}', file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
