"""Small lazy-loading command dispatcher; optional browser stays optional."""
import importlib
import sys


def _semantic_review_main(argv):
    """Inspect one already captured local file without replaying source code."""
    import argparse
    import hashlib
    import json
    import os
    from pathlib import Path

    from .dom_replay import _read_bounded, _reject_symlink_path
    from .semantic_review import MAX_SOURCE_BYTES, review_semantic_source

    parser = argparse.ArgumentParser(description="Bounded offline semantic review of captured source bytes.")
    parser.add_argument("--input", required=True, help="already captured local file")
    parser.add_argument("--content-type", required=True, help="captured response media type")
    parser.add_argument("--output", required=True, help="new private JSON result file")
    parser.add_argument("--max-bytes", type=int, default=MAX_SOURCE_BYTES)
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.max_bytes <= MAX_SOURCE_BYTES:
            raise ValueError("invalid_limit")
        if not args.content_type or len(args.content_type) > 256 or any(
            ord(char) < 32 or ord(char) == 127 for char in args.content_type
        ):
            raise ValueError("invalid_content_type")
        output = _reject_symlink_path(Path(args.output))
        if output.exists() or not output.parent.is_dir():
            raise ValueError("unsafe_output")
        body = _read_bounded(Path(args.input), args.max_bytes, invalid="invalid_input")
        result = review_semantic_source(body, args.content_type, max_bytes=args.max_bytes)
        result["source_sha256"] = hashlib.sha256(body).hexdigest()
        result["review_mode"] = "offline_static"
        with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                       "w", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=True, indent=2)
            stream.write("\n")
        return 0 if result["source_text_complete"] and result["source_structure_complete"] else 3
    except (OSError, ValueError, TypeError, UnicodeError):
        print('{"error":"invalid_local_input"}', file=sys.stderr)
        return 2


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    commands = {
        "probe": "probe", "browser": "browser", "inventory": "inventory",
        "discover": "discovery", "github-discover": "github_discovery",
        "ledger": "ledger", "analyze": "classifiers",
        "search-plan": "search_plan", "locators": "locators", "doctor": "doctor",
        "channels-doctor": "channel_health",
        "forensics": "forensic_cli", "channel-discover": "discovery_channels",
        "discovery-eval": "discovery_eval", "asset-graph": "asset_graph", "asset-profile": "asset_profile", "asset-locations": "asset_locations",
        "trace-assets": "asset_trace",
        "prior-records": "prior_records", "github-history": "github_history",
        "dom-replay": "dom_replay",
        "audit": "audit", "gate-review": "gate_review",
        "patch-followup": "patch_followup",
        "semantic-review": "__offline_semantic_review__",
    }
    if not args or args[0] in ("-h", "--help"):
        print("usage: open-detective {" + ",".join(commands) + "} [options]")
        print("All network measurements require an explicit ownership scope.")
        return 0
    if args[0] == "--version":
        from . import __version__
        print(__version__)
        return 0
    module = commands.get(args.pop(0))
    if module is None:
        print("unknown_command", file=sys.stderr)
        return 2
    if module == "__offline_semantic_review__":
        return _semantic_review_main(args)
    return importlib.import_module(f"sudetect.{module}").main(args)


if __name__ == "__main__":
    raise SystemExit(main())
