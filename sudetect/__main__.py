"""Small lazy-loading command dispatcher; optional browser stays optional."""
import importlib
import sys


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
    return importlib.import_module(f"sudetect.{module}").main(args)


if __name__ == "__main__":
    raise SystemExit(main())
