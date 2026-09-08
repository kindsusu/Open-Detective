"""Private local URL handoff. Only opaque IDs leave this store.

This is an owner-controlled plaintext SQLite file, not an encryption service.
Place it on an access-controlled/encrypted volume; never publish or commit it.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlsplit
import uuid

SCOPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REFERENCE = re.compile(r"^opaque:[0-9a-f]{32}$")


class LocatorError(ValueError):
    pass


class LocatorStore:
    def __init__(self, path):
        path = Path(path)
        if path.is_symlink() or not path.parent.is_dir():
            raise LocatorError("invalid locator store")
        if not path.exists():
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        if not path.is_file():
            raise LocatorError("invalid locator store")
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS locators (ref TEXT PRIMARY KEY, scope_id TEXT NOT NULL, url TEXT NOT NULL, UNIQUE(scope_id,url))")
        self.db.commit()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self.db.close()

    def put(self, scope_id, url):
        if not isinstance(scope_id, str) or not SCOPE.fullmatch(scope_id):
            raise LocatorError("invalid locator scope")
        if not isinstance(url, str) or not 1 <= len(url) <= 8192 or any(ord(c) < 32 for c in url):
            raise LocatorError("invalid locator")
        try:
            p = urlsplit(url)
            if p.scheme not in ("https", "http") or not p.hostname or p.username or p.password:
                raise LocatorError("invalid locator")
            _ = p.port
        except ValueError:
            raise LocatorError("invalid locator") from None
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO locators VALUES(?,?,?)", ("opaque:" + uuid.uuid4().hex, scope_id, url))
            return self.db.execute("SELECT ref FROM locators WHERE scope_id=? AND url=?", (scope_id, url)).fetchone()[0]

    def get(self, scope_id, locator_ref):
        if not isinstance(scope_id, str) or not SCOPE.fullmatch(scope_id) or not isinstance(locator_ref, str) or not REFERENCE.fullmatch(locator_ref):
            raise LocatorError("invalid locator reference")
        row = self.db.execute("SELECT url FROM locators WHERE scope_id=? AND ref=?", (scope_id, locator_ref)).fetchone()
        if not row:
            raise LocatorError("locator not found in scope")
        return row[0]


def resolve_target(url, store_path=None, locator_scope=None, locator_ref=None):
    """Resolve an explicit URL OR a scoped store entry, never a caller-forged ID."""
    if any((store_path, locator_scope, locator_ref)):
        if url or not all((store_path, locator_scope, locator_ref)):
            raise LocatorError("provide complete locator reference or URL")
        with LocatorStore(store_path) as store:
            return store.get(locator_scope, locator_ref), locator_ref
    if not url:
        raise LocatorError("target required")
    return url, None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Private locator handoff; stdout never contains original URLs")
    parser.add_argument("--store", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("add")
    add.add_argument("--scope-id", required=True)
    add.add_argument("--url", required=True)
    bind = sub.add_parser("bind")
    bind.add_argument("--scope-id", required=True)
    bind.add_argument("--locator-ref", required=True)
    bind.add_argument("--scope", required=True)
    bind.add_argument("--db", required=True)
    bind.add_argument("--asset-id", required=True)
    bind.add_argument("--provider", required=True)
    args = parser.parse_args(argv)
    try:
        with LocatorStore(args.store) as store:
            if args.command == "add":
                result = {"locator_ref": store.put(args.scope_id, args.url), "handoff": "ready"}
            else:
                from .policy import Scope
                from .ledger import Ledger
                scope = Scope.load(args.scope)
                scope.authorize(store.get(args.scope_id, args.locator_ref))
                with Ledger(args.db) as ledger:
                    eid = ledger.register_asset(args.asset_id, provider=args.provider, scope_id=args.scope_id,
                        required_alias_ids=[], target_id=args.locator_ref, policy_id=scope.policy_id)
                result = {"event_id": eid, "asset_id": args.asset_id, "target_id": args.locator_ref, "policy_id": scope.policy_id}
        print(json.dumps(result))
        return 0
    except (ValueError, OSError, sqlite3.Error):
        print(json.dumps({"error": "locator_handoff_failed"}))
        return 2
