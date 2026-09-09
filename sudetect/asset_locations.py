"""Explicit private asset-to-location export, without network access."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
import stat


def _regular(path: Path) -> Path:
    for part in (path, *path.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 1024:
            raise ValueError('linked path')
    if not path.is_file():
        raise ValueError('not a file')
    return path.resolve()


def export_locations(report_path, store_path, scope_id):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', scope_id):
        raise ValueError('invalid scope')
    report_path = _regular(Path(report_path).absolute())
    store_path = _regular(Path(store_path).absolute())
    with report_path.open('rb') as stream:
        data = stream.read(8_388_609)
    if len(data) > 8_388_608:
        raise ValueError('report too large')
    report = json.loads(data)
    if not isinstance(report, dict) or not isinstance(report.get('assets'), list):
        raise ValueError('invalid report')
    if report.get('scope_id') is not None and report['scope_id'] != scope_id:
        raise ValueError('scope mismatch')
    if len(report['assets']) > 5000:
        raise ValueError('too many assets')
    rows = []
    seen = set()
    db = sqlite3.connect(store_path.as_uri() + '?mode=ro', uri=True)
    try:
        for asset in report['assets']:
            if not isinstance(asset, dict):
                raise ValueError('invalid asset')
            identifier, ref = asset.get('asset_id'), asset.get('locator_ref')
            if not isinstance(identifier, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,255}', identifier) or identifier in seen:
                raise ValueError('invalid asset id')
            seen.add(identifier)
            if ref is None:
                rows.append({'asset_id': identifier, 'location_state': 'NO_REFERENCE'})
                continue
            if not isinstance(ref, str) or not re.fullmatch(r'opaque:[0-9a-f]{32}', ref):
                raise ValueError('invalid reference')
            match = db.execute('SELECT url FROM locators WHERE scope_id=? AND ref=?', (scope_id, ref)).fetchone()
            rows.append({'asset_id': identifier, 'locator_ref': ref,
                         'location_state': 'RESOLVED' if match else 'NOT_FOUND_IN_SCOPE',
                         **({'private_location': match[0]} if match else {})})
    finally:
        db.close()
    return {'classification': 'PRIVATE_LOCATION_MAPPING_DO_NOT_PUBLISH',
            'scope_id': scope_id, 'assets': rows,
            'limitations': ['No network requests were made.',
                            'Locations do not prove ownership, access, or sensitive exposure.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Export exact asset locations to a private local file; never publish this file.')
    for name in ('input', 'locator-store', 'scope-id', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        result = export_locations(args.input, args.locator_store, args.scope_id)
        output = Path(args.output).absolute()
        for parent in output.parents:
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 1024:
                raise ValueError('linked output directory')
        raw = (json.dumps(result, ensure_ascii=True, indent=2) + '\n').encode()
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
        print(json.dumps({'status': 'PRIVATE_EXPORT_WRITTEN', 'assets': len(result['assets'])}))
        return 0
    except (OSError, ValueError, sqlite3.Error, RecursionError):
        print(json.dumps({'error': 'private_location_export_failed'}))
        return 2
