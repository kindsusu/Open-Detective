#!/usr/bin/env bash
# Offline smoke checks; the complete suite is `python -m unittest discover -s tests`.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
TMPROOT="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
TMP="$(mktemp -d "$TMPROOT/open-detective-test.XXXXXX")"
TMP="$(cd "$TMP" && pwd -P)"
case "$TMP" in
  "$TMPROOT"/open-detective-test.*) ;;
  *) echo "temporary_directory_out_of_scope" >&2; exit 2 ;;
esac
trap 'rm -rf -- "$TMP"' EXIT INT TERM

PYTHON_BIN="${PYTHON:-python}"
if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(sys.version_info < (3,11))' >/dev/null 2>&1; then
  echo "python_3_11_required" >&2
  exit 2
fi

"$PYTHON_BIN" -m py_compile \
  "$ROOT/sudetect/policy.py" "$ROOT/sudetect/evidence.py" \
  "$ROOT/sudetect/transport.py" "$ROOT/sudetect/probe.py"

"$PYTHON_BIN" - "$TMP/scope.json" <<'PY'
import json, sys
from datetime import datetime, timedelta, timezone
json.dump({
  "policy_id": "offline-smoke",
  "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
  "targets": [{"origin": "https://app.example", "owner": "team",
               "ownership_evidence": "record-id", "path_prefixes": ["/"]}],
  "exclude_urls": [], "max_bytes": 1024, "max_requests": 5,
  "timeout": 1, "max_redirects": 1
}, open(sys.argv[1], "w", encoding="utf-8"))
PY

set +e
OUTPUT="$(PYTHONPATH="$ROOT" "$PYTHON_BIN" -m sudetect.probe \
  --scope "$TMP/scope.json" 'https://user:pw@app.example/' 2>/dev/null)"
STATUS=$?
set -e
[ "$STATUS" -eq 0 ]
case "$OUTPUT" in
  *'credentials in URL rejected'*) ;;
  *) echo "credential URL was not rejected safely" >&2; exit 1 ;;
esac
case "$OUTPUT" in
  *'user:pw'*) echo "credential leaked into output" >&2; exit 1 ;;
esac

printf 'https://user:pw@app.example/\tfirst\r\n\r\n# comment\r\nhttps://app.example/?token=x\tsecond' > "$TMP/targets.tsv"
LINES="$(PYTHONPATH="$ROOT" "$PYTHON_BIN" -m sudetect.probe \
  --scope "$TMP/scope.json" --batch "$TMP/targets.tsv" | wc -l | tr -d ' ')"
[ "$LINES" = 2 ]
echo "PASS offline probe smoke checks"
