#!/usr/bin/env bash
# Scope-bound anonymous positive-control health check.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PYTHON_BIN="${PYTHON:-python}"
if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(sys.version_info < (3,11))' >/dev/null 2>&1; then
  echo "python_3_11_required" >&2
  exit 2
fi
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
exec "$PYTHON_BIN" -m sudetect.channel_health "$@"
