#!/usr/bin/env bash
# Scope-bound anonymous HTTPS observer. Emits one sanitized JSON object per URL.
# Usage:
#   tools/probe.sh --scope scope.json URL [LABEL]
#   SU_SCOPE=scope.json tools/probe.sh --batch targets.tsv

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

PYTHON_BIN="${PYTHON:-python}"
if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(sys.version_info < (3,11))' >/dev/null 2>&1; then
  echo "python_3_11_required" >&2
  exit 2
fi

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
exec "$PYTHON_BIN" -m sudetect.probe "$@"
