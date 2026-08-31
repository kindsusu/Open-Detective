#!/usr/bin/env bash
# su-detect / probe.sh - anonymous exposure measurement
#
# Usage: bash probe.sh <URL> [label]
#        bash probe.sh --batch <list-file>     (one "URL<TAB>label" per line)
#
# Rules (see ops/verify.md)
#   - Sends no auth tokens and no cookies (anonymous vantage point)
#   - The reproducibility invariant is sha256, not byte count
#   - Never prints credential-bearing headers (Set-Cookie and friends)
#   - Strips the final URI's query string (auth redirects carry a JWT in the URL)
#   - Truncates the temp file per request (prevents showing the previous response)
#   - Keeps the request count minimal (no mass scanning)

set -uo pipefail
UA="su-detect/1.0 (authorized asset exposure check)"
TIMEOUT="${SU_TIMEOUT:-25}"

probe_one () {
  local url="$1" label="${2:-$1}"
  local body hdr
  body="$(mktemp)"; hdr="$(mktemp)"        # fresh file per request - never reuse
  trap 'rm -f "$body" "$hdr"' RETURN

  local out code size final ctype
  out="$(curl -sL --max-time "$TIMEOUT" -A "$UA" \
          --cookie-jar /dev/null --cookie /dev/null \
          -D "$hdr" -o "$body" \
          -w '%{http_code}\t%{size_download}\t%{url_effective}\t%{content_type}' \
          "$url" 2>/dev/null)"
  local rc=$?

  if [ $rc -ne 0 ]; then
    printf '%s\tERR\t-\t-\t-\t-\t-\tcurl_exit=%d\n' "$label" "$rc"
    return
  fi
  IFS=$'\t' read -r code size final ctype <<< "$out"

  local sha="-"
  [ -s "$body" ] && sha="$(sha256sum "$body" | cut -c1-16)"

  # Never emit credential-bearing headers
  local etag lastmod
  etag="$(grep -i '^etag:' "$hdr" | tail -1 | tr -d '\r' | cut -d' ' -f2-)"
  lastmod="$(grep -i '^last-modified:' "$hdr" | tail -1 | tr -d '\r' | cut -d' ' -f2-)"

  # Verdict: is the final URI an authentication gate?
  local verdict="EXPOSED"
  case "$final" in
    *cloudflareaccess.com*|*login.microsoftonline.com*|*accounts.google.com*|*okta.com*|*auth0.com*)
      verdict="AUTH-GATE" ;;
  esac
  case "$code" in
    404|410) verdict="ABSENT" ;;
    401|403) verdict="BLOCKED" ;;
  esac
  # No body means it is not exposed
  [ "$verdict" = "EXPOSED" ] && [ "${size:-0}" -lt 1 ] && verdict="NO-BODY"

  # Strip the final URI's query string - auth redirects put a JWT in the URL
  local final_safe="${final%%[?]*}"
  if [ "$final_safe" != "$final" ]; then final_safe="${final_safe}?<query-omitted>"; fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$label" "$code" "${size:-0}" "$sha" "$verdict" "${etag:--}" "${lastmod:--}" "$final_safe"
}

header () {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "LABEL" "CODE" "BYTES" "SHA256(16)" "VERDICT" "ETAG" "LAST-MODIFIED" "FINAL-URI"
}

case "${1:-}" in
  --batch)
    [ -f "${2:-}" ] || { echo "a list file is required: $0 --batch <file>" >&2; exit 2; }
    header
    while IFS=$'\t' read -r u l; do
      [ -z "${u:-}" ] && continue
      case "$u" in \#*) continue ;; esac
      probe_one "$u" "${l:-$u}"
    done < "$2"
    ;;
  ""|-h|--help)
    sed -n '2,15p' "$0"; exit 0 ;;
  *)
    header; probe_one "$1" "${2:-}" ;;
esac

# Reading the verdicts (see ops/verify.md)
#   EXPOSED    the body was served in full to an anonymous request
#   AUTH-GATE  the final URI is an identity provider - body not served
#   BLOCKED    401/403
#   ABSENT     404/410
#   ERR        DNS failure, TLS mismatch, etc. Distinguish via the curl_exit code
#
# Always measure a control alongside the target. If the control also looks wrong,
# the measurement is wrong, not the result.
