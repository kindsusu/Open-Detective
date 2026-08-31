#!/usr/bin/env bash
# su-detect / probe.sh - anonymous exposure measurement
#
# Usage: bash probe.sh <URL> [label]
#        bash probe.sh --batch <list-file>     (one "URL<TAB>label" per line)
#
# Environment:
#   SU_TIMEOUT     per-request timeout in seconds        (default 25)
#   SU_MAX_BYTES   hard cap on response body bytes       (default 10485760)
#   SU_MAX_REDIRS  redirect limit                        (default 5)
#   SU_IDP_HOSTS   space-separated identity-provider hosts to treat as auth gates
#                  (default: the common hosted providers; add your own IdP here)
#
# Rules (see ops/verify.md)
#   - Sends no auth tokens and no cookies (anonymous vantage point)
#   - The reproducibility invariant is sha256, not byte count
#   - Never prints credential-bearing headers, and never prints a query string:
#     labels and final URIs are both masked, because either can carry a token
#   - http/https only; refuses loopback, private, link-local and reserved targets
#   - Never reports EXPOSED without a real HTTP status code
#   - When the verdict cannot be determined, returns UNKNOWN rather than guessing
#   - Bounded body buffer, removed on EXIT/INT/TERM
#   - Keeps the request count minimal (no mass scanning)

set -uo pipefail
UA="su-detect/1.1 (authorized asset exposure check)"
TIMEOUT="${SU_TIMEOUT:-25}"
MAX_BYTES="${SU_MAX_BYTES:-10485760}"
MAX_REDIRS="${SU_MAX_REDIRS:-5}"
IDP_HOSTS="${SU_IDP_HOSTS:-cloudflareaccess.com login.microsoftonline.com accounts.google.com okta.com auth0.com onelogin.com pingidentity.com duosecurity.com}"

# ---------------------------------------------------------------- helpers

# Strip fragment, query, and userinfo, then drop control characters.
# Used for BOTH the default label and the reported final URI.
mask_url () {
  local s="${1:-}"
  s="${s%%#*}"
  local had_query=""
  case "$s" in *\?*) had_query=1 ;; esac
  s="${s%%\?*}"
  s="$(printf '%s' "$s" | sed -E 's#^([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@]*@#\1#')"
  s="$(printf '%s' "$s" | tr -d '\000-\037\177' | tr '\t' ' ')"
  [ -n "$had_query" ] && s="${s}?<query-omitted>"
  printf '%s' "$s"
}

# A user-supplied label must never smuggle a token or break the TSV.
# Anything from the first '?' or '#' onward is dropped, URL or not: a label is a
# short identifier, and a query string in one is far more likely to be a leaked
# token than deliberate prose.
clean_label () {
  local s="${1:-}"
  case "$s" in
    *://*) s="$(mask_url "$s")" ;;
    *\?*|*\#*) s="${s%%[?#]*}?<query-omitted>" ;;
  esac
  printf '%s' "$s" | tr -d '\000-\037\177' | tr '\t' ' '
}

scheme_of () { printf '%s' "${1:-}" | sed -nE 's#^([a-zA-Z][a-zA-Z0-9+.-]*)://.*#\1#p' | tr 'A-Z' 'a-z'; }

host_of () {
  printf '%s' "${1:-}" \
    | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#^[^/@]*@##; s#[/?#].*$##; s#^\[([^]]*)\]:?[0-9]*$#\1#; s#:[0-9]+$##' \
    | tr 'A-Z' 'a-z'
}

# Registrable-ish domain: last two labels, or three when the second-to-last is a
# known second-level suffix. Crude but adequate for same-site comparison.
site_of () {
  local h="${1:-}" n2 n3
  case "$h" in *[a-z]*) ;; *) printf '%s' "$h"; return ;; esac   # bare IP
  n2="$(printf '%s' "$h" | awk -F. '{if (NF>=2) print $(NF-1)}')"
  case "$n2" in
    co|or|ne|go|re|pe|ac|com|net|org|gov|edu)
      n3="$(printf '%s' "$h" | awk -F. '{if (NF>=3) print $(NF-2)"."$(NF-1)"."$NF; else print $0}')"
      printf '%s' "$n3" ;;
    *)
      printf '%s' "$h" | awk -F. '{if (NF>=2) print $(NF-1)"."$NF; else print $0}' ;;
  esac
}

resolve_ip () {
  python -c "
import socket,sys
try: print(socket.gethostbyname(sys.argv[1]))
except Exception: print('')
" "${1:-}" 2>/dev/null
}

is_blocked_ip () {
  local ip="${1:-}"
  [ -z "$ip" ] && return 1
  case "$ip" in
    0.*|10.*|127.*|169.254.*|192.168.*|192.0.0.*|192.0.2.*|198.18.*|198.19.*|198.51.100.*|203.0.113.*|22[4-9].*|23[0-9].*|24[0-9].*|25[0-5].*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*) return 0 ;;
    ::1|fe80:*|fc00:*|fd*) return 0 ;;
  esac
  return 1
}

is_idp_host () {
  local h="${1:-}" p
  for p in $IDP_HOSTS; do
    [ "$h" = "$p" ] && return 0
    case "$h" in *".$p") return 0 ;; esac
  done
  return 1
}

emit () {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"
}

# ---------------------------------------------------------------- probe

probe_one () {
  local raw_url="${1:-}" raw_label="${2:-}"
  local label
  if [ -n "$raw_label" ]; then label="$(clean_label "$raw_label")"
  else label="$(mask_url "$raw_url")"; fi

  # 1. scheme gate - this tool measures public web exposure only
  local scheme; scheme="$(scheme_of "$raw_url")"
  case "$scheme" in
    http|https) ;;
    "") emit "$label" "-" "-" "-" "REJECTED" "-" "-" "no-scheme"; return ;;
    *)  emit "$label" "-" "-" "-" "REJECTED" "-" "-" "scheme=$scheme"; return ;;
  esac

  # 2. target gate - refuse loopback / private / link-local / reserved
  local host0 ip0; host0="$(host_of "$raw_url")"; ip0="$(resolve_ip "$host0")"
  if [ -z "$ip0" ]; then
    emit "$label" "-" "-" "-" "ERR" "-" "-" "dns-failed"; return
  fi
  if is_blocked_ip "$ip0"; then
    emit "$label" "-" "-" "-" "REJECTED" "-" "-" "non-public-address"; return
  fi

  local body hdr
  body="$(mktemp)"; hdr="$(mktemp)"
  trap 'rm -f "$body" "$hdr"' EXIT INT TERM

  local out code size final rc
  out="$(curl -sL --max-time "$TIMEOUT" -A "$UA" \
          --proto '=http,https' --proto-redir '=http,https' \
          --max-redirs "$MAX_REDIRS" --max-filesize "$MAX_BYTES" \
          --cookie-jar /dev/null --cookie /dev/null \
          -D "$hdr" -o "$body" \
          -w '%{http_code}\t%{size_download}\t%{url_effective}' \
          "$raw_url" 2>/dev/null)"
  rc=$?

  if [ $rc -ne 0 ]; then
    rm -f "$body" "$hdr"; trap - EXIT INT TERM
    emit "$label" "-" "-" "-" "ERR" "-" "-" "curl_exit=$rc"; return
  fi
  IFS=$'\t' read -r code size final <<< "$out"

  # 3. a real HTTP status is required before any exposure claim
  case "$code" in
    [1-5][0-9][0-9]) ;;
    *) rm -f "$body" "$hdr"; trap - EXIT INT TERM
       emit "$label" "${code:--}" "${size:-0}" "-" "UNKNOWN" "-" "-" "no-http-status"; return ;;
  esac

  local sha="-"
  [ -s "$body" ] && sha="$(sha256sum "$body" | cut -c1-16)"

  # Never emit credential-bearing headers
  local etag lastmod
  etag="$(grep -i '^etag:' "$hdr" | tail -1 | tr -d '\r' | cut -d' ' -f2-)"
  lastmod="$(grep -i '^last-modified:' "$hdr" | tail -1 | tr -d '\r' | cut -d' ' -f2-)"

  rm -f "$body" "$hdr"; trap - EXIT INT TERM

  # 4. where did we land? Host comparison is exact - never substring.
  local hostF ipF verdict note
  hostF="$(host_of "$final")"; note="-"
  ipF="$(resolve_ip "$hostF")"
  if [ -n "$ipF" ] && is_blocked_ip "$ipF"; then
    emit "$label" "$code" "${size:-0}" "$sha" "REJECTED" "${etag:--}" "${lastmod:--}" "redirected-to-non-public"
    return
  fi

  if is_idp_host "$hostF"; then
    verdict="AUTH-GATE"
  elif [ "$(site_of "$hostF")" != "$(site_of "$host0")" ]; then
    # Landed off-site on something we cannot classify. Do not guess EXPOSED.
    verdict="UNKNOWN"; note="off-site-redirect"
  else
    case "$code" in
      404|410)   verdict="ABSENT" ;;
      401|403)   verdict="BLOCKED" ;;
      2??)       if [ "${size:-0}" -lt 1 ]; then verdict="NO-BODY"; else verdict="EXPOSED"; fi ;;
      3??)       verdict="UNKNOWN"; note="unresolved-redirect" ;;
      *)         verdict="UNKNOWN"; note="http-$code" ;;
    esac
  fi

  emit "$label" "$code" "${size:-0}" "$sha" "$verdict" "${etag:--}" "${lastmod:--}" "$(mask_url "$final")"
  [ "$note" != "-" ] && return 0
  return 0
}

header () {
  emit "LABEL" "CODE" "BYTES" "SHA256(16)" "VERDICT" "ETAG" "LAST-MODIFIED" "FINAL-URI"
}

case "${1:-}" in
  --batch)
    [ -f "${2:-}" ] || { echo "a list file is required: $0 --batch <file>" >&2; exit 2; }
    header
    while IFS=$'\t' read -r u l; do
      [ -z "${u:-}" ] && continue
      case "$u" in \#*) continue ;; esac
      probe_one "$u" "${l:-}"
    done < "$2"
    ;;
  ""|-h|--help)
    sed -n '2,25p' "$0"; exit 0 ;;
  *)
    header; probe_one "$1" "${2:-}" ;;
esac

# Reading the verdicts (see ops/verify.md)
#   EXPOSED    the body was served in full to an anonymous request
#   AUTH-GATE  the final host is a configured identity provider - body not served
#   BLOCKED    401/403
#   ABSENT     404/410
#   NO-BODY    2xx with an empty body
#   UNKNOWN    could not be classified (off-site redirect, unresolved 3xx, no HTTP status).
#              Deliberately not EXPOSED - an unproven exposure is not an exposure.
#   REJECTED   out of scope by design: non-http(s) scheme, or a non-public address
#   ERR        DNS failure, TLS mismatch, transfer error. See the curl_exit code
#
# Always measure a control alongside the target. If the control also looks wrong,
# the measurement is wrong, not the result.
#
# Known limit: curl validates the scheme of every redirect hop, but this script can
# only resolve the FIRST and FINAL hosts. A redirect chain that transits a private
# address in between is not detected. Lower SU_MAX_REDIRS if that matters to you.
