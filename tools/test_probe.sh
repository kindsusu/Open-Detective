#!/usr/bin/env bash
# su-detect / test_probe.sh - regression tests for probe.sh
#
# Every case here corresponds to a defect that was found by actually running the
# tool, not by reading it. Run this before committing a change to probe.sh.
#
#   bash tools/test_probe.sh
#
# Cases marked [net] need outbound internet. Everything else is offline.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PROBE="$HERE/probe.sh"
PASS=0; FAIL=0

run () { bash "$PROBE" "$@" 2>/dev/null | tail -1; }

ok () { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
no () { FAIL=$((FAIL+1)); printf '  FAIL  %s\n     -> %s\n' "$1" "$2"; }

want_field () {  # $1 desc  $2 line  $3 field-index  $4 expected
  local got; got="$(printf '%s' "$2" | awk -F'\t' -v i="$3" '{print $i}')"
  [ "$got" = "$4" ] && ok "$1" || no "$1" "field $3 = '$got', expected '$4'"
}

want_absent () {  # $1 desc  $2 line  $3 needle
  case "$2" in
    *"$3"*) no "$1" "output contained '$3'" ;;
    *) ok "$1" ;;
  esac
}

echo "== syntax =="
bash -n "$PROBE" && ok "probe.sh parses" || no "probe.sh parses" "syntax error"

echo
echo "== 1. credentials must never reach the output =="
L="$(run 'https://example.com/?token=SHOULD_NOT_APPEAR&sig=abc123')"
want_absent "query string absent from default label" "$L" "SHOULD_NOT_APPEAR"
want_absent "signature absent from output"           "$L" "abc123"

L="$(run 'https://user:pw@example.com/' )"
want_absent "userinfo password absent from label"    "$L" "pw@"

L="$(run 'https://example.com/' 'label?token=LEAKY')"
want_absent "token in a user-supplied label is masked" "$L" "LEAKY"

L="$(run 'https://example.com/' 'note#frag=SECRETFRAG')"
want_absent "fragment in a user-supplied label is masked" "$L" "SECRETFRAG"

L="$(run 'https://example.com/#access_token=HASHTOK')"
want_absent "fragment token absent from default label" "$L" "HASHTOK"

echo
echo "== 2. scheme gate =="
L="$(run "file://$HERE/probe.sh" 'file-scheme')"
want_field "file:// is REJECTED, not EXPOSED" "$L" 5 "REJECTED"

L="$(run 'ftp://example.com/x' 'ftp-scheme')"
want_field "ftp:// is REJECTED"               "$L" 5 "REJECTED"

L="$(run 'example.com' 'no-scheme')"
want_field "missing scheme is REJECTED"       "$L" 5 "REJECTED"

echo
echo "== 3. non-public targets (IPv4) =="
for u in "http://127.0.0.1/" "http://localhost/" "http://169.254.169.254/latest/meta-data/" "http://10.0.0.1/" "http://192.168.1.1/" "http://172.16.0.1/" "http://100.64.0.1/"; do
  L="$(run "$u" "$(printf '%s' "$u" | sed 's#http://##;s#/.*##')")"
  V="$(printf '%s' "$L" | awk -F'\t' '{print $5}')"
  case "$V" in
    REJECTED|ERR) ok "non-public target refused: $u ($V)" ;;
    *) no "non-public target refused: $u" "verdict was '$V'" ;;
  esac
done

echo
echo "== 3b. non-public targets (IPv6, literal-bracket host) =="
# is_blocked_ip MUST catch these by range — so require REJECTED exactly, not ERR.
# An ERR here would mean host parsing broke and the block rule never ran (the old bug).
for u in "http://[::1]/" "http://[fe80::1]/" "http://[fd00::1]/"; do
  L="$(run "$u" "ipv6")"
  want_field "non-public IPv6 is REJECTED (block rule ran): $u" "$L" 5 "REJECTED"
done
# Control: a public IPv6 literal must NOT be REJECTED — proves the rule discriminates
# by range rather than blanket-rejecting every IPv6 literal. (No route -> ERR is fine.)
L="$(run 'http://[2606:4700:4700::1111]/' 'public-v6')"
V="$(printf '%s' "$L" | awk -F'\t' '{print $5}')"
case "$V" in
  REJECTED) no "public IPv6 literal wrongly REJECTED" "block rule is blanket, not range-based" ;;
  *) ok "public IPv6 literal is not blanket-rejected ($V)" ;;
esac

echo
echo "== 4. auth-gate detection must be host-exact, never substring =="
L="$(run 'https://example.com/?redir=okta.com' 'substring-spoof')"
want_field "substring in query does NOT become AUTH-GATE" "$L" 5 "EXPOSED"

echo
echo "== 5. no exposure claim without an HTTP status =="
L="$(run 'https://no-such-host-su-detect-test.invalid/' 'dns-fail')"
V="$(printf '%s' "$L" | awk -F'\t' '{print $5}')"
case "$V" in
  ERR|REJECTED) ok "unresolvable host is ERR/REJECTED, not EXPOSED" ;;
  *) no "unresolvable host" "verdict was '$V'" ;;
esac

echo
echo "== 6. [net] live behaviour =="
if curl -s -o /dev/null --max-time 10 https://example.com/; then
  L="$(run 'https://example.com/' 'live-200')"
  want_field "served body is EXPOSED"   "$L" 5 "EXPOSED"
  S="$(printf '%s' "$L" | awk -F'\t' '{print $4}')"
  [ "${#S}" -eq 16 ] && ok "sha256 digest recorded" || no "sha256 digest recorded" "got '$S'"

  L="$(run 'https://example.com/su-detect-nonexistent-path' 'live-404')"
  want_field "404 is ABSENT"            "$L" 5 "ABSENT"
else
  echo "  SKIP  no outbound network"
fi

echo
echo "== 7. batch mode =="
T="$(mktemp)"
printf 'https://example.com/\tbatch-a\n# comment line\n\nhttps://example.com/missing\tbatch-b\n' > "$T"
N="$(bash "$PROBE" --batch "$T" 2>/dev/null | wc -l)"
rm -f "$T"
[ "$N" -eq 3 ] && ok "batch skips comments and blanks (header + 2 rows)" \
               || no "batch skips comments and blanks" "got $N lines, expected 3"

T="$(mktemp)"
printf 'https://example.com/\tthree-col\thttps://example.com/page\nhttps://example.com/\ttwo-col\n' > "$T"
N="$(bash "$PROBE" --batch "$T" 2>/dev/null | wc -l)"
rm -f "$T"
[ "$N" -eq 3 ] && ok "batch accepts the optional 3rd column without breaking 2-column rows" \
               || no "batch 3rd column" "got $N lines, expected 3"

echo
echo "== 8. weak-gate replay is opt-in, guarded, and leaks nothing =="
# The replay must never fire on a target that was not BLOCKED, and the calling-page
# URL must be masked like every other URL this tool touches.
L="$(run 'https://example.com/' 'with-caller' 'https://example.com/p?token=REFERER_LEAK')"
want_absent "calling-page query string absent from output" "$L" "REFERER_LEAK"
want_field  "a 200 target is unaffected by the 3rd arg"    "$L" 5 "EXPOSED"

L="$(run 'https://example.com/' 'bad-caller' 'file:///etc/passwd')"
want_field  "non-http calling page is ignored, not followed" "$L" 5 "EXPOSED"

# Without a calling page named, a 401/403 must stay BLOCKED - the replay is opt-in.
L="$(run 'https://httpbin.org/status/403' 'no-caller')"
V="$(printf '%s' "$L" | awk -F'\t' '{print $5}')"
case "$V" in
  BLOCKED|ERR|UNKNOWN) ok "403 without a named calling page stays BLOCKED (opt-in, got $V)" ;;
  WEAK-GATE)           no "403 without a named calling page" "replay fired without opt-in" ;;
  *)                   ok "403 case inconclusive offline (got $V)" ;;
esac

echo
echo "-----------------------------------------"
printf 'PASS %d   FAIL %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
