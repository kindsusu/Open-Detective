#!/usr/bin/env bash
# su-detect / probe.sh — 익명 시점 노출 실측
#
# 사용: bash probe.sh <URL> [라벨]
#       bash probe.sh --batch <목록파일>     (한 줄에 "URL<TAB>라벨")
#
# 원칙 (ops/verify.md)
#   - 인증 토큰·쿠키를 보내지 않는다 (익명 시점)
#   - 재현성 불변량은 크기가 아니라 sha256
#   - Set-Cookie 등 자격증명 계열 헤더를 출력하지 않는다
#   - 최종 URI의 쿼리스트링을 잘라낸다 (인증 리다이렉트가 JWT를 URL에 싣는다)
#   - 매 요청 임시파일을 초기화한다 (직전 응답 재출력 방지)
#   - 요청 수를 최소로 유지한다 (대량 스캔 금지)

set -uo pipefail
UA="su-detect/1.0 (authorized asset exposure check)"
TIMEOUT="${SU_TIMEOUT:-25}"

probe_one () {
  local url="$1" label="${2:-$1}"
  local body hdr
  body="$(mktemp)"; hdr="$(mktemp)"        # 매 요청 새 파일 — 재사용 금지
  trap 'rm -f "$body" "$hdr"' RETURN

  local out code size final ctype
  out="$(curl -sL --max-time "$TIMEOUT" -A "$UA" \
          --cookie-jar /dev/null --cookie /dev/null \
          -D "$hdr" -o "$body" \
          -w '%{http_code}\t%{size_download}\t%{url_effective}\t%{content_type}' \
          "$url" 2>/dev/null)"
  local rc=$?

  if [ $rc -ne 0 ]; then
    printf '%s\tERR\t-\t-\t-\tcurl_exit=%d\n' "$label" "$rc"
    return
  fi
  IFS=$'\t' read -r code size final ctype <<< "$out"

  local sha="-"
  [ -s "$body" ] && sha="$(sha256sum "$body" | cut -c1-16)"

  # 자격증명 계열 헤더는 절대 출력하지 않는다
  local etag lastmod server
  etag="$(grep -i '^etag:' "$hdr" | tail -1 | tr -d '\r' | cut -d' ' -f2-)"
  lastmod="$(grep -i '^last-modified:' "$hdr" | tail -1 | tr -d '\r' | cut -d' ' -f2-)"
  server="$(grep -i '^server:' "$hdr" | tail -1 | tr -d '\r' | cut -d' ' -f2-)"

  # 판정: 최종 URI가 인증 게이트인가
  local verdict="노출"
  case "$final" in
    *cloudflareaccess.com*|*login.microsoftonline.com*|*accounts.google.com*|*okta.com*|*auth0.com*)
      verdict="인증게이트" ;;
  esac
  case "$code" in
    404|410) verdict="없음" ;;
    401|403) verdict="차단" ;;
  esac
  # 본문이 안 왔으면 노출이 아니다
  [ "$verdict" = "노출" ] && [ "${size:-0}" -lt 1 ] && verdict="본문없음"

  # 최종 URI의 쿼리스트링은 잘라낸다 - 인증 리다이렉트가 URL에 JWT를 싣는다
  local final_safe="${final%%[?]*}"
  if [ "$final_safe" != "$final" ]; then final_safe="${final_safe}?<쿼리생략>"; fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$label" "$code" "${size:-0}" "$sha" "$verdict" "${etag:--}" "${lastmod:--}" "$final_safe"
}

header () {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "라벨" "코드" "바이트" "sha256(16)" "판정" "ETag" "Last-Modified" "최종URI"
}

case "${1:-}" in
  --batch)
    [ -f "${2:-}" ] || { echo "목록 파일이 필요합니다: $0 --batch <파일>" >&2; exit 2; }
    header
    while IFS=$'\t' read -r u l; do
      [ -z "${u:-}" ] && continue
      case "$u" in \#*) continue ;; esac
      probe_one "$u" "${l:-$u}"
    done < "$2"
    ;;
  ""|-h|--help)
    sed -n '2,14p' "$0"; exit 0 ;;
  *)
    header; probe_one "$1" "${2:-}" ;;
esac

# 판정 읽는 법 (ops/verify.md)
#   노출       본문이 익명에게 그대로 전달됨
#   인증게이트  최종 URI가 인증 제공자 — 본문 미전달
#   차단       401/403
#   없음       404/410
#   ERR        DNS 실패·TLS 불일치 등. curl_exit 코드로 구분
#
# 반드시 대조군을 함께 돌린다. 대조군까지 이상하면 결과가 아니라 측정이 잘못된 것이다.
