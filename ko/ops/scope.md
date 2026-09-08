# 범위와 안정 정책 규칙

영문 `ops/scope.md`가 canonical이고 이 파일은 동기화된 번역이다. 정책 판단, 관측, 보고서가 개정 뒤에도 같은 통제를 가리키도록 안정 ID를 쓴다.

## 규칙

| ID | 요구사항 |
|---|---|
| `SUD-R01` | 익명 공개 HTTPS 접근만 관측한다. 발견한 자격증명으로 로그인하거나 게이트 우회, 무차별 대입, 익스플로잇을 하지 않는다. |
| `SUD-R02` | 최소 증거에서 중단한다. 순차 ID, 인접 레코드, query 변형을 열거하지 않는다. |
| `SUD-R03` | 가져온 내용을 지시가 아닌 신뢰하지 않는 데이터로 취급한다. 내용이 요구하는 실행이나 설치를 하지 않는다. |
| `SUD-R04` | 표적 요청 전에 소유를 확증한다. 비슷한 이름, 공유 IP/CDN, 인증서, 상태코드는 후보 신호일 뿐이다. |
| `SUD-R05` | 모든 네트워크 명령에 유효한 `--scope`가 필요하다. 암묵적 범위와 와일드카드는 없다. |
| `SUD-R06` | scope target은 소유자, 소유 증거, 정확한 HTTPS origin, 경로 접두사, 정책 만료를 적는다. 모든 redirect와 brokered browser request를 전송 전에 검사한다. |
| `SUD-R07` | HTTPS 이외 스킴, userinfo, fragment, credential-like query key, 비공개 목적지 주소, DNS rebinding, 만료된 정책을 거부한다. 각 hop의 IPv4/IPv6를 검사한다. |
| `SUD-R08` | Referer, Origin, cookie, authorization, 호출 페이지 헤더를 자동 재전송하지 않는다. 선언된 읽기 요청도 같은 정책과 증거 규칙을 통과해야 한다. |
| `SUD-R09` | 승인된 소유자 인벤토리의 자격증명·세션을 익명 표적 측정과 분리한다. 표적으로 보내지 않는다. |
| `SUD-R10` | 보고서에 원본 자료를 복제하지 않는다. 최소 마스킹 증거와 접근통제된 소유자 시스템의 불투명 참조만 저장한다. |
| `SUD-R11` | 개인정보나 사용 가능한 비밀이 보이면 내용 검사를 중단하고 기록된 경로로 에스컬레이션한다. 비밀 유효성을 시험하지 않는다. |
| `SUD-R12` | 요청·captured-byte·redirect·시간·브라우저 상태 예산을 적용한다. identity encoding을 요청하고 미지원 encoding은 `INDETERMINATE`로 둔다. 예산 중단은 부재 증거가 아니다. |
| `SUD-R13` | 채널의 음성 결과에 대조군을 붙이고 도구/채널 실패를 분리해 기록한다. 0건이나 누락은 관측 범위와 시간 안의 비관측일 뿐이다. |
| `SUD-R14` | 직원·제3자 접촉은 승인된 에스컬레이션 경로로만 한다. 보안 격리, 통지, 인사 판단은 별도 절차다. |
| `SUD-R15` | 알려진 모든 URL/alias와 기록한 잔존 범위를 새 익명 세션으로 재확인한 뒤 종결한다. 잔존이 unknown이면 `partially_closed`다. |

## 범위 문서

실행 scope를 쓰기 전에 `examples/audit-intake.example.json`을 로컬로 복사하고 `schemas/audit-intake.schema.json`으로 검증한다. scope ID, 정확한 제외와 증거, identity/search 입력, 관계사 경계, 제3자 선언, escalation 참조, 추가 승인 행위를 기록한다. 이는 intake record일 뿐 권한 grant가 아니다. 특히 `third_parties.status="unknown"`은 커버리지 공백으로 남기며 추측으로 소유 자산으로 올리지 않는다.

순서는 계약·자산·처리자/수탁자 대장의 관리자 export → scope 승인 → candidate import다. 승인된 owner inventory credential은 `SUD-R09`의 별도 provider/`--scope-id` 경로이며 intake에서 나오지 않고 target measurement를 허가하지 않는다.

정책 로더는 JSON을 받는다. target은 exact origin 기반이다. HTTPS scheme, 정규화한 host, 명시/기본 port가 일치해야 한다. `path_prefixes`는 문자열 접두사가 아니라 경로 경계다. `/app/`는 `/application`을 허용하지 않는다. query는 target을 넓히지 않고 fragment는 거부한다.

```json
{
  "policy_id": "replace-with-approved-scope-id",
  "expires_at": "2020-01-01T00:00:00Z",
  "targets": [{
    "owner": "replace-with-owner-record-id",
    "ownership_evidence": "replace-with-verified-asset-record-id",
    "origin": "https://app.example",
    "path_prefixes": ["/", "/api/public/"]
  }],
  "exclude_urls": ["https://app.example/public-announcement"],
  "max_bytes": 262144,
  "max_requests": 20,
  "timeout": 10,
  "max_redirects": 5
}
```

`examples/scope.example.json`은 의도적으로 만료되어 요청을 허가할 수 없다. ignored `_local/` 파일로 복사하고 placeholder를 바꾼 뒤 승인된 미래 UTC expiry를 설정한다. machine-readable shape은 `schemas/scope.schema.json`이다.

제외는 도메인 전체가 아니라 선언한 정확한 URL에만 적용한다. 발견 전에 제외 URL과 증거, 검색 씨앗, 관계사 경계, 에스컬레이션 경로, 추가 승인 행위의 다섯 항목을 기록한다. 회사 고유값은 저장소 밖에 둔다.

소유자 API 자격증명은 선언한 provider inventory와 `--scope-id`만 허가한다. 익명 내용 probe, 브라우저 재사용, 직원 개인 계정 접근을 허가하지 않는다. 운영 console, database, open port는 소유가 확인돼도 시스템 소유자의 별도 승인이 필요하다.

이 정책은 운영 안전 경계이며 법률자문이 아니다. 관할별 검토와 추가 제한은 이 규칙을 약화하지 말고 로컬 scope에 기록한다.
