# su-detect 한국어 번역

이 파일은 루트 `SKILL.md`의 번역이며 설치용 frontmatter가 없다. 설치되는 스킬 항목은 하나다.

**범위 → 인벤토리/발견 → 소유 확인 → 익명 관측 → 내용 분류 → 격리 → 재측정** 순서로 실행한다. 새 관측 없이 종결을 주장하지 않는다.

## 필수 정책

`ko/ops/scope.md`를 읽는다. 측정 명령에는 정확한 HTTPS origin, 소유자, 소유 증거, 경로 접두사, 만료 시각이 있는 `--scope` 파일이 필요하다. 모든 `SUD-Rxx` 규칙을 적용한다. 회사 고유값은 로컬 입력에만 둔다.

소유자 인벤토리는 명시적으로 승인된 읽기 자격증명을 사용할 수 있다. 이 자격증명, 프로세스, 브라우저 프로필, 출력은 익명 표적 측정과 분리한다. 발견 결과는 소유 증거가 조직과 연결할 때까지 후보다.

```bash
python -m sudetect probe --scope scope.json <url>
python -m sudetect browser <url> --scope scope.json --duration 3
python -m sudetect inventory --provider import --scope-id TEAM --input inventory.json
python -m sudetect discover --input candidates.json --scope-id TEAM
python -m sudetect search-plan plan --output _local/plan.json --scope-id TEAM --company-en "<수행자 입력>"
python -m sudetect doctor --reference .
python -m sudetect channels-doctor --config _local/channels.json --scope _local/control-scope.json --output _local/channel-health.json
python -m sudetect github-discover --scope-id TEAM --account approved-account --channel-health _local/channel-health.json
python -m sudetect search-plan run --plan _local/plan.json --locator-store _local/locators.sqlite --channel-health _local/channel-health.json
python -m sudetect search-plan run-until-budget --plan _local/plan.json --locator-store _local/locators.sqlite --request-budget 60 --channel-health _local/channel-health.json
python -m sudetect locators --store _local/locators.sqlite bind --scope-id TEAM --locator-ref "opaque:<id>" --scope _local/scope.json --db audit.sqlite --asset-id asset-1 --provider import
python -m sudetect ledger --db audit.sqlite due
```

`tools/probe.sh`는 Python probe만 감싼다. 예전 분류를 다시 만들거나 호출 페이지 헤더를 자동 재전송하지 않는다.

## 필수 발견 계획

최초 공개 탐색 전에는 국문·영문 이름, 별칭, 업종·업무 용어, 알려진 URL로 `search-plan`을 생성한다. 제한된 작업을 실행하고 남은 작업은 deferred로 보존한다. 몇 개의 수기 검색으로 대체하거나 생성한 후보를 실제 검색한 것처럼 보고하지 않는다.

## 판정 계약

```text
access: BODY_SERVED | ACCESS_DENIED_OBSERVED | AUTH_REDIRECT_OBSERVED |
        NOT_FOUND_OBSERVED | INDETERMINATE
content: PUBLIC_UI | SENSITIVE_CONTENT_CONFIRMED | SENSITIVE_CANDIDATE |
         CLIENT_ENCRYPTED_OBSERVED | NOT_INSPECTED
confidence: confirmed | probable | unknown
```

상태는 요청 하나의 관측이다. `BODY_SERVED`는 민감한 내용이라는 뜻이 아니다. `SENSITIVE_CONTENT_CONFIRMED`에는 연결된 관측, 실제 최소 증거, 소유 증거, 익명 조건이 필요하다. password input은 `LOGIN_FORM_INDICATOR`일 뿐 `PUBLIC_UI`, 보호, 민감으로 자동 판정하지 않는다. 거부된 API는 `ACCESS_DENIED_OBSERVED`다. IdP 리다이렉트는 그 경로의 `AUTH_REDIRECT_OBSERVED`만 뒷받침한다.

부분 캡처에는 `capture_complete=false`, 검사 바이트 수, 중단 이유를 적는다. 전체 digest와 prefix digest를 구분한다. 지원하지 않는 브라우저 transport나 관측하지 못한 Service Worker/WebSocket은 `INDETERMINATE`이며 전체 egress 통제를 주장하지 않는다.

## intake와 단계 게이트

발견 전에 `examples/audit-intake.example.json`, `schemas/audit-intake.schema.json`으로 로컬 `audit-intake`를 기록한다. 제외와 증거, 국문/영문 식별자·alias·업종·기능·known URL·domain, 관계사 경계, 제3자 선언, owner/escalation 참조, 추가 승인 행위를 담는다. 실행 scope나 네트워크 grant가 아니다. `third_parties.status="unknown"`은 공백이며 추측으로 소유를 만들지 않는다.

순서는 (1) 경계·제외·소유 참조·에스컬레이션 intake, (2) 오프라인 identifier와 search plan, (3) 명령이 실제로 불러온 runtime root를 보고 검수한 `.` source tree와 비교하는 `doctor --reference .`, (4) scope 승인 fresh positive control을 `channels-doctor`로 실행한 뒤 공개 GitHub 발견이다. 계약·자산·처리자/수탁자 대장의 관리자 export를 받은 다음 실행 scope를 승인하고 candidate를 import한다. owner-inventory credential은 별도 권한 경로로 유지한다.

`channels-doctor`는 config와 scope가 유효한 실행에서 report를 저장하고 바뀐 channel 행만 stdout에 출력한다. HTTP 200, complete capture, 설정한 `json_pointer` 또는 `body_contains` 기대값 일치가 모두 있어야 `OK`다. 일반 body marker보다 구체적인 JSON-pointer 식별 검증을 우선한다. 도달했지만 실패하면 `DEGRADED`, 도달 불가 또는 HTTP 404/410이면 `DEAD`다. 이 report는 형식과 freshness를 검사하는 로컬 운영 근거이며 전자서명·원격 attestation·로컬 파일 변경 가능 수행자에 대한 보안 경계가 아니다. 실제 GitHub 작업은 channel별 fresh control을 요구한다. repository 목록은 `github-repositories`, 검색 seed는 repository 목록 확장이 가능하므로 `github-repositories`, `github-user-search`, `github-repository-search`가 모두 필요하다. import 결과는 `observed_at`에 유효한 health가 필요하고 이후 만료가 과거 결과를 지우지 않는다. synthetic input은 실제 control 증명이 아니며 control 성공도 회사 전체 발견 완료가 아니다.

GitHub control ID는 `api.github.com`에 맞춘다. 차례로 repository detail 또는 `/users|orgs/<owner>/repos`, `/search/users`, `/search/repositories?q=…`를 쓴다. 다른 endpoint marker로 대신할 수 없고 detail control은 pagination·permission을 보장하지 않는다.

## 인벤토리, 발견, 브라우저

구현된 소유자 인벤토리는 Vercel project/deployment/alias/domain과 GitHub organization 또는 승인 account의 repository 및 선택적 recursive tree completeness를 수집한다. 페이지 끝까지 처리하고 cursor 종료, 권한, truncation, rate limit, 시간 범위를 기록한다. collector가 반환하지 않는 Pages/deployment URL은 provenance가 있는 normalized import 또는 passive discovery로 넣는다. 비공개 repository도 공개 deployment를 남길 수 있다. 단일 채널의 0건은 제한된 비관측이며 실패했다면 더욱 그렇다.

`tools/idgen.py`는 오프라인 후보 생성에만 쓴다. 플랫폼 validator가 유효하지 않은 이름을 거른다. 이름 유사성은 소유 증거도 프로빙 승인도 아니다.

정적 관측으로 내용 도착 여부를 답할 수 없을 때만 `brokered_anonymous_browser`를 쓴다. 새 Playwright context는 raw browser header, cookie, auth, referrer 없이 승인된 GET document/script/stylesheet/XHR/fetch를 정책 제한 transport broker로 보낸다. Service Worker를 끄고 WebSocket server 연결을 막으며 message는 local sink에서 버린다. DOM 검토에서 candidate가 없을 때 제한된 live `input`, `textarea`, `select` 값도 검사한다. canvas pixel, snapshot 밖 shadow DOM, JavaScript heap, interaction 이후 상태, 외부 protocol과 미지원 동작은 측정하지 않는다. OS firewall이나 전체 egress 보장은 아니다. 자격증명 입력, DOM gate 제거, challenge 해결, ID 열거, 저장 세션 사용을 하지 않는다. 테스트는 합성 fixture만 사용한다.

## 증거, 조치, 대장

최소 증거에서 중단한다. runtime classifier는 `SENSITIVE_CANDIDATE`, `NOT_INSPECTED`의 잠정 결과를 내며 `PUBLIC_UI`에는 별도 게시 의도 검토가 필요하다. 응답에서 후보를 찾으면 렌더링 전에 멈추고, 런타임 상태에서 찾으면 추가 관찰을 멈춘다. 실제 `SENSITIVE_CONTENT_CONFIRMED`는 사람의 evidence review가 대장에 기록한다. `SYNTHETIC_CONTENT_CONFIRMED`는 test canary 전용이다. 개인정보나 사용 가능한 비밀이 보이면 내용 수집을 멈추고 에스컬레이션한다. 발견한 비밀을 시험하지 않는다. 승인된 소유자 측 확인의 별도 증거가 없으면 실제 유효성은 unknown이다. `0`과 `false`는 실제 값으로 보존한다. 집계도 privacy control과 provenance가 필요하다.

원 locator와 민감 산출물은 접근통제된 소유자 시스템에 둔다. 공유 출력에는 마스킹 위치, 유형, 대략 건수, 적절한 hash/HMAC 참조, evidence ID만 둔다. query, fragment, userinfo, path, header, redirect, log, screenshot, trace를 정화한다.

현재 노출에는 피해를 기준으로 긴급 격리, 비밀 회전, 로그 보존을 판단하면서 서비스 연속성을 계획한다. SSO 뒤에서도 애플리케이션 권한 검사를 유지한다. 원 URL, 알려진 모든 deployment와 alias, cache, 승인된 archive 채널을 재확인한다.

workflow 상태는 `candidate`, `ownership_pending`, `verification_pending`, `open`, `containment_pending`, `recheck_pending`, `partially_closed`, `closed`, `reopened`다. SQLite가 운영 기준이며 Markdown은 내보내기다. asset과 alias를 opaque locator `target_id`, `policy_id`에 바인딩하며 ledger는 불일치를 거부한다. append-only observation/event, alias, control, proof reference, recheck, due date를 기록한다. 종결 뒤 현재 `BODY_SERVED`, unknown/incomplete 결과, 같은 시각 충돌은 finding을 재개하거나 재검토 상태로 돌린다. 의미 있는 변화, 종결, 실패, 사용자 조치 필요만 알린다.

`search-plan`은 수행자 alias와 생성된 변형을 구분하고 미실행 작업은 `deferred`로 둔다. 모든 필수 channel이 완료되거나 사유와 함께 `not_applicable`이 될 때까지 상태는 `PARTIAL`이다. 정확한 후보 URL은 로컬 locator store에 두고 공유 출력에는 `locator_ref`와 handoff state만 남긴다. ref도 `probe`나 `browser` 전 scope 허가가 필요하다. `doctor`는 runtime/source parity만 확인하며 저장소 수정·push는 이미 설치된 runtime을 갱신하지 않는다.

observation 기반 사실, 대조군, 소유자와 심각도, unknown과 해소 조건, 격리와 기한, 재측정 증거, 하지 않은 행위를 보고한다. 커버리지는 정확한 scope, channel, 완료 page로 표현한다. 합성 테스트를 배포나 실제 자산 검증으로 표현하지 않는다.

지원 파일: `ko/ops/discovery.md`, `ko/ops/verify.md`, `ko/ops/triage.md`, `ko/ops/evidence.md`, `ko/ops/remediate.md`, `ko/surfaces/inventory.md`, `ko/assets/ledger-template.md`.

익명 `github-discover`는 공개 사용자·저장소 검색과 알려진 계정/Pages 링크 확장을 지원한다. 관례상 Pages URL 후보와 실제 배포 실측을 분리한다. 전체 회사 자산의 발견 완료를 뜻하지 않는다.
