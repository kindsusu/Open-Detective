# Open-Detective 탐지 실행기 구현 결과

작성일: 2026-10-06. 기준 커밋: `8204d0fa9e2563d003d8f0b32580d4202882d345`.
이 문서는 해당 기준의 로컬 변경을 설명한다. 원격 push·릴리스·설치된 스킬 교체는 수행하지 않았다.
회사 실서비스 재탐색과 코드 검증은 별개이며 이번 검증에는 합성 자료를 사용했다.

## 구현 결과

| 영역 | 적용한 변경 | 관련 파일 |
|---|---|---|
| 공통 실행 | Codex·Claude가 동일 case와 CLI, 절차를 사용한다. 에이전트 이름은 판정 규칙을 바꾸지 않는다. | `AGENTS.md`, `CLAUDE.md`, `ops/audit-workflow.md`, 한국어 번역 |
| 지속 작업 | 작업 큐, 요청·바이트·분석·시간 예산, lease, 재시도 시각, 중단 후 재개, foreground worker를 추가했다. | `sudetect/audit.py`, `sudetect/scheduler.py` |
| 처음부터 발견 | 사용자 역할어에 기본 역할어를 합치고 후보 출처를 유지한다. 잔여 예산에 맞는 후속 작업을 계속 선택한다. | `idgen.py`, `identifiers.py`, `search_plan.py` |
| 채널 제한 | GitHub search/core 제한을 분리하고 Retry-After를 지킨다. 한 채널 실패가 독립 콘텐츠 작업을 종료하지 않는다. | `github_discovery.py`, `search_plan.py`, `audit.py` |
| 저장소·배포 | 관측된 브랜치/커밋으로 tree를 읽고 페이지에 연결되지 않은 문서도 후보로 만든다. Pages·homepage·CDN 후보는 정확한 URL을 private locator에 저장한다. | `repository_assets.py`, `github_discovery.py`, `asset_graph.py` |
| 외부 채널 연결 | `audit import`로 채널 결과의 검색어·scope ID·health 근거·개수·locator를 대조한다. 중복 import와 과거 관측 덮어쓰기를 방지한다. | `audit.py`, `discovery_channels.py` |
| 콘텐츠 | 차량번호·사업자번호, 기밀 표시의 위치/부정 문맥, 수수료 표 구조, 실제 필드/빈 템플릿을 구분한다. CSS margin·패키지 버전 오탐을 줄였다. | `classifiers.py`, `asset_profile.py` |
| 큰 자료·PDF | 허용된 분석 바이트까지 읽고 청크 경계 신호를 보존한다. PDF 파서를 별도 프로세스에 격리하고 제한 시간을 넘기면 종료한다. | `classifiers.py`, `documents.py` |
| 화면 잠금 | 공개 응답에 이미 포함된 자료, 정적 비밀 후보, 서버 요청, 템플릿, 암호문을 독립 기록한다. 승인된 제한 패턴만 격리 Chromium에서 검토한다. | `gate_review.py`, `schemas/gate-capability.schema.json` |
| 동적 자료 | 익명 브라우저에서 구성되는 관측 URL을 큐에 연결한다. 같은 실행 구간의 완료 응답은 메모리에서 재사용한다. | `audit.py`, `browser.py` |
| 증거·실패 | DNS/TLS/timeout/reset 등을 안전한 코드로 기록한다. 원문 예외·비밀 값을 공유 출력으로 내보내지 않는다. | `transport.py`, `evidence_redaction.py` |
| 보고·평가 | 동일 Ledger의 append-only 결과와 이벤트에서 보고한다. held-out 정답은 evaluate 경로에서만 읽는다. | `audit.py`, `scheduler.py`, 관련 스키마 |

## 누락을 방지하는 동작

- 한 자산에서 민감 후보를 찾더라도 다른 ready 작업을 계속한다.
- 200 응답, 비밀번호 입력란 또는 암호화 표시만으로 안전/유출/인증 우회를 확정하지 않는다.
- 일부 PDF 실패, 분석 상한, 누락된 의존성, 승인 밖 후보, 미연결 채널은 별도 상태와 재개 조건으로 남긴다.
- scope·capability·의존성·예산이 바뀌면 해결 가능한 콘텐츠 후속 작업을 다시 선택한다. 같은 입력으로 끝없이 재시도하지 않는다.
- 저장된 결과와 원장 반영 사이에서 중단돼도 결과를 재사용하며 완료 요청을 다시 보내지 않는다.
- 예산은 요청 전에 원자적으로 예약한다. 중단된 실제 요청이 없었다고 가정해 예약을 돌려주지 않는다.
- 브라우저 시작 시간과 실제 페이지 관측 시간을 분리했다. 느린 시작 때문에 첫 요청도 관찰하지 못하는 회귀를 추가했다.

## 검증

실행 환경: Windows, Python 3.12.3, Playwright 1.58.0과 Chromium, pypdf, jsonschema.
의존성·브라우저·임시 파일은 무시되는 `_local/` 아래에 준비했다.

최종 검증 수치와 부하 결과는 이 문서 하단의 검증 기록에 기재한다.

주요 회귀 근거:

| 요구 | 검증 |
|---|---|
| seed만으로 독립 발견 | `test_discovery_improvements.py`의 역할 계정·저장소·연결 도메인, `test_audit.py`의 새 배포·스크립트·PDF 큐 연결 |
| 예산·요청 제한 | 비싼 작업 뒤 저렴한 작업 선택, search 제한 중 core 실행, Retry-After 준수 |
| 복구·중복 방지 | 만료 lease 회수, stale worker 결과 거절, 결과 commit 후 원장 반영 중단, 이미 완료된 수집의 재요청 금지 |
| 공통 에이전트 계약 | 같은 fixture에서 codex/claude 레이블의 정규화한 큐 상태 비교, 동일 adapter 문서 검사 |
| 업무자료·오탐 | 기밀 표시·수수료 표·번호·채워진 JSON 양성 사례와 CSS·버전·템플릿 음성 사례 |
| 큰 자료·PDF | 256 KiB 뒤 신호·UTF-8/청크 경계·부분 분석, PDF 텍스트·이미지 공백·파서 제한시간·출력 누설 차단 |
| 화면 잠금 | 실제 Chromium의 숨김 자료 표시·제한된 고정값 입력, 외부 요청 차단, 합성 수신 서버에 전달된 요청 0 |
| 외부 import | 동일 근거 중복 방지, 중단 재개, 미해결 scope 유지, 부분 결과 보존, 과거 결과의 최신 상태 덮어쓰기 거절 |
| 보고 | 원장/결과 개수 일치, append-only 이력, 정확한 파일명·비밀 canary가 보고서에 없는지 확인 |
| 배포 패키지 | wheel 생성, 소스 트리와 분리된 runtime, 새 명령 help, 기존 CLI 별칭, 임시 가상환경 설치 |

테스트는 합성 환경에서의 기능 검증이다. 실제 회사 전체 자산 발견률이나 모든 개인정보 유형의 재현율을 측정한 결과는 아니다.

## 호환성과 운영

기존 CLI와 `su-detect` 별칭을 유지했다. 패키지 버전은 기존 2.0.0이며 새 릴리스 버전은 발행하지 않았다.
기존 Ledger/LocatorStore를 재사용하고 audit 작업·실행·결과 테이블과 append-only trigger를 추가한다.
기존 관측을 삭제하거나 새 DB로 옮기지 않는다. 정확한 URL과 intake를 포함한 case는 비공개 운영 자료다.

공통 실행 예:

```sh
open-detective audit init --case _local/case --intake _local/intake.json --mode discovery
open-detective audit plan --case _local/case --profile thorough
open-detective audit run --case _local/case --scope _local/scope.json --capabilities _local/capabilities.json --budget _local/budget.json --channel-health _local/health.json --agent codex
open-detective audit resume --case _local/case --scope _local/scope.json --capabilities _local/capabilities.json --budget _local/budget.json --channel-health _local/health.json --agent claude
open-detective audit report --case _local/case --output _local/report.json
```

`worker`는 같은 예산 구간 안에서 재시도 시각까지 대기하는 foreground 프로세스다.
대화 종료 후 모델이 자동으로 계속 실행되거나 예산이 자동 갱신되는 기능은 아니다.
case당 발견 실행기는 하나만 사용하고 외부 import 전에 중지한다.

## 남은 한계와 별도 검증

1. **OCR·시각 자료:** 텍스트 PDF는 분석하지만 스캔 PDF, 이미지·복잡한 Form·base64의 시각 내용을 자동 판독하지 않는다. 미분석 상태를 유지한다.
2. **범용 인증/계산 로직:** 공개 응답의 정적 자료·계산 단서는 분석한다. 격리 실행은 인식 가능한 고정 클라이언트 잠금 패턴과 안전한 숨김 텍스트 투영에 한정한다. 임의 앱의 전체 상호작용, 암호문 복호화, 실서버 로그인·인가 시험은 구현 완료로 주장하지 않는다.
3. **외부 검색 서비스:** GitHub 메타데이터 외 지원 채널은 운영자가 제공자/export와 health를 설정하고 `channel-discover` 결과를 가져오는 흐름이다. 모든 검색 엔진을 자동으로 연결하는 기능은 아니다. 외부 실행의 요청 예산은 별도 집계한다.
4. **import 신뢰:** 운영자 제공 보고서의 구조와 출처 연결을 검증한다. 편집 가능한 메타데이터만으로 실제 실행을 독립 증명할 수 없으며 보고서에 이 한계를 표시한다.
5. **자료 검토·마스킹:** 기본 공유 출력은 원문 인용 대신 신호·유형·개수·위치·opaque 근거를 제공한다. 임의 문맥의 부분 마스킹 인용과 스크린샷은 완전한 안전성을 보장하지 않으므로 자동 공개하지 않는다. 담당 부서 확정·공개 승인·최종 민감성 판단은 검토가 필요하다.
6. **완전성:** 깊이·요청·크기·시간 제한, 미발견 자산과 public index 공백이 존재한다. `thorough`는 유한 예산 검사이며 회사 전체 무누락을 보장하지 않는다.
7. **실환경 확인:** Codex와 Claude 양쪽 모델/호스트를 실제로 실행한 비교, GitHub Actions의 전체 OS/Python 조합, 실제 회사 재탐색은 수행하지 않았다. 동일 Python 계약의 합성 시험과 구분한다.

## 검증 기록

- 전체 회귀: `python -m unittest discover -s tests -q` — **477개 통과, 실패 0, skip 0**, 308.860초. 필수 CLI 인자 누락·기존 파일 덮어쓰기 거절을 확인하는 음성 테스트의 안내 출력은 예상 결과다.
- 마지막 import 상태 보호·보고서 보완 후 해당 통합 회귀: `python -m unittest discover -s tests -p 'test_audit*.py' -q` — **22개 통과, 실패 0, skip 0**, 133.347초. 전체 회귀에 포함된 테스트와 중복되므로 두 수를 합산하지 않는다.
- 패키지: `python -m pip wheel . --no-deps --no-build-isolation --no-cache-dir --wheel-dir dist`, `python tools/test_wheel.py` — **통과**. 최종 wheel SHA-256: `7f96893d145c4a3dcf9a23fa315235423547f18cf1af9968f980c583b1baa232`.
- `git diff --check`, `python -m compileall -q sudetect tools/test_audit_soak.py` — **통과**.
- `python tools/idgen.py --selftest` — **통과**, 합성 seed 쌍에서 후보 399개. 후보 수는 실제 존재 자산 수가 아니다.
- 별도 부하 검증: `python tools/test_audit_soak.py` — **통과**, 331.062초.
  합성 자산 **2,000개**, 실행 구간 **22개**, 일시 실패 재시도 **25건**, 실제 fetcher
  호출 **2,025회**, 성공 요청 중복 **0건**, 대상 콘텐츠 작업 미완료 **0건**.
  원장 관측과 결과는 각각 **2,025건**으로 실패 관측도 보존했다.
  결과 commit 직후·원장 projection 직전에 주입한 중단을 복구했고 해당 성공
  요청은 반복하지 않았다. 각 구간에서 Case를 닫고 다시 열었다. OS 프로세스를
  실제 강제 종료한 시험과 동일하다고 주장하지 않는다.
  채널 health가 없는 기본 discovery 작업 **1건은 blocked_input으로 보존**했다.
  따라서 콘텐츠 부하 시나리오는 완료됐지만 case 전체 `queue_complete=false`이며,
  이 차이를 숨기지 않는 것까지 합격 조건으로 확인했다.

재실행 시 설치된 선택 의존성과 Chromium이 필요하다. 이 작업 환경에서는
`PYTHONPATH=_local/test-deps`, `PLAYWRIGHT_BROWSERS_PATH=_local/playwright-browsers`,
`TEMP`/`TMP`는 `_local/test-temp`의 절대 경로를 사용했다. Chromium 실행은 이
환경의 기본 파일 sandbox 밖에서 수행했고, 합성 페이지의 요청은 테스트 broker로
통제했다. 실제 회사 서비스 로그인·대상 자료 수집은 수행하지 않았다.
