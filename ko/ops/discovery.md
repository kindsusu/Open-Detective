# 발견과 인벤토리 절차

발견은 provenance가 있는 후보를 만든다. 소유를 확정하거나 요청을 허가하지 않는다.

## 소유자 인벤토리 우선

자격증명을 분리한 프로세스에서 명시적으로 승인된 read-only 소유자 API 또는 export를 쓴다(`SUD-R09`). provider, account/team scope, API version, retrieval time, credential identity reference, permission, cursor/page, time filter, rate-limit state, truncation flag, completion을 기록한다.

Vercel은 team → project → deployment → alias/domain과 protection metadata를 모은다. 요청한 보존 기간 전체의 deployment cursor를 처리하고 production domain, project alias, branch/preview alias, immutable deployment URL을 구분한다. 보호 설정은 확인할 metadata이며 익명 차단의 증거가 아니다.

GitHub의 구현된 collector는 organization 또는 정확히 인증된 account의 repository를 나열하고 선택적으로 recursive tree completeness를 검사한다. 검증된 `Link` pagination을 끝까지 따른다. tree response가 truncated면 공백을 저장하고 partial tree로 completeness를 추론하지 않는다. 별도 익명 `github-discover` channel은 공개 repository metadata에서 관례상 Pages URL 후보를 만든다. owner deployment environment와 private source/custom domain의 정확한 Pages 목록은 owner 제공 normalized record가 필요하다. repository visibility와 deployment visibility는 독립적이다. private repository도 public site를 배포할 수 있다.

page inventory에는 page URL, parent project/deployment, 가능한 경우 source commit, alias relationship, owner evidence를 보존한다. “page complete”는 선언한 scope의 모든 provider page/cursor가 미해결 permission, rate limit, truncation, time-window 공백 없이 끝난 상태다.

## Provenance 가져오기

정규화 JSON은 필드 이름이 달라도 다음 개념이 필요하다.

```text
source, retrieved_at, owner_scope, locator, relationship,
ownership_evidence, completeness, cursor_or_page, source_record_id
```

source와 retrieval time이 없는 행은 거부하거나 격리한다. dedup을 위해 source record ID를 보존한다. 생산자가 성공한 제한 쿼리와 종료 조건을 표시하지 않았다면 0행을 complete로 보지 않는다. 가져온 자격증명이나 비밀 포함 URL은 공유 출력 전에 정화한다.

## 공개 발견

승인된 씨앗을 public repository, search engine, CT, DNS record, archive, public storage metadata, document/share index, hosting platform에서 보완한다. 현재 `discover` 명령은 수행자가 수집한 normalized JSON을 가져올 뿐 이 채널을 crawl하거나 query하지 않는다. 각 import record에 query/source channel, observation time, pagination/completeness, limitation을 둔다. 검색 index와 archive는 지연되고 불완전하다.

이름을 만들기 전에 소유 metadata에서 찾은 정확한 public link를 사용한다. shared IP, favicon 유사성, 이름 유사성, certificate adjacency, reverse-IP output은 confidence가 있는 graph edge이지 ownership이 아니다. 새로 확증한 owned host에 CT/DNS/search를 다시 적용하되 무관한 tenant로 확장하지 않는다.

```bash
python tools/idgen.py --ko "<이름>" --en "<공식 로마자 표기>" --industry "<업종어>"
python tools/idgen.py --en "<이름>" --targets github --limit 100
```

생성기는 오프라인이다. 플랫폼별 namespace 규칙으로 후보를 검증하고 소유 검토로 보낸다. 후보량은 대량 스캔을 허가하지 않는다. `search-plan`은 수행자 alias와 생성 변형을 구분하고, 미실행 작업을 `deferred`로 보존한다. 모든 필수 channel이 완료되거나 사유와 함께 `not_applicable`이 될 때까지 `PARTIAL`이며 `COMPLETE`는 선언한 plan 범위만 뜻한다. 정확한 후보 URL은 로컬 locator store에만 두고 공유 결과에는 `locator_ref`와 handoff state만 남긴다. ref를 풀어도 측정 승인은 아니며 probe/browser가 scope를 다시 검사한다.

## 일정과 출력

증거가 강한 graph neighbor를 우선하면서 분리된 brand/team 탐색 예산도 남긴다. ownership confidence, possible impact, freshness, information gain, request cost, privacy cost를 scheduling heuristic에 쓸 수 있지만 입증된 확률 모델로 표현하지 않는다.

후보는 대장에 `workflow=candidate` 또는 `ownership_pending`으로 쓴다. 정확한 scope grant와 ownership evidence가 있을 때만 `verification_pending`으로 올린다. 지원하지 않는 channel은 failure/unknown으로 기록하며 조용히 버리지 않는다.

## 익명 GitHub 메타데이터 발견

실제 익명 GitHub 실행 전 `python -m sudetect channels-doctor --config _local/channels.json --scope _local/control-scope.json --output _local/channel-health.json [--previous _local/channel-health.previous.json]`을 실행한다. config는 로컬 수행자 입력이며 control URL도 실행 scope가 필요하고 추가 네트워크 접근을 허가하지 않는다. `github-discover`와 `search-plan run`에는 fresh report가 필요하다. repository 목록에는 `github-repositories`, 검색 seed에는 두 검색이 repository 목록 확장으로 이어질 수 있으므로 `github-repositories`, `github-user-search`, `github-repository-search`가 모두 필요하다. 한 channel의 정상은 다른 channel의 정상이나 회사 전체 발견 완료가 아니다.

config와 scope가 유효한 실행마다 `OK`, `DEGRADED`, `DEAD`, 측정 시각, 만료, 최소 관측 근거를 저장하며 control body를 복사하지 않는다. `OK`에는 HTTP 200, complete capture, 기대 JSON pointer 또는 body marker 일치가 모두 필요하다. 일반 body marker는 false positive가 가능하므로 구체적인 JSON-pointer 식별 검증을 우선한다. `DEAD`에는 도달 불가 control과 HTTP 404/410이 포함된다. report는 검사된 로컬 운영 근거이며 전자서명·원격 attestation·로컬 파일 변경에 대한 경계가 아니다. 외부 plan import는 `web`, `documents`, `certificate_transparency` 각 channel의 control이 해당 작업 `observed_at`에 유효해야 하며 이후 만료가 이미 유효한 과거 import를 무효로 만들지 않는다. 저장하는 health provenance에는 검증한 불투명 control 식별자와 시각만 넣고 policy text는 넣지 않는다. synthetic fixture는 실제 channel 검증이 아니다.

GitHub control ID는 `api.github.com` endpoint family와 맞아야 한다. `github-repositories`는 `/repos/<owner>/<repo>` 또는 `/users|orgs/<owner>/repos`, `github-user-search`는 `/search/users`, `github-repository-search`는 nonempty `q`가 있는 `/search/repositories`를 쓴다. 다른 endpoint의 일반 공개 marker로 대신할 수 없다. Detail API control은 core repository family의 proxy일 뿐 pagination·permission coverage를 보장하지 않는다.

`python -m sudetect github-discover --scope-id TEAM --account approved-account --channel-health _local/channel-health.json`는 자격증명 없이 공개 저장소 메타데이터를 조회한다. `--seed`는 사용자·저장소 검색, `--known-url`은 제공된 GitHub/GitHub Pages 링크에서 계정·저장소를 추출한다. 계정을 알게 되면 웹 검색 0건이어도 공개 저장소 목록을 조회한다. 저장소명, `has_pages`, 홈페이지 메타데이터와 관례상 Pages 주소를 후보로 연결한다. 생성한 주소는 실제 배포 확인이 아니며 커스텀 도메인·비공개 소스의 Pages는 누락될 수 있다.

페이지 연결을 검증하고 요청·시간·응답 크기·계정·결과 상한을 적용한다. 실행 방법, 출처 그래프, 채널별 완전성과 오류를 출력한다. `COMPLETE`는 실행한 제한된 메타데이터 채널만 뜻하며 회사 전체 자산의 완전성을 뜻하지 않는다. 실제 식별자와 결과는 ignored `_local/`에 둔다. 회사명만 사용한 독립 발견과 제공 URL에서의 확장을 별도 평가한다. 놓친 URL을 입력해 다시 찾는 것은 기존 자동 발견 능력의 증거가 아니다.

미확인 계정 가설·API 실패·검색 절단·브라우저 미측정은 커버리지 공백으로 남긴다. 알려진 사례 회수율과 민감정보 분류 정밀도를 분리한다. 생성된 모든 주소를 자동 프로빙하지 말고 정확히 승인된 URL만 익명 실측한다.

선택적인 locator store는 평문 SQLite다. 소유자가 접근을 제한하고 암호화한 저장 볼륨에 보관한다. opaque 참조가 원 URL을 암호화하지는 않는다. 로컬 검색 manifest에는 입력 회사명, 검색어, 공개 저장소 메타데이터가 들어 있으므로 마스킹 보고서로 간주해 공개하지 않는다.

## 페이지 처리와 부재 관측

GitHub는 다음 페이지 Link에 계정명 대신 숫자 사용자 ID를 넣을 수 있다. 익명 수집기는 현재 저장소 행 모두가 요청한 login과 동일한 양수 owner ID를 가리키고 다음 URL도 해당 ID와 일치할 때만 전환한다. host·검색 조건은 유지하고 page는 정확히 1씩 증가해야 한다. 계정 확장 한도에 걸려도 이미 반환된 저장소 후보는 버리지 않으며 보류된 계정 작업을 기록한다.

정확한 계정·저장소의 첫 요청에서 받은 404는 `not_found_observed`로 기록하는 제한된 메타데이터 관측 완료다. 실제 부재나 회사의 다른 계정 부재를 증명하지 않는다. 검색 endpoint의 404와 후속 페이지의 404는 미완료로 유지한다. rate-limit 근거 헤더가 있는 403과 429는 `RATE_LIMITED`, 그 외 403은 `ACCESS_DENIED`다. 둘 모두 검색 성공 0건으로 처리하지 않는다.

프로토콜 대조: [GitHub 페이지 처리](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api), [GitHub REST 문제 해결](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api).

## 명시적 예산으로 검색 재개

일반 `search-plan run`은 planned 작업을 총 요청 예산(기본 20회)과 작업별 한도(기본 6회) 안에서 실행한다. 알려진 URL을 우선한다. 전체 identity, industry 문맥, function 문맥 query family를 번갈아 조회하되 각 family 안에서는 순서를 보존하며, 짧거나 넓은 단어와 검색에서 나온 계정 확장은 뒤에 둔다. eligible query와 identity account 후보는 1:1로 번갈아 처리한다. 이는 제한된 heuristic이므로 전체 표기가 지연될 수 있으며 exhaustive 또는 최적 recall을 뜻하지 않는다. 한도에 닿은 쿼리는 미완료로 남긴다. 의도적으로 더 깊이 재조회할 때는 `--per-job-request-budget`을 최대 30까지 늘린다.

```bash
python -m sudetect search-plan run-until-budget --plan _local/plan.json --locator-store _local/locators.sqlite --request-budget 60 --per-job-request-budget 6 --max-batches 30 --channel-health _local/channel-health.json
python -m sudetect search-plan run --plan _local/plan.json --locator-store _local/locators.sqlite --retry-failed --request-budget 20 --per-job-request-budget 10 --channel-health _local/channel-health.json
python -m sudetect search-plan status --plan _local/plan.json
```

`run-until-budget`은 총예산을 명시해야 하며 deferred GitHub 작업도 순차 검토한다. 일반 `run`은 기존 deferred 작업을 암묵적으로 올리지 않는다. `run-until-budget` 또는 명시적 `--resume-query-budget` / `--resume-account-budget`을 사용한다. 실패 작업의 선택은 `--retry-failed`로 별도 제어한다. 선택된 작업은 한 실행에서 최대 한 번 수행한다. rate-limit 응답을 받으면 후속 제공사 요청을 멈추고 실행을 종료하며, 제한 해제까지 기다리거나 무한 재시도하지 않는다. 매 batch가 원자적으로 저장되고 작업별 시도 이력과 원본 batch 메타데이터를 비공개 plan에 보존하며 집계 요청 수는 이 기록과 일치해야 한다. 상태는 최신 작업 근거와 남은 계정 확장을 반영하고 다음 작업 사유를 별도로 제공한다. 과거 실패 이력은 삭제하지 않는다. 작업별 증거가 없는 구형 partial/failed plan은 legacy coverage gap을 유지한다. 기존 plan은 이력으로 보존하고 같은 이름 입력으로 새 version-2 plan을 생성한다. 일부 재시도나 임의 import로 이 공백을 없애지 않는다. 선언된 plan 완료도 인터넷 전체 발견을 증명하지 않는다.
