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

`python -m sudetect github-discover --scope-id TEAM --account approved-account`는 자격증명 없이 공개 저장소 메타데이터를 조회한다. `--seed`는 사용자·저장소 검색, `--known-url`은 제공된 GitHub/GitHub Pages 링크에서 계정·저장소를 추출한다. 계정을 알게 되면 웹 검색 0건이어도 공개 저장소 목록을 조회한다. 저장소명, `has_pages`, 홈페이지 메타데이터와 관례상 Pages 주소를 후보로 연결한다. 생성한 주소는 실제 배포 확인이 아니며 커스텀 도메인·비공개 소스의 Pages는 누락될 수 있다.

페이지 연결을 검증하고 요청·시간·응답 크기·계정·결과 상한을 적용한다. 실행 방법, 출처 그래프, 채널별 완전성과 오류를 출력한다. `COMPLETE`는 실행한 제한된 메타데이터 채널만 뜻하며 회사 전체 자산의 완전성을 뜻하지 않는다. 실제 식별자와 결과는 ignored `_local/`에 둔다. 회사명만 사용한 독립 발견과 제공 URL에서의 확장을 별도 평가한다. 놓친 URL을 입력해 다시 찾는 것은 기존 자동 발견 능력의 증거가 아니다.

미확인 계정 가설·API 실패·검색 절단·브라우저 미측정은 커버리지 공백으로 남긴다. 알려진 사례 회수율과 민감정보 분류 정밀도를 분리한다. 생성된 모든 주소를 자동 프로빙하지 말고 정확히 승인된 URL만 익명 실측한다.

선택적인 locator store는 평문 SQLite다. 소유자가 접근을 제한하고 암호화한 저장 볼륨에 보관한다. opaque 참조가 원 URL을 암호화하지는 않는다. 로컬 검색 manifest에는 입력 회사명, 검색어, 공개 저장소 메타데이터가 들어 있으므로 마스킹 보고서로 간주해 공개하지 않는다.
