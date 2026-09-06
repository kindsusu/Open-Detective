# su-detect 수정본 적용 안내

2026-09-06 · 기준 커밋 `f1e127bdb404a3bab88a3bcd57701806d99e1723`에서 수정 · 패키지 버전 `2.0.0`

기존 절차 중심 저장소에 실행 가능한 Python 측정·브라우저·인벤토리·추적 모듈을 추가했다. `BODY_SERVED`라는 전송 관측과 민감 내용의 확정을 분리하고, 범위·소유 확인을 실제 요청 전에 강제한다. 자동 분류는 후보를 제시하며 실제 기밀 여부와 소유 근거를 대신 확정하지 않는다.

## 핵심 변경

| 영역 | 구현한 동작 |
|---|---|
| 요청 경계 | 정확한 HTTPS origin/경로·만료·제외 URL 검사, A/AAAA public unicast 검증, DNS pin과 TLS hostname 검증, 리다이렉트 전 재검사 |
| 익명 측정 | 쿠키·Authorization·Referer·환경 프록시 없이 제한된 GET, 공유 요청 예산, 본문 상한, 206/잘린 본문과 전체 SHA 구분 |
| 클라이언트 로그인 | 초기 HTML·숨김 JSON·JS 비밀번호 패턴·평문 연락처 후보를 분석하고, Chromium에서 로그인 전 GET fetch/XHR 응답과 렌더링 DOM 관찰 |
| 브라우저 통제 | 새 context, 정책 transport가 가져온 본문만 fulfill, 외부 scope/POST/다운로드 제한, Service Worker 차단, WebSocket 서버 연결 차단 및 로컬 메시지 폐기 |
| 발견 | Vercel 프로젝트·배포·alias·domain·보호 설정, GitHub 저장소와 선택적 tree 메타데이터 수집, 공개 검색 결과의 provenance import |
| 추적 | SQLite 이벤트·관측·alias·사건·재측정 queue, claim lease와 재시도, 조치 이후 원 경로와 모든 alias 검증, 신규 alias/민감 내용 관측 시 재개방 |
| 증거 | 원문·헤더·DOM·토큰을 보고서에 복사하지 않고 최소 신호와 마스킹 locator 기록, 선택적 HMAC 상관 ID |
| 운영 | Python 패키징, 기존 shell 진입점 호환, 한·영 문서와 규칙 ID 동기화, 합성 회귀 테스트와 CI 정의 |

## 로컬에서 실행

저장소 루트에서 Python 3.11 이상으로 실행한다. Windows PowerShell의 예시는 다음과 같다.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[browser,test]"
.\.venv\Scripts\python.exe -m playwright install chromium
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

`examples/scope.example.json`은 의도적으로 만료된 예제다. ignored `_local/`에 복사하여 실제 소유 증거, 정확한 origin과 경로, 유효기간으로 바꾼 뒤 사용한다. 토큰은 지정한 환경 변수로만 인벤토리 프로세스에 제공한다. 검색·표적 브라우저에 관리 API 토큰을 전달하지 않는다.

```powershell
.\.venv\Scripts\python.exe -m sudetect probe --scope _local/scope.json https://approved.example/
.\.venv\Scripts\python.exe -m sudetect browser https://approved.example/ --scope _local/scope.json --duration 3
.\.venv\Scripts\python.exe -m sudetect inventory --provider vercel --scope-id TEAM_ID --token-env VERCEL_TOKEN
.\.venv\Scripts\python.exe -m sudetect inventory --provider github --scope-id ORG --token-env GITHUB_TOKEN
.\.venv\Scripts\python.exe -m sudetect discover --input examples/discovery-import.json --scope-id fixture-team
.\.venv\Scripts\python.exe -m sudetect ledger --db _local/audit.sqlite --help
```

`discover` 예제는 CT 채널이 PLANNED이므로 PARTIAL이 정상이다. 실제 검색 결과를 직접 수집해 같은 입력 형식으로 가져온다. 조회 실패·미실행·권한 공백을 성공 0건으로 처리하지 않는다. `search-plan`은 이 상태를 재개 가능한 manifest로 보존한다. 수행자가 준 alias는 명시적 검색 씨앗일 뿐이며, alias만으로 발견이 충분하다고 가정하지 않는다. 국문 복합명 원형·띄어쓰기·브랜드·업종, 영문 브랜드 단독·업종 결합/분리 표기를 제한된 우선순위로 별도 생성하고, 넓은 단어 후보는 뒤로 미룬다.

대장 흐름은 `register → open → remediate → import-observation → close`다. `import-observation`에는 원 URL/alias와 대응하는 `--asset-id`, 필요한 `--alias-id`를 연결한다. 종결에는 조치 이후 관측, 전체 캡처, 적절한 접근/내용 상태와 서로 다른 관측·정책·대조군 증거 참조가 필요하다. `--expected-policy`나 `--control-healthy`는 실제 확인 결과일 때만 설정한다. opaque 증거 참조의 형식 검증은 외부 증거 저장소의 진위를 보증하지 않는다.

`schedule/due/claim/complete/retry`는 영속 작업 큐 명령이다. 실제 시각에 실행하는 상주 worker와 외부 알림 채널은 아직 연결하지 않았다. 이 변경으로 정기 스캔이나 알림을 자동 시작하지 않는다.

정확한 candidate URL은 `_local/`의 locator store에 두고 공유 결과에는 `locator_ref`와 handoff state만 남긴다. `locators bind`로 승인된 ref를 asset의 `target_id`, scope의 `policy_id`에 묶은 뒤에만 probe/browser observation을 재측정 증거로 가져온다. 바인딩이 달라지거나 종결 후 `BODY_SERVED`, unknown/incomplete, 같은 시각 충돌이 발생하면 finding은 재개 또는 재검토된다. `doctor --reference .`는 실행 중 runtime과 검수 source의 parity를 읽기 전용으로 비교한다. 저장소 수정·push는 이미 설치된 runtime을 자동 갱신하지 않는다.

## 실제 검증 범위와 한계

합성 입력의 정상 로그인+API 401, 숨김 표식, 로그인 전 runtime fetch, 평문 표의 연락처 후보, public key, 프롬프트 인젝션 텍스트, scope 밖 요청, POST, WebSocket, 압축 응답, DOM 상한을 검증한다. HTTP 측정 JSON을 실제 CLI로 대장에 가져와 종결하고 신규 alias로 재개방하는 통합 사례도 포함한다. 정확한 실행 결과는 동봉한 변경 결과 보고서를 따른다. CI 정의를 추가한 것은 원격 CI 실행 성공과 다르다.

현재 구현은 인터넷 전체 자동 발견 시스템이나 범용 취약점 스캐너가 아니다. CT·검색엔진·insane-search·browser-use 전용 커넥터, 공개 탭 클릭 계획, WebSocket/Service Worker 데이터 검사, PDF/오피스/OCR 심층 검사, 범용 LLM 판정 worker, 외부 증거 vault, 상주 scheduler는 미구현이다. 현재 브라우저 엔진은 Playwright이며 stateless GET broker로 동작하므로 실제 사용자의 쿠키·POST 기반 앱과 행동이 다를 수 있다. 미검사 영역은 안전 판정으로 바꾸지 않는다.

이메일·전화번호·필드명·비밀번호 패턴은 공개 연락처나 데모 데이터에도 나타날 수 있다. 후보 정밀도·재현율은 승인된 회사 정답 세트로 별도 측정해야 한다. 자료가 링크 없이 미색인 개인 배포에 존재하거나, 계정 토큰이 일부 자산만 볼 수 있으면 이 엔진도 완전성을 보장할 수 없다.

브라우저 dead proxy와 DNS 차단은 OS 수준 격리가 아니다. 신뢰할 수 없는 페이지를 운영 규모로 다룰 때는 별도 프로세스/컨테이너의 시간·메모리·egress 제한을 적용해야 한다. 출력은 최소화하지만 일반 Python 메모리나 OS swap의 암호화까지 구현하지는 않는다.

## 명세 대조 출처

Vercel 프로젝트 continuation과 배포 alias 요청 형식은 [프로젝트 목록 API](https://vercel.com/docs/rest-api/projects/retrieve-a-list-of-projects) 및 [배포 alias API](https://vercel.com/docs/rest-api/aliases/list-deployment-aliases)를 대조한다. GitHub 인벤토리의 권한·페이지 처리는 [저장소 REST API](https://docs.github.com/en/rest/repos/repos), 브라우저 interception은 [Playwright BrowserContext](https://playwright.dev/python/docs/api/class-browsercontext)를 따른다. 제공사 인증 계정의 실호출 검증은 이번에 수행하지 않았다.

## GitHub 누락 사례 후속 보완

`python -m sudetect github-discover --scope-id TEAM --account approved-account` 명령을 추가했다. 공개 사용자/저장소 검색, 알려진 계정의 전체 공개 저장소 페이지 처리, 제공된 Pages URL의 계정/저장소 역추적, 출처 그래프와 채널별 오류를 지원한다. `--seed` 및 `--known-url`을 반복 지정할 수 있다. 배포 URL은 후보이며 소유 확인과 익명 실측이 별도로 필요하다.

식별자 생성기는 영문 브랜드+업종 복합형의 하이픈 및 숫자 접미사, 브랜드+업무명을 우선순위에 반영한다. 분류기는 JS 비밀번호 비교와 동적 fetch 미해결 신호를 보완했다. 실제 회사명/URL은 공개 테스트에 넣지 않았으며, 독립 발견과 제공 계정 확장 결과는 로컬 보고서에서 따로 평가한다.
