# 실행 레이어 — 어떻게 찾는가

채널이 "어디를 보는가"라면 이 문서는 "어떤 도구로 보는가"다.
**여기 있는 것은 전부 2026-08-31에 직접 돌려 작동을 확인했다.**
작동하지 않는 것을 목록에 두면 거짓 음성을 만들므로, 실패한 도구는 §5에 사유와 함께 격리했다.

## 1. 계정·저장소 열거 — 익명 시점

노출 판정의 정본이다. **검색 API가 아니라 REST 리스팅**을 쓴다.

```bash
# 조직인지 개인 계정인지 먼저 확인한다 (404면 조직이 아니다)
curl -s "https://api.github.com/users/<계정>"        # type: User | Organization

# 익명이 보는 공개 저장소 — 이것이 노출 판정
curl -s "https://api.github.com/users/<계정>/repos?per_page=100&sort=pushed"
curl -s "https://api.github.com/orgs/<조직>/repos?per_page=100"
```

- 익명 레이트리밋 **60req/hr**. 인증 시 core 5000/hr, search 30/min, **code_search 10/min**(가장 빡빡).
- 인증 `gh search`는 **점검자 본인 private 저장소를 결과에 섞는다.** 인벤토리 확보용으로만 쓴다.
- 계정 하나를 찾으면 **역추적**한다: 커밋 author, 조직 멤버, 포크, 관계사 명칭 조합.

**파일 내용을 받지 않고 위험도 분류하기** — 개인정보 접근을 최소화하는 정공법이다.

```bash
curl -s "https://api.github.com/repos/<계정>/<저장소>/git/trees/HEAD?recursive=1"
```

`json`·`env`·`ya?ml`·`csv`·`xlsx?`·`sql`·`pem`·`key`·`bak` 확장자를 우선 표시한다.
**설정·데이터 파일이 든 저장소가 가장 위험하다.**

## 2. 서브도메인·자산 발견

### 2-1. Certificate Transparency — 병행한다
```bash
# CertSpotter: 안정적이나 유효 인증서만 반환
curl -s "https://api.certspotter.com/v1/issuances?domain=<도메인>&include_subdomains=true&expand=dns_names"

# crt.sh: 폐기 이력까지 보이나 불안정 → 재시도
for i in 1 2 3 4 5; do
  curl -s -f "https://crt.sh/?q=%25.<도메인>&output=json" && break
  sleep 5
done
```
- crt.sh는 **죽은 게 아니라 불안정**하다(8회 시도에서 200 1회·404 2회·502 5회·타임아웃 1회).
- crt.sh의 **404는 Apache 에러 페이지**이지 인증서 0건이 아니다.
- CertSpotter 무료는 **유효 인증서만** → 폐기된 과거 서브도메인은 영원히 안 잡힌다. **보완재**다.

### 2-2. 역방향 IP — 가장 수확이 큰 한 수
```bash
IP=$(python -c "import socket;print(socket.gethostbyname('<도메인>'))")
curl -s "https://internetdb.shodan.io/$IP"        # 무인증. hostnames·ports·cpes
```
**CT를 apex 하나에만 돌리면 놓친다.** 같은 박스의 다른 도메인이 드러나면
그 도메인들에 대해 §2-1을 각각 다시 돌린다.

> 실측: 역방향 조회 한 번으로 `<도메인B>`·`<도메인C>`·`<도메인D>`가 드러났고,
> 그 중 `dev.<제2도메인>`이 무인증 노출로 확인됐다.

- **InternetDB의 `ports`는 반드시 직접 접속으로 대조한다.** stale이 실증됐다(443 라이브인데 목록에 없음).
- **`vulns` 필드는 리포트에서 배제한다.** 버전 없는 CPE에 제품 CVE 전체가 매칭된다.

### 2-3. 서브도메인 추측 — 보조 수단
`dev`·`staging`·`test`·`admin`·`api`·`mail`·`erp`·`groupware`·`metabase`·`grafana`·`kibana`.
DNS 해석 여부만 본다. **CT보다 신뢰도가 낮으므로 CT를 먼저 돌린다.**

## 3. 아카이브·잔존

```bash
# Wayback CDX — 형식이 틀리면 거짓 음성이 난다
curl -s "http://web.archive.org/cdx/search/cdx?url=<대상>*&output=json&collapse=urlkey&fl=original,timestamp,statuscode"

# 단일 URL 빠른 확인
curl -s "https://archive.org/wayback/available?url=<대상>"

# 제3자 CDN 미러 — 커밋 고정 경로는 사실상 영구
curl -sI "https://cdn.jsdelivr.net/gh/<계정>/<저장소>@<ref>/<경로>"

# 커밋 SHA 직접 조회 — 브랜치에서 제거돼도 GC 전까지 200
curl -s "https://api.github.com/repos/<계정>/<저장소>/commits/<SHA>"
```

- `url=<대상>*`의 **`*`와 `output=json`이 없으면 0건처럼 보인다.** 대조군을 함께 돌린다.
- archive.today는 **`-L`로 따라가야** 404(없음)와 스냅샷이 갈린다. 302는 도메인 로테이션이라 신호가 없다.
- Software Heritage는 GitHub를 상시 크롤한다 — **오늘 없음이 내일 없음을 보장하지 않는다.**

> **단일 채널의 음성은 부재의 증거가 아니다.** 실증: `<user>.github.io`는 Wayback 0건이지만
> jsDelivr가 `<repo>@main/index.html`을 200/약 82KB로 서빙 중이다.

## 4. 검색엔진 dork

WebSearch 도구 또는 각 엔진에서 직접. **국내는 네이버를 반드시 병행**한다.

| 목적 | 질의 |
|---|---|
| 문서 유출 | `"<회사명>" filetype:pdf OR filetype:xlsx OR filetype:hwp` |
| 구글 문서·시트 | `site:docs.google.com "<회사명>"` |
| AI 공유링크 | `site:chatgpt.com/share OR site:claude.ai/share "<회사명>"` |
| AI 회의록 | `site:clovanote.naver.com "<회사명>"` |
| 배포 호스팅 | `site:github.io OR site:pages.dev OR site:vercel.app "<회사명>"` |
| 코드 놀이터 | `site:codepen.io OR site:jsfiddle.net OR site:codesandbox.io "<회사명>"` |
| 공개 보드 | `site:trello.com OR site:notion.site "<회사명>"` |

```bash
curl -s -A "Mozilla/5.0" "https://search.naver.com/search.naver?query=<URL인코딩된_회사명>"
```

> **dork 단독으로는 부족하다.** 실증: 노출된 GitHub Pages 8건이 dork로 **전혀 안 잡혔다**(색인 안 됨).
> 계정 열거로만 발견됐다. **채널마다 커버리지가 다르므로 병행이 필수다.**

## 5a. 노출 실측 — 크롤러의 눈

`tools/probe.sh` 참조. 판정 규칙 전문은 `ops/verify.md`. 이것이 **1차 스윕**이다 — 자산당 한 요청,
JS 없음, Phase 1이 찾은 전부에 배치로 돌릴 만큼 가볍다.

```bash
bash tools/probe.sh "https://<대상>/" "<라벨>"
bash tools/probe.sh --batch targets.tsv
```

기록: 상태코드 · **sha256** · ETag · Last-Modified · 최종 URI · 본문 크기.
**크기는 보조 지표다.** 재현성의 불변량은 다이제스트다.

## 5b. 런타임 관찰 — 브라우저의 눈

`probe.sh`는 크롤러처럼 HTML을 받는다. 그러나 점점 많은 사이트가 거의 빈 껍데기만 보내고 **JS가 그
다음에 실제 데이터를 가져온다.** curl 단독 패스는 그런 사이트를 `NO-BODY`나 작은 본문으로 넘기고 —
노출을 통째로 놓친다. 실제 익명 방문자의 브라우저는 그 JS를 돌려 데이터를 받는다. 이 단계가 그 시점을
재현한다.

**발견 이후에만, 좁힌 표적에만 실행한다 — 전체 스윕이 아니다.** 크롤러의 눈이 먼저·넓게 가고,
브라우저의 눈이 나중·좁게 간다. 느리고, 배치가 안 되며, 점검자를 데이터 자체에 노출시키기 때문이다.

### 트리거 — 언제 5b를 켜는가

5a의 표적에 대해, 아래 중 하나가 성립할 때**만** 5b를 돌린다.

- 5a가 `NO-BODY`이거나 실제 페이지보다 훨씬 작은 본문(클라이언트 렌더 껍데기)이었다
- 표적이 **앱 서버**다 (프레임워크 쿠키, `X-Powered-By`, `<div id="root">` 같은 SPA 마운트 지점)
  — 정적 HTML이 아니다
- 5a가 `EXPOSED`인데 "**구체적으로 무엇이 샜나**"가 아직 안 풀렸다 — 페이지가 데이터를 로드하거나,
  API를 부르거나, 클라이언트측 게이트를 가졌다
- **클라이언트측 잠금 화면**이 있어 겉치레 게이트인지 진짜 암호화인지 가려야 한다

아무것도 성립하지 않으면 — 5a가 이미 본문을 전량 받아온 평범한 정적 페이지면 — **5b를 돌리지 않는다.**
브라우저가 더할 것이 없고, 매 실행에는 대가가 있다.

### 각 단계가 하는 일

| 단계 | 도구 | 확인하는 것 |
|---|---|---|
| 익명 로드 | `navigate` | 익명 방문자 재현. **로그인·비밀번호·저장 세션 없음.** |
| 네트워크 관찰 | `read_network_requests` | 페이지가 실제로 부른 **데이터 fetch** — `GET /api/customers → 200, 2MB`가 진짜 노출. 추측이 아니라 목격 |
| 렌더된 DOM 읽기 | `read_page` / `get_page_text` | JS 실행 **후** 화면. 비밀번호 없이 콘텐츠가 뜨면 게이트는 겉치레 |
| 콘솔 읽기 | `read_console_messages` | 앱이 남긴 엔드포인트·키·에러 |
| 상태 점검(읽기 전용) | `javascript_tool` | 관리자 토큰이 스토리지에 남는지, 전역에 무엇이 있는지 — **점검만, 게이트 해제 금지** |

### 잠금 화면 판별 (5b가 값을 하는 지점)

클라이언트측 "잠금 화면"은 둘 중 하나이고, 5b가 이를 가른다.

- **겉치레 게이트** — JS가 `display`를 토글하거나 `password === "x"`를 확인하고 div를 드러낸다.
  데이터는 익명 응답에 **이미 전송됐다.** 그걸 읽는 건 뚫는 게 아니라 서버가 이미 보낸 본문을 읽는
  것이다. 판정: **EXPOSED**, 그리고 DOM/네트워크가 드러낸 *무엇을* 보고한다.
- **클라이언트측 암호화** — 콘텐츠가 암호문 블롭이고 비밀번호가 키를 만든다(StatiCrypt류). 들어가려면
  무차별 대입·크랙이다. **하지 않는다.** "클라이언트측 암호화 — 복호화 안 함"으로 기록하고, 조치는
  서버측 인증으로 보낸다.

> 차이는 비밀번호를 시도해서가 아니라 **읽어서** 결정한다. 겉치레 토글 뒤에 평문 데이터가 있으면 노출이고,
> 암호문이면 멈추고 보고한다.

### 5b의 절대 한계 — 점검과 공격의 경계

- **비인증으로 로드되는 것만 관찰한다.** 비밀번호 입력·무차별 대입·우회 금지. 브라우저는 익명 방문자가
  보는 것을 보려고 있는 것이지 그 이상이 아니다.
- **`javascript_tool`은 상태를 읽지, 게이트를 풀지 않는다.** `sessionStorage`를 들여다보는 건 관찰이고,
  복호화나 로그인을 스크립팅하는 건 익스플로잇이다.
- **이제 점검자가 데이터를 본다.** curl은 해시만 떴지만 브라우저는 렌더한다. 그래서 불변 원칙 10·11이
  여기서 더 무겁다 — 복사하지 않고, **개인정보가 화면에 뜨는 순간 중단**해 CPO로 넘긴다. 행을 읽지 말고
  구조·필드 형태로 등급을 매긴다.
- **확정/미확정 규율은 그대로다.** 시스템에 작용하지 않고는 관찰할 수 없는 동작이면 **미확정**으로 둔다 —
  그것이 밀어붙일 이유가 되지 않는다.

## 6. 스토리지 버킷

```bash
curl -s -o /dev/null -w "%{http_code}" "https://<이름>.s3.amazonaws.com/"
curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/<이름>/"
curl -s -o /dev/null -w "%{http_code}" "https://<계정>.blob.core.windows.net/?restype=container&comp=list"
curl -s -o /dev/null -w "%{http_code}" "https://kr.object.ncloudstorage.com/<이름>/"
```
판정은 `ops/verify.md`의 버킷 절을 따른다. **S3/GCS 한정 규칙이며 Azure에서 무너진다.**
**403은 안전도 소유도 뜻하지 않는다.**

## 7. 패키지·레지스트리
```bash
curl -s "https://registry.npmjs.org/-/v1/search?text=<키워드>&size=20"
curl -s "https://hub.docker.com/v2/search/repositories/?query=<키워드>&page_size=20"
curl -s "https://huggingface.co/api/models?search=<키워드>&limit=20"
```
언어스택과 무관한 레지스트리(Maven·NuGet·RubyGems·crates.io·Go proxy)는 **해당 자산이 존재할 근거가 있을 때만** 본다.

## 8. 작동하지 않는 것 — 쓰지 않는다

| 도구 | 실측 결과 | 판단 |
|---|---|---|
| Google 캐시 | 200이나 본문이 `<title>Google Search</title>` | **폐지.** 양성 대조군으로도 확인 |
| grep.app | 429 / Vercel Security Checkpoint | 차단 |
| searchcode API | 404 (엔드포인트 2종) | 폐지 |
| publicwww | 200이나 "Sign Up" | 유료 |
| Shodan·Censys 정식 API | 401 | 유료키. **InternetDB로 대체** |
| VirusTotal · HIBP 도메인검색 | 401 | 유료키 |
| Common Crawl | 작동하나 Wayback과 중복·파싱비용 과대 | 잔존 교차확인이 필요할 때만 |
| GH Archive | 작동하나 시간당 21MB | 삭제 저장소 이벤트 추적에만 |
| Postman 공개검색 API | 404 | dork로 대체 |
| Supabase·Vercel 프리뷰 열거 | DNS 없음 / 404 | **열거 불가.** 앱 소스에서 실제 ref를 얻어야 한다 |
