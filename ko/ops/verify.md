# 익명 실측과 판정 규칙

실측은 **어떤 접근 동작을 관측했는가**와 **최소 내용 증거가 무엇을 확정했는가**를 분리해 답한다. URL 하나로 사이트 전체 보호를 추론하지 않는다.

## 접근

| 값 | 증거 |
|---|---|
| `BODY_SERVED` | transport가 2xx 응답을 관측했다(제한된 부분 캡처 206 포함). 실제 바이트가 없거나 public UI, error document, sensitive content일 수 있다. |
| `ACCESS_DENIED_OBSERVED` | transport가 이 요청에서 HTTP 401 또는 403을 관측했다. 상태 관측이며 실제 authorization boundary 확인이 아니다. |
| `AUTH_REDIRECT_OBSERVED` | 별도 classifier 또는 사람의 evidence review가 관측된 redirect를 authentication flow로 식별한다. 현재 probe는 IdP 비슷한 이름으로 이 값을 추론하지 않는다. 비승인 cross-origin redirect는 `INDETERMINATE`다. |
| `NOT_FOUND_OBSERVED` | transport가 이 요청에서 HTTP 404 또는 410을 관측했다. 상태 관측이며 resource 부재 확인이 아니다. |
| `INDETERMINATE` | timeout, DNS/TLS/policy/budget 실패, 부분적 미지원 동작, 모호한 challenge, 증거 부족이다. |

현재 probe JSON은 observation/time/policy ID, masked target reference, HTTP status, 승인된 redirect reference, access/content, 가능한 경우 captured bytes, completeness, full/prefix digest, 제한된 reason code를 기록한다. response content type과 resolved connection address는 일시적인 enforcement input이며 직렬화하지 않는다. downstream ledger는 evidence policy가 허용할 때 tool/rule version과 보호된 network metadata를 추가할 수 있다. 완전한 SHA-256은 전체 캡처에만 적용하고 일부 캡처는 `prefix_sha256`을 쓴다.

challenge/error-page indicator와 soft-404 의미 판단은 provisional classifier 또는 사람의 evidence review가 맡는다. content 해석을 바꾸거나 workflow를 pending으로 유지할 수 있지만 probe의 `ACCESS_DENIED_OBSERVED`와 `NOT_FOUND_OBSERVED`는 문자 그대로 상태 관측이다. 어느 값도 안전, authorization 정확성, resource 부재를 증명하지 않는다.

## 내용

| 값 | 증거 |
|---|---|
| `PUBLIC_UI` | 로그인 양식이나 공개 안내처럼 게시 의도가 있는 UI/내용임을 증거가 뒷받침한다. |
| `SENSITIVE_CONTENT_CONFIRMED` | 익명 응답의 보호 개인정보·기밀을 실제 최소 증거로 확인했다. observation과 ownership evidence가 필요하다. |
| `SENSITIVE_CANDIDATE` | parser, 이름, 필드, 문맥이 민감성을 시사하지만 실제 보호 값이나 소유가 확정되지 않았다. |
| `CLIENT_ENCRYPTED_OBSERVED` | 암호문만 관측했다. 평문/키 노출과 보호 효과는 별도 질문이다. |
| `NOT_INSPECTED` | 내용을 검사하지 않았거나 접근 결과만으로 판정할 수 없다. |

내용 확실성은 `confirmed`, `probable`, `unknown`이고 workflow 상태는 별도다. AI 설명은 evidence ID를 인용해야 하며 후보를 confirmed로 올릴 수 없다.

## 측정 순서

1. 만료되지 않은 정책을 로드·검증한다(`SUD-R05`~`SUD-R07`).
2. 연결 전에 exact origin, path boundary, owner, ownership evidence를 맞춘다. 측정 transport는 GET만 보낸다.
3. A/AAAA를 확인하고 비공개 주소를 거부하며 검증한 주소에 요청을 고정한다. 따라가는 redirect마다 반복한다.
4. 주변 자격증명/config, cookie, 별도 broker가 없는 proxy 상속, Referer, 자동 auth를 끈다(`SUD-R08`, `SUD-R09`).
5. redirect/request/time/captured-byte 예산을 적용한다(`SUD-R12`). transport는 identity encoding을 요청하고 non-identity content encoding은 unsupported로 표시한다. decompression budget을 주장하지 않는다.
6. 캡처 시점에 증거를 정화하고 적절한 대조군 뒤 음성을 해석한다(`SUD-R10`, `SUD-R13`).

예전 “weak gate” 재시도는 자동 실행하지 않는다. 401/403 뒤 다른 헤더로 2xx가 나와도 routing, 공개 UI, 데이터 중 무엇인지 알 수 없다. 실제 최소 민감 내용 증거만 노출을 확정한다.

## 브라우저 승격

정적 HTML이 shell이거나, JavaScript가 익명 데이터 요청을 시작하거나, hidden DOM/hydration data에 내용이 이미 있을 수 있거나, content type이 모호하면 승격한다. 새 context에는 저장 cookie, extension, cache, Service Worker state가 없다. navigation 전에 routing을 설치하고 지원되는 HTTP request를 정책으로 검사하며 미지원 동작은 측정하지 않는다.

`brokered_anonymous_browser`는 raw browser header, cookie, auth, referrer 없이 승인된 GET document/script/stylesheet/XHR/fetch를 pinned policy transport로 보낸다. Service Worker를 끄고 WebSocket server 연결을 막으며 message는 local sink에서 버린다. popup을 닫고 download를 거부하며 dead proxy와 blocked host resolving으로 Chromium을 실행해 지원되는 page request가 broker를 거치게 한다. WebSocket 시도는 `websocket_not_observed`로 기록되고 browser result를 incomplete로 만든다. DOM 검토에 candidate가 없을 때 제한된 live `input`, `textarea`, `select` 값도 검사한다. canvas pixel, serialized snapshot 밖 shadow DOM, JavaScript heap, interaction 이후 상태는 측정하지 않는다. password input은 `LOGIN_FORM_INDICATOR`만 만들며 `PUBLIC_UI`, 보호, 민감을 확정하지 않는다. 외부 protocol과 그 밖의 미지원 browser 동작은 측정하지 않고 `INDETERMINATE`로 둔다. 이는 observer 통제이며 OS firewall 보장이나 전체 egress 증거가 아니다.

브라우저는 response byte와 제한된 DOM snapshot을 일시적으로 분석한 뒤 raw DOM 없이 정화된 observation/classifier summary만 출력한다. screenshot, HAR, trace를 생성하지 않는다.

## 대조군과 재측정

타인의 데이터에 접근하지 않으면서 같은 채널을 시험하는 대조군을 고른다. 알려진 공개 endpoint, 설정된 missing path, 소유자 제공 보호 fixture가 예다. target과 control이 함께 실패하면 채널 실패로 기록한다. 변동 서비스는 제한된 반복 관측이 필요하며 무응답이나 변화 없음은 이벤트 미수신의 증거가 아니다.

새 익명 context로 정확한 원 locator, 알려진 모든 alias/deployment, 관련 cache, 승인된 archive channel을 확인한다. 동적 digest 변화만으로 조치 성공이나 재발을 증명하지 않는다. access/content 증거를 비교하고 잔존 unknown은 `partially_closed`로 둔다.

브라우저 결과의 `complete`는 정해진 범위의 수집과 자동 분석이 끝났다는 뜻이다. `content_review_complete`는 별도의 공개 의도·민감도 검토 근거가 생기기 전까지 false로 유지한다. 파서 완료나 탐지 신호 없음은 민감 정보 부재를 증명하지 않는다. identity encoding인 probe 응답이 잘렸다면 수집된 앞부분에서 잠정 신호를 보존할 수 있지만 `analysis_complete`와 `capture_complete`는 false다. 이 앞부분 분석을 위해 추가 내용을 요청하지 않는다.
