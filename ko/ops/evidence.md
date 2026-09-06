# 증거 처리

증거는 두 번째 노출을 만들지 않으면서 판단을 입증해야 한다. source에서 metadata를 캡처하고 log, model input, report, screenshot, export 전에 정화한다.

각 observation은 opaque ID, UTC time, policy/rule/tool version, anonymous mode, masked canonical locator, redirect observation, access/content/confidence, inspected bytes, completeness, digest type/value, stop reason, control result, evidence reference를 기록한다. raw artifact는 retention과 audit log가 있는 소유자 승인 encrypted/access-controlled system에만 둔다.

probe의 `target_id`는 기본적으로 무작위 `opaque:` 식별자다. 수행자가 `SUDETECT_LOCATOR_HMAC_KEY`를 명시적으로 설정하면 승인된 cross-run matching을 위한 안정적인 keyed `hmac-sha256:` 참조가 된다. locator의 plain hash는 쓰지 않는다. path, document ID, share token의 entropy가 낮을 수 있다. HMAC key는 report와 source control 밖에서 보호·회전한다. 같은 key가 없으면 무작위 opaque ID는 의도적으로 실행 간 상관할 수 없다.

로컬 locator handoff에서는 opaque store ref 자체가 측정 `target_id`다. recheck를 ledger에 넣기 전에 정확한 `policy_id`와 함께 바인딩한다. 변경·누락·불일치한 target/policy binding은 종결 증거가 아니다.

URL userinfo, path segment, query, fragment, header, cookie, redirect, console output, DOM text, filename, screenshot, HAR, trace를 정화한다. `<email>`, `<token>`, `<record-id>` 같은 placeholder로 구조를 보존한다. 안정적인 비밀 비교에는 접근통제된 keyed HMAC을 쓴다. entropy가 낮은 비밀의 plain hash는 값을 노출할 수 있다.

개인정보는 명단 대신 유형과 제한된 대략 건수를 기록한다. 비밀은 provider/type, 안전한 경우에만 masked prefix/suffix, location class, `live_validity=unknown`을 기록한다. audit process에서 로그인, data API 호출, secret 회전을 하지 않는다. 소유자 측 validity/rotation 증거는 별도 event다.

`0`과 `false`는 typed value로 남긴다. null, absent, empty string, redacted, truncated, not inspected를 구분한다. 모든 집계에 source, selection boundary, 조기 중단 여부를 적는다.

보고서는 confirmed fact, candidate, unknown, failure를 분리한다. 역할과 목적에 따라 접근을 제한하며 privacy, security, legal, HR, third-party recipient는 자기 작업에 필요한 최소 필드만 받는다.
