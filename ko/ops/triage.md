# 증거 기반 분류

접근과 내용을 분리한 뒤 분류한다. 심각도는 URL의 인상이 아니라 확정된 영향을 나타낸다.

| 등급 | 최소 근거 | 대응 |
|---|---|---|
| S | private credential/key material 또는 privileged secret 확정. 실제 유효성은 별도 | 중단, 증거 제한, 소유자 측 회전과 로그 검토 |
| A | 개인정보 또는 보호되는 개인 record 확정 | 중단, privacy escalation, 격리와 필요한 로그 보존 |
| B | 기밀 사업 내용 확정 | 격리, 소유자 통지, 계약·운영 영향 평가 |
| C | 비밀이나 보호 데이터가 확정되지 않은 내부 구조/configuration | 소유자 검토와 최소 공개 정리 |
| D | public UI/brand content 또는 보호 값이 확정되지 않은 후보 | 게시 의도·소유 기록, 노출 주장 없음 |

`SENSITIVE_CANDIDATE`는 확정 S/A/B finding이 아니다. 사람의 evidence review가 observation ID, masked proof reference, owner evidence, anonymous condition, reviewer, time과 함께 대장에 `SENSITIVE_CONTENT_CONFIRMED`를 기록한다. 실제 내용의 자동 classifier는 provisional이다. synthetic canary는 테스트에서 synthetic 전용 confirmed label을 낼 수 있지만 live proof로 쓰지 않는다.

content type, field name, document property, worksheet name, archive member name, masked example처럼 필요한 최소 metadata부터 본다. hidden sheet, failed redaction, document metadata, EXIF, embedded JSON, source map, hydration data, anonymous fetch는 정책과 예산이 허용할 때만 검사한다.

`0`과 `false`를 채워진 값으로 취급한다. null, empty, redacted, sampled, actual value를 구분한다. count와 fill rate도 원본 데이터를 처리하므로 sample/boundary, provenance, privacy purpose, access control, stop condition을 기록한다. 집계가 privacy 의무를 없앤다고 주장하지 않는다.

public/publishable key와 private/service-role secret의 영향은 다르다. 인증이나 데이터 접근을 시도하지 않고 유형과 문맥을 식별한다. client ciphertext만으로 보호 효과나 평문 노출을 확정하지 않는다.

조직 소유 자산은 책임 있는 service/data owner에게 보낸다. 직원 개인 계정의 자료는 승인된 security/takedown 경로로 처리하고 인사 조치와 분리한다. 제3자 자산은 추가 probing 없이 승인된 통지를 사용한다. 소유 미확정은 `ownership_pending`으로 둔다.
