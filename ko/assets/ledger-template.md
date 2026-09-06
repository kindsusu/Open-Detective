# 노출 대장 내보내기

이 Markdown은 검토/내보내기 view다. SQLite 대장이 운영 source of truth이고 observation과 event는 append-only다.

## Finding

| 필드 | 값 |
|---|---|
| finding_id | |
| asset_id / endpoint_id | |
| owner / ownership_evidence | |
| masked_locator / protected_locator_ref | |
| severity | S / A / B / C / D / unassigned |
| workflow | candidate / ownership_pending / verification_pending / open / containment_pending / recheck_pending / partially_closed / closed / reopened |
| assignee / escalation_route | |
| action_due_at / recheck_due_at | |
| created_at / updated_at | |

## 최신 observation

| observation_id | observed_at | anonymous_mode | access | content | confidence | capture_complete | digest_kind/value | evidence_ref | control_id | stop_reason |
|---|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | | |

access 값: `BODY_SERVED`, `ACCESS_DENIED_OBSERVED`, `AUTH_REDIRECT_OBSERVED`, `NOT_FOUND_OBSERVED`, `INDETERMINATE`.

content 값: `PUBLIC_UI`, `SENSITIVE_CONTENT_CONFIRMED`, `SENSITIVE_CANDIDATE`, `CLIENT_ENCRYPTED_OBSERVED`, `NOT_INSPECTED`.

## Alias와 deployment

| alias_id | masked_locator | deployment_id | relationship_source | ownership_evidence | first_seen | last_checked | status |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

## Control과 proof

| control_id | purpose | expected | observed | observed_at | channel_status | evidence_ref |
|---|---|---|---|---|---|---|
| | | | | | | |

## Event와 recheck history

| event_id | occurred_at | type | from_state | to_state | actor | reason/evidence_ref | next_due_at |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

종결에는 알려진 모든 live locator의 새 익명 observation과 선언한 residue scope 완료가 필요하다. archive/cache/alias coverage가 unknown이면 `partially_closed`다. raw 개인정보, secret, header, token 포함 URL을 여기에 붙이지 않는다.
