# Exposure ledger export

This Markdown is a review/export view. The SQLite ledger is the operational source of truth; observations and events are append-only.

## Finding

| Field | Value |
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

## Latest observation

| observation_id | observed_at | anonymous_mode | access | content | confidence | capture_complete | digest_kind/value | evidence_ref | control_id | stop_reason |
|---|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | | |

Allowed access values: `BODY_SERVED`, `ACCESS_DENIED_OBSERVED`, `AUTH_REDIRECT_OBSERVED`, `NOT_FOUND_OBSERVED`, `INDETERMINATE`.

Allowed content values: `PUBLIC_UI`, `SENSITIVE_CONTENT_CONFIRMED`, `SENSITIVE_CANDIDATE`, `CLIENT_ENCRYPTED_OBSERVED`, `NOT_INSPECTED`.

## Aliases and deployments

| alias_id | masked_locator | deployment_id | relationship_source | ownership_evidence | first_seen | last_checked | status |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

## Controls and proof

| control_id | purpose | expected | observed | observed_at | channel_status | evidence_ref |
|---|---|---|---|---|---|---|
| | | | | | | |

## Event and recheck history

| event_id | occurred_at | type | from_state | to_state | actor | reason/evidence_ref | next_due_at |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

Closure requires a new anonymous observation for every known live locator and completion of the declared residue scope. Unknown archive/cache/alias coverage produces `partially_closed`. Do not paste raw personal data, secrets, headers, or token-bearing URLs here.
