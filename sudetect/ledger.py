"""SQLite append-only event ledger and current-state projections."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


_NS = uuid.UUID("0212cff4-d3b4-45b7-8e8d-c89771d1a8d9")
_ACCESS_VALUES = {"BODY_SERVED", "ACCESS_DENIED_OBSERVED", "AUTH_REDIRECT_OBSERVED", "NOT_FOUND_OBSERVED", "INDETERMINATE"}
_CONTENT_VALUES = {"PUBLIC_UI", "SENSITIVE_CONTENT_CONFIRMED", "SENSITIVE_CANDIDATE", "CLIENT_ENCRYPTED_OBSERVED", "NOT_INSPECTED"}
_CLOSURE_ACCESS = {"ACCESS_DENIED_OBSERVED", "AUTH_REDIRECT_OBSERVED", "NOT_FOUND_OBSERVED"}
_CLOSURE_CONTENT = {"NOT_INSPECTED", "PUBLIC_UI"}
_REOPEN_CONTENT = {"SENSITIVE_CONTENT_CONFIRMED", "SENSITIVE_CANDIDATE"}
_ENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_EVIDENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}:[A-Za-z0-9][A-Za-z0-9._/=-]{0,255}$")
_NORMAL_PROBE_REASONS = {None, "", "access_denied_status", "not_found_status", "response_observed"}
_CHALLENGE_SIGNALS = {"CHALLENGE_PAGE_INDICATOR", "WAF_CHALLENGE", "BOT_CHALLENGE"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _time(value: str | None, *, future_ok: bool = False) -> tuple[str, datetime]:
    if not isinstance(value, str) or not value:
        raise LedgerError("valid timestamp required")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        raise LedgerError("valid timestamp required") from None
    if parsed.tzinfo is None:
        raise LedgerError("timezone required")
    parsed = parsed.astimezone(timezone.utc)
    if not future_ok and parsed > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise LedgerError("future timestamp rejected")
    return parsed.isoformat().replace("+00:00", "Z"), parsed


def _evidence(value: str | None) -> str:
    if not isinstance(value, str) or not _EVIDENCE_RE.fullmatch(value):
        raise LedgerError("opaque evidence reference required")
    return value


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool): raise LedgerError(f"{name} must be boolean")
    return value


def _canonical(data: Mapping[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _id(prefix: str, *parts: object) -> str:
    return f"{prefix}_{uuid.uuid5(_NS, chr(31).join(map(str, parts))).hex}"


class LedgerError(ValueError):
    pass


class Ledger:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self._init()

    def __enter__(self) -> "Ledger": return self
    def __exit__(self, *args: object) -> None: self.close()
    def close(self) -> None: self.db.close()

    def _init(self) -> None:
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS events(
          sequence INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id TEXT NOT NULL UNIQUE, event_type TEXT NOT NULL,
          entity_id TEXT NOT NULL, occurred_at TEXT NOT NULL,
          payload_json TEXT NOT NULL, payload_hash TEXT NOT NULL
        );
        CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'events are append-only'); END;
        CREATE TABLE IF NOT EXISTS assets(asset_id TEXT PRIMARY KEY, provider TEXT, scope_id TEXT, required_aliases_json TEXT NOT NULL, updated_at TEXT NOT NULL, target_id TEXT, policy_id TEXT, alias_bindings_json TEXT NOT NULL DEFAULT '{"bindings":{}}', binding_changed_at TEXT);
        CREATE TABLE IF NOT EXISTS observations(observation_id TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES assets(asset_id), alias_id TEXT, observed_at TEXT NOT NULL, access TEXT NOT NULL, content TEXT NOT NULL, capture_complete INTEGER NOT NULL, expected_policy INTEGER NOT NULL, control_healthy INTEGER NOT NULL, evidence_ref TEXT NOT NULL, policy_evidence_ref TEXT, control_evidence_ref TEXT, reason_code TEXT, payload_hash TEXT NOT NULL, target_id TEXT, policy_id TEXT);
        CREATE TABLE IF NOT EXISTS findings(finding_id TEXT PRIMARY KEY, asset_id TEXT NOT NULL, status TEXT NOT NULL, opened_at TEXT NOT NULL, remediation_at TEXT, closed_at TEXT, evidence_ref TEXT, updated_at TEXT NOT NULL, closure_state_json TEXT);
        CREATE TABLE IF NOT EXISTS jobs(job_id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, due_at TEXT NOT NULL, state TEXT NOT NULL, attempt INTEGER NOT NULL, claim_token TEXT, lease_until TEXT, last_error TEXT, updated_at TEXT NOT NULL);
        """)
        asset_columns = {row["name"] for row in self.db.execute("PRAGMA table_info(assets)")}
        observation_columns = {row["name"] for row in self.db.execute("PRAGMA table_info(observations)")}
        finding_columns = {row["name"] for row in self.db.execute("PRAGMA table_info(findings)")}
        if "target_id" not in asset_columns:
            self.db.execute("ALTER TABLE assets ADD COLUMN target_id TEXT")
        if "policy_id" not in asset_columns:
            self.db.execute("ALTER TABLE assets ADD COLUMN policy_id TEXT")
        if "alias_bindings_json" not in asset_columns:
            self.db.execute("ALTER TABLE assets ADD COLUMN alias_bindings_json TEXT NOT NULL DEFAULT '{\"bindings\":{}}'")
        if "binding_changed_at" not in asset_columns:
            self.db.execute("ALTER TABLE assets ADD COLUMN binding_changed_at TEXT")
        if "target_id" not in observation_columns:
            self.db.execute("ALTER TABLE observations ADD COLUMN target_id TEXT")
        if "policy_id" not in observation_columns:
            self.db.execute("ALTER TABLE observations ADD COLUMN policy_id TEXT")
        if "closure_state_json" not in finding_columns:
            self.db.execute("ALTER TABLE findings ADD COLUMN closure_state_json TEXT")
        if not self.db.execute("PRAGMA foreign_key_list(observations)").fetchall():
            self.db.execute("""CREATE TABLE IF NOT EXISTS observations_quarantine AS
                SELECT *, '' AS quarantine_reason FROM observations WHERE 0""")
            self.db.execute("""INSERT INTO observations_quarantine
                SELECT o.*, 'UNKNOWN_ASSET' FROM observations o
                WHERE NOT EXISTS (SELECT 1 FROM assets a WHERE a.asset_id=o.asset_id)
                AND NOT EXISTS (SELECT 1 FROM observations_quarantine q WHERE q.observation_id=o.observation_id)""")
            self.db.execute("""CREATE TABLE observations_with_fk(
                observation_id TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES assets(asset_id), alias_id TEXT,
                observed_at TEXT NOT NULL, access TEXT NOT NULL, content TEXT NOT NULL, capture_complete INTEGER NOT NULL,
                expected_policy INTEGER NOT NULL, control_healthy INTEGER NOT NULL, evidence_ref TEXT NOT NULL,
                policy_evidence_ref TEXT, control_evidence_ref TEXT, reason_code TEXT, payload_hash TEXT NOT NULL,
                target_id TEXT, policy_id TEXT)""")
            self.db.execute("""INSERT INTO observations_with_fk SELECT o.* FROM observations o
                WHERE EXISTS (SELECT 1 FROM assets a WHERE a.asset_id=o.asset_id)""")
            self.db.execute("DROP TABLE observations")
            self.db.execute("ALTER TABLE observations_with_fk RENAME TO observations")
        legacy_absent_assets = {row[0] for row in self.db.execute("SELECT DISTINCT asset_id FROM observations WHERE access='ABSENT'")}
        # ABSENT predates the measured-access vocabulary. Keep the original
        # event, but quarantine the projection as an unverified observation.
        self.db.execute("UPDATE observations SET access='INDETERMINATE', reason_code=COALESCE(reason_code,'LEGACY_ACCESS_VALUE') WHERE access='ABSENT'")
        stale_closed = self.db.execute("""SELECT f.finding_id,f.asset_id FROM findings f JOIN assets a ON a.asset_id=f.asset_id
            WHERE f.status='CLOSED' AND (a.target_id IS NULL OR a.policy_id IS NULL OR f.asset_id IN
            (SELECT asset_id FROM observations WHERE reason_code='LEGACY_ACCESS_VALUE'))""").fetchall()
        migration_when = _now()
        for row in stale_closed:
            reason = "LEGACY_ABSENT_EVIDENCE" if row["asset_id"] in legacy_absent_assets else "LEGACY_UNBOUND_ASSET"
            eid = self._event("FINDING_REOPENED", row["finding_id"],
                              {"evidence_ref":f"migration:{row['finding_id']}","reason_code":reason},
                              occurred_at=migration_when)
            self.db.execute("""UPDATE findings SET status='RECHECK_PENDING',closed_at=NULL,evidence_ref=?,
                updated_at=?,closure_state_json=NULL WHERE finding_id=?""",
                (f"event:{eid}",migration_when,row["finding_id"]))
        self.db.commit()

    def _event(self, event_type: str, entity_id: str, payload: Mapping[str, Any], *, event_id: str | None = None, occurred_at: str | None = None) -> str:
        occurred_at = occurred_at or _now()
        body = _canonical(payload)
        digest = hashlib.sha256(body.encode()).hexdigest()
        event_id = event_id or _id("evt", event_type, entity_id, occurred_at, digest)
        try:
            self.db.execute("INSERT INTO events(event_id,event_type,entity_id,occurred_at,payload_json,payload_hash) VALUES(?,?,?,?,?,?)", (event_id,event_type,entity_id,occurred_at,body,digest))
        except sqlite3.IntegrityError:
            row = self.db.execute("SELECT event_type,entity_id,payload_hash FROM events WHERE event_id=?", (event_id,)).fetchone()
            if not row or (row["event_type"], row["entity_id"], row["payload_hash"]) != (event_type, entity_id, digest):
                raise LedgerError("event id collision")
        return event_id

    def register_asset(self, asset_id: str, *, provider: str, scope_id: str,
                       required_alias_ids: Sequence[str] = (), target_id: str | None = None,
                       policy_id: str | None = None,
                       alias_bindings: Mapping[str, str] | None = None,
                       event_id: str | None = None) -> str:
        if not _ENTITY_RE.fullmatch(asset_id) or not _ENTITY_RE.fullmatch(provider) or not _ENTITY_RE.fullmatch(scope_id): raise LedgerError("valid asset metadata required")
        if target_id is not None and not _ENTITY_RE.fullmatch(str(target_id)): raise LedgerError("valid target id required")
        if policy_id is not None and not _ENTITY_RE.fullmatch(str(policy_id)): raise LedgerError("valid policy id required")
        supplied_bindings = {str(key): str(value) for key, value in (alias_bindings or {}).items()}
        if any(not _ENTITY_RE.fullmatch(str(x)) for x in [*required_alias_ids, *supplied_bindings]): raise LedgerError("valid alias id required")
        if any(not _ENTITY_RE.fullmatch(value) for value in supplied_bindings.values()): raise LedgerError("valid alias target id required")
        aliases = sorted(set(str(x) for x in required_alias_ids) | set(supplied_bindings))
        existing = self.db.execute("SELECT * FROM assets WHERE asset_id=?", (asset_id,)).fetchone()
        old_aliases: set[str] = set()
        old_bindings: dict[str, str] = {}
        binding_changed = False
        if existing:
            old_aliases = set(json.loads(existing["required_aliases_json"])["aliases"])
            aliases = sorted(set(aliases) | old_aliases)
            old_bindings = dict(json.loads(existing["alias_bindings_json"] or '{"bindings":{}}').get("bindings", {}))
            if target_id is None: target_id = existing["target_id"]
            if policy_id is None: policy_id = existing["policy_id"]
        bindings = {**old_bindings, **supplied_bindings}
        if existing:
            binding_changed = (existing["scope_id"] != scope_id or existing["target_id"] != target_id or existing["policy_id"] != policy_id
                               or any(old_bindings.get(key) != value for key, value in supplied_bindings.items()))
        when = _now()
        binding_changed_at = ("1970-01-01T00:00:00Z" if not existing else
                              when if binding_changed or existing["binding_changed_at"] is None else existing["binding_changed_at"])
        payload = {"provider":provider,"scope_id":scope_id,"required_alias_ids":aliases,
                                  "target_id":target_id,"policy_id":policy_id,"alias_bindings":bindings}
        with self.db:
            eid = self._event("ASSET_REGISTERED", asset_id, payload, event_id=event_id, occurred_at=when)
            self.db.execute("""INSERT INTO assets(asset_id,provider,scope_id,required_aliases_json,updated_at,target_id,policy_id,alias_bindings_json,binding_changed_at)
                VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET provider=excluded.provider,scope_id=excluded.scope_id,
                required_aliases_json=excluded.required_aliases_json,updated_at=excluded.updated_at,target_id=excluded.target_id,
                policy_id=excluded.policy_id,alias_bindings_json=excluded.alias_bindings_json,binding_changed_at=excluded.binding_changed_at""",
                (asset_id,provider,scope_id,_canonical({"aliases":aliases}),when,target_id,policy_id,_canonical({"bindings":bindings}),binding_changed_at))
            newly_required = sorted(set(aliases) - old_aliases) if existing else []
            finding = self.db.execute("SELECT finding_id,status FROM findings WHERE asset_id=? ORDER BY opened_at DESC LIMIT 1", (asset_id,)).fetchone()
            if (newly_required or binding_changed) and finding and finding["status"] == "CLOSED":
                reopen_ref = f"event:{eid}"
                reason = "ASSET_BINDING_CHANGED" if binding_changed else "REQUIRED_ALIAS_ADDED"
                self._event("FINDING_REOPENED", finding["finding_id"], {"evidence_ref":reopen_ref,"reason_code":reason,"alias_ids":newly_required}, occurred_at=when)
                self.db.execute("UPDATE findings SET status='REOPENED',closed_at=NULL,evidence_ref=?,updated_at=? WHERE finding_id=?", (reopen_ref,when,finding["finding_id"]))
        return eid

    def add_observation(self, asset_id: str, *, verdict: str | None = None, access: str | None = None,
                        content: str = "NOT_INSPECTED", evidence_ref: str,
                        observed_at: str | None = None, alias_id: str | None = None,
                        target_id: str | None = None, policy_id: str | None = None,
                        healthy: bool | None = None, capture_complete: bool = True,
                        expected_policy: bool = False, policy_evidence_ref: str | None = None,
                        control_healthy: bool = False, control_evidence_ref: str | None = None,
                        reason_code: str | None = None, observation_id: str | None = None,
                        event_id: str | None = None) -> str:
        asset = self.db.execute("SELECT * FROM assets WHERE asset_id=?", (asset_id,)).fetchone()
        if not asset:
            raise LedgerError("asset missing")
        aliases = set(json.loads(asset["required_aliases_json"])["aliases"])
        if alias_id is not None and alias_id not in aliases:
            raise LedgerError("alias not registered")
        bindings = dict(json.loads(asset["alias_bindings_json"] or '{"bindings":{}}').get("bindings", {}))
        bound_target = bindings.get(alias_id) if alias_id is not None else asset["target_id"]
        target_id = target_id if target_id is not None else bound_target
        policy_id = policy_id if policy_id is not None else asset["policy_id"]
        if target_id is not None and not _ENTITY_RE.fullmatch(str(target_id)): raise LedgerError("valid target id required")
        if policy_id is not None and not _ENTITY_RE.fullmatch(str(policy_id)): raise LedgerError("valid policy id required")
        if bound_target is not None and target_id != bound_target: raise LedgerError("observation target binding mismatch")
        if asset["policy_id"] is not None and policy_id != asset["policy_id"]: raise LedgerError("observation policy binding mismatch")
        evidence_ref = _evidence(evidence_ref)
        observed_at, _ = _time(observed_at or _now())
        capture_complete = _boolean(capture_complete, "capture_complete")
        expected_policy = _boolean(expected_policy, "expected_policy")
        control_healthy = _boolean(control_healthy, "control_healthy")
        access = str(access or verdict or "INDETERMINATE").upper()
        content = str(content).upper()
        if access not in _ACCESS_VALUES: raise LedgerError("invalid access value")
        if content not in _CONTENT_VALUES: raise LedgerError("invalid content value")
        if policy_evidence_ref is not None: policy_evidence_ref = _evidence(policy_evidence_ref)
        if control_evidence_ref is not None: control_evidence_ref = _evidence(control_evidence_ref)
        observation_id = observation_id or _id("obs", asset_id, alias_id or "asset", observed_at, access, content, evidence_ref)
        payload = {"asset_id":asset_id,"observation_id":observation_id,"observed_at":observed_at,"alias_id":alias_id,
                   "target_id":target_id,"policy_id":policy_id,"access":access,"content":content,
                   "evidence_ref":evidence_ref,"capture_complete":capture_complete,"expected_policy":expected_policy,
                   "policy_evidence_ref":policy_evidence_ref,"control_healthy":control_healthy,
                   "control_evidence_ref":control_evidence_ref,"reason_code":reason_code}
        digest = hashlib.sha256(_canonical(payload).encode()).hexdigest()
        with self.db:
            self._event("OBSERVATION_ADDED", asset_id, payload, event_id=event_id, occurred_at=observed_at)
            existing = self.db.execute("SELECT payload_hash FROM observations WHERE observation_id=?", (observation_id,)).fetchone()
            if existing and existing["payload_hash"] != digest:
                raise LedgerError("observation id collision")
            self.db.execute("""INSERT OR IGNORE INTO observations(
                observation_id,asset_id,alias_id,observed_at,access,content,capture_complete,expected_policy,
                control_healthy,evidence_ref,policy_evidence_ref,control_evidence_ref,reason_code,payload_hash,target_id,policy_id)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (observation_id,asset_id,alias_id,observed_at,access,content,capture_complete,expected_policy,
                 control_healthy,evidence_ref,policy_evidence_ref,control_evidence_ref,reason_code,digest,target_id,policy_id))
            finding = self.db.execute("SELECT finding_id,status,remediation_at,closed_at,closure_state_json FROM findings WHERE asset_id=? ORDER BY opened_at DESC LIMIT 1", (asset_id,)).fetchone()
            closure_state = json.loads(finding["closure_state_json"] or "{}") if finding else {}
            baseline = closure_state.get(alias_id or "__asset__", {})
            is_current_or_newer = bool(baseline.get("observed_at")) and _time(observed_at)[1] >= _time(baseline["observed_at"])[1]
            if finding and finding["status"] == "CLOSED" and is_current_or_newer:
                unexpected_access = access not in _CLOSURE_ACCESS
                access_changed = bool(baseline) and access != baseline.get("access")
                incomplete = (not capture_complete or bool(reason_code) or not expected_policy or not control_healthy
                              or not policy_evidence_ref or not control_evidence_ref or content not in _CLOSURE_CONTENT)
                if content in _REOPEN_CONTENT or unexpected_access or access_changed or incomplete:
                    status = "REOPENED" if content in _REOPEN_CONTENT or unexpected_access or access_changed else "RECHECK_PENDING"
                    self._set_finding(finding["finding_id"], status, evidence_ref=evidence_ref,
                                      event_type="FINDING_REOPENED", when=observed_at)
        return observation_id

    def open_finding(self, asset_id: str, *, evidence_ref: str, finding_id: str | None = None, event_id: str | None = None) -> str:
        evidence_ref = _evidence(evidence_ref)
        if not self.db.execute("SELECT 1 FROM assets WHERE asset_id=?", (asset_id,)).fetchone():
            raise LedgerError("asset missing")
        when = _now(); finding_id = finding_id or _id("fnd", asset_id, when)
        with self.db:
            self._event("FINDING_OPENED", finding_id, {"asset_id":asset_id,"evidence_ref":evidence_ref}, event_id=event_id, occurred_at=when)
            self.db.execute("""INSERT OR IGNORE INTO findings(
                finding_id,asset_id,status,opened_at,remediation_at,closed_at,evidence_ref,updated_at,closure_state_json)
                VALUES(?,?,?,?,?,?,?,?,NULL)""", (finding_id,asset_id,"OPEN",when,None,None,evidence_ref,when))
        return finding_id

    def record_remediation(self, finding_id: str, *, evidence_ref: str, remediated_at: str | None = None, event_id: str | None = None) -> str:
        evidence_ref = _evidence(evidence_ref)
        when, _ = _time(remediated_at or _now())
        with self.db:
            eid = self._event("REMEDIATION_RECORDED", finding_id, {"evidence_ref":evidence_ref}, event_id=event_id, occurred_at=when)
            cur = self.db.execute("UPDATE findings SET status='RECHECK_PENDING',remediation_at=?,closed_at=NULL,evidence_ref=?,updated_at=?,closure_state_json=NULL WHERE finding_id=?", (when,evidence_ref,when,finding_id))
            if not cur.rowcount: raise LedgerError("unknown finding")
        return eid

    def _set_finding(self, finding_id: str, status: str, *, evidence_ref: str, event_type: str, when: str) -> str:
        eid = self._event(event_type, finding_id, {"evidence_ref":evidence_ref}, occurred_at=when)
        closed = when if status == "CLOSED" else None
        self.db.execute("UPDATE findings SET status=?,closed_at=?,evidence_ref=?,updated_at=? WHERE finding_id=?", (status,closed,evidence_ref,when,finding_id))
        return eid

    def close_finding(self, finding_id: str, *, evidence_ref: str, event_id: str | None = None) -> str:
        evidence_ref = _evidence(evidence_ref)
        finding = self.db.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        if not finding or not finding["remediation_at"]: raise LedgerError("remediation evidence required")
        asset = self.db.execute("SELECT * FROM assets WHERE asset_id=?", (finding["asset_id"],)).fetchone()
        if not asset: raise LedgerError("asset missing")
        aliases = json.loads(asset["required_aliases_json"])["aliases"]
        bindings = dict(json.loads(asset["alias_bindings_json"] or '{"bindings":{}}').get("bindings", {}))
        if not asset["target_id"] or not asset["policy_id"]:
            raise LedgerError("asset target and policy binding required")
        if not asset["binding_changed_at"]:
            raise LedgerError("asset binding review required")
        missing_bindings = [alias for alias in aliases if not bindings.get(alias)]
        if missing_bindings:
            raise LedgerError(f"alias target binding required: {missing_bindings[0]}")
        _, remediation_dt = _time(finding["remediation_at"])
        _, binding_dt = _time(asset["binding_changed_at"])
        evidence_floor = max(remediation_dt, binding_dt)
        observations = self.db.execute("SELECT * FROM observations WHERE asset_id=?", (finding["asset_id"],)).fetchall()
        after_remediation = [row for row in observations if _time(row["observed_at"])[1] > evidence_floor]
        latest: dict[str, list[sqlite3.Row]] = {}
        latest_times: dict[str, datetime] = {}
        # All observations in a latest-timestamp tie are closure evidence.  A
        # source with coarse timestamps cannot hide a conflicting observation
        # behind SQLite row order.
        for row in after_remediation:
            key = row["alias_id"] or "__asset__"
            observed_dt = _time(row["observed_at"])[1]
            if key not in latest_times or observed_dt > latest_times[key]:
                latest_times[key] = observed_dt
                latest[key] = [row]
            elif observed_dt == latest_times[key]:
                latest[key].append(row)
        # The primary/origin URL and every known alias are independent exposure
        # boundaries.  A healthy alias does not prove the origin is closed.
        required = ["__asset__", *aliases]
        closure_state: dict[str, dict[str, str]] = {}
        for alias in required:
            rows = latest.get(alias)
            if not rows: raise LedgerError(f"alias not rechecked: {alias}")
            expected_target = asset["target_id"] if alias == "__asset__" else bindings[alias]
            if len({(row["access"], row["content"]) for row in rows}) != 1:
                raise LedgerError(f"conflicting latest observations: {alias}")
            for row in rows:
                independent = (
                    row["policy_evidence_ref"] and row["control_evidence_ref"]
                    and row["policy_evidence_ref"] != row["control_evidence_ref"]
                    and row["policy_evidence_ref"] != row["evidence_ref"]
                    and row["control_evidence_ref"] != row["evidence_ref"]
                )
                binding_matches = row["target_id"] == expected_target and row["policy_id"] == asset["policy_id"]
                if not (
                    row["access"] in _CLOSURE_ACCESS and row["capture_complete"]
                    and row["expected_policy"] and row["control_healthy"] and independent
                    and row["content"] in _CLOSURE_CONTENT and not row["reason_code"]
                    and binding_matches
                ):
                    raise LedgerError(f"unsafe closure evidence: {alias}")
            closure_state[alias] = {"access": rows[0]["access"], "target_id": expected_target,
                                    "policy_id": asset["policy_id"], "observed_at": rows[0]["observed_at"],
                                    "observation_ids": sorted(row["observation_id"] for row in rows)}
        when = _now()
        with self.db:
            eid = self._event("FINDING_CLOSED", finding_id, {"evidence_ref":evidence_ref,"required_alias_ids":required}, event_id=event_id, occurred_at=when)
            self.db.execute("UPDATE findings SET status='CLOSED',closed_at=?,evidence_ref=?,updated_at=?,closure_state_json=? WHERE finding_id=?", (when,evidence_ref,when,_canonical(closure_state),finding_id))
        return eid

    def reopen_finding(self, finding_id: str, *, evidence_ref: str, event_id: str | None = None) -> str:
        evidence_ref = _evidence(evidence_ref)
        when = _now()
        with self.db:
            eid = self._event("FINDING_REOPENED", finding_id, {"evidence_ref":evidence_ref}, event_id=event_id, occurred_at=when)
            cur = self.db.execute("UPDATE findings SET status='REOPENED',closed_at=NULL,evidence_ref=?,updated_at=? WHERE finding_id=?", (evidence_ref,when,finding_id))
            if not cur.rowcount: raise LedgerError("unknown finding")
        return eid

    def enqueue_due(self, finding_id: str, due_at: str, *, job_id: str | None = None, event_id: str | None = None) -> str:
        due_at, _ = _time(due_at, future_ok=True)
        if not self.db.execute("SELECT 1 FROM findings WHERE finding_id=?", (finding_id,)).fetchone(): raise LedgerError("unknown finding")
        job_id = job_id or _id("job",finding_id,due_at); when=_now()
        with self.db:
            self._event("JOB_ENQUEUED",job_id,{"finding_id":finding_id,"due_at":due_at},event_id=event_id,occurred_at=when)
            self.db.execute("INSERT OR IGNORE INTO jobs VALUES(?,?,?,'PENDING',0,NULL,NULL,NULL,?)",(job_id,finding_id,due_at,when))
        return job_id

    def claim_due(self, *, now: str | None = None, worker_id: str = "local", lease_seconds: int = 300, event_id: str | None = None) -> dict[str, Any] | None:
        now, now_dt = _time(now or _now())
        if not worker_id or not 1 <= lease_seconds <= 86400: raise LedgerError("invalid claim settings")
        lease_until = (now_dt + timedelta(seconds=lease_seconds)).isoformat().replace("+00:00", "Z")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row=self.db.execute("SELECT * FROM jobs WHERE (state='PENDING' AND due_at<=?) OR (state='CLAIMED' AND lease_until<=?) ORDER BY due_at,job_id LIMIT 1",(now,now)).fetchone()
            if not row:
                self.db.commit(); return None
            token=_id("claim",row["job_id"],row["attempt"]+1,worker_id,now)
            changed=self.db.execute("UPDATE jobs SET state='CLAIMED',attempt=attempt+1,claim_token=?,lease_until=?,updated_at=? WHERE job_id=? AND ((state='PENDING' AND due_at<=?) OR (state='CLAIMED' AND lease_until<=?))",(token,lease_until,now,row["job_id"],now,now)).rowcount
            if changed != 1:
                self.db.rollback(); return None
            self._event("JOB_CLAIMED",row["job_id"],{"claim_token":token,"worker_id":worker_id,"attempt":row["attempt"]+1,"lease_until":lease_until},event_id=event_id,occurred_at=now)
            self.db.commit()
        except Exception:
            self.db.rollback(); raise
        return {"job_id":row["job_id"],"finding_id":row["finding_id"],"claim_token":token,"attempt":row["attempt"]+1,"lease_until":lease_until}

    def complete_due(self, job_id: str, *, claim_token: str, result_ref: str, event_id: str | None = None) -> bool:
        result_ref = _evidence(result_ref)
        when=_now()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row=self.db.execute("SELECT state,claim_token FROM jobs WHERE job_id=?",(job_id,)).fetchone()
            if not row: raise LedgerError("unknown job")
            if row["state"] == "COMPLETE": self.db.commit(); return False
            changed=self.db.execute("UPDATE jobs SET state='COMPLETE',lease_until=NULL,updated_at=? WHERE job_id=? AND state='CLAIMED' AND claim_token=?",(when,job_id,claim_token)).rowcount
            if changed != 1: raise LedgerError("invalid claim")
            self._event("JOB_COMPLETED",job_id,{"claim_token":claim_token,"result_ref":result_ref},event_id=event_id,occurred_at=when)
            self.db.commit()
        except Exception:
            self.db.rollback(); raise
        return True

    def retry_due(self, job_id: str, *, claim_token: str, due_at: str, error_code: str, event_id: str | None = None) -> bool:
        due_at, _ = _time(due_at, future_ok=True)
        if not error_code or len(error_code) > 64 or not error_code.replace("_", "").isalnum(): raise LedgerError("safe error code required")
        when=_now()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row=self.db.execute("SELECT state,claim_token FROM jobs WHERE job_id=?",(job_id,)).fetchone()
            if not row: raise LedgerError("unknown job")
            if row["state"] == "PENDING": self.db.commit(); return False
            changed=self.db.execute("UPDATE jobs SET state='PENDING',due_at=?,claim_token=NULL,lease_until=NULL,last_error=?,updated_at=? WHERE job_id=? AND state='CLAIMED' AND claim_token=?",(due_at,error_code,when,job_id,claim_token)).rowcount
            if changed != 1: raise LedgerError("invalid claim")
            self._event("JOB_RETRY_SCHEDULED",job_id,{"due_at":due_at,"error_code":error_code},event_id=event_id,occurred_at=when)
            self.db.commit()
        except Exception:
            self.db.rollback(); raise
        return True

    def list_findings(self, status: str | None = None) -> list[dict[str, Any]]:
        query="SELECT * FROM findings"; params:tuple[Any,...]=()
        if status: query += " WHERE status=?"; params=(status,)
        return [dict(row) for row in self.db.execute(query+" ORDER BY opened_at,finding_id",params)]

    def due_jobs(self, now: str | None = None) -> list[dict[str, Any]]:
        now, _ = _time(now or _now())
        return [dict(row) for row in self.db.execute("SELECT * FROM jobs WHERE (state='PENDING' AND due_at<=?) OR (state='CLAIMED' AND lease_until<=?) ORDER BY due_at,job_id",(now,now))]

    def import_observation(self, payload: Mapping[str, Any], *, asset_id: str | None = None, alias_id: str | None = None, expected_policy: bool | None = None, policy_evidence_ref: str | None = None, control_healthy: bool | None = None, control_evidence_ref: str | None = None, event_id: str | None = None) -> str:
        """Import normalized ledger data or the JSON emitted by ``sudetect probe``."""
        mode = payload.get("mode")
        browser_mode = mode == "brokered_anonymous_browser"
        normalized = dict(payload)
        forced_reason_code: str | None = None
        if browser_mode:
            children = payload.get("observations")
            blocked = payload.get("blocked")
            mains = [item for item in children if isinstance(item, Mapping) and item.get("is_main_document") is True] if isinstance(children, list) else []
            source_target = payload.get("target_id")
            source_policy = payload.get("policy_id")
            child_items = [item for item in children if isinstance(item, Mapping)] if isinstance(children, list) else []
            main_matches = (len(mains) == 1 and mains[0].get("target_id") == source_target
                            and mains[0].get("policy_id") == source_policy)
            all_resources_complete = bool(child_items) and all(
                item.get("capture_complete") is True and item.get("analysis_complete") is True
                and item.get("policy_id") == source_policy for item in child_items
            )
            aggregate_complete = (
                payload.get("complete") is True and payload.get("capture_complete") is True
                and payload.get("analysis_complete") is True and all_resources_complete
                and isinstance(blocked, list) and not blocked and payload.get("reason") == "bounded_observation_completed"
                and main_matches
            )
            content_values = [item.get("content") for item in child_items]
            content_values.append(payload.get("content"))
            signal_codes = {
                signal.get("code") if isinstance(signal, Mapping) else signal
                for item in child_items for signal in (item.get("signals") if isinstance(item.get("signals"), list) else [])
            }
            sensitive_confirmed = (any(value in {"SENSITIVE_CONTENT_CONFIRMED", "SYNTHETIC_CONTENT_CONFIRMED"} for value in content_values)
                                   or "SYNTHETIC_CANARY_PRESENT" in signal_codes)
            sensitive_candidate = "SENSITIVE_CANDIDATE" in content_values or bool(signal_codes & {"SENSITIVE_FIELD_NAMES", "SENSITIVE_VALUES_CANDIDATE"})
            normalized["access"] = mains[0].get("access", payload.get("access")) if mains else payload.get("access")
            normalized["content"] = ("SENSITIVE_CONTENT_CONFIRMED" if sensitive_confirmed else
                                     "SENSITIVE_CANDIDATE" if sensitive_candidate else
                                     payload.get("content") or (mains[0].get("content") if mains else None))
            normalized["capture_complete"] = aggregate_complete
            normalized["analysis_complete"] = aggregate_complete
            normalized["reason"] = "response_observed" if aggregate_complete else "browser_observation_incomplete"
            forced_reason_code = None if aggregate_complete else "PROBE_INCOMPLETE"
        payload = normalized
        asset_id = asset_id or payload.get("asset_id")
        access = payload.get("access") or payload.get("verdict")
        if not asset_id or not access or not payload.get("observation_id"): raise LedgerError("invalid observation")
        asset = self.db.execute("SELECT * FROM assets WHERE asset_id=?", (str(asset_id),)).fetchone()
        if not asset: raise LedgerError("asset missing")
        selected_alias = alias_id if alias_id is not None else payload.get("alias_id")
        source_target = payload.get("target_id")
        source_policy = payload.get("policy_id")
        if not isinstance(source_target, str) or not isinstance(source_policy, str):
            raise LedgerError("observation target and policy binding required")
        bindings = dict(json.loads(asset["alias_bindings_json"] or '{"bindings":{}}').get("bindings", {}))
        expected_target = bindings.get(selected_alias) if selected_alias is not None else asset["target_id"]
        if expected_target is None or asset["policy_id"] is None:
            raise LedgerError("asset target and policy binding required")
        if source_target != expected_target: raise LedgerError("observation target binding mismatch")
        if source_policy != asset["policy_id"]: raise LedgerError("observation policy binding mismatch")
        observation_id = str(payload["observation_id"])
        evidence_ref = str(payload.get("evidence_ref") or f"observation:{observation_id}")
        reason = payload.get("reason_code") or payload.get("reason")
        signals = payload.get("signals") if isinstance(payload.get("signals"), list) else []
        signal_codes = {
            item.get("code") if isinstance(item, Mapping) else item
            for item in signals if isinstance(item, (str, Mapping))
        }
        # Probe error text is untrusted diagnostic input.  Retain only a stable
        # code indicating that a reason existed; never store or echo its text.
        analysis_incomplete = payload.get("analysis_complete") is False
        reason_code = forced_reason_code or ("CHALLENGE_OBSERVED" if signal_codes & _CHALLENGE_SIGNALS else ("PROBE_INCOMPLETE" if analysis_incomplete or reason not in _NORMAL_PROBE_REASONS else None))
        return self.add_observation(
            str(asset_id), access=str(access), content=str(payload.get("content") or "NOT_INSPECTED"),
            evidence_ref=evidence_ref, observed_at=payload.get("observed_at"),
            alias_id=selected_alias, target_id=source_target, policy_id=source_policy,
            capture_complete=payload.get("capture_complete") if isinstance(payload.get("capture_complete"), bool) else False,
            expected_policy=(payload.get("expected_policy") if isinstance(payload.get("expected_policy"), bool) else False) if expected_policy is None else expected_policy, policy_evidence_ref=policy_evidence_ref or payload.get("policy_evidence_ref"),
            control_healthy=(payload.get("control_healthy") if isinstance(payload.get("control_healthy"), bool) else False) if control_healthy is None else control_healthy, control_evidence_ref=control_evidence_ref or payload.get("control_evidence_ref"),
            reason_code=reason_code, observation_id=observation_id, event_id=event_id,
        )


def main(argv: Iterable[str] | None = None) -> int:
    parser=argparse.ArgumentParser(description="Append-only finding ledger")
    parser.add_argument("--db",required=True); sub=parser.add_subparsers(dest="command",required=True)
    sub.add_parser("init")
    reg=sub.add_parser("register"); reg.add_argument("asset_id"); reg.add_argument("--provider",required=True); reg.add_argument("--scope-id",required=True); reg.add_argument("--target-id"); reg.add_argument("--policy-id"); reg.add_argument("--alias-id",action="append",default=[]); reg.add_argument("--alias-binding",action="append",default=[],metavar="ALIAS=TARGET"); reg.add_argument("--event-id")
    opn=sub.add_parser("open"); opn.add_argument("asset_id"); opn.add_argument("--evidence-ref",required=True); opn.add_argument("--finding-id"); opn.add_argument("--event-id")
    rem=sub.add_parser("remediate"); rem.add_argument("finding_id"); rem.add_argument("--evidence-ref",required=True); rem.add_argument("--at"); rem.add_argument("--event-id")
    imp=sub.add_parser("import-observation"); imp.add_argument("--input",required=True); imp.add_argument("--asset-id"); imp.add_argument("--alias-id"); imp.add_argument("--expected-policy",action="store_true",default=None); imp.add_argument("--policy-evidence-ref"); imp.add_argument("--control-healthy",action="store_true",default=None); imp.add_argument("--control-evidence-ref"); imp.add_argument("--event-id")
    ls=sub.add_parser("list"); ls.add_argument("--status")
    due=sub.add_parser("due"); due.add_argument("--now")
    sched=sub.add_parser("schedule"); sched.add_argument("finding_id"); sched.add_argument("--due-at",required=True); sched.add_argument("--job-id"); sched.add_argument("--event-id")
    claim=sub.add_parser("claim"); claim.add_argument("--now"); claim.add_argument("--worker-id",default="local"); claim.add_argument("--lease-seconds",type=int,default=300); claim.add_argument("--event-id")
    done=sub.add_parser("complete"); done.add_argument("job_id"); done.add_argument("--claim-token",required=True); done.add_argument("--result-ref",required=True); done.add_argument("--event-id")
    retry=sub.add_parser("retry"); retry.add_argument("job_id"); retry.add_argument("--claim-token",required=True); retry.add_argument("--due-at",required=True); retry.add_argument("--error-code",required=True); retry.add_argument("--event-id")
    close=sub.add_parser("close"); close.add_argument("finding_id"); close.add_argument("--evidence-ref",required=True); close.add_argument("--event-id")
    reopen=sub.add_parser("reopen"); reopen.add_argument("finding_id"); reopen.add_argument("--evidence-ref",required=True); reopen.add_argument("--event-id")
    args=parser.parse_args(list(argv) if argv is not None else None)
    try:
        with Ledger(args.db) as ledger:
            if args.command=="init": result={"initialized":True}
            elif args.command=="register":
                bindings: dict[str, str] = {}
                for item in args.alias_binding:
                    if "=" not in item: raise LedgerError("alias binding must be ALIAS=TARGET")
                    alias, target = item.split("=", 1)
                    if not alias or not target or alias in bindings: raise LedgerError("invalid alias binding")
                    bindings[alias] = target
                result={"event_id":ledger.register_asset(args.asset_id,provider=args.provider,scope_id=args.scope_id,
                    required_alias_ids=args.alias_id,target_id=args.target_id,policy_id=args.policy_id,
                    alias_bindings=bindings,event_id=args.event_id)}
            elif args.command=="open": result={"finding_id":ledger.open_finding(args.asset_id,evidence_ref=args.evidence_ref,finding_id=args.finding_id,event_id=args.event_id)}
            elif args.command=="remediate": result={"event_id":ledger.record_remediation(args.finding_id,evidence_ref=args.evidence_ref,remediated_at=args.at,event_id=args.event_id)}
            elif args.command=="import-observation": result={"observation_id":ledger.import_observation(json.loads(Path(args.input).read_text(encoding="utf-8")),asset_id=args.asset_id,alias_id=args.alias_id,expected_policy=args.expected_policy,policy_evidence_ref=args.policy_evidence_ref,control_healthy=args.control_healthy,control_evidence_ref=args.control_evidence_ref,event_id=args.event_id)}
            elif args.command=="list": result={"findings":ledger.list_findings(args.status)}
            elif args.command=="due": result={"jobs":ledger.due_jobs(args.now)}
            elif args.command=="schedule": result={"job_id":ledger.enqueue_due(args.finding_id,args.due_at,job_id=args.job_id,event_id=args.event_id)}
            elif args.command=="claim": result={"job":ledger.claim_due(now=args.now,worker_id=args.worker_id,lease_seconds=args.lease_seconds,event_id=args.event_id)}
            elif args.command=="complete": result={"changed":ledger.complete_due(args.job_id,claim_token=args.claim_token,result_ref=args.result_ref,event_id=args.event_id)}
            elif args.command=="retry": result={"changed":ledger.retry_due(args.job_id,claim_token=args.claim_token,due_at=args.due_at,error_code=args.error_code,event_id=args.event_id)}
            elif args.command=="reopen": result={"event_id":ledger.reopen_finding(args.finding_id,evidence_ref=args.evidence_ref,event_id=args.event_id)}
            else: result={"event_id":ledger.close_finding(args.finding_id,evidence_ref=args.evidence_ref,event_id=args.event_id)}
        json.dump(result,sys.stdout,ensure_ascii=False,sort_keys=True);sys.stdout.write("\n");return 0
    except (LedgerError,OSError,json.JSONDecodeError) as exc:
        json.dump({"error":"LEDGER_OPERATION_FAILED"},sys.stdout,sort_keys=True);sys.stdout.write("\n");return 2


if __name__ == "__main__": raise SystemExit(main())
