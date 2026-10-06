"""Persistent audit queue sharing Ledger's SQLite connection and event stream.

Budgets are per run. A new run has fresh limits; prior consumption remains in
audit_runs and is reported separately. A reservation represents actual work,
never an estimate. Workers must reserve immediately before each real request.
"""

from __future__ import annotations

import json
import math
import re
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from .ledger import Ledger, LedgerError, _now


STATES = frozenset({"pending", "ready", "running", "retry_wait", "blocked_scope", "blocked_input", "succeeded", "failed_terminal", "cancelled"})
FINAL = frozenset({"succeeded", "failed_terminal", "cancelled"})
CLAIMABLE = frozenset({"ready", "retry_wait"})
LIMITS = {"max_requests": 100, "max_download_bytes": 50_000_000,
          "max_analysis_bytes": 50_000_000, "max_seconds": 3600,
          "max_attempts": 3, "max_jobs": 1000}
_IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_REASONS = frozenset({"no_ready_work", "budget_exhausted", "time_exhausted", "jobs_exhausted", "scope_expired",
                      "ready_exhausted", "input_required", "environment_failure", "user_stop"})


def _stamp(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError):
        raise LedgerError("valid timezone-aware timestamp required") from None


def _integer(value: Any, name: str, *, zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < (0 if zero else 1):
        raise LedgerError(f"{name} must be a finite {'nonnegative' if zero else 'positive'} integer")
    return value


def _json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        raise LedgerError("JSON-serializable finite value required") from None


class Scheduler:
    """Audit jobs/runs projected beside Ledger tables in the same database."""

    def __init__(self, ledger: Ledger):
        self.ledger = ledger
        self.db = ledger.db
        case_file = Path(ledger.path).parent / "case.json"
        self.case_id = ledger.path
        if case_file.is_file() and not case_file.is_symlink():
            try:
                candidate = json.loads(case_file.read_text(encoding="utf-8")).get("case_id")
                if isinstance(candidate, str) and candidate:
                    self.case_id = candidate
            except (OSError, ValueError, TypeError):
                pass
        self.db.execute("PRAGMA busy_timeout=5000")
        self._monotonic_starts: dict[str, float] = {}
        with self.db:
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS audit_jobs(
              job_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, job_type TEXT NOT NULL,
              asset_ref TEXT NOT NULL, dedupe_key TEXT NOT NULL UNIQUE,
              parent_job_id TEXT, origin_evidence_ref TEXT, scope_id TEXT NOT NULL,
              policy_id TEXT, capabilities_required TEXT NOT NULL, state TEXT NOT NULL,
              priority INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
              next_eligible_at TEXT, estimated_cost INTEGER NOT NULL,
              actual_cost TEXT NOT NULL DEFAULT '{"requests":0,"download_bytes":0,"analysis_bytes":0}',
              checkpoint TEXT, last_error_code TEXT, lease_owner TEXT,
              lease_expires_at TEXT, result_refs TEXT NOT NULL DEFAULT '[]',
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              FOREIGN KEY(parent_job_id) REFERENCES audit_jobs(job_id)
            );
            CREATE INDEX IF NOT EXISTS audit_jobs_claim ON audit_jobs(state,next_eligible_at,priority);
            CREATE TABLE IF NOT EXISTS audit_runs(
              run_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, state TEXT NOT NULL,
              started_at TEXT NOT NULL, last_checked_at TEXT NOT NULL, ended_at TEXT,
              reason TEXT, budget_json TEXT NOT NULL, requests INTEGER NOT NULL DEFAULT 0,
              download_bytes INTEGER NOT NULL DEFAULT 0,
              analysis_bytes INTEGER NOT NULL DEFAULT 0, jobs_claimed INTEGER NOT NULL DEFAULT 0
            );
            """)

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.rollback()
            raise
        else:
            self.db.commit()

    def _event(self, kind: str, entity: str, payload: Mapping[str, Any]) -> None:
        self.ledger._event(kind, entity, payload)

    def _job(self, row: Any) -> dict[str, Any]:
        result = dict(row)
        for key in ("capabilities_required", "actual_cost", "checkpoint", "result_refs"):
            result[key] = json.loads(result[key]) if result[key] is not None else None
        return result

    def _run(self, row: Any) -> dict[str, Any]:
        result = dict(row)
        result["budget"] = json.loads(result.pop("budget_json"))
        return result

    def enqueue(self, job_type: str, asset_ref: str, *, scope_id: str,
                policy_id: str | None = None, parent_job_id: str | None = None,
                origin_evidence_ref: str | None = None, capabilities_required: tuple[str, ...] = (),
                priority: int = 0, estimated_cost: int = 1, state: str = "ready",
                dedupe_key: str | None = None, checkpoint: Any = None) -> str:
        for name, value in (("job_type", job_type), ("asset_ref", asset_ref), ("scope_id", scope_id)):
            if not isinstance(value, str) or not _IDENT.fullmatch(value):
                raise LedgerError(f"valid {name} required")
        if policy_id is not None and (not isinstance(policy_id, str) or not _IDENT.fullmatch(policy_id)):
            raise LedgerError("valid policy_id required")
        if origin_evidence_ref is not None and (not isinstance(origin_evidence_ref, str) or not _IDENT.fullmatch(origin_evidence_ref)):
            raise LedgerError("valid origin_evidence_ref required")
        if state not in STATES - {"running"}:
            raise LedgerError("invalid initial job state")
        if isinstance(priority, bool) or not isinstance(priority, int):
            raise LedgerError("priority must be integer")
        _integer(estimated_cost, "estimated_cost")
        if isinstance(capabilities_required, (str, bytes)) or any(not isinstance(c, str) or not _IDENT.fullmatch(c) for c in capabilities_required):
            raise LedgerError("valid capabilities_required required")
        caps = sorted(set(capabilities_required))
        checkpoint_json = _json(checkpoint) if checkpoint is not None else None
        key = dedupe_key or f"{scope_id}:{job_type}:{asset_ref}:{policy_id or ''}:{parent_job_id or ''}"
        if not isinstance(key, str) or not key or len(key) > 512:
            raise LedgerError("valid dedupe_key required")
        with self._transaction():
            existing = self.db.execute("SELECT * FROM audit_jobs WHERE dedupe_key=?", (key,)).fetchone()
            if existing:
                if (existing["job_type"], existing["asset_ref"], existing["scope_id"]) != (job_type, asset_ref, scope_id):
                    raise LedgerError("dedupe key collision")
                if state == "ready" and existing["state"] in {"pending", "blocked_scope", "blocked_input"}:
                    when = _now()
                    self.db.execute("UPDATE audit_jobs SET state='ready',next_eligible_at=NULL,updated_at=? WHERE job_id=?", (when, existing["job_id"]))
                    self._event("AUDIT_JOB_RESUMED", existing["job_id"], {"state": "ready", "checkpoint": json.loads(existing["checkpoint"]) if existing["checkpoint"] else None})
                return existing["job_id"]
            if parent_job_id and not self.db.execute("SELECT 1 FROM audit_jobs WHERE job_id=?", (parent_job_id,)).fetchone():
                raise LedgerError("parent job missing")
            job_id = f"aj_{uuid.uuid4().hex}"
            when = _now()
            self.db.execute("""INSERT INTO audit_jobs(job_id,case_id,job_type,asset_ref,dedupe_key,parent_job_id,
                origin_evidence_ref,scope_id,policy_id,capabilities_required,state,priority,estimated_cost,
                checkpoint,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (job_id, self.case_id, job_type, asset_ref, key, parent_job_id, origin_evidence_ref,
                 scope_id, policy_id, _json(caps), state, priority, estimated_cost, checkpoint_json, when, when))
            self._event("AUDIT_JOB_ENQUEUED", job_id, {"job_type": job_type, "asset_ref": asset_ref,
                "dedupe_key": key, "scope_id": scope_id, "state": state, "checkpoint": checkpoint})
            return job_id

    def start_run(self, budget: dict[str, Any]) -> str:
        if not isinstance(budget, dict) or set(budget) - set(LIMITS):
            raise LedgerError("invalid budget keys")
        limits = {**LIMITS, **budget}
        for name, value in limits.items():
            if name == "max_seconds":
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                    raise LedgerError("max_seconds must be finite and positive")
            else:
                _integer(value, name)
        run_id = f"ar_{uuid.uuid4().hex}"
        when = _now()
        with self._transaction():
            self.db.execute("INSERT INTO audit_runs(run_id,case_id,state,started_at,last_checked_at,budget_json) VALUES(?,?,?,?,?,?)",
                            (run_id, self.case_id, "running", when, when, _json(limits)))
            self._event("AUDIT_RUN_STARTED", run_id, {"budget": limits})
        self._monotonic_starts[run_id] = time.monotonic()
        return run_id

    def _checked_run(self, run_id: str) -> dict[str, Any]:
        row = self.db.execute("SELECT * FROM audit_runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise LedgerError("run missing")
        run = self._run(row)
        wall = datetime.now(timezone.utc)
        last = datetime.fromisoformat(run["last_checked_at"].replace("Z", "+00:00"))
        now = max(wall, last)
        start = datetime.fromisoformat(run["started_at"].replace("Z", "+00:00"))
        elapsed = max(0.0, (now - start).total_seconds())
        if run_id in self._monotonic_starts:
            elapsed = max(elapsed, time.monotonic() - self._monotonic_starts[run_id])
        checked_at = now.isoformat().replace("+00:00", "Z")
        if checked_at != run["last_checked_at"]:
            self.db.execute("UPDATE audit_runs SET last_checked_at=? WHERE run_id=?", (checked_at, run_id))
        run["elapsed_seconds"] = elapsed
        run["last_checked_at"] = checked_at
        return run

    def _active(self, run: dict[str, Any]) -> bool:
        if run["state"] != "running":
            return False
        if run["elapsed_seconds"] >= run["budget"]["max_seconds"]:
            self._end(run["run_id"], "time_exhausted")
            return False
        return True

    def _end(self, run_id: str, reason: str) -> None:
        when = _now()
        changed = self.db.execute("UPDATE audit_runs SET state='ended',reason=?,ended_at=? WHERE run_id=? AND state='running'", (reason, when, run_id)).rowcount
        if changed:
            self._event("AUDIT_RUN_ENDED", run_id, {"reason": reason})

    def claim(self, run_id: str, worker_id: str = "local", lease_seconds: int = 300) -> dict[str, Any] | None:
        _integer(lease_seconds, "lease_seconds")
        if not isinstance(worker_id, str) or not _IDENT.fullmatch(worker_id):
            raise LedgerError("valid worker_id required")
        with self._transaction():
            run = self._checked_run(run_id)
            if not self._active(run):
                return None
            if run["jobs_claimed"] >= run["budget"]["max_jobs"]:
                self._end(run_id, "jobs_exhausted")
                return None
            now = _now()
            for row in self.db.execute("SELECT job_id,attempts FROM audit_jobs WHERE state='running' AND lease_expires_at<=?", (now,)).fetchall():
                new_state = "failed_terminal" if row["attempts"] >= run["budget"]["max_attempts"] else "ready"
                self.db.execute("UPDATE audit_jobs SET state=?,lease_owner=NULL,lease_expires_at=NULL,last_error_code='LEASE_EXPIRED',updated_at=? WHERE job_id=?", (new_state, now, row["job_id"]))
                self._event("AUDIT_LEASE_EXPIRED", row["job_id"], {"state": new_state, "reason_code": "LEASE_EXPIRED"})
            remaining = run["budget"]["max_requests"] - run["requests"]
            rows = self.db.execute("""SELECT j.* FROM audit_jobs j
                WHERE j.state IN ('ready','retry_wait') AND (j.next_eligible_at IS NULL OR j.next_eligible_at<=?)
                ORDER BY (j.priority + CAST((julianday(?) - julianday(j.created_at))*24 AS INTEGER)) DESC,
                         j.created_at,j.job_id""", (now, now)).fetchall()
            for row in rows:
                if row["estimated_cost"] > remaining:
                    continue
                if row["attempts"] >= run["budget"]["max_attempts"]:
                    self.db.execute("UPDATE audit_jobs SET state='failed_terminal',last_error_code='ATTEMPTS_EXHAUSTED',updated_at=? WHERE job_id=?", (now, row["job_id"]))
                    self._event("AUDIT_JOB_FINISHED", row["job_id"], {"state": "failed_terminal", "reason_code": "ATTEMPTS_EXHAUSTED"})
                    continue
                token = f"lease_{uuid.uuid4().hex}"
                expires = (datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)).isoformat().replace("+00:00", "Z")
                self.db.execute("""UPDATE audit_jobs SET state='running',attempts=attempts+1,lease_owner=?,
                    lease_expires_at=?,updated_at=? WHERE job_id=?""", (token, expires, now, row["job_id"]))
                self.db.execute("UPDATE audit_runs SET jobs_claimed=jobs_claimed+1 WHERE run_id=?", (run_id,))
                self._event("AUDIT_JOB_CLAIMED", row["job_id"], {"run_id": run_id, "worker_id": worker_id,
                    "lease_owner": token, "lease_expires_at": expires, "attempt": row["attempts"] + 1,
                    "checkpoint": json.loads(row["checkpoint"]) if row["checkpoint"] else None})
                return self._job(self.db.execute("SELECT * FROM audit_jobs WHERE job_id=?", (row["job_id"],)).fetchone())
            return None

    def reserve(self, run_id: str, *, requests: int = 0, download_bytes: int = 0, analysis_bytes: int = 0) -> bool:
        amounts = {"requests": requests, "download_bytes": download_bytes, "analysis_bytes": analysis_bytes}
        for name, value in amounts.items():
            _integer(value, name, zero=True)
        with self._transaction():
            run = self._checked_run(run_id)
            if not self._active(run):
                return False
            if any(run[key] + value > run["budget"][f"max_{key}"] for key, value in amounts.items()):
                return False
            self.db.execute("""UPDATE audit_runs SET requests=requests+?,download_bytes=download_bytes+?,
                analysis_bytes=analysis_bytes+? WHERE run_id=?""",
                (requests, download_bytes, analysis_bytes, run_id))
            # The public API has no job argument. Attribute only when exactly one
            # job is leased; with parallel workers the run totals remain exact.
            active = self.db.execute("SELECT job_id,actual_cost FROM audit_jobs WHERE state='running' AND lease_expires_at>?", (_now(),)).fetchall()
            if len(active) == 1:
                cost = json.loads(active[0]["actual_cost"])
                for key, value in amounts.items():
                    cost[key] += value
                self.db.execute("UPDATE audit_jobs SET actual_cost=? WHERE job_id=?", (_json(cost), active[0]["job_id"]))
            self._event("AUDIT_BUDGET_RESERVED", run_id, amounts)
            return True

    def finish(self, job_id: str, lease_owner: str, *, state: str = "succeeded",
               result_refs: tuple[str, ...] = (), checkpoint: Any = None,
               error_code: str | None = None, next_eligible_at: str | None = None) -> bool:
        if state not in STATES - {"running", "ready", "pending"}:
            raise LedgerError("invalid finish state")
        if isinstance(result_refs, (str, bytes)) or any(not isinstance(ref, str) or not _IDENT.fullmatch(ref) for ref in result_refs):
            raise LedgerError("valid result_refs required")
        if error_code is not None and (not isinstance(error_code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", error_code)):
            raise LedgerError("safe error_code required")
        eligible = _stamp(next_eligible_at)
        if state == "retry_wait" and eligible is None:
            raise LedgerError("retry_wait requires next_eligible_at")
        checkpoint_json = _json(checkpoint) if checkpoint is not None else None
        with self._transaction():
            row = self.db.execute("SELECT * FROM audit_jobs WHERE job_id=?", (job_id,)).fetchone()
            if row is None or row["state"] != "running" or row["lease_owner"] != lease_owner or row["lease_expires_at"] <= _now():
                return False
            refs = list(dict.fromkeys([*json.loads(row["result_refs"]), *result_refs]))
            saved_checkpoint = checkpoint_json if checkpoint is not None else row["checkpoint"]
            now = _now()
            self.db.execute("""UPDATE audit_jobs SET state=?,result_refs=?,checkpoint=?,last_error_code=?,
                next_eligible_at=?,lease_owner=NULL,lease_expires_at=NULL,updated_at=? WHERE job_id=?""",
                (state, _json(refs), saved_checkpoint, error_code, eligible, now, job_id))
            self._event("AUDIT_JOB_FINISHED", job_id, {"state": state, "result_refs": refs,
                "checkpoint": json.loads(saved_checkpoint) if saved_checkpoint else None,
                "error_code": error_code, "next_eligible_at": eligible})
            return True

    def end_run(self, run_id: str, reason: str) -> None:
        if reason not in _REASONS:
            raise LedgerError("invalid run end reason")
        with self._transaction():
            if not self.db.execute("SELECT 1 FROM audit_runs WHERE run_id=?", (run_id,)).fetchone():
                raise LedgerError("run missing")
            if reason == "no_ready_work":
                run = self._checked_run(run_id)
                if run["elapsed_seconds"] >= run["budget"]["max_seconds"]:
                    reason = "time_exhausted"
                elif run["jobs_claimed"] >= run["budget"]["max_jobs"]:
                    reason = "jobs_exhausted"
                elif any(run[key] >= run["budget"][f"max_{key}"] for key in ("requests", "download_bytes", "analysis_bytes")) and self.db.execute("""SELECT 1 FROM audit_jobs WHERE state IN ('ready','retry_wait')
                    AND (next_eligible_at IS NULL OR next_eligible_at<=?) LIMIT 1""", (_now(),)).fetchone():
                    reason = "budget_exhausted"
                elif self.db.execute("""SELECT 1 FROM audit_jobs WHERE state IN ('ready','retry_wait')
                    AND (next_eligible_at IS NULL OR next_eligible_at<=?)
                    AND estimated_cost>? LIMIT 1""",
                    (_now(), run["budget"]["max_requests"] - run["requests"])).fetchone():
                    reason = "budget_exhausted"
            self._end(run_id, reason)

    def unblock(self, job_id: str, policy_id: str | None = None) -> bool:
        """Resume a blocked job after the caller has verified scope or input."""
        if policy_id is not None and (not isinstance(policy_id, str) or not _IDENT.fullmatch(policy_id)):
            raise LedgerError("valid policy_id required")
        with self._transaction():
            row = self.db.execute("SELECT state,checkpoint FROM audit_jobs WHERE job_id=?", (job_id,)).fetchone()
            if row is None or row["state"] not in {"blocked_scope", "blocked_input"}:
                return False
            self.db.execute("""UPDATE audit_jobs SET state='ready',policy_id=COALESCE(?,policy_id),
                next_eligible_at=NULL,last_error_code=NULL,updated_at=? WHERE job_id=?""",
                (policy_id, _now(), job_id))
            self._event("AUDIT_JOB_RESUMED", job_id, {"state": "ready", "policy_id": policy_id,
                "checkpoint": json.loads(row["checkpoint"]) if row["checkpoint"] else None})
            return True

    def get_run(self, run_id: str) -> dict[str, Any]:
        row = self.db.execute("SELECT * FROM audit_runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise LedgerError("run missing")
        return self._run(row)

    def status(self) -> dict[str, Any]:
        jobs = [self._job(row) for row in self.db.execute("SELECT * FROM audit_jobs ORDER BY created_at,job_id")]
        counts = {state: 0 for state in sorted(STATES)}
        for job in jobs:
            counts[job["state"]] += 1
        runs = [self._run(row) for row in self.db.execute("SELECT * FROM audit_runs ORDER BY started_at,run_id")]
        total = {key: sum(run[key] for run in runs) for key in ("requests", "download_bytes", "analysis_bytes", "jobs_claimed")}
        pending_times = [job["next_eligible_at"] for job in jobs if job["state"] == "retry_wait" and job["next_eligible_at"]]
        unresolved = len(jobs) - counts["succeeded"]
        return {"jobs": jobs, "counts": counts, "unresolved": unresolved, "complete": unresolved == 0,
                "next_action_at": min(pending_times) if pending_times else None,
                "current_run": next((run for run in reversed(runs) if run["state"] == "running"), runs[-1] if runs else None),
                "all_runs_usage": total, "runs": runs}
