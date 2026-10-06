"""Explicit synthetic audit soak run; excluded from the default unittest suite.

Run from the repository root: python tools/test_audit_soak.py
Only in-memory HTTPS responses are used. Temporary case data is removed on exit.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sudetect.audit import Case, _project_observation, init_case, run_case  # noqa: E402
from sudetect.policy import Scope  # noqa: E402
from sudetect.transport import FetchResult  # noqa: E402


def policy():
    return Scope.from_dict({
        "policy_id": "synthetic-soak", "expires_at": "2099-01-01T00:00:00Z",
        "targets": [{"origin": "https://soak.invalid", "owner": "synthetic-owner",
                     "ownership_evidence": "fixture:soak", "path_prefixes": ["/"]}],
        "max_requests": 256, "max_bytes": 4096,
    })


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=int, default=2000)
    parser.add_argument("--segment-requests", type=int, default=100)
    args = parser.parse_args(argv)
    if args.assets < 3 or args.segment_requests < 2:
        parser.error("assets >= 3 and segment-requests >= 2 required")

    temp_root = ROOT / "_local" / "test-temp"
    temp_root.mkdir(parents=True, exist_ok=True)
    os.environ["TEMP"] = os.environ["TMP"] = str(temp_root)
    tempfile.tempdir = str(temp_root)
    started = time.monotonic()
    failure_indexes = set(range(7, args.assets, max(11, args.assets // 25)))
    crash_index = min(args.assets - 1, max(2, args.assets // 3))
    requests = Counter()
    successes = Counter()
    failures = Counter()
    crash = {"armed": True, "committed": False, "projection_absent": False, "recovered": False}
    segments = 0
    background = {}

    def fetcher(url, scope):
        scope.authorize(url)
        scope.budget.consume()
        index = int(url.rsplit("/", 1)[-1].removesuffix(".json"))
        requests[index] += 1
        timeout = index in failure_indexes and failures[index] == 0
        if timeout:
            failures[index] += 1
            body = b""
            access, reason, status, complete = "INDETERMINATE", "timeout", None, False
        else:
            successes[index] += 1
            body = json.dumps({"status": "public", "item": index}, separators=(",", ":")).encode()
            access, reason, status, complete = "BODY_SERVED", "response_observed", 200, True
        observation = {
            "observation_id": f"synthetic-{index}-{requests[index]}",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "policy_id": scope.policy_id, "access": access, "capture_complete": complete,
            "http_status": status, "reason": reason, "sha256": hashlib.sha256(body).hexdigest(),
            "redirects": [],
        }
        return FetchResult(observation, body, {"content-type": "application/json"})

    with tempfile.TemporaryDirectory(prefix="audit-soak-", dir=temp_root) as temporary:
        case_path = Path(temporary) / "case"
        init_case(case_path, {"scope_id": "synthetic-soak", "identity": {"company_en": "Synthetic Soak"}})
        # Run the initialized discovery job. Missing channel health leaves it
        # visibly blocked; it is never hidden by direct state manipulation.
        with Case(case_path) as case:
            run_case(case, {"max_requests": 2, "max_jobs": 1}, scope=policy(), fetcher=fetcher)
            segments += 1
            for index in range(args.assets):
                case.enqueue_url(f"https://soak.invalid/item/{index}.json", scope=policy())
            crash_ref = case.locators.put(case.scope_id,
                                          f"https://soak.invalid/item/{crash_index}.json")

        def interrupt_projection(case, job, observation):
            if job["asset_ref"] == crash_ref and crash["armed"]:
                crash["armed"] = False
                crash["committed"] = case.prior_result(job) is not None
                crash["projection_absent"] = not case.ledger.db.execute(
                    "SELECT 1 FROM observations WHERE observation_id=?",
                    (observation["observation_id"],)).fetchone()
                raise KeyboardInterrupt
            return _project_observation(case, job, observation)

        # Every segment has a fresh Case and Scope, matching a new process's
        # persisted state. A bounded request allowance forces many segments.
        limit = (args.assets + len(failure_indexes)) * 3 // args.segment_requests + 50
        for _ in range(limit):
            with Case(case_path) as case:
                with patch("sudetect.audit._project_observation", side_effect=interrupt_projection):
                    run_case(case, {"max_requests": args.segment_requests,
                                    "max_download_bytes": args.segment_requests * 4096,
                                    "max_analysis_bytes": args.segment_requests * 4096,
                                    "max_jobs": args.segment_requests + 4},
                             scope=policy(), fetcher=fetcher)
                segments += 1
                if crash["committed"] and not crash["recovered"]:
                    crash["recovered"] = bool(case.ledger.db.execute(
                        "SELECT 1 FROM observations WHERE observation_id=?",
                        (f"synthetic-{crash_index}-{requests[crash_index]}",)).fetchone())
                status = case.queue.status()
                stress = [job for job in status["jobs"] if job["job_type"] == "capture"]
                if len(stress) == args.assets and all(job["state"] == "succeeded" for job in stress):
                    background = {state: count for state, count in status["counts"].items()
                                  if state != "succeeded" and count}
                    break
                # Test-only clock advancement for retry_wait and expired leases.
                case.ledger.db.execute("""UPDATE audit_jobs SET next_eligible_at='2000-01-01T00:00:00Z'
                    WHERE job_type='capture' AND state='retry_wait'""")
                case.ledger.db.execute("""UPDATE audit_jobs SET lease_expires_at='2000-01-01T00:00:00Z'
                    WHERE job_type='capture' AND state='running'""")
                case.ledger.db.commit()
        else:
            raise AssertionError("segment limit reached before all synthetic captures succeeded")

        duplicate_success = sum(max(0, count - 1) for count in successes.values())
        failed_retries = sum(failures.values())
        actual_requests = sum(requests.values())
        if (actual_requests != args.assets + failed_retries or duplicate_success != 0
                or not all(successes[index] == 1 for index in range(args.assets))
                or crash["armed"] or not all(crash[key] for key in ("committed", "projection_absent", "recovered"))):
            raise AssertionError({"actual_requests": actual_requests, "failed_retries": failed_retries,
                                  "duplicate_success": duplicate_success, "crash": crash})
        with Case(case_path) as case:
            status = case.queue.status()
            stress = [job for job in status["jobs"] if job["job_type"] == "capture"]
            observation_count = case.ledger.db.execute(
                "SELECT COUNT(*) FROM observations WHERE observation_id LIKE 'synthetic-%'").fetchone()[0]
            result_count = case.ledger.db.execute(
                "SELECT COUNT(*) FROM audit_results WHERE job_id IN (SELECT job_id FROM audit_jobs WHERE job_type='capture')").fetchone()[0]
            if observation_count != args.assets + failed_retries or result_count != args.assets + failed_retries:
                raise AssertionError({"observations": observation_count, "results": result_count})
            remaining = Counter(job["state"] for job in stress if job["state"] != "succeeded")
            output = {
                "assets": args.assets, "actual_requests": actual_requests,
                "failed_retries": failed_retries, "duplicate_success_requests": duplicate_success,
                "interruption_recovery": crash, "total_run_segments": segments,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "unfinished_states": dict(remaining), "background_unfinished_states": background,
                "observations": observation_count, "results": result_count,
                "stress_complete": not remaining and len(stress) == args.assets,
                "queue_complete": status["complete"],
            }
            print(json.dumps(output, ensure_ascii=False, sort_keys=True))
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
