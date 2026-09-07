"""Strict, non-synthetic channel-health reports for offline gate tests."""
from datetime import datetime, timedelta, timezone
import uuid


def health_report(*channels, now=None, status="OK"):
    current = now or datetime.now(timezone.utc)
    stamp = lambda value: value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    expires = current + timedelta(minutes=5)
    controls = [{
        "channel_id": channel, "control_id": f"control-{index}", "status": status,
        "observed_at": stamp(current), "expires_at": stamp(expires),
        "observation_id": str(uuid.uuid4()), "policy_id": "policy-1",
        "reason_code": "expectation_matched" if status == "OK" else "fixture_degraded",
        "capture_complete": True, "http_status": 200,
    } for index, channel in enumerate(channels, 1)]
    return {"schema_version": "1.0", "kind": "channel_health", "status": "OK" if status == "OK" else "PARTIAL",
            "synthetic": False, "observed_at": stamp(current), "expires_at": stamp(expires), "controls": controls}
