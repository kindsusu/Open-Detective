import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from sudetect.channel_health import _changed, _validate_config, extract_health_provenance, load_health_report, main, run_checks, validate_health
from sudetect.policy import Scope
from sudetect.transport import FetchResult


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def scope():
    return Scope.from_dict({
        "policy_id": "fixture-policy", "expires_at": "2099-01-01T00:00:00Z",
        "targets": [{"origin": "https://app.example", "owner": "fixture", "ownership_evidence": "ticket-1", "path_prefixes": ["/"]}],
        "exclude_urls": [], "max_requests": 16,
    })


def config():
    return {"max_age_seconds": 3600, "controls": [{
        "channel_id": "fixture-channel", "control_id": "control-fixture",
        "url": "https://app.example/control", "expect": {"kind": "json_pointer", "pointer": "/full_name", "equals": "octocat/Hello-World"},
    }]}


def github_scope():
    return Scope.from_dict({
        "policy_id": "fixture-policy", "expires_at": "2099-01-01T00:00:00Z",
        "targets": [{"origin": "https://api.github.com", "owner": "fixture", "ownership_evidence": "ticket-1", "path_prefixes": ["/"]}],
        "exclude_urls": [], "max_requests": 16,
    })


def github_config(channel="github-repositories", url="https://api.github.com/repos/octocat/Hello-World"):
    return {"controls": [{"channel_id": channel, "control_id": "github-control", "url": url,
                            "expect": {"kind": "json_pointer", "pointer": "/full_name", "equals": "octocat/Hello-World"}}]}


def result(*, body=b'{"full_name":"octocat/Hello-World"}', status=200, complete=True, observation_id="12345678-1234-4234-9234-123456789abc"):
    return FetchResult({"observation_id": observation_id, "http_status": status, "capture_complete": complete}, body)


class ChannelHealthTests(unittest.TestCase):
    def test_200_mismatch_is_degraded_not_ok(self):
        report = run_checks(config(), scope(), fetcher=lambda *args, **kwargs: result(body=b'{"full_name":"wrong"}'), now=NOW)
        control = report["controls"][0]
        self.assertEqual("PARTIAL", report["status"])
        self.assertEqual(("DEGRADED", "expectation_mismatch"), (control["status"], control["reason_code"]))
        self.assertTrue(report["synthetic"])

    def test_stale_future_and_synthetic_are_rejected(self):
        healthy = run_checks(config(), scope(), fetcher=lambda *args, **kwargs: result(), now=NOW)
        healthy["synthetic"] = False
        self.assertEqual([], validate_health(healthy, ["fixture-channel"], now=NOW))
        stale = json.loads(json.dumps(healthy)); stale["expires_at"] = "2025-12-31T23:59:59Z"
        self.assertIn("stale", validate_health(stale, ["fixture-channel"], now=NOW))
        future = json.loads(json.dumps(healthy)); future["observed_at"] = "2026-01-01T00:00:01Z"
        self.assertIn("future", validate_health(future, ["fixture-channel"], now=NOW))
        healthy["synthetic"] = True
        self.assertIn("invalid", validate_health(healthy, ["fixture-channel"], now=NOW))

    def test_bad_config_is_rejected_before_any_network_request(self):
        bad = config(); bad["controls"].append(dict(bad["controls"][0]))
        fetcher = Mock()
        with self.assertRaises(ValueError):
            run_checks(bad, scope(), fetcher=fetcher, now=NOW)
        fetcher.assert_not_called()
        outside = config(); outside["controls"][0]["url"] = "https://outside.example/control"
        with self.assertRaises(ValueError):
            run_checks(outside, scope(), fetcher=fetcher, now=NOW)
        fetcher.assert_not_called()

    def test_github_controls_are_bound_to_their_api_families_before_network(self):
        fetcher = Mock()
        invalid = [
            github_config("github-repositories", "https://api.github.com/search/repositories?q=octocat"),
            github_config("github-user-search", "https://api.github.com/search/repositories?q=octocat"),
            github_config("github-repository-search", "https://api.github.com/search/repositories?q="),
            github_config("github-user-search", "https://api.github.com/search/users?q=octocat&token=secret"),
            github_config("github-repositories", "https://api.github.com/users/octocat/repos?per_page=0"),
            github_config("github-repositories", "https://github.com/repos/octocat/Hello-World"),
            github_config("github-repositories", "https://api.github.com/repos/oct.o/correct_repo.v2"),
        ]
        for controls in invalid:
            with self.subTest(controls=controls["controls"][0]["channel_id"]):
                with self.assertRaises(ValueError):
                    run_checks(controls, github_scope(), fetcher=fetcher, now=NOW)
        fetcher.assert_not_called()
        report = run_checks(github_config(), github_scope(), fetcher=lambda *args, **kwargs: result(), now=NOW)
        self.assertEqual("OK", report["status"])
        report = run_checks(github_config(url="https://api.github.com/repos/octocat/my_repo.v2"), github_scope(), fetcher=lambda *args, **kwargs: result(), now=NOW)
        self.assertEqual("OK", report["status"])

    def test_public_example_uses_valid_github_control_urls(self):
        sample = json.loads(Path(__file__).parents[1].joinpath("examples", "channel-health.example.json").read_text(encoding="utf-8"))
        controls, _ = _validate_config(sample, github_scope())
        self.assertEqual(["github-repositories", "github-user-search", "github-repository-search"], [item["channel_id"] for item in controls])

    def test_failure_does_not_place_raw_exception_or_control_url_in_report(self):
        def broken(*args, **kwargs):
            raise RuntimeError("secret marker https://app.example/control")
        report = run_checks(config(), scope(), fetcher=broken, now=NOW)
        encoded = json.dumps(report)
        self.assertEqual("DEAD", report["controls"][0]["status"])
        self.assertNotIn("secret marker", encoded)
        self.assertNotIn("https://app.example/control", encoded)

    def test_changed_only_compares_semantic_health(self):
        old = run_checks(config(), scope(), fetcher=lambda *args, **kwargs: result(), now=NOW)
        new = run_checks(config(), scope(), fetcher=lambda *args, **kwargs: result(), now=NOW + timedelta(minutes=1))
        self.assertEqual([], _changed(new, old))
        new["controls"][0]["reason_code"] = "capture_incomplete"
        new["controls"][0]["status"] = "DEGRADED"
        self.assertEqual("fixture-channel", _changed(new, old)[0]["channel_id"])
        new["controls"][0]["control_id"] = "new-control"
        self.assertEqual("fixture-channel", _changed(new, old)[0]["channel_id"])

    def test_compressed_and_python_equality_controls_cannot_be_ok(self):
        compressed = result(); compressed.headers["content-encoding"] = "gzip"
        report = run_checks(config(), scope(), fetcher=lambda *args, **kwargs: compressed, now=NOW)
        self.assertEqual("DEGRADED", report["controls"][0]["status"])
        weak = config(); weak["controls"][0]["expect"]["equals"] = True
        report = run_checks(weak, scope(), fetcher=lambda *args, **kwargs: result(body=b'{"full_name":1}'), now=NOW)
        self.assertEqual("DEGRADED", report["controls"][0]["status"])

    def test_validate_accepts_unrelated_dead_but_rejects_bad_required_and_shape(self):
        healthy = run_checks(config(), scope(), fetcher=lambda *args, **kwargs: result(), now=NOW)
        healthy["synthetic"] = False
        extra = dict(healthy["controls"][0]); extra.update({"channel_id": "other-channel", "control_id": "other-control", "status": "DEAD", "reason_code": "control_unreachable", "observation_id": None, "capture_complete": False, "http_status": None})
        healthy["controls"].append(extra); healthy["status"] = "PARTIAL"
        self.assertEqual([], validate_health(healthy, ["fixture-channel"], now=NOW))
        self.assertEqual(["invalid"], validate_health(healthy, [["unhashable"]], now=NOW))
        healthy["extra"] = True
        self.assertIn("invalid", validate_health(healthy, ["fixture-channel"], now=NOW))

    def test_hostile_shapes_never_raise_or_leak_previous_url(self):
        healthy = run_checks(config(), scope(), fetcher=lambda *args, **kwargs: result(), now=NOW)
        healthy["synthetic"] = False
        for value in ([], {}, None):
            malformed = json.loads(json.dumps(healthy)); malformed["controls"][0]["status"] = value
            self.assertIn("invalid", validate_health(malformed, ["fixture-channel"], now=NOW))
            self.assertEqual([], extract_health_provenance(malformed, ["fixture-channel"]))
        previous = {"controls": [{"channel_id": "https://secret.example/?token=VALUE"}]}
        changed = json.dumps(_changed(healthy, previous))
        self.assertNotIn("secret.example", changed)
        self.assertNotIn("VALUE", changed)

    def test_bounded_report_loader_and_provenance_exclude_policy_text(self):
        healthy = run_checks(config(), scope(), fetcher=lambda *args, **kwargs: result(), now=NOW)
        healthy["synthetic"] = False
        healthy["controls"][0]["policy_id"] = "operator ticket text"
        provenance = extract_health_provenance(healthy, ["fixture-channel"])
        self.assertEqual({"channel_id", "control_id", "observation_id", "status", "observed_at", "expires_at"}, set(provenance[0]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "report.json"); path.write_bytes(b"{" * 129)
            with self.assertRaises(ValueError): load_health_report(path)

    def test_extreme_timestamp_is_invalid_without_provenance_exception(self):
        healthy = run_checks(config(), scope(), fetcher=lambda *args, **kwargs: result(), now=NOW)
        healthy["synthetic"] = False
        healthy["controls"][0]["observed_at"] = "9999-12-31T23:59:59-23:59"
        self.assertIn("invalid", validate_health(healthy, ["fixture-channel"], now=NOW))
        self.assertEqual([], extract_health_provenance(healthy, ["fixture-channel"]))

    def test_cli_rewrites_report_and_only_prints_safe_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); policy = root / "scope.json"; controls = root / "controls.json"; output = root / "health.json"
            policy.write_text(json.dumps({
                "policy_id": "fixture-policy", "expires_at": "2099-01-01T00:00:00Z",
                "targets": [{"origin": "https://app.example", "owner": "fixture", "ownership_evidence": "ticket-1", "path_prefixes": ["/"]}], "exclude_urls": [],
            }), encoding="utf-8")
            controls.write_text(json.dumps(config()), encoding="utf-8")
            out = io.StringIO()
            with patch("sudetect.channel_health.fetch", return_value=result()), contextlib.redirect_stdout(out):
                self.assertEqual(0, main(["--config", str(controls), "--scope", str(policy), "--output", str(output)]))
            self.assertTrue(output.exists())
            output_json = json.loads(out.getvalue())
            self.assertEqual({"changed", "status"}, set(output_json))
            self.assertEqual("fixture-channel", output_json["changed"][0]["channel_id"])
            self.assertNotIn("https://app.example/control", out.getvalue())


if __name__ == "__main__":
    unittest.main()
