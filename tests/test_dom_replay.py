"""Tests for the local, inert Playwright DOM replay."""
from datetime import datetime, timedelta, timezone
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sudetect.dom_replay import _InertFixtureParser, main, replay


CANARY = "OPEN_DETECTIVE_DOM_REPLAY_CONTROL"
ROOT = Path(__file__).resolve().parents[1]
INERT_HTML = f"""<!doctype html>
<html><head><style>#app {{ border: 0 }}</style></head><body>
<main id="login-screen"><input type="password"></main>
<section id="app" style="display: none"><p>{CANARY}</p><input type="text"></section>
</body></html>"""


def manifest(path: Path, raw: bytes | None = None) -> dict:
    payload = path.read_bytes() if raw is None else raw
    return {
        "case_id": "synthetic-case",
        "fixture_path": str(path),
        "fixture_sha256": hashlib.sha256(payload).hexdigest(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "owner_ref": "fixture:owner",
        "approved_action": "remove_login_show_app",
        "control_canary": CANARY,
    }


class DomReplayValidationTests(unittest.TestCase):
    def parse(self, text):
        parser = _InertFixtureParser()
        parser.feed(text)
        parser.close()
        return parser

    def test_rejects_active_resource_navigation_event_and_css_urls(self):
        bad = [
            '<script>1</script>', '<img src="x">', '<a href="/x">x</a>',
            '<form action="/x"></form>', '<div onclick="x()"></div>',
            '<style>x{background:url(https://example.test/x)}</style>',
            '<div style="background: url(/x)"></div>',
            '<meta http-equiv="refresh" content="0;url=/x">', '<iframe></iframe>',
        ]
        for text in bad:
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "active_or_navigable"):
                self.parse(text)

    def test_rejects_duplicate_attributes(self):
        with self.assertRaisesRegex(ValueError, "duplicate_attribute"):
            self.parse('<div id="app" id="app"></div>')

    def test_checked_in_example_is_hash_pinned_and_intentionally_expired(self):
        example = json.loads((ROOT / "examples/dom-replay.example.json").read_text(encoding="utf-8"))
        fixture = ROOT / "examples" / example["fixture_path"]
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), example["fixture_sha256"])
        example["fixture_path"] = str(fixture)
        with self.assertRaisesRegex(ValueError, "expired_scope"):
            replay(example)

    def test_manifest_requires_exact_nonempty_approval_fields_before_browser(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory, "fixture.html")
            fixture.write_text(INERT_HTML, encoding="utf-8")
            base = manifest(fixture)
            variants = []
            for field in ("case_id", "owner_ref", "control_canary"):
                changed = dict(base)
                changed[field] = ""
                variants.append(changed)
            changed = dict(base)
            changed["approved_action"] = "arbitrary_script"
            variants.append(changed)
            changed = dict(base)
            changed["expires_at"] = "2000-01-01T00:00:00Z"
            variants.append(changed)
            changed = dict(base)
            changed["extra"] = True
            variants.append(changed)
            for value in variants:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    replay(value)

    def test_rejects_hash_mismatch_and_duplicate_or_missing_targets_before_browser(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory, "fixture.html")
            fixture.write_text(INERT_HTML, encoding="utf-8")
            wrong_hash = manifest(fixture)
            wrong_hash["fixture_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "fixture_mismatch"):
                replay(wrong_hash)
            for html in (
                INERT_HTML.replace('id="app"', 'id="other"'),
                INERT_HTML.replace('</body>', '<div id="app"></div></body>'),
            ):
                fixture.write_text(html, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "missing_or_ambiguous"):
                    replay(manifest(fixture))

    def test_help_does_not_import_playwright(self):
        real_import = __import__

        def guarded(name, *args, **kwargs):
            if name.startswith("playwright"):
                raise AssertionError("help imported optional browser dependency")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=guarded), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main(["--help"])
        self.assertEqual(raised.exception.code, 0)

    def test_cli_failure_emits_only_stable_sanitized_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            secret = "SECRET_SHOULD_NOT_BE_ECHOED"
            manifest_path.write_text('{"fixture_path":"' + secret + '"', encoding="utf-8")
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                self.assertEqual(main(["--manifest", str(manifest_path),
                                       "--output", str(root / "report.json")]), 2)
            self.assertEqual(json.loads(error.getvalue()), {"error": "invalid_manifest"})
            self.assertNotIn(secret, error.getvalue())

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlinks unavailable")
    def test_rejects_fixture_symlink_and_output_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture.html"
            fixture.write_text(INERT_HTML, encoding="utf-8")
            linked = root / "linked.html"
            try:
                linked.symlink_to(fixture)
            except OSError:
                self.skipTest("symlink creation unavailable")
            value = manifest(fixture)
            value["fixture_path"] = str(linked)
            with self.assertRaisesRegex(ValueError, "symlink_path"):
                replay(value)

            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest(fixture)), encoding="utf-8")
            output = root / "report.json"
            output.write_text("keep", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--manifest", str(manifest_path), "--output", str(output)]), 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep")


@unittest.skipUnless(importlib.util.find_spec("playwright"), "optional Playwright not installed")
class DomReplayBrowserTests(unittest.TestCase):
    def test_real_browser_mutates_dom_and_measures_visibility_and_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory, "fixture.html")
            fixture.write_text(INERT_HTML, encoding="utf-8")
            result = replay(manifest(fixture))
            self.assertEqual(fixture.read_text(encoding="utf-8"), INERT_HTML)
        self.assertEqual(result["network_request_attempts"], 0)
        self.assertEqual(result["baseline"]["targets"]["login_screen"]["count"], 1)
        self.assertTrue(result["baseline"]["targets"]["login_screen"]["visible"])
        self.assertEqual(result["baseline"]["targets"]["app"]["computed_display"], "none")
        self.assertFalse(result["baseline"]["targets"]["app"]["visible"])
        self.assertEqual(result["after"]["targets"]["login_screen"]["count"], 0)
        self.assertEqual(result["after"]["targets"]["app"]["computed_display"], "flex")
        self.assertTrue(result["after"]["targets"]["app"]["visible"])
        self.assertLess(result["after"]["element_count"], result["baseline"]["element_count"])
        self.assertLess(result["after"]["node_count"], result["baseline"]["node_count"])
        self.assertEqual(result["after"]["form_control_count"], 1)
        self.assertTrue(result["control_canary"]["baseline_present"])
        self.assertTrue(result["control_canary"]["after_present"])
        self.assertFalse(result["control_canary"]["finding_claim"])
        self.assertNotIn(CANARY, json.dumps(result))

    def test_hidden_ancestor_cannot_be_reported_as_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory, "fixture.html")
            html = INERT_HTML.replace('<section id="app"', '<div hidden><section id="app"').replace(
                '</section>\n</body>', '</section></div>\n</body>')
            fixture.write_text(html, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "dom_mutation_failed"):
                replay(manifest(fixture))

    def test_missing_or_removed_control_canary_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory, "fixture.html")
            fixture.write_text(INERT_HTML.replace(CANARY, "OTHER"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "control_canary_missing"):
                replay(manifest(fixture))

            fixture.write_text(INERT_HTML.replace(
                '<main id="login-screen"><input type="password"></main>',
                f'<main id="login-screen"><input type="password">{CANARY}</main>').replace(
                    f'<p>{CANARY}</p>', '<p>OTHER</p>'), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "control_canary_changed"):
                replay(manifest(fixture))

    def test_cli_creates_fresh_sanitized_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture.html"
            fixture.write_text(INERT_HTML, encoding="utf-8")
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest(fixture)), encoding="utf-8")
            output = root / "report.json"
            self.assertEqual(main(["--manifest", str(manifest_path), "--output", str(output)]), 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(report["interpretation"]["synthetic_fixture_only"])
            self.assertEqual(report["interpretation"]["server_exposure"], "not_measured")
            self.assertNotIn(INERT_HTML, output.read_text(encoding="utf-8"))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--manifest", str(manifest_path), "--output", str(output)]), 2)


if __name__ == "__main__":
    unittest.main()
