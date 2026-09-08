import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from sudetect.__main__ import main


class CommandTests(unittest.TestCase):
    def test_github_discovery_command_dispatches_without_network(self):
        from unittest.mock import patch
        with patch('sudetect.github_discovery.main', return_value=0) as command:
            self.assertEqual(main(['github-discover', '--scope-id', 'fixture-team']), 0)
        command.assert_called_once_with(['--scope-id', 'fixture-team'])

    def test_forensics_command_dispatches_without_loading_anonymous_measurement(self):
        from unittest.mock import patch
        with patch('sudetect.forensic_cli.main', return_value=0) as command:
            self.assertEqual(main(['forensics', 'verify', '--manifest', 'local.json']), 0)
        command.assert_called_once_with(['verify', '--manifest', 'local.json'])

    def test_forensics_cli_runs_approved_local_evidence_flow_without_source_stdout(self):
        opaque=lambda value: f"opaque:{value:032x}"
        case={"schema_version":"1.0","case_id":"case_"+"1"*32,"purpose_ref":opaque(2),
              "retention_until":"2099-01-01T00:00:00Z","authorization":{"authorization_ref":opaque(3),
              "valid_from":"2020-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z","revoked":False},
              "collectors":[{"collector_id":"col_"+"4"*32,"tool":"fixture","version":"1","read_only":True}],
              "allowed_sources":[{"source_id":"src_"+"5"*32,"source_type":"normalized_event_jsonl",
              "collector_id":"col_"+"4"*32,"source_provenance_ref":opaque(6),"authorization_ref":opaque(3)}]}
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); case_path=root/"case.json"; case_path.write_text(json.dumps(case),encoding="utf-8")
            source_record={"event_id":"evt_"+"6"*32,"event_time":"2026-09-08T00:00:00Z",
                           "ingest_time":"2026-09-08T00:01:00Z","clock_uncertainty_ms":0,
                           "actor_ref":opaque(7),"asset_ref":opaque(8),"activity":"fixture_activity"}
            export=root/"export.jsonl"; export.write_text(json.dumps(source_record)+"\n",encoding="utf-8")
            evidence=root/"evidence"; evidence.mkdir(); out=io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(["forensics","acquire","--case",str(case_path),"--source-id",case["allowed_sources"][0]["source_id"],"--export",str(export),"--evidence-dir",str(evidence)]),0)
            acquired=json.loads(out.getvalue()); self.assertEqual("ACQUIRED",acquired["status"]); self.assertNotIn("export.jsonl",out.getvalue())
            manifest=evidence/acquired["evidence_id"]/'manifest.json'; out=io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(["forensics","verify","--manifest",str(manifest),"--evidence-dir",str(evidence)]),0)
            self.assertEqual("VERIFIED",json.loads(out.getvalue())["status"])
            source_ref="sha256:"+hashlib.sha256(json.dumps(source_record,ensure_ascii=False,sort_keys=True,separators=(",", ":")).encode()).hexdigest()
            timeline_event={**source_record,"source_id":case["allowed_sources"][0]["source_id"],
                            "evidence_id":acquired["evidence_id"],"source_record_ref":source_ref}
            events=root/"events.jsonl"; events.write_text(json.dumps(timeline_event)+"\n",encoding="utf-8")
            timeline=root/"timeline.json"; out=io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(["forensics","timeline","--case",str(case_path),"--events",str(events),"--evidence-dir",str(evidence),"--output",str(timeline)]),0)
            self.assertEqual("CREATED",json.loads(out.getvalue())["status"])
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(["forensics","timeline-verify","--timeline",str(timeline),"--evidence-dir",str(evidence)]),0)
            self.assertEqual("VERIFIED",json.loads(out.getvalue())["status"])
            custody_event={"event_id":"evt_"+"9"*32,"event_type":"fixture_collected","actor_ref":opaque(10),
                           "evidence_id":acquired["evidence_id"],"occurred_at":"2026-09-08T00:02:00Z","action_ref":opaque(11)}
            event_path=root/"custody-event.json"; event_path.write_text(json.dumps(custody_event),encoding="utf-8")
            chain=root/"custody.jsonl"; out=io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(["forensics","custody-add","--case",str(case_path),"--chain",str(chain),"--event",str(event_path),"--evidence-dir",str(evidence)]),0)
            custody=json.loads(out.getvalue()); self.assertEqual("APPENDED",custody["status"])
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(["forensics","custody-verify","--chain",str(chain),"--expected-head",custody["head_hash"]]),0)
            self.assertEqual("VERIFIED",json.loads(out.getvalue())["status"])
            self.assertNotIn("fixture_activity", out.getvalue())

    def test_discovery_and_asset_graph_commands_dispatch_without_network(self):
        from unittest.mock import patch
        for command_name, module, args in (
            ("channel-discover", "sudetect.discovery_channels.main", ["--config", "local.json"]),
            ("discovery-eval", "sudetect.discovery_eval.main", ["--input", "local.json", "--output", "out.json"]),
            ("asset-graph", "sudetect.asset_graph.main", ["--input", "local.json", "--output", "out.json"]),
        ):
            with self.subTest(command=command_name), patch(module,return_value=0) as command:
                self.assertEqual(main([command_name,*args]),0)
            command.assert_called_once_with(args)

    def test_help_and_version_no_optional_import(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(['--help']), 0)
            self.assertEqual(main(['--version']), 0)
        self.assertIn('usage: open-detective', out.getvalue())
        self.assertIn('2.0.0', out.getvalue())

    def test_unknown_command_safe(self):
        out = io.StringIO()
        with contextlib.redirect_stderr(out):
            self.assertEqual(main(['https://secret.example/?token=SECRET']), 2)
        self.assertEqual(out.getvalue().strip(), 'unknown_command')

    def test_scope_required_no_network(self):
        import os
        from unittest.mock import patch
        out = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(out):
            self.assertEqual(main(['probe', 'https://app.example/']), 2)
        self.assertIn('scope', out.getvalue())


if __name__ == '__main__':
    unittest.main()
