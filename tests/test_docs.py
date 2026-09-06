import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY_PAIRS = [
    ("ops/scope.md", "ko/ops/scope.md"),
    ("ops/discovery.md", "ko/ops/discovery.md"),
    ("ops/verify.md", "ko/ops/verify.md"),
    ("ops/triage.md", "ko/ops/triage.md"),
    ("ops/evidence.md", "ko/ops/evidence.md"),
    ("ops/remediate.md", "ko/ops/remediate.md"),
    ("ops/identifiers.md", "ko/ops/identifiers.md"),
    ("surfaces/inventory.md", "ko/surfaces/inventory.md"),
    ("assets/ledger-template.md", "ko/assets/ledger-template.md"),
]

ACCESS = {
    "BODY_SERVED", "ACCESS_DENIED_OBSERVED", "AUTH_REDIRECT_OBSERVED",
    "NOT_FOUND_OBSERVED", "INDETERMINATE",
}
CONTENT = {
    "PUBLIC_UI", "SENSITIVE_CONTENT_CONFIRMED", "SENSITIVE_CANDIDATE",
    "CLIENT_ENCRYPTED_OBSERVED", "NOT_INSPECTED",
}


class DocumentationTests(unittest.TestCase):
    def read(self, relative):
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_single_skill_frontmatter(self):
        self.assertTrue(self.read("SKILL.md").startswith("---\n"))
        self.assertFalse(self.read("ko/SKILL.md").startswith("---"))

    def test_stable_rule_ids_are_complete_and_synchronized(self):
        expected = {f"SUD-R{i:02d}" for i in range(1, 16)}
        for path in ("ops/scope.md", "ko/ops/scope.md"):
            found = set(re.findall(r"SUD-R\d{2}", self.read(path)))
            self.assertEqual(expected, found, path)

    def test_decision_vocabulary_is_synchronized(self):
        for path in ("README.md", "README.ko.md", "SKILL.md", "ko/SKILL.md",
                     "ops/verify.md", "ko/ops/verify.md",
                     "assets/ledger-template.md", "ko/assets/ledger-template.md"):
            text = self.read(path)
            self.assertTrue(ACCESS.issubset(set(re.findall(r"[A-Z_]+", text))), path)
            self.assertTrue(CONTENT.issubset(set(re.findall(r"[A-Z_]+", text))), path)

    def test_translation_pairs_and_markdown_links_exist(self):
        for english, korean in POLICY_PAIRS:
            self.assertTrue((ROOT / english).is_file(), english)
            self.assertTrue((ROOT / korean).is_file(), korean)

        link_pattern = re.compile(r"\[[^]]+\]\(([^)]+)\)")
        for doc in ("README.md", "README.ko.md"):
            for link in link_pattern.findall(self.read(doc)):
                if "://" not in link and not link.startswith("#"):
                    self.assertTrue((ROOT / link.split("#", 1)[0]).exists(), f"{doc}: {link}")

    def test_no_legacy_single_verdict_language(self):
        docs = ["README.md", "README.ko.md", "SKILL.md", "ko/SKILL.md"]
        docs += [item for pair in POLICY_PAIRS for item in pair]
        legacy = re.compile(r"\b(?:EXPOSED|WEAK-GATE|AUTH-GATE)\b")
        for path in docs:
            self.assertIsNone(legacy.search(self.read(path)), path)

    def test_documented_cli_contract_matches_current_commands(self):
        for path in ("README.md", "README.ko.md", "SKILL.md", "ko/SKILL.md"):
            text = self.read(path)
            self.assertIn("inventory --provider import --scope-id TEAM --input inventory.json", text, path)
            self.assertIn("discover --input candidates.json --scope-id TEAM", text, path)
            self.assertIn("ledger --db audit.sqlite due", text, path)
            self.assertNotIn("ledger --database", text, path)
        for path in ("README.md", "README.ko.md"):
            self.assertIn('"targets"', self.read(path), path)
            self.assertNotIn('"grants"', self.read(path), path)

    def test_status_verdicts_are_documented_as_observations(self):
        for path in ("ops/verify.md", "ko/ops/verify.md"):
            text = self.read(path)
            self.assertRegex(text, r"401.*403")
            self.assertRegex(text, r"404.*410")
            self.assertNotIn("after challenge/error-page discrimination", text)
            self.assertNotIn("confirmed not-found", text)
            self.assertIn("prefix_sha256", text)
            self.assertIn("identity encoding", text)


if __name__ == "__main__":
    unittest.main()
