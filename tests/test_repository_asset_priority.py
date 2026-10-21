"""The bounded tree keeps late data files ahead of large media folders."""
import json
import unittest

from sudetect.repository_assets import analyze_tree


class RepositoryAssetPriorityTests(unittest.TestCase):
    def test_late_source_file_survives_media_saturated_limit(self):
        tree = "https://api.github.com/repos/sample-org/site/git/trees/main?recursive=1"
        entries = [{"path": f"images/{index:04d}.png", "type": "blob",
                    "sha": "a" * 40, "size": 12} for index in range(1001)]
        entries.append({"path": "script.js", "type": "blob", "sha": "b" * 40, "size": 42})
        entries.append({"path": "unsafe/../ignored.json", "type": "blob",
                        "sha": "c" * 40, "size": 7})

        report, urls = analyze_tree(json.dumps({"tree": entries, "truncated": False}).encode(), tree)

        self.assertEqual("PARTIAL", report["status"])
        self.assertEqual("FILE_LIMIT_REACHED", report["error_code"])
        self.assertTrue(report["file_limit_reached"])
        self.assertEqual(1003, report["tree_entries"])
        self.assertEqual(1, report["rejected_blobs"])
        self.assertEqual(1000, report["files_emitted"])
        self.assertEqual(1000, len(urls))
        self.assertTrue(urls[0].endswith("/script.js"))
        self.assertEqual("source_code", report["files"][0]["candidate_kind"])
        self.assertEqual(list(range(1000)), [row["file_index"] for row in report["files"]])
        self.assertTrue(all(url.endswith(".png") for url in urls[1:]))


if __name__ == "__main__":
    unittest.main()
