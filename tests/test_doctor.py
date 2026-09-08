import unittest
from pathlib import Path

from sudetect.doctor import check, runtime_files


ROOT=Path(__file__).resolve().parents[1]


class DoctorTests(unittest.TestCase):
    def test_runtime_inventory_includes_new_local_workflows(self):
        relative={path.relative_to(ROOT).as_posix() for path in runtime_files(ROOT)}
        self.assertTrue({"sudetect/forensics.py", "sudetect/forensic_cli.py",
                         "sudetect/discovery_channels.py", "sudetect/discovery_eval.py",
                         "sudetect/asset_graph.py", "ops/forensics.md",
                         "ops/discovery-optimization.md"}.issubset(relative))

    def test_current_source_satisfies_required_runtime_files(self):
        result=check(ROOT)
        self.assertNotIn("RUNTIME_FILES_MISSING",result["errors"])


if __name__ == "__main__":
    unittest.main()
