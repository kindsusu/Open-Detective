"""Run the built runtime away from the source tree, without optional dependencies."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile


def main():
    root = Path(__file__).resolve().parents[1]
    wheel = max((root / "dist").glob("su_detect-*.whl"), key=lambda p: p.stat().st_mtime)
    with tempfile.TemporaryDirectory(prefix="su-detect-wheel-") as temporary:
        target = Path(temporary)
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(target)
        env = dict(os.environ, PYTHONPATH=str(target), PYTHONIOENCODING="utf-8")
        for args in (["--help"], ["search-plan", "--help"], ["search-plan", "plan",
                     "--scope-id", "fixture", "--company-en", "Melody Rent Car",
                     "--output", str(target / "plan.json")]):
            subprocess.run([sys.executable, "-S", "-m", "sudetect", *args],
                           cwd=target, env=env, check=True, capture_output=True, text=True)
        subprocess.run([sys.executable, "-S", "-m", "sudetect.idgen", "--selftest"],
                       cwd=target, env=env, check=True, capture_output=True, text=True)
    print("PASS installed wheel: isolated CLI, identifier generation, search plan")


if __name__ == "__main__":
    main()
