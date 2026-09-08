"""Run the built runtime away from the source tree, without optional dependencies."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import venv
import zipfile


def main():
    root = Path(__file__).resolve().parents[1]
    wheel = max((root / "dist").glob("open_detective-*.whl"), key=lambda p: p.stat().st_mtime)
    with tempfile.TemporaryDirectory(prefix="open-detective-wheel-") as temporary:
        target = Path(temporary)
        with zipfile.ZipFile(wheel) as archive:
            metadata_name = next(name for name in archive.namelist()
                                 if name.endswith(".dist-info/METADATA"))
            metadata = archive.read(metadata_name).decode("utf-8")
            entry_points_name = next(name for name in archive.namelist()
                                     if name.endswith(".dist-info/entry_points.txt"))
            entry_points = archive.read(entry_points_name).decode("utf-8")
            assert "Name: open-detective" in metadata.splitlines()
            assert "open-detective = sudetect.__main__:main" in entry_points.splitlines()
            assert "su-detect = sudetect.__main__:main" in entry_points.splitlines()
            archive.extractall(target)
        env = dict(os.environ, PYTHONPATH=str(target), PYTHONIOENCODING="utf-8")
        for args in (["--help"], ["search-plan", "--help"], ["search-plan", "plan",
                     "--scope-id", "fixture", "--company-en", "Melody Rent Car",
                     "--output", str(target / "plan.json")]):
            subprocess.run([sys.executable, "-S", "-m", "sudetect", *args],
                           cwd=target, env=env, check=True, capture_output=True, text=True)
        subprocess.run([sys.executable, "-S", "-m", "sudetect.idgen", "--selftest"],
                       cwd=target, env=env, check=True, capture_output=True, text=True)
        environment = target / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        scripts = environment / ("Scripts" if os.name == "nt" else "bin")
        subprocess.run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)],
                       cwd=target, check=True, capture_output=True, text=True)
        suffix = ".exe" if os.name == "nt" else ""
        for command in ("open-detective", "su-detect"):
            completed = subprocess.run([str(scripts / f"{command}{suffix}"), "--version"],
                                       cwd=target, check=True, capture_output=True, text=True)
            assert completed.stdout.strip() == "2.0.0"
    print("PASS Open-Detective wheel: metadata, CLI aliases, isolated runtime")


if __name__ == "__main__":
    main()
