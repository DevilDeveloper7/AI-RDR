"""Startup launcher checks that do not start any servers."""
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHERS = ("run.sh", "RUN.command")


def test_launchers_are_in_the_repo_root_and_executable():
    for name in LAUNCHERS:
        assert (ROOT / name).is_file(), f"{name} is missing from the repo root"
        assert os.access(ROOT / name, os.X_OK), f"{name} is not executable (chmod +x {name})"


def test_launchers_have_valid_shell_syntax():
    for name in LAUNCHERS:
        assert subprocess.run(["bash", "-n", str(ROOT / name)]).returncode == 0


def test_help_and_check_modes():
    helped = subprocess.run(["bash", str(ROOT / "run.sh"), "--help"], capture_output=True, text=True)
    assert helped.returncode == 0 and "--setup-only" in helped.stdout
    checked = subprocess.run(["bash", str(ROOT / "run.sh"), "--check"], capture_output=True, text=True)
    assert checked.returncode == 0 and "Python" in checked.stdout and "Node" in checked.stdout


def test_unknown_option_is_rejected():
    res = subprocess.run(["bash", str(ROOT / "run.sh"), "--bogus"], capture_output=True, text=True)
    assert res.returncode != 0


def test_stop_mode_is_safe_when_nothing_is_running():
    res = subprocess.run(["bash", str(ROOT / "run.sh"), "--stop"], capture_output=True, text=True)
    assert res.returncode == 0 and "nothing to stop" in res.stdout.lower()
