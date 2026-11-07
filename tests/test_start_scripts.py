"""B: pornirea dintr-un dublu-click (start.bat, start.command). Doar UI local, fără admin, rețea sau instalări."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SCRIPTS = [ROOT / "start.bat", ROOT / "start.command"]
FORBIDDEN = ["sudo", "runas", "pip install", "--confirm", " scan", "watch", "trap", "listen", "0.0.0.0",
             "curl", "wget", "Invoke-WebRequest", "nmap", "netsh", "Set-NetFirewall", "New-NetFirewallRule"]


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_script_starts_only_the_local_ui(path):
    text = path.read_text(encoding="utf-8")
    assert "-m netscan ui --port 5055" in text
    urls = re.findall(r"https?://[^\s\"']+", text)
    assert urls and all(u.startswith("http://127.0.0.1:5055") for u in urls)
    for bad in FORBIDDEN:
        assert bad not in text, bad
    assert ".venv" in text                                     # folosește mediul virtual dacă există


def test_macos_script_has_shebang():
    assert (ROOT / "start.command").read_text(encoding="utf-8").startswith("#!/bin/bash\n")


@pytest.mark.skipif(shutil.which("git") is None, reason="git lipsește")
def test_macos_script_is_executable_in_git():
    out = subprocess.run(["git", "ls-files", "-s", "start.command"], cwd=ROOT, capture_output=True, text=True).stdout
    assert not out or out.startswith("100755"), out           # gol = încă necomis (rulat înainte de git add)
