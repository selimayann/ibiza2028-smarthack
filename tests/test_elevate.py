"""B: pornirea pasului de admin din aplicație. Nimic nu se lansează de fapt: fereastra sistemului e simulată."""
import re
import subprocess
import sys
from pathlib import Path

import pytest

from netscan.scan import elevate

ROOT = Path(__file__).parent.parent


def test_command_is_fixed_and_isolated():
    cmd = elevate.command("scan", python="py")
    assert cmd == ["py", "-I", str(ROOT / "netscan" / "scan" / "_elevated.py"), "scan"]
    assert Path(cmd[2]).is_file()


@pytest.mark.parametrize("job", ["", "watch", "scan; rm -rf /", "../x", "SCAN"])
def test_unknown_jobs_are_refused(job):
    with pytest.raises(ValueError):
        elevate.command(job)
    with pytest.raises(ValueError):
        elevate.launch(job, platform="win32", shell_execute=lambda *a: pytest.fail("lansat"))


@pytest.mark.parametrize("rc, ok, code", [(42, True, elevate.STARTED), (5, False, elevate.DENIED),
                                          (2, False, elevate.FAILED)])
def test_windows_uses_runas_with_fixed_arguments(rc, ok, code):
    calls = []
    res = elevate.launch("auto", platform="win32", shell_execute=lambda *a: calls.append(a) or rc)
    exe, params, cwd = calls[0]
    assert exe == sys.executable and cwd == str(ROOT)
    assert params == subprocess.list2cmdline(["-I", str(elevate.ENTRY), "auto"])
    assert (res.ok, res.code) == (ok, code)


class R:
    def __init__(self, rc, err=""):
        self.returncode, self.stderr = rc, err


def test_macos_asks_for_the_admin_password_and_runs_in_background():
    calls = []
    res = elevate.launch("scan", platform="darwin", run=lambda args, **kw: calls.append((args, kw)) or R(0))
    args, kw = calls[0]
    assert args[:2] == ["osascript", "-e"] and "with administrator privileges" in args[2]
    assert args[2].rstrip().endswith('&" with administrator privileges') and kw["shell"] is False
    assert res.ok
    denied = elevate.launch("scan", platform="darwin", run=lambda *a, **k: R(1, "User canceled. (-128)"))
    assert denied.code == elevate.DENIED


def test_applescript_quotes_odd_paths():
    script = elevate.applescript("scan", python='/tmp/a"b\\c d/python')
    body = script[len('do shell script "'):script.rindex('" with administrator privileges')]
    assert not re.search(r'(?<!\\)"', body)                   # niciun " neescapat în textul comenzii
    assert "'/tmp/a\\\"b\\\\c d/python'" in body              # calea e citată pentru shell


def test_entry_point_refuses_unknown_jobs_from_any_folder(tmp_path):
    r = subprocess.run([sys.executable, "-I", str(elevate.ENTRY), "bogus"], cwd=tmp_path, capture_output=True,
                       timeout=60)
    assert r.returncode == 2 and not any(tmp_path.iterdir())
