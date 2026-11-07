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


# ---------- Linux (pkexec): fereastra închisă / parola greșită nu lasă UI-ul „în aer” ----------

class FakeProc:
    """pkexec simulat: `poll()` întoarce None de `running` ori, apoi codul de ieșire."""

    def __init__(self, rc, running=2):
        self.rc, self.running, self.waited = rc, running, False

    def poll(self):
        if self.running > 0:
            self.running -= 1
            return None
        return self.rc

    def wait(self):
        self.waited = True
        return self.rc


def _linux(proc, started):
    calls = []

    def popen(args, **kw):
        calls.append((args, kw))
        return proc

    res = elevate.launch("scan", platform="linux", started=started, popen=popen, sleep=lambda s: None)
    return res, calls


def test_linux_dialog_closed_is_denied():
    res, calls = _linux(FakeProc(126), started=lambda: False)
    assert res == elevate.Launch(False, elevate.DENIED)
    assert calls[0][0][0] == "pkexec" and calls[0][1]["shell"] is False


def test_linux_wrong_password_is_auth_failed():
    res, _ = _linux(FakeProc(127), started=lambda: False)
    assert res == elevate.Launch(False, elevate.AUTH_FAILED)


def test_linux_exit_without_progress_is_failed():
    res, _ = _linux(FakeProc(1), started=lambda: False)
    assert res == elevate.Launch(False, elevate.FAILED)


def test_linux_quick_exit_with_progress_is_started():
    # procesul de admin a scris progresul (de ex. „refuzat” de guardrail) și s-a terminat: UI-ul arată progresul
    res, _ = _linux(FakeProc(0, running=0), started=lambda: True)
    assert res == elevate.Launch(True, elevate.STARTED)


def test_linux_started_when_progress_appears_and_process_is_reaped():
    proc = FakeProc(None, running=10**6)          # scanarea rulează în continuare
    seen = iter([False, False, True])
    res, _ = _linux(proc, started=lambda: next(seen))
    assert res == elevate.Launch(True, elevate.STARTED)
    for _ in range(100):                          # firul care așteaptă procesul (fără zombie)
        if proc.waited:
            break
        import time
        time.sleep(0.01)
    assert proc.waited
