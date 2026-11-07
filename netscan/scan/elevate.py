"""Pornește scanarea nmap (pasul cu drepturi de administrator) DOAR când utilizatorul apasă butonul din aplicație,
prin fereastra de permisiune a sistemului: UAC pe Windows, parola de administrator pe macOS, pkexec pe Linux.

- Comanda e FIXĂ: `<python> -I <repo>/netscan/scan/_elevated.py <scan|auto>`. Nimic din cerere sau din pagină
  nu ajunge în ea; pe Windows și Linux nu trece prin shell, iar pe macOS textul e construit doar din căi locale,
  citate.
- `-I` (izolat): procesul de admin ignoră variabilele PYTHON* și folderul curent, ca nimeni să nu poată strecura
  alt cod în el.
- Procesul de admin face aceleași verificări ca `scan --confirm` (rețea, SSID, guardrail) și scrie DOAR în scans/
  (NFR-04). Istoricul îl scrie aplicația, ca utilizator normal (live.py).
- Fiecare pornire cere din nou acordul utilizatorului (echivalentul lui `--confirm`).
"""
from __future__ import annotations

import ctypes
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
ENTRY = Path(__file__).with_name("_elevated.py")
JOBS = ("scan", "auto")          # o scanare / scanare completă automată la intervale (până la oprire)

STARTED = "STARTED"
DENIED = "DENIED"                # utilizatorul a refuzat fereastra de permisiune
FAILED = "FAILED"
UNSUPPORTED = "UNSUPPORTED"

_SW_HIDE = 0
_SE_ERR_ACCESSDENIED = 5


@dataclass(frozen=True)
class Launch:
    ok: bool
    code: str


def command(job: str, python: Optional[str] = None) -> list[str]:
    if job not in JOBS:
        raise ValueError("job necunoscut")
    return [python or sys.executable, "-I", str(ENTRY), job]


def applescript(job: str, python: Optional[str] = None) -> str:
    """macOS: `do shell script … with administrator privileges`, în fundal (revine imediat după parolă)."""
    cmd = " ".join(shlex.quote(a) for a in command(job, python)) + " >/dev/null 2>&1 &"
    escaped = cmd.replace("\\", "\\\\").replace('"', '\\"')
    return f'do shell script "{escaped}" with administrator privileges'


def _shell_execute_runas(exe: str, params: str, cwd: str) -> int:
    fn = ctypes.windll.shell32.ShellExecuteW
    fn.restype = ctypes.c_void_p
    return int(fn(None, "runas", exe, params, cwd, _SW_HIDE) or 0)


def launch(job: str, platform: Optional[str] = None,
           shell_execute: Callable[[str, str, str], int] = None,
           run: Callable = subprocess.run) -> Launch:
    """Blochează până răspunde utilizatorul la fereastra de permisiune: apelați-o dintr-un fir separat."""
    args = command(job)
    platform = platform or sys.platform
    if platform == "win32":
        try:
            rc = (shell_execute or _shell_execute_runas)(args[0], subprocess.list2cmdline(args[1:]), str(REPO_ROOT))
        except (AttributeError, OSError):
            return Launch(False, FAILED)
        if rc > 32:
            return Launch(True, STARTED)
        return Launch(False, DENIED if rc == _SE_ERR_ACCESSDENIED else FAILED)
    if platform == "darwin":
        try:
            r = run(["osascript", "-e", applescript(job)], capture_output=True, text=True, timeout=300,
                    shell=False, check=False)
        except (OSError, subprocess.SubprocessError):
            return Launch(False, FAILED)
        if r.returncode == 0:
            return Launch(True, STARTED)
        return Launch(False, DENIED if "-128" in (r.stderr or "") else FAILED)
    if platform.startswith("linux"):
        try:
            subprocess.Popen(["pkexec", *args], shell=False, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError:
            return Launch(False, FAILED)
        return Launch(True, STARTED)   # dacă fereastra e refuzată, progresul rămâne „aștept permisiunea”
    return Launch(False, UNSUPPORTED)
