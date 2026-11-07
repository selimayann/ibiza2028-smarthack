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
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
ENTRY = Path(__file__).with_name("_elevated.py")
JOBS = ("scan", "auto")          # o scanare / scanare completă automată la intervale (până la oprire)

STARTED = "STARTED"
DENIED = "DENIED"                # utilizatorul a refuzat fereastra de permisiune
AUTH_FAILED = "AUTH_FAILED"      # Linux: parola greșită / permisiunea n-a putut fi cerută (pkexec 127)
FAILED = "FAILED"

# Codurile de ieșire ale lui pkexec (man pkexec): 126 = fereastra închisă / permisiune refuzată,
# 127 = autentificare eșuată sau fără agent de autentificare.
_PKEXEC_DISMISSED = 126
_PKEXEC_AUTH_FAILED = 127
_POLL_S = 0.3
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


def _watch_pkexec(proc, started: Optional[Callable[[], bool]], sleep: Callable[[float], None]) -> Launch:
    """Linux: pkexec rulează procesul de admin în prim-plan, deci nu „revine” după parolă. Așteptăm până când
    fie procesul de admin a scris progresul (= permisiune dată, scanarea a pornit), fie pkexec s-a terminat:
    126 = fereastra închisă, 127 = parolă greșită / fără fereastră, altceva fără progres = n-a pornit.
    Fără `started`, întoarcem imediat STARTED (ca înainte). Procesul e mereu așteptat (fără procese zombie)."""
    reap = lambda: threading.Thread(target=proc.wait, name="netscan-pkexec-wait", daemon=True).start()
    if started is None:
        reap()
        return Launch(True, STARTED)
    while True:
        rc = proc.poll()
        if rc is not None:
            if rc == _PKEXEC_DISMISSED:
                return Launch(False, DENIED)
            if rc == _PKEXEC_AUTH_FAILED:
                return Launch(False, AUTH_FAILED)
            # s-a terminat repede, dar a apucat să scrie progresul (de ex. „refuzat” de guardrail): îl arată UI-ul
            return Launch(True, STARTED) if started() else Launch(False, FAILED)
        if started():
            reap()
            return Launch(True, STARTED)
        sleep(_POLL_S)


def launch(job: str, platform: Optional[str] = None,
           shell_execute: Callable[[str, str, str], int] = None,
           run: Callable = subprocess.run, *, started: Optional[Callable[[], bool]] = None,
           popen: Callable = subprocess.Popen, sleep: Callable[[float], None] = time.sleep) -> Launch:
    """Blochează până răspunde utilizatorul la fereastra de permisiune: apelați-o dintr-un fir separat.
    `started()` spune dacă procesul de admin a început să scrie progresul (folosit pe Linux)."""
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
            proc = popen(["pkexec", *args], shell=False, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError:
            return Launch(False, FAILED)
        return _watch_pkexec(proc, started, sleep)
    return Launch(False, UNSUPPORTED)
