"""„Descarcă PDF”: raportul salvat direct ca fișier PDF, pe acest calculator.

Browserul nu poate salva un PDF fără fereastra lui de tipărire, așa că aplicația folosește un browser deja instalat
(Edge e pe orice Windows; altfel Chrome / Chromium) pornit FĂRĂ fereastră, care deschide pagina raportului de pe
acest calculator (doar 127.0.0.1) și o salvează ca PDF. Fără internet: doar pagina noastră locală, cu serviciile de
fundal ale browserului oprite. Pagina raportului se micșorează singură ca să încapă pe o pagină A4 (report.js).
Nu e niciun browser potrivit: None, iar aplicația deschide fereastra obișnuită de tipărire.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

TIMEOUT_S = 40

# Serviciile de fundal ale browserului oprite: doar pagina locală, nimic altceva trimis.
_QUIET = ["--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--disable-extensions",
          "--disable-background-networking", "--disable-component-update", "--disable-sync",
          "--disable-domain-reliability", "--disable-client-side-phishing-detection", "--metrics-recording-only",
          "--disable-default-apps", "--no-pdf-header-footer", "--print-to-pdf-no-header", "--virtual-time-budget=2500"]


def find_browser() -> Optional[str]:
    """Edge sau Chrome / Chromium instalat pe calculator (căi fixe sau din PATH)."""
    cands: list[str] = []
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"), os.environ.get("LOCALAPPDATA")):
            if base:
                cands += [str(Path(base) / "Microsoft/Edge/Application/msedge.exe"),
                          str(Path(base) / "Google/Chrome/Application/chrome.exe")]
    elif sys.platform == "darwin":
        cands += ["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                  "/Applications/Chromium.app/Contents/MacOS/Chromium"]
    for name in ("microsoft-edge", "google-chrome", "chromium", "chromium-browser", "msedge", "chrome"):
        found = shutil.which(name)
        if found:
            cands.append(found)
    return next((c for c in cands if c and Path(c).is_file()), None)


def make_pdf(url: str, browser: Optional[str] = None) -> Optional[bytes]:
    """PDF-ul paginii locale `url` (doar http://127.0.0.1:...). None dacă nu se poate (fără browser, eroare, timp)."""
    if not url.startswith("http://127.0.0.1:"):
        return None
    exe = browser or find_browser()
    if not exe:
        return None
    with tempfile.TemporaryDirectory(prefix="safeeel-pdf-") as tmp:
        out = Path(tmp) / "raport.pdf"
        cmd = [exe, *_QUIET, f"--user-data-dir={Path(tmp) / 'profile'}", f"--print-to-pdf={out}", url]
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=TIMEOUT_S,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError):
            return None
        data = out.read_bytes() if out.is_file() else b""
    return data if data.startswith(b"%PDF") else None
