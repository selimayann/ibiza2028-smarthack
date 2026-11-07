"""Pre-flight pentru Test Set (Oneata): rulează analiza de DOUĂ ori și verifică că rezultatul e identic.

Utilizare:
    python scripts/preflight.py <folder_cu_xml> --out <folder_rezultate>

Ce face:
1. rulează exact comanda oficială `python -m netscan analyze <folder> --out <tmp> --unmatched`
   de două ori, în două procese și foldere temporare separate (deci și cu altă ordine internă a
   dicționarelor Python: PYTHONHASHSEED diferă între procese);
2. compară findings.csv și scores.csv byte cu byte; dacă diferă, se oprește cu eroare (cod 1)
   și NU scrie nimic în --out;
3. copiază rezultatul în --out: findings.csv, scores.csv, unmatched_services.csv, hashes.txt;
4. afișează: fișierele, rândurile, fișierele cu ERROR, scorul per fișier, serviciile văzute care nu
   sunt în catalog și SHA-256 pentru findings.csv și scores.csv.

Nu are nevoie de drepturi de administrator și nu folosește rețeaua (doar citește fișiere XML).
Coduri de ieșire: 0 = totul identic, 1 = rulările diferă sau analiza a eșuat, 2 = argumente greșite.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RESULT_FILES = ("findings.csv", "scores.csv")
UNMATCHED = "unmatched_services.csv"
HASHES = "hashes.txt"
_ERROR_LINE = re.compile(r"^(?P<file>.+?): EROARE \((?P<code>[A-Z_]+)\)$")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_analyze(folder: Path, out: Path) -> str:
    """O rulare a comenzii oficiale, într-un proces separat. Întoarce ce a afișat comanda."""
    env = dict(os.environ)
    env.pop("PYTHONHASHSEED", None)  # fiecare proces cu ordinea lui: prindem orice nedeterminism
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, "-m", "netscan", "analyze", str(folder), "--out", str(out), "--unmatched"],
        cwd=REPO, env=env, capture_output=True, text=True, encoding="utf-8",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"analyze a eșuat (cod {proc.returncode}):\n{proc.stderr.strip()}")
    return proc.stdout


def git_commit() -> str:
    """Commit-ul exact folosit (pentru tag-ul `final`); „+modificări” dacă codul care calculează rezultatul
    (netscan/, pyproject.toml) are schimbări necomise, inclusiv fișiere noi."""
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True,
                              check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--", "netscan", "pyproject.toml"], cwd=REPO,
                               capture_output=True, text=True, check=True).stdout.strip()
        return head + (" +modificări necomise" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "necunoscut (fără git)"


def read_csv(path: Path) -> list[list[str]]:
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.reader(handle))


def preflight(folder: Path, out: Path, stream=sys.stdout) -> int:
    def say(text: str = "") -> None:
        print(text, file=stream)

    xml_files = sorted(p.name for p in folder.glob("*.xml") if p.is_file())
    with tempfile.TemporaryDirectory(prefix="preflight-") as tmp:
        run1, run2 = Path(tmp) / "rulare1", Path(tmp) / "rulare2"
        try:
            stdout1 = run_analyze(folder, run1)
            run_analyze(folder, run2)
        except RuntimeError as exc:
            say(f"OPRIT: {exc}")
            return 1

        different = [n for n in RESULT_FILES if (run1 / n).read_bytes() != (run2 / n).read_bytes()]
        if different:
            say("OPRIT: cele două rulări NU sunt identice: " + ", ".join(different))
            say("Nu încărca nimic. Rezultatul depinde de rulare: e un bug în motor (spune-i lui Radu).")
            return 1

        out.mkdir(parents=True, exist_ok=True)
        for name in (*RESULT_FILES, UNMATCHED):
            shutil.copyfile(run1 / name, out / name)

    findings = read_csv(out / "findings.csv")[1:]
    scores = read_csv(out / "scores.csv")[1:]
    unmatched = read_csv(out / UNMATCHED)[1:]
    errors = {m["file"]: m["code"] for m in (_ERROR_LINE.match(line) for line in stdout1.splitlines()) if m}
    hashes = {name: sha256(out / name) for name in RESULT_FILES}
    commit = git_commit()

    say(f"Folder: {folder}")
    say(f"Fișiere .xml: {len(xml_files)}   Rânduri în findings.csv: {len(findings)}   "
        f"Fișiere cu ERROR: {sum(1 for _, s in scores if s == 'ERROR')}")
    say()
    say("Scor per fișier:")
    width = max((len(f) for f, _ in scores), default=4)
    for file, score in scores:
        rows = sum(1 for r in findings if r[0] == file)
        detail = f"ERROR ({errors.get(file, '?')})" if score == "ERROR" else f"{score:>3}   {rows} {'rând' if rows == 1 else 'rânduri'}"
        say(f"  {file:<{width}}  {detail}")
    say()
    say(f"Servicii văzute care nu sunt în catalog: {len(unmatched)}")
    for file, ip, port, proto, service in unmatched:
        say(f"  {file}  {ip}:{port}/{proto}  {service or '(fără nume)'}")
    say()
    say("Cele două rulări sunt identice byte cu byte.")
    for name, digest in hashes.items():
        say(f"  SHA-256 {name}: {digest}")
    say(f"  Commit: {commit}")

    buf = io.StringIO()
    for name, digest in hashes.items():
        buf.write(f"{digest}  {name}\n")
    buf.write(f"# commit: {commit}\n# folder: {folder.name}\n")
    (out / HASHES).write_text(buf.getvalue(), encoding="utf-8")
    say(f"Scrise în {out}: findings.csv, scores.csv, {UNMATCHED}, {HASHES}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pre-flight Test Set: două rulări identice, hash-uri, raport.")
    parser.add_argument("folder", help="folderul cu fișierele nmap XML")
    parser.add_argument("--out", required=True, help="unde se copiază rezultatul final")
    args = parser.parse_args(argv)
    folder, out = Path(args.folder).resolve(), Path(args.out).resolve()
    if not folder.is_dir():
        print(f"Eroare: '{args.folder}' nu este un folder.", file=sys.stderr)
        return 2
    return preflight(folder, out)


if __name__ == "__main__":
    sys.exit(main())
