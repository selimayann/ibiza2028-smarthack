"""D6: unmatched_services.csv. Testul obligatoriu: findings.csv și scores.csv
sunt identice byte cu byte cu și fără opțiunea --unmatched."""

from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

import pytest

from netscan.engine import analyze_folder, find_unmatched, write_unmatched_csv

ROOT = Path(__file__).resolve().parent.parent
FOLDERS = [ROOT / "fixtures" / "validation", ROOT / "fixtures" / "traps"]


def _analyze(folder: Path, out: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "netscan", "analyze", str(folder), "--out", str(out), *extra],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )


@pytest.mark.parametrize("folder", FOLDERS, ids=lambda p: p.name)
def test_main_csvs_identical_with_and_without_option(folder, tmp_path):
    plain, with_opt = tmp_path / "plain", tmp_path / "opt"
    _analyze(folder, plain)
    _analyze(folder, with_opt, "--unmatched")
    for name in ("findings.csv", "scores.csv"):
        assert (plain / name).read_bytes() == (with_opt / name).read_bytes()


@pytest.mark.parametrize("folder", FOLDERS, ids=lambda p: p.name)
def test_file_only_written_on_request(folder, tmp_path):
    plain, with_opt = tmp_path / "plain", tmp_path / "opt"
    _analyze(folder, plain)
    _analyze(folder, with_opt, "--unmatched")
    assert not (plain / "unmatched_services.csv").exists()
    path = with_opt / "unmatched_services.csv"
    raw = path.read_bytes()
    assert raw.startswith(b"file,ip,port,proto,service\r\n")
    assert b"\n" not in raw.replace(b"\r\n", b"")


def test_default_stdout_unchanged(tmp_path):
    out = _analyze(FOLDERS[0], tmp_path / "a").stdout
    assert "fără constatare" not in out


def test_rows_are_open_ports_without_finding():
    scans = analyze_folder(FOLDERS[0])
    rows = find_unmatched(scans)
    assert rows == sorted(set(rows), key=lambda r: (r[0], tuple(map(int, r[1].split("."))), r[2], r[3], r[4]))
    findings = {(s.file, f.ip, f.port) for s in scans for f in s.findings}
    opened = {
        (s.file, h.ip, p.port): p
        for s in scans for h in s.hosts for p in h.ports if p.state == "open"
    }
    for file, ip, port, proto, service in rows:
        assert (file, ip, port) in opened and (file, ip, port) not in findings
        assert opened[(file, ip, port)].state == "open"


def test_error_files_and_closed_ports_are_skipped(tmp_path):
    scans = analyze_folder(FOLDERS[1])
    rows = find_unmatched(scans)
    errors = {s.file for s in scans if s.status == "error"}
    assert not any(r[0] in errors for r in rows)
    closed = {
        (s.file, h.ip, p.port) for s in scans for h in s.hosts for p in h.ports if p.state != "open"
    }
    open_ = {
        (s.file, h.ip, p.port) for s in scans for h in s.hosts for p in h.ports if p.state == "open"
    }
    for r in rows:
        assert (r[0], r[1], r[2]) in open_
    assert closed is not None


def test_formula_service_names_are_neutralised(tmp_path):
    from netscan.model import Host, Port, Scan

    host = Host(ip="10.0.0.5", device_id="ip:10.0.0.5", vendor="X",
                ports=[Port(port=9, proto="tcp", state="open", service="=cmd|' /C calc'!A0")])
    scan = Scan(file="f.xml", status="ok", hosts=[host], findings=[], score=100)
    path, count = write_unmatched_csv([scan], tmp_path)
    assert count == 1
    with open(path, newline="", encoding="utf-8") as handle:
        row = list(csv.reader(handle))[1]
    assert row[4].startswith("'=")
