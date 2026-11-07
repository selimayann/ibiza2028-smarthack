"""Scanările reale din lab (fixtures/lab/): integritatea și rezultatul motorului, ca în docs/lab.md."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from netscan.engine.analyze import analyze_file

LAB = Path(__file__).parent.parent / "fixtures" / "lab"

GATEWAY = {("UNKNOWN_DEVICE", None), ("FTP_CLEARTEXT", 21)}
TARGET_AFTER = {
    ("UNKNOWN_DEVICE", None),
    ("SSH_OPEN", 22),
    ("MQTT_EXPOSED", 1883),
    ("FTP_CLEARTEXT", 2121),
    ("OUTDATED_SERVICE", 2121),
    ("HTTP_ADMIN_CLEARTEXT", 8080),
}
TARGET_BEFORE = TARGET_AFTER | {("TELNET_OPEN", 2323), ("DB_EXPOSED", 6379)}

EXPECTED = {
    "scan_01_before.xml": (TARGET_BEFORE, 0),
    "scan_02.xml": (TARGET_BEFORE, 0),
    "scan_03_after.xml": (TARGET_AFTER, 30),
}


def test_files_match_sha256sums():
    # Fișierele sunt exact cele produse de tool pe laptopul-scanner (nimic editat de mână).
    lines = (LAB / "SHA256SUMS.txt").read_text().split()
    sums = {name.lstrip("*"): digest for digest, name in zip(lines[::2], lines[1::2])}
    assert set(sums) == set(EXPECTED)
    for name, digest in sums.items():
        assert hashlib.sha256((LAB / name).read_bytes()).hexdigest() == digest, name


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_engine_results_match_lab_md(name):
    target, score = EXPECTED[name]
    scan = analyze_file(LAB / name)
    assert scan.status == "ok"
    got = {(f.ip, f.code, f.port) for f in scan.findings}
    want = {("172.20.10.1", c, p) for c, p in GATEWAY} | {("172.20.10.14", c, p) for c, p in target}
    assert got == want
    assert scan.score == score


def test_scan_before_has_at_least_five_codes_and_after_improves():
    before = analyze_file(LAB / "scan_01_before.xml")
    after = analyze_file(LAB / "scan_03_after.xml")
    assert len({f.code for f in before.findings}) >= 5
    assert len(after.findings) < len(before.findings)
    assert after.score > before.score


def test_macs_are_randomized_not_hardware():
    # Bitul „administrat local” (a doua cifră hex din primul octet: 2, 6, A, E) = MAC aleatoriu.

    for name in EXPECTED:
        macs = re.findall(r'addr="([0-9A-Fa-f:]{17})" addrtype="mac"', (LAB / name).read_text())
        assert macs, name
        assert all(m[1].upper() in "26AE" for m in macs), name
