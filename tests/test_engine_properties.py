"""Proprietăți ale motorului: determinism, confidențialitate MAC, folder cu fișier stricat, CLI,
contract (sample.json)."""

from __future__ import annotations

import json
import random
import re
from pathlib import Path

from netscan.cli import main
from netscan.engine import analyze_file, analyze_folder
from netscan.engine.common import error_scan
from netscan.model import Scan
from tests import nmapxml as x
from tests.helpers import run_folder

ROOT = Path(__file__).resolve().parent.parent


def write_synthetic(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    for name, build in x.SYNTHETIC_VALIDATION.items():
        (folder / name).write_text(build(), encoding="utf-8")


# --------------------------- determinism (NFR-05) -------------------------- #
def test_same_input_same_output_bytes(tmp_path):
    write_synthetic(tmp_path / "in")
    run_folder(tmp_path / "in", tmp_path / "o1")
    run_folder(tmp_path / "in", tmp_path / "o2")
    for name in ("findings.csv", "scores.csv"):
        assert (tmp_path / "o1" / name).read_bytes() == (tmp_path / "o2" / name).read_bytes()


def test_json_dump_is_identical_between_runs(tmp_path):
    path = tmp_path / "v3.xml"
    path.write_text(x.v3_small_office(), encoding="utf-8")
    a = json.dumps(analyze_file(path).to_dict(), sort_keys=True)
    b = json.dumps(analyze_file(path).to_dict(), sort_keys=True)
    assert a == b


def test_order_of_hosts_and_ports_in_xml_does_not_matter(tmp_path):
    ports = [
        x.port(21, name="ftp", product="vsftpd", version="2.3.4"),
        x.port(23, name="telnet"),
        x.port(80, name="http", title="Admin"),
        x.port(161, "udp", name="snmp"),
        x.port(445, name="microsoft-ds"),
        x.port(139, name="netbios-ssn"),
    ]
    hosts = [
        ("192.168.1.9", "AA:00:00:00:00:09", "V"),
        ("192.168.1.10", "AA:00:00:00:00:0A", "V"),
        ("192.168.1.2", "AA:00:00:00:00:02", "V"),
    ]
    baseline = None
    for seed in range(8):
        rnd = random.Random(seed)
        shuffled_hosts = hosts[:]
        rnd.shuffle(shuffled_hosts)
        xml = x.nmaprun([
            x.host(ip, mac, vendor, ports=rnd.sample(ports, len(ports)))
            for ip, mac, vendor in shuffled_hosts
        ])
        path = tmp_path / f"s{seed}.xml"
        path.write_text(xml, encoding="utf-8")
        scan = analyze_file(path)
        result = [(f.ip, f.port, f.code) for f in scan.findings]
        if baseline is None:
            baseline = result
        assert result == baseline
    # ordinea din contract: IP numeric (.2 înainte de .9 înainte de .10), apoi port, apoi cod
    ips = [ip for ip, _, _ in baseline]
    assert ips == sorted(ips, key=lambda s: tuple(int(p) for p in s.split(".")))


# --------------------------- confidențialitate ----------------------------- #
def test_real_mac_never_appears_in_scan_output(tmp_path):
    mac = "DE:AD:BE:EF:12:34"
    xml = x.nmaprun([x.host("192.168.1.5", mac, "Vendor", ports=[x.port(23, name="telnet")])])
    path = tmp_path / "m.xml"
    path.write_text(xml, encoding="utf-8")
    scan = analyze_file(path)
    dumped = json.dumps(scan.to_dict())
    for needle in (mac, mac.lower(), mac.replace(":", ""), "EF:12:34", "ef:12:34", "12:34"):
        assert needle not in dumped
    assert scan.hosts[0].mac_masked == "DE:AD:BE:XX:XX:XX"
    assert re.fullmatch(r"[0-9a-f]{12}", scan.hosts[0].device_id)

    out = tmp_path / "out"
    from netscan.engine import write_results
    f_path, s_path = write_results([scan], out)
    for p in (f_path, s_path):
        assert mac not in p.read_text(encoding="utf-8")


def test_device_id_is_stable_and_depends_on_salt(tmp_path, monkeypatch):
    xml = x.nmaprun([x.host("192.168.1.5", "AA:00:00:00:00:01", "V", ports=[])])
    path = tmp_path / "d.xml"
    path.write_text(xml, encoding="utf-8")

    monkeypatch.setenv("NETSCAN_SALT", "salt-1")
    a1 = analyze_file(path).hosts[0].device_id
    a2 = analyze_file(path).hosts[0].device_id
    monkeypatch.setenv("NETSCAN_SALT", "salt-2")
    b = analyze_file(path).hosts[0].device_id
    assert a1 == a2 and a1 != b


def test_device_id_without_mac_uses_ip(tmp_path):
    path = tmp_path / "d.xml"
    path.write_text(x.nmaprun([x.host("192.168.1.77", ports=[])]), encoding="utf-8")
    host = analyze_file(path).hosts[0]
    assert host.device_id == "ip:192.168.1.77" and host.mac_masked is None


def test_device_id_survives_ip_change(tmp_path):
    """Același MAC, alt IP (DHCP): același device_id (necesar istoricului)."""
    a = tmp_path / "a.xml"
    b = tmp_path / "b.xml"
    a.write_text(x.nmaprun([x.host("192.168.1.5", "AA:00:00:00:00:01", "V", ports=[])]), encoding="utf-8")
    b.write_text(x.nmaprun([x.host("192.168.1.55", "AA:00:00:00:00:01", "V", ports=[])]), encoding="utf-8")
    assert analyze_file(a).hosts[0].device_id == analyze_file(b).hosts[0].device_id


# --------------------------- folder cu fișier stricat ---------------------- #
def test_folder_continues_after_broken_file(tmp_path):
    write_synthetic(tmp_path / "in")
    (tmp_path / "in" / "V0_empty.xml").write_text("", encoding="utf-8")
    (tmp_path / "in" / "V9_garbage.xml").write_bytes(b"\x00\xff\x00")
    scans = analyze_folder(tmp_path / "in")
    by_name = {s.file: s for s in scans}
    assert by_name["V0_empty.xml"].status == "error"
    assert by_name["V9_garbage.xml"].status == "error"
    assert by_name["V1_home_basic.xml"].score == 90
    assert [s.file for s in scans] == sorted(s.file for s in scans)


def test_folder_ignores_non_xml_files_and_subfolders(tmp_path):
    folder = tmp_path / "in"
    write_synthetic(folder)
    (folder / "notes.txt").write_text("nu e scanare", encoding="utf-8")
    (folder / "sub").mkdir()
    (folder / "sub" / "nested.xml").write_text(x.v1_home_basic(), encoding="utf-8")
    assert "notes.txt" not in [s.file for s in analyze_folder(folder)]
    assert "nested.xml" not in [s.file for s in analyze_folder(folder)]


# --------------------------- CSV: format exact ----------------------------- #
def test_csv_exact_bytes(tmp_path):
    folder = tmp_path / "in"
    folder.mkdir()
    (folder / "V4_legacy.xml").write_text(x.v4_legacy(), encoding="utf-8")
    (folder / "V7_broken.xml").write_text(x.v7_broken(), encoding="utf-8")
    run_folder(folder, tmp_path / "out")
    findings = (tmp_path / "out" / "findings.csv").read_bytes()
    scores = (tmp_path / "out" / "scores.csv").read_bytes()
    assert findings == (
        b"file,ip,port,finding_code,severity\r\n"
        b"V4_legacy.xml,192.168.1.1,23,TELNET_OPEN,high\r\n"
        b"V4_legacy.xml,192.168.1.1,80,HTTP_ADMIN_CLEARTEXT,medium\r\n"
        b"V4_legacy.xml,192.168.1.1,161,SNMP_EXPOSED,medium\r\n"
        b"V4_legacy.xml,192.168.1.60,21,FTP_CLEARTEXT,medium\r\n"
        b"V4_legacy.xml,192.168.1.60,21,OUTDATED_SERVICE,high\r\n"
        b"V4_legacy.xml,192.168.1.99,,UNKNOWN_DEVICE,low\r\n"
    )
    assert scores == b"file,network_score\r\nV4_legacy.xml,25\r\nV7_broken.xml,ERROR\r\n"


# --------------------------- CLI -------------------------------------------- #
def test_cli_analyze_writes_both_files(tmp_path, capsys):
    write_synthetic(tmp_path / "in")
    code = main(["analyze", str(tmp_path / "in"), "--out", str(tmp_path / "out")])
    captured = capsys.readouterr().out
    assert code == 0
    assert (tmp_path / "out" / "findings.csv").exists()
    assert (tmp_path / "out" / "scores.csv").exists()
    assert "V7_broken.xml: EROARE (TRUNCATED)" in captured
    assert "V1_home_basic.xml: scor 90, 1 constatări" in captured


def test_cli_missing_folder_is_a_clean_error(tmp_path, capsys):
    code = main(["analyze", str(tmp_path / "nu_exista"), "--out", str(tmp_path / "out")])
    assert code == 2
    assert "nu este un folder" in capsys.readouterr().err


def test_cli_empty_folder_writes_headers_only(tmp_path):
    (tmp_path / "in").mkdir()
    assert main(["analyze", str(tmp_path / "in"), "--out", str(tmp_path / "out")]) == 0
    assert (tmp_path / "out" / "findings.csv").read_text() == "file,ip,port,finding_code,severity\n"
    assert (tmp_path / "out" / "scores.csv").read_text() == "file,network_score\n"


# --------------------------- contract --------------------------------------- #
def test_sample_json_matches_the_model_contract():
    data = json.loads((ROOT / "fixtures" / "sample.json").read_text(encoding="utf-8"))
    scan = Scan.from_dict(data)
    assert scan.to_dict() == data  # același set de câmpuri, aceleași tipuri
    assert sum(f.points for f in scan.findings) == 100 - scan.score


def test_error_scan_has_null_score_in_contract():
    scan = error_scan("x.xml", "EMPTY")
    d = scan.to_dict()
    assert d["status"] == "error" and d["score"] is None and d["hosts"] == [] and d["findings"] == []
    assert Scan.from_dict(d).to_dict() == d
