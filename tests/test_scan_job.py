"""B: scanarea completă pornită din aplicație (pasul de admin). Fără nmap real și fără drepturi de admin."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from netscan.engine.parser import analyze_file
from netscan.scan import runner, scan_job

ROOT = Path(__file__).parent.parent
LAB = ROOT / "fixtures" / "lab"

NMAP_OUT = """Starting Nmap 7.98 ( https://nmap.org ) at 2026-11-07 22:50 GTB Standard Time
Initiating ARP Ping Scan at 22:50
Scanning 14 hosts [1 port/host]
Completed ARP Ping Scan at 22:50, 1.20s elapsed (14 total hosts)
Initiating SYN Stealth Scan at 22:50
Scanning 4 hosts [1003 ports/host]
Discovered open port 21/tcp on 172.20.10.1
Discovered open port 8080/tcp on 172.20.10.14
Stats: 0:00:35 elapsed; 0 hosts completed (4 up), 4 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 45.50% done; ETC: 22:52 (0:00:42 remaining)
Completed SYN Stealth Scan at 22:51, 70.10s elapsed (4012 total ports)
Initiating UDP Scan at 22:51
UDP Scan Timing: About 20.00% done; ETC: 22:53 (0:01:20 remaining)
Discovered open port 53/udp on 172.20.10.1
Completed UDP Scan at 22:52, 60.00s elapsed (20 total ports)
Initiating Service scan at 22:52
Service scan Timing: About 66.67% done; ETC: 22:53 (0:00:10 remaining)
Completed Service scan at 22:53, 30.00s elapsed (6 services on 4 hosts)
NSE: Script scanning 4 hosts.
Initiating NSE at 22:53
Completed NSE at 22:53, 1.02s elapsed
Nmap done: 16 IP addresses (4 hosts up) scanned in 190.12 seconds""".splitlines()


def test_progress_follows_the_nmap_phases():
    p = scan_job.Progress("scan", now=lambda: 1.0)
    seen = []
    for line in NMAP_OUT:
        p.feed(line)
        seen.append((p.data["phase"], p.data["percent"]))
        if line.startswith("SYN Stealth Scan Timing"):
            assert p.data["eta_s"] == 42 and p.data["phase"] == "tcp"
    percents = [pc for _, pc in seen]
    assert percents == sorted(percents) and percents[-1] == 99.0         # 100 doar când XML-ul e gata
    assert [d["port"] for d in p.data["discovered"]] == [21, 8080, 53]
    assert p.data["hosts_up"] == 4
    p.finish("done", file="scan_x.xml")
    assert p.data["percent"] == 100.0 and p.data["file"] == "scan_x.xml"


def test_nse_prescan_at_the_start_does_not_jump_the_bar():
    """Cu --script, nmap rulează NSE și înainte de scanare; bara nu are voie să sară la final (văzut live)."""
    p = scan_job.Progress("scan", now=lambda: 1.0)
    for line in ["NSE: Loaded 1 scripts for scanning.", "NSE: Script Pre-scanning.", "Initiating NSE at 22:53",
                 "Completed NSE at 22:53, 0.00s elapsed", "Initiating ARP Ping Scan at 22:53"]:
        p.feed(line)
    assert p.data["percent"] == 0.0 and p.data["phase"] == "discover"
    p.feed("Initiating SYN Stealth Scan at 22:53")
    p.feed("SYN Stealth Scan Timing: About 69.74% done; ETC: 23:01 (0:07:25 remaining)")
    assert p.data["phase"] == "tcp" and 25 < p.data["percent"] < 35 and p.data["eta_s"] == 445
    p.feed("Initiating SYN Stealth Scan at 22:58")            # alt grup de dispozitive: bara nu scade
    assert p.data["percent"] > 25


@pytest.mark.parametrize("line", [
    "Discovered open port 99999/tcp on 172.20.10.1", "Discovered open port 80/tcp on 999.1.1.1",
    "Discovered open port 80/sctp on 172.20.10.1", "<script>alert(1)</script>", "x" * 10000,
    "Bogus Timing: About 50.00% done",
])
def test_hostile_or_unknown_lines_change_nothing(line):
    p = scan_job.Progress("scan", now=lambda: 1.0)
    before = json.dumps(p.data)
    p.feed(line)
    assert json.dumps(p.data) == before


def _write(tmp_path, data):
    (tmp_path / scan_job.PROGRESS_FILE).write_text(json.dumps(data) if not isinstance(data, str) else data,
                                                   encoding="utf-8")


@pytest.mark.parametrize("bad", ["{nu e json", json.dumps([1, 2]), json.dumps({"state": "hacked"}),
                                 json.dumps({"state": "running", "x": "y" * 70000})])
def test_read_progress_rejects_broken_files(tmp_path, bad):
    _write(tmp_path, bad)
    assert scan_job.read_progress(tmp_path) is None


def test_read_progress_sanitizes_fields(tmp_path):
    _write(tmp_path, {"state": "done", "file": "../../data/netscan.db", "percent": 900, "phase": "<b>",
                      "discovered": [{"ip": "172.20.10.1", "port": 21, "proto": "tcp"},
                                     {"ip": "evil", "port": 1, "proto": "tcp"},
                                     {"ip": "172.20.10.1", "port": 70000, "proto": "tcp"}],
                      "msg_ro": "a" * 1000, "pid": "123"})
    p = scan_job.read_progress(tmp_path)
    assert p["file"] is None and p["percent"] == 0.0 and p["phase"] is None and p["pid"] is None
    assert p["discovered"] == [{"ip": "172.20.10.1", "port": 21, "proto": "tcp"}] and len(p["msg_ro"]) == 300


class Plan:
    def __init__(self, ok, out_path=None, code="OK"):
        self.ok, self.out_path, self.reason_code = ok, out_path, code
        self.msg_ro, self.msg_en = "Ești conectat la altă rețea Wi-Fi.", "Wrong Wi-Fi."


def test_run_once_writes_only_inside_scans(tmp_path, monkeypatch):
    """NFR-04: procesul de admin scrie doar XML-ul și progresul, în scans/; nimic în data/ sau în istoric."""
    monkeypatch.chdir(tmp_path)
    scans = tmp_path / "scans"
    scans.mkdir()

    def prepare(target, out_path):
        assert target is None                                   # ținta o alege guardrail-ul, nu cererea
        return Plan(True, str(out_path))

    def execute(plan, on_line, should_stop):
        assert plan.out_path.endswith(".xml.part")          # în lucru nu e un *.xml (nu apare ca scanare)
        for line in NMAP_OUT:
            on_line(line)
        Path(plan.out_path).write_text("<nmaprun/>")
        return plan

    rc = scan_job.run_once(scans, "scan", scan_job.ProgressWriter(scans, every_s=0), prepare=prepare, execute=execute)
    written = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())
    assert rc == 0 and len(written) == 2 and written[0] == "scans/.scan_progress.json"
    assert written[1].startswith("scans/scan_") and written[1].endswith(".xml")
    p = scan_job.read_progress(scans)
    assert p["state"] == "done" and p["percent"] == 100.0 and p["file"] == Path(written[1]).name


def test_failed_scan_leaves_no_partial_file(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()

    class Failed(Plan):
        def __init__(self):
            super().__init__(False, code=runner.NMAP_FAILED)

    def execute(plan, on_line, should_stop):
        Path(plan.out_path).write_text("<nmaprun><host>")    # oprit la jumătate
        return Failed()

    rc = scan_job.run_once(scans, "scan", scan_job.ProgressWriter(scans, every_s=0),
                           prepare=lambda t, out_path: Plan(True, str(out_path)), execute=execute)
    assert rc == 2 and sorted(p.name for p in scans.iterdir()) == [".scan_progress.json"]


def test_run_once_refused_plan_records_why(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    rc = scan_job.run_once(scans, "scan", scan_job.ProgressWriter(scans, every_s=0),
                           prepare=lambda t, out_path: Plan(False, code="WRONG_SSID"),
                           execute=lambda *a, **k: pytest.fail("nu trebuia să scaneze"))
    p = scan_job.read_progress(scans)
    assert rc == 2 and p["state"] == "refused" and p["code"] == "WRONG_SSID" and "altă rețea" in p["msg_ro"]


def test_main_unknown_job_does_nothing(tmp_path):
    assert scan_job.main(["rm -rf /"], scans_dir=tmp_path / "s", load_env=False) == 2
    assert not (tmp_path / "s").exists()


def test_main_refuses_when_a_scan_is_already_running(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        (scans / scan_job.LOCK_FILE).write_text(str(proc.pid))
        assert scan_job.main(["scan"], scans_dir=scans, run=lambda *a: pytest.fail("a doua scanare"),
                             load_env=False) == 3
    finally:
        proc.kill()


def test_auto_job_repeats_until_the_stop_file(tmp_path):
    scans = tmp_path / "scans"
    runs, clock = [], [1000.0]

    def run(scans_dir, job, writer):
        runs.append(job)
        return 0

    def sleep(s):
        clock[0] += 60
        if len(runs) == 2:
            (scans / scan_job.STOP_FILE).write_text("stop")

    scans.mkdir()
    (scans / scan_job.APP_ALIVE_FILE).write_text("viu")              # aplicația e deschisă
    rc = scan_job.main(["auto"], scans_dir=scans, run=run, sleep=sleep, now=lambda: clock[0], load_env=False)
    assert rc == 0 and runs == ["auto", "auto"]
    assert not (scans / scan_job.LOCK_FILE).exists() and not (scans / scan_job.STOP_FILE).exists()
    assert scan_job.read_progress(scans)["state"] == "stopped"


# --- runner.execute_streaming ---------------------------------------------------------------------------

class FakeProc:
    def __init__(self, lines, rc=0):
        self.stdout = iter(line + "\n" for line in lines)
        self.rc, self.terminated = rc, False

    def poll(self):
        return None if not self.terminated else self.rc

    def terminate(self):
        self.terminated = True

    def wait(self):
        return self.rc


def _plan(tmp_path, probes):
    out = tmp_path / "scans" / "scan_x.xml"
    return runner.ScanPlan(True, "OK", "", "", target="172.20.10.0/28",
                           args=["nmap", "-n", "-sS", "--max-rate", "100", "-oX", str(out), "172.20.10.0/28"],
                           out_path=str(out), service_probes=str(probes), versiondb=str(out.parent / "db"))


def test_execute_streaming_only_adds_display_flags(tmp_path, monkeypatch):
    probes = tmp_path / "probes"
    probes.write_text("Probe TCP NULL q||\n")
    plan = _plan(tmp_path, probes)
    monkeypatch.setattr(runner, "is_admin", lambda: True)
    calls, lines = [], []

    def popen(args, **kw):
        calls.append((args, kw))
        Path(plan.out_path).write_text("<nmaprun/>")
        return FakeProc(NMAP_OUT[:3])

    assert runner.execute_streaming(plan, lines.append, nmap_path="C:/nmap.exe", popen=popen, poll_s=0.01).ok
    args, kw = calls[0]
    assert args == ["C:/nmap.exe", "-v", "--stats-every", "5s", *runner.SPEED_ARGS, *plan.args[1:]]
    assert kw.get("shell") is False and lines == NMAP_OUT[:3]


def test_execute_streaming_refuses_without_admin(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "is_admin", lambda: False)
    plan = _plan(tmp_path, tmp_path / "probes")
    res = runner.execute_streaming(plan, print, popen=lambda *a, **k: pytest.fail("nmap fără admin"))
    assert not res.ok and res.reason_code == runner.NOT_ADMIN


def test_execute_streaming_stop_terminates_nmap(tmp_path, monkeypatch):
    probes = tmp_path / "probes"
    probes.write_text("Probe TCP NULL q||\n")
    monkeypatch.setattr(runner, "is_admin", lambda: True)
    proc = FakeProc([])
    res = runner.execute_streaming(_plan(tmp_path, probes), print, should_stop=lambda: True, nmap_path="nmap",
                                   popen=lambda *a, **k: proc, poll_s=0.01)
    import time
    for _ in range(100):
        if proc.terminated:
            break
        time.sleep(0.01)
    assert proc.terminated and res.reason_code in (runner.STOPPED, runner.NMAP_FAILED)


def test_engine_reads_progress_output_xml_the_same(tmp_path):
    """Cu -v și --stats-every, nmap pune în XML și <taskprogress>, <hosthint>; motorul trebuie să dea același rezultat."""
    src = (LAB / "scan_01_before.xml").read_text(encoding="utf-8")
    start = src.index(">", src.index("<nmaprun")) + 1
    extra = ('<verbose level="1"/><taskbegin task="ARP Ping Scan" time="1"/>'
             '<taskprogress task="SYN Stealth Scan" time="2" percent="45.50" remaining="42" etc="3"/>'
             '<hosthint><status state="up" reason="arp-response" reason_ttl="0"/>'
             '<address addr="172.20.10.99" addrtype="ipv4"/></hosthint>')
    (tmp_path / "scan_01_before.xml").write_text(src[:start] + extra + src[start:], encoding="utf-8")
    a, b = analyze_file(str(LAB / "scan_01_before.xml")), analyze_file(str(tmp_path / "scan_01_before.xml"))
    assert (a.score, [f.__dict__ for f in a.findings], [h.ip for h in a.hosts]) == \
           (b.score, [f.__dict__ for f in b.findings], [h.ip for h in b.hosts])


def test_lock_holder_ignores_dead_and_own_pids(tmp_path):
    (tmp_path / scan_job.LOCK_FILE).write_text(str(os.getpid()))
    (tmp_path / scan_job.WATCH_LOCK_FILE).write_text("999999999")
    assert scan_job.lock_holder(tmp_path) is None


def test_lock_stores_pid_and_start_time_and_a_reused_pid_is_not_a_holder(tmp_path):
    scan_job.write_lock(tmp_path)
    data = json.loads((tmp_path / scan_job.LOCK_FILE).read_text())
    assert data["pid"] == os.getpid() and isinstance(data["created"], float)
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        (tmp_path / scan_job.LOCK_FILE).write_text(json.dumps({"pid": proc.pid, "created": 12345.0}))
        assert scan_job.lock_holder(tmp_path) is None                 # același PID, alt proces (pornit altă dată)
        real = scan_job._create_time(proc.pid)
        (tmp_path / scan_job.LOCK_FILE).write_text(json.dumps({"pid": proc.pid, "created": real}))
        assert scan_job.lock_holder(tmp_path) == proc.pid
    finally:
        proc.kill()


def test_stale_lock_is_removed_and_said(tmp_path):
    (tmp_path / scan_job.LOCK_FILE).write_text(json.dumps({"pid": 999999999, "created": 1.0}))
    said = []
    assert scan_job.clear_stale_lock(tmp_path, log=said.append)
    assert not (tmp_path / scan_job.LOCK_FILE).exists() and "999999999" in said[0]
    assert not scan_job.clear_stale_lock(tmp_path, log=said.append) and len(said) == 1


def test_busy_because_of_the_terminal_monitor_is_written_for_the_app(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        (scans / scan_job.WATCH_LOCK_FILE).write_text(str(proc.pid))
        assert scan_job.main(["scan"], scans_dir=scans, run=lambda *a: pytest.fail("a doua scanare"),
                             load_env=False) == 3
    finally:
        proc.kill()
    p = scan_job.read_progress(scans)
    assert p["state"] == "refused" and p["code"] == "BUSY" and p["msg_en"]
