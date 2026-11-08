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
    expected = [a if a != plan.out_path else plan.out_path + runner.PART_SUFFIX for a in plan.args[1:]]
    assert args == ["C:/nmap.exe", "-v", "--stats-every", "5s", *runner.SPEED_ARGS, *expected]   # -oX în .part
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



# ---------- o singură scanare odată; aplicația nu vede fișierul pe jumătate scris ----------

def test_nmap_writes_a_part_file_that_becomes_xml_only_at_the_end(tmp_path, monkeypatch):
    probes = tmp_path / "probes"
    probes.write_text("Probe TCP NULL q||\n")
    plan = _plan(tmp_path, probes)
    monkeypatch.setattr(runner, "is_admin", lambda: True)
    seen = {}

    def popen(args, **kw):
        part = Path(args[args.index("-oX") + 1])
        part.write_text("<nmaprun>")                       # pe jumătate scris, cât rulează
        seen["xml_while_running"] = sorted(p.name for p in Path(plan.out_path).parent.glob("*.xml"))
        part.write_text("<nmaprun/>")
        return FakeProc(NMAP_OUT[:1])

    assert runner.execute_streaming(plan, lambda l: None, nmap_path="C:/nmap.exe", popen=popen, poll_s=0.01).ok
    assert seen["xml_while_running"] == []                 # aplicația (care citește *.xml) nu vede nimic
    assert Path(plan.out_path).read_text() == "<nmaprun/>" and not Path(plan.out_path + runner.PART_SUFFIX).exists()


def test_failed_scan_leaves_no_half_file(tmp_path, monkeypatch):
    probes = tmp_path / "probes"
    probes.write_text("Probe TCP NULL q||\n")
    plan = _plan(tmp_path, probes)
    monkeypatch.setattr(runner, "is_admin", lambda: True)

    def popen(args, **kw):
        Path(args[args.index("-oX") + 1]).write_text("<nmaprun>")
        return FakeProc(NMAP_OUT[:1], rc=1)

    r = runner.execute_streaming(plan, lambda l: None, nmap_path="C:/nmap.exe", popen=popen, poll_s=0.01)
    assert not r.ok and list(Path(plan.out_path).parent.glob("*.part")) == [] and not Path(plan.out_path).exists()


def test_only_one_scan_at_a_time(tmp_path, monkeypatch):
    probes = tmp_path / "probes"
    probes.write_text("Probe TCP NULL q||\n")
    plan = _plan(tmp_path, probes)
    monkeypatch.setattr(runner, "is_admin", lambda: True)
    scans = Path(plan.out_path).parent
    assert runner.acquire_lock(scans)                       # altă scanare (de ex. din terminal) rulează acum
    called = []
    r = runner.execute_streaming(plan, lambda l: None, nmap_path="C:/nmap.exe",
                                 popen=lambda *a, **k: called.append(a), poll_s=0.01)
    assert r.reason_code == runner.ALREADY_RUNNING and called == [] and runner.scan_running(scans)
    runner.release_lock(scans)
    assert not runner.scan_running(scans)


def test_a_lock_left_by_a_dead_process_is_replaced(tmp_path):
    (tmp_path / runner.LOCK_NAME).write_text("999999")     # PID care nu există
    assert runner.acquire_lock(tmp_path)
    runner.release_lock(tmp_path)


def test_power_saving_laptops_get_a_full_second_to_answer():
    i = runner.SPEED_ARGS.index("--max-rtt-timeout")
    assert runner.SPEED_ARGS[i + 1] == "1000ms" and runner.SPEED_ARGS[:2] == ["--min-rate", "80"]



# ---------- scanarea vede aceleași dispozitive ca protecția live (tabela ARP a sistemului) ----------

def _netplan(tmp_path):
    from netscan.scan import network as net
    out = tmp_path / "scans" / "scan_y.xml"
    info = net.NetworkInfo(iface="Wi-Fi", ip="172.20.10.10", cidr="172.20.10.0/28", gateway="172.20.10.1", status=net.OK)
    return runner.ScanPlan(True, "OK", "", "", network=info, target="172.20.10.0/28",
                           args=["nmap", "-n", "-sS", "--max-rate", "100", "-oX", str(out), "172.20.10.0/28"], out_path=str(out))


def test_scan_targets_the_devices_the_system_sees_connected(tmp_path):
    plan = _netplan(tmp_path)
    poked = []
    known = runner.known_hosts(plan, poke=lambda ips, bind: poked.extend(ips),
                               read=lambda info: {"172.20.10.1": 1, "172.20.10.14": 1, "172.20.10.3": 1, "8.8.8.8": 1},
                               sleep=lambda s: None)
    assert known == ["172.20.10.1", "172.20.10.3", "172.20.10.14"]          # doar din hotspot, fără laptopul nostru
    assert "172.20.10.10" not in poked and len(poked) == 13
    args = runner._with_known(plan.args, plan, known)
    assert args[-5:] == ["-Pn", "--disable-arp-ping", "172.20.10.1", "172.20.10.3", "172.20.10.14"]
    assert "172.20.10.0/28" not in args


def test_without_the_system_table_the_scan_is_as_before(tmp_path):
    plan = _netplan(tmp_path)
    assert runner.known_hosts(plan, poke=lambda *a: None, read=lambda info: None, sleep=lambda s: None) == []
    assert runner._with_known(plan.args, plan, []) == plan.args
    boom = lambda *a: (_ for _ in ()).throw(OSError("fără rețea"))
    assert runner.known_hosts(plan, poke=boom, read=boom, sleep=lambda s: None) == []



def test_gateway_and_laptops_are_scanned_in_two_short_passes_into_one_file(tmp_path):
    """Telefonul-hotspot răspunde doar la ARP-ul lui nmap, laptopurile doar la cel al sistemului: două treceri."""
    plan = _netplan(tmp_path)
    passes = runner._passes(plan.args, plan, ["172.20.10.1", "172.20.10.2", "172.20.10.14"])
    assert len(passes) == 2
    gw, rest = passes
    assert gw[-1] == "172.20.10.1" and "-Pn" not in gw and gw[gw.index("-oX") + 1].endswith(".gw")
    assert rest[-4:] == ["-Pn", "--disable-arp-ping", "172.20.10.2", "172.20.10.14"]
    assert rest[rest.index("-oX") + 1] == plan.out_path
    # fără gateway în listă: o singură trecere; fără listă: ca înainte
    assert len(runner._passes(plan.args, plan, ["172.20.10.2"])) == 1
    assert runner._passes(plan.args, plan, []) == [plan.args]


def test_hosts_from_the_gateway_pass_are_merged_into_the_main_file(tmp_path):
    main, extra = tmp_path / "a.xml", tmp_path / "a.xml.gw"
    main.write_text('<nmaprun><host><address addr="172.20.10.2"/></host><runstats><finished/></runstats></nmaprun>')
    extra.write_text('<nmaprun><host><address addr="172.20.10.1"/></host><runstats/></nmaprun>')
    runner._merge_hosts(main, extra)
    text = main.read_text()
    assert text.index("172.20.10.2") < text.index("172.20.10.1") < text.index("<runstats>") and not extra.exists()
