"""B: monitorul periodic. Fără nmap real: pregătirea, execuția și analiza sunt simulate."""
import json
from dataclasses import replace
from pathlib import Path

import pytest

from netscan.engine.parser import analyze_file
from netscan.model import Host, Port
from netscan.scan import local_data, runner, watch

VAL = Path(__file__).parent.parent / "fixtures" / "validation"
V6A = analyze_file(str(VAL / "V6a_before.xml"))
V6B = analyze_file(str(VAL / "V6b_after.xml"))


class Plan:
    def __init__(self, ok=True, msg="ok"):
        self.ok, self._msg = ok, msg

    def message(self, lang="ro"):
        return self._msg


def fake_cycle_env(tmp_path, scans, plan_ok=True, exec_ok=True):
    """Funcții false pentru run_cycle: fiecare apel 'scanează' următorul Scan din listă."""
    calls = {"prepare": 0, "execute": 0, "saved": []}
    it = iter(scans)

    def prepare(target, out_path=None):
        calls["prepare"] += 1
        calls["out"] = out_path
        return Plan(plan_ok, "Ești conectat la altă rețea Wi-Fi decât hotspotul echipei, așa că nu scanez.")

    def execute(plan):
        calls["execute"] += 1
        Path(calls["out"]).parent.mkdir(parents=True, exist_ok=True)
        Path(calls["out"]).write_text("<nmaprun/>")
        return Plan(exec_ok, "eșec")

    def analyze(path):
        return next(it)

    kw = dict(prepare=prepare, execute=execute, analyze=analyze, save=calls["saved"].append,
              scans_dir=tmp_path / "scans", db_path=tmp_path / "data" / "netscan.db")
    return calls, kw


# --- alertele ---------------------------------------------------------------------------------------------

def test_v6a_to_v6b_three_resolved_and_score():
    alerts = watch.build_alerts(V6A, V6B, ts=1.0)
    kinds = [a.kind for a in alerts]
    assert kinds.count("FINDING_RESOLVED") == 3
    assert "FINDING_NEW" not in kinds and "NEW_DEVICE" not in kinds
    score = next(a for a in alerts if a.kind == "SCORE")
    assert "60 → 100" in score.text_ro and "60 → 100" in score.text_en


def test_new_device_and_new_port_alerts():
    newcomer = Host(ip="192.168.1.77", device_id="nou", mac_masked="02:00:00:XX:XX:XX",
                    ports=[Port(23, "tcp", "open", "telnet")])
    newer = replace(V6B, hosts=[*V6B.hosts, newcomer])
    alerts = watch.build_alerts(V6B, newer, ts=1.0)
    nd = next(a for a in alerts if a.kind == "NEW_DEVICE")
    assert nd.ip == "192.168.1.77" and "Dispozitiv nou în rețea: 192.168.1.77" in nd.text_ro
    assert "telefon" in nd.text_ro.lower() or "laptop" in nd.text_ro.lower()     # MAC privat -> telefon/laptop
    assert any(a.kind == "PORT_OPENED" and a.port == 23 for a in alerts)


def test_no_alerts_when_nothing_changes():
    assert watch.build_alerts(V6B, V6B) == []


def test_alert_texts_never_contain_mac():
    for a in watch.build_alerts(V6A, V6B):
        for h in V6A.hosts + V6B.hosts:
            if h.mac_masked:
                assert h.mac_masked not in a.text_ro and h.mac_masked not in a.text_en


# --- un ciclu ---------------------------------------------------------------------------------------------

def test_wrong_network_skips_without_scanning(tmp_path):
    calls, kw = fake_cycle_env(tmp_path, [V6A], plan_ok=False)
    res = watch.run_cycle(None, **kw)
    assert res.status == "skipped" and "nu am scanat" in res.message
    assert calls["execute"] == 0 and calls["saved"] == []


def test_failed_execution(tmp_path):
    calls, kw = fake_cycle_env(tmp_path, [V6A], exec_ok=False)
    assert watch.run_cycle(None, **kw).status == "failed"
    assert calls["saved"] == []


def test_baseline_then_changes_written_locally(tmp_path):
    calls, kw = fake_cycle_env(tmp_path, [V6A, V6B])
    first = watch.run_cycle(None, **kw)
    assert first.status == "baseline" and calls["saved"] == [V6A]
    second = watch.run_cycle(first.scan, **kw)
    assert second.status == "changes" and "Problemă rezolvată" in second.message
    events = local_data.read_events(local_data.alerts_path(kw["db_path"]))
    assert len(events) == len(second.alerts) and all("ts" in e and "kind" in e for e in events)


def test_watch_xml_files_are_pruned(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    for i in range(8):
        (scans / f"watch_2026110{i}_000000.xml").write_text("x")
    (scans / "scan_01_before.xml").write_text("x")     # scanările manuale nu se ating
    watch._prune_xml(scans, keep=5)
    left = sorted(p.name for p in scans.iterdir())
    assert len([n for n in left if n.startswith("watch_")]) == 5 and "scan_01_before.xml" in left


# --- bucla ------------------------------------------------------------------------------------------------

def test_interval_minimum():
    lines = []
    assert watch.watch(5, confirm=True, out=lines.append) == 2
    assert "minim" in lines[0]


def test_dry_run_never_scans(monkeypatch):
    monkeypatch.setattr(runner, "prepare_scan", lambda target=None, **k: Plan(False, "refuz"))
    called = []
    lines = []
    rc = watch.watch(15, confirm=False, out=lines.append, cycle=lambda *a, **k: called.append(1))
    assert rc == 2 and called == [] and lines == ["refuz"]


def test_loop_runs_cycles_and_releases_lock(tmp_path):
    db = tmp_path / "data" / "netscan.db"
    results = iter([watch.CycleResult("baseline", "baza", scan=V6A), watch.CycleResult("changes", "schimbări")])
    slept, lines = [], []
    rc = watch.watch(15, confirm=True, max_cycles=2, out=lines.append, sleep=slept.append,
                     cycle=lambda prev, **k: next(results), db_path=db)
    assert rc == 0 and slept == [900] and any("baza" in l for l in lines)
    assert not (db.parent / "watch.lock").exists()


def test_second_monitor_is_refused(tmp_path):
    import os
    db = tmp_path / "data" / "netscan.db"
    db.parent.mkdir(parents=True)
    import subprocess, sys
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        (db.parent / "watch.lock").write_text(str(proc.pid))
        lines = []
        assert watch.watch(15, confirm=True, max_cycles=1, out=lines.append, db_path=db,
                           cycle=lambda *a, **k: pytest.fail("nu trebuia să ruleze")) == 2
        assert str(proc.pid) in lines[0]
    finally:
        proc.kill()


def test_delete_history_also_deletes_alerts_and_trap(tmp_path):
    from netscan.ui import storage
    db = tmp_path / "data" / "netscan.db"
    local_data.append_events(local_data.alerts_path(db), [{"ts": 1.0, "kind": "SCORE"}])
    local_data.append_events(local_data.trap_path(db), [{"ts": 1.0, "ip": "172.20.10.5", "port": 2323}])
    storage.delete_history(db)
    assert not local_data.alerts_path(db).exists() and not local_data.trap_path(db).exists()
