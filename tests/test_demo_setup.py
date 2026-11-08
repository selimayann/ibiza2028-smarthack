"""scripts/demo_load_history.py: cele 3 scanări din lab intră în istoric o singură dată."""
import importlib.util
import io
import re
from pathlib import Path

from netscan.ui import storage
from tests.test_ui_app import make_client, sample

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "fixtures" / "lab"

_spec = importlib.util.spec_from_file_location("demo_load_history", ROOT / "scripts" / "demo_load_history.py")
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)


def run(db, *args):
    buf = io.StringIO()
    code = demo.main(["--db", str(db), *args], stream=buf)
    return code, buf.getvalue()


def test_loads_the_three_lab_scans_in_order(tmp_path):
    db = tmp_path / "demo.db"
    code, out = run(db)
    assert code == 0, out
    items = storage.list_scans(db)
    assert [(s.file, s.score) for s in items] == [("scan_01_before.xml", 0), ("scan_02.xml", 0), ("scan_03_after.xml", 30)]
    assert out.count("salvată") == 3 and "era deja" not in out


def test_running_it_again_does_not_duplicate(tmp_path):
    db = tmp_path / "demo.db"
    run(db)
    code, out = run(db)
    assert code == 0 and out.count("era deja în istoric") == 3
    assert len(storage.list_scans(db)) == 3


def test_does_not_touch_what_is_already_in_history(tmp_path):
    db = tmp_path / "demo.db"
    mine = storage.save_scan(sample(), db)
    storage.set_device_name("e1f2a3b4c5d6", "Camera mea", db)
    run(db)
    assert storage.get_scan(mine, db).file == sample().file     # scanarea deja salvată e neatinsă
    assert len(storage.list_scans(db)) == 4
    assert storage.device_names(db) == {"e1f2a3b4c5d6": "Camera mea"}


def test_missing_folder_and_folder_without_scans(tmp_path):
    db = tmp_path / "demo.db"
    assert run(db, "--folder", str(tmp_path / "nu_exista"))[0] == 2
    empty = tmp_path / "gol"
    empty.mkdir()
    assert run(db, "--folder", str(empty))[0] == 2
    assert storage.list_scans(db) == []


def test_unreadable_files_are_skipped(tmp_path):
    folder = tmp_path / "mix"
    folder.mkdir()
    (folder / "stricat.xml").write_bytes(b"<nmaprun start=")
    (folder / "scan_01_before.xml").write_bytes((LAB / "scan_01_before.xml").read_bytes())
    db = tmp_path / "demo.db"
    assert run(db, "--folder", str(folder))[0] == 0
    assert [s.file for s in storage.list_scans(db)] == ["scan_01_before.xml"]


def test_history_page_shows_the_loaded_lab_trend(tmp_path):
    """Ce vede juriul după pregătire: pagina de istoric are cele 3 scanări și trendul 0 → 30."""
    db = tmp_path / "demo.db"
    run(db)
    client, app = make_client(tmp_path, [sample()])
    app.config["DB_PATH"] = db
    page = client.get("/history").get_data(as_text=True)
    for name in ("scan_01_before.xml", "scan_02.xml", "scan_03_after.xml"):
        assert name in page
    assert re.search(r"de la 0 la 30", page)
