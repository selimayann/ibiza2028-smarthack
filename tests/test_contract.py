"""Toți: fixtures/sample.json se încarcă în modelul din netscan/model.py fără erori."""
import json
from pathlib import Path

from netscan.model import Scan


def test_sample_json_matches_contract():
    data = json.loads((Path(__file__).parent.parent / "fixtures" / "sample.json").read_text(encoding="utf-8"))
    scan = Scan.from_dict(data)
    assert scan.status == "ok"
    assert scan.score == max(0, 100 - sum(f.points for f in scan.findings))
