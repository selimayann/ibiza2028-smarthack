"""Constante și ajutoare comune ale motorului (nu modifică contractul din netscan/model.py)."""
from __future__ import annotations

from netscan.model import Scan

STATUS_OK = "ok"
STATUS_ERROR = "error"


def error_scan(file: str, error_code: str) -> Scan:
    """Un fișier care nu a putut fi analizat: status error, fără score, fără findings."""
    return Scan(file=file, status=STATUS_ERROR, error_code=error_code)
