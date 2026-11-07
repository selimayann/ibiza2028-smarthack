"""Parser nmap XML (Radu). Doar defusedxml; limită de mărime; erori ca Scan(status="error").
Vezi docs/roles/A_Radu_Motor.md, secțiunea 2.2.
"""
from netscan.model import Scan


def analyze_file(path: str) -> Scan:
    raise NotImplementedError


def analyze_folder(path: str) -> list[Scan]:
    raise NotImplementedError
