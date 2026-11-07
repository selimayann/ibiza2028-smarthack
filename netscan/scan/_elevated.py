"""Punctul de intrare al pasului cu drepturi de administrator. Îl pornește DOAR elevate.launch(), după acordul
utilizatorului (UAC / parola de admin). Rulat cu `python -I`: fără folderul curent și fără variabile PYTHON*."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from netscan.scan.scan_job import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
