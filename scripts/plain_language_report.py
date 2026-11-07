"""Raportul testului de limbaj simplu: LIX, cea mai lungă propoziție, jargon neexplicat, pași fără verb.

    python scripts/plain_language_report.py          # tabel Markdown, per cod și limbă
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netscan.explain import LANGS  # noqa: E402
from netscan.explain.plain import MAX_SENTENCE_WORDS, measure  # noqa: E402
from netscan.scan.ai_check import CATALOG  # noqa: E402


def main() -> int:
    print(f"| Cod | Limbă | LIX | Cuvinte max./propoziție (≤{MAX_SENTENCE_WORDS}) | Jargon neexplicat | Pași fără verb de acțiune |")
    print("|---|---|---:|---:|---|---|")
    totals = {lang: [] for lang in LANGS}
    for code in sorted(CATALOG):
        for lang in LANGS:
            r = measure(code, lang)
            totals[lang].append(r.lix)
            print(f"| {code} | {lang} | {r.lix:.1f} | {r.max_words} | {', '.join(r.jargon) or '–'} | "
                  f"{'; '.join(s[:40] + '…' for s in r.bad_steps) or '–'} |")
    for lang, vals in totals.items():
        print(f"\nLIX mediu {lang}: {sum(vals) / len(vals):.1f} (min {min(vals):.1f}, max {max(vals):.1f})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
