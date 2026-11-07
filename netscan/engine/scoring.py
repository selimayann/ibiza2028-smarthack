"""Scorul standard de rețea (FR-09): max(0, 100 - suma punctelor constatărilor)."""

from __future__ import annotations

from collections.abc import Iterable

from netscan.model import Finding


def compute_score(findings: Iterable[Finding]) -> int:
    return max(0, 100 - sum(f.points for f in findings))
