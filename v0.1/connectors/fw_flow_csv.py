"""Egress FQDN-logging (4.4). CSV met kolom fqdn verplicht.

Pass als ≥95% van de rijen een FQDN-waarde heeft (niet leeg, niet '-').
"""
from __future__ import annotations
from ._csv_helpers import read_rows, missing_cols, pct

REQUIRED = {"fqdn"}


def _has_fqdn(v: str | None) -> bool:
    val = (v or "").strip()
    return bool(val) and val not in {"-", "n/a", "null"}


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        return {"verdict": "unparsed", "missing": miss}
    total = len(rows)
    covered = sum(1 for r in rows if _has_fqdn(r.get("fqdn")))
    p = pct(covered, total)
    verdict = "pass" if total > 0 and p >= 95 else "fail"
    return {"verdict": verdict, "total": total, "covered": covered,
            "pct": p, "threshold_pct": 95}
