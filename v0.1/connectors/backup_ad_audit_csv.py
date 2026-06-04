"""Backup AD isolatie (6.2). CSV: backup_system, prod_ad_trust.

Row OK als prod_ad_trust=false.
"""
from __future__ import annotations
from ._csv_helpers import read_rows, missing_cols, truthy, count_covered, pct

REQUIRED = {"backup_system", "prod_ad_trust"}


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        return {"verdict": "unparsed", "missing": miss}
    total, covered = count_covered(
        rows, lambda r: not truthy(r.get("prod_ad_trust")))
    verdict = "pass" if total and covered == total else "fail"
    return {"verdict": verdict, "total": total, "covered": covered,
            "pct": pct(covered, total)}
