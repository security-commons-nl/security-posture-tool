"""Tier-0 LogonWorkstations-set (3.2). CSV: account, logon_workstations_set."""
from __future__ import annotations
from ._csv_helpers import read_rows, missing_cols, truthy, count_covered, pct

REQUIRED = {"account", "logon_workstations_set"}


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        return {"verdict": "unparsed", "missing": miss}
    total, covered = count_covered(
        rows, lambda r: truthy(r.get("logon_workstations_set")))
    verdict = "pass" if total and covered == total else "fail"
    return {"verdict": verdict, "total": total, "covered": covered,
            "pct": pct(covered, total)}
