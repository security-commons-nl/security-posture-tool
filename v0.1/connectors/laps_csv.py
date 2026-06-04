"""LAPS-dekking (3.4): CSV met device_name + laps_configured."""
from __future__ import annotations

from ._csv_helpers import read_rows, missing_cols, truthy, count_covered, pct

REQUIRED = {"device_name", "laps_configured"}


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        return {"verdict": "unparsed", "missing": miss}
    total, covered = count_covered(rows, lambda r: truthy(r.get("laps_configured")))
    verdict = "pass" if total and covered == total else "fail"
    return {"verdict": verdict, "total": total, "covered": covered,
            "pct": pct(covered, total)}
