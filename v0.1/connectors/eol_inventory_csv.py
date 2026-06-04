"""EOL-lijst (5.3). CSV: system, eol_date, migration_date.

Row OK als migration_date gevuld is.
"""
from __future__ import annotations
from ._csv_helpers import read_rows, missing_cols, count_covered, pct

REQUIRED = {"system", "eol_date", "migration_date"}


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        return {"verdict": "unparsed", "missing": miss}
    total, covered = count_covered(
        rows, lambda r: bool((r.get("migration_date") or "").strip()))
    verdict = "pass" if total and covered == total else "fail"
    return {"verdict": verdict, "total": total, "covered": covered,
            "pct": pct(covered, total)}
