"""ASR Office-macros block (7.2): CSV met device_name + asr_office_macros_blocked."""
from __future__ import annotations

from ._csv_helpers import read_rows, missing_cols, truthy, count_covered, pct

REQUIRED = {"device_name", "asr_office_macros_blocked"}


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        return {"verdict": "unparsed", "missing": miss}
    total, covered = count_covered(
        rows, lambda r: truthy(r.get("asr_office_macros_blocked")))
    verdict = "pass" if total and covered == total else "fail"
    return {"verdict": verdict, "total": total, "covered": covered,
            "pct": pct(covered, total)}
