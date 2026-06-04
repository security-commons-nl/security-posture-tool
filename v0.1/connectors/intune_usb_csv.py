"""USB default block (7.4). CSV: device, usb_blocked_default."""
from __future__ import annotations
from ._csv_helpers import read_rows, missing_cols, truthy, count_covered, pct

REQUIRED = {"device", "usb_blocked_default"}


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        return {"verdict": "unparsed", "missing": miss}
    total, covered = count_covered(
        rows, lambda r: truthy(r.get("usb_blocked_default")))
    verdict = "pass" if total and covered == total else "fail"
    return {"verdict": verdict, "total": total, "covered": covered,
            "pct": pct(covered, total)}
