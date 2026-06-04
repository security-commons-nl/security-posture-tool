"""Geen lokale admin voor users (7.3). CSV: device, user_count_in_admins."""
from __future__ import annotations
from ._csv_helpers import read_rows, missing_cols, count_covered, pct

REQUIRED = {"device", "user_count_in_admins"}


def _ok(r: dict) -> bool:
    try:
        return int(r.get("user_count_in_admins") or 0) == 0
    except ValueError:
        return False


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        return {"verdict": "unparsed", "missing": miss}
    total, covered = count_covered(rows, _ok)
    verdict = "pass" if total and covered == total else "fail"
    return {"verdict": verdict, "total": total, "covered": covered,
            "pct": pct(covered, total)}
