"""Service-accounts (3.3). CSV: sam, in_da, auth_type, pw_len.

Row OK als: in_da=false AND (auth_type=gmsa OR pw_len >= 25).
"""
from __future__ import annotations
from ._csv_helpers import read_rows, missing_cols, truthy, count_covered, pct

REQUIRED = {"sam", "in_da", "auth_type", "pw_len"}


def _ok(r: dict) -> bool:
    if truthy(r.get("in_da")):
        return False
    auth = (r.get("auth_type") or "").strip().lower()
    if auth == "gmsa":
        return True
    try:
        return int(r.get("pw_len") or 0) >= 25
    except ValueError:
        return False


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        return {"verdict": "unparsed", "missing": miss}
    total, covered = count_covered(rows, _ok)
    da_count = sum(1 for r in rows if truthy(r.get("in_da")))
    verdict = "pass" if total and covered == total and da_count == 0 else "fail"
    return {"verdict": verdict, "total": total, "covered": covered,
            "pct": pct(covered, total), "in_da_count": da_count}
