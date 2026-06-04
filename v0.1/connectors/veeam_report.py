"""Backup report (6.1). CSV: job_name, last_success, immutable, errors.

Pass als elk job: immutable=true, errors=0, last_success <= 24u oud.
"""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from ._csv_helpers import read_rows, missing_cols, truthy, count_covered, pct

REQUIRED = {"job_name", "last_success", "immutable", "errors"}


def _parse_dt(v: str) -> datetime | None:
    if not v:
        return None
    s = v.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _ok(r: dict) -> bool:
    if not truthy(r.get("immutable")):
        return False
    try:
        if int(r.get("errors") or 0) != 0:
            return False
    except ValueError:
        return False
    dt = _parse_dt(r.get("last_success") or "")
    if dt is None:
        return False
    return (datetime.now(timezone.utc) - dt) <= timedelta(hours=24)


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        return {"verdict": "unparsed", "missing": miss}
    total, covered = count_covered(rows, _ok)
    immutable_count = sum(1 for r in rows if truthy(r.get("immutable")))
    verdict = "pass" if total and covered == total else "fail"
    return {"verdict": verdict, "total": total, "covered": covered,
            "pct": pct(covered, total), "immutable_count": immutable_count}
