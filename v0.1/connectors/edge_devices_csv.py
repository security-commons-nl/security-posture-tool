"""Edge/VPN patch-SLA (5.2). CSV: device, last_patched_at (ISO).

Row OK als last_patched_at binnen 72 uur. Geen data → fail.
"""
from __future__ import annotations
from datetime import datetime, timezone, timedelta

from ._csv_helpers import read_rows, missing_cols, count_covered, pct

REQUIRED = {"device", "last_patched_at"}
MAX_AGE_HOURS = 72


def _parse_dt(val: str) -> datetime | None:
    if not val:
        return None
    v = val.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        try:
            dt = datetime.strptime(v, "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _ok(r: dict) -> bool:
    dt = _parse_dt(r.get("last_patched_at") or "")
    if dt is None:
        return False
    age = datetime.now(timezone.utc) - dt
    return age <= timedelta(hours=MAX_AGE_HOURS)


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        return {"verdict": "unparsed", "missing": miss}
    total, covered = count_covered(rows, _ok)
    verdict = "pass" if total and covered == total else "fail"
    return {"verdict": verdict, "total": total, "covered": covered,
            "pct": pct(covered, total), "max_age_hours": MAX_AGE_HOURS}
