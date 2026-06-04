"""SIEM flow-logs (4.1 + 4.6) — dekt beide items in één upload.

CSV verwacht kolommen: timestamp, src_ip, dst_ip, src_vlan, dst_vlan.

4.1 — Flow-retentie: ≥1 row in 24u venster (gebaseerd op timestamp-kolom).
4.6 — East-west: ≥1 flow waar src_vlan != dst_vlan (beide niet 'wan'/'internet').
"""
from __future__ import annotations
from datetime import datetime, timezone, timedelta

from ._csv_helpers import read_rows, missing_cols

REQUIRED = {"timestamp", "src_vlan", "dst_vlan"}
EXTERNAL_ZONES = {"wan", "internet", "external", "", "any"}


def _parse_ts(val: str) -> datetime | None:
    if not val:
        return None
    v = val.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        unparsed = {"verdict": "unparsed", "missing": miss}
        return {"per_item": {"4.1": unparsed, "4.6": unparsed}}

    now = datetime.now(timezone.utc)
    last_24h_cut = now - timedelta(hours=24)
    recent = 0
    east_west = 0
    for r in rows:
        ts = _parse_ts(r.get("timestamp") or "")
        if ts and ts >= last_24h_cut:
            recent += 1
        src = (r.get("src_vlan") or "").strip().lower()
        dst = (r.get("dst_vlan") or "").strip().lower()
        if (src and dst and src != dst
                and src not in EXTERNAL_ZONES
                and dst not in EXTERNAL_ZONES):
            east_west += 1

    r41 = {"verdict": "pass" if recent > 0 else "fail",
           "total_rows": len(rows), "rows_last_24h": recent}
    r46 = {"verdict": "pass" if east_west > 0 else "fail",
           "total_rows": len(rows), "east_west_flows": east_west}
    return {"per_item": {"4.1": r41, "4.6": r46}}
