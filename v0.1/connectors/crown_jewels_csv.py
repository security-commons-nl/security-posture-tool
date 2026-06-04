"""Kroonjuwelen-CSV parser (1.1 + 1.2).

1.1 — Lijst bestaat, elk item heeft minstens naam + eigenaar.
1.2 — Alle kolommen gevuld (vlan_or_subnet, backup_type, rto, rpo).

Input-kolommen verwacht: name, owner, vlan_or_subnet, backup_type, rto, rpo.
"""
from __future__ import annotations

from ._csv_helpers import read_rows, missing_cols, count_covered, pct


REQUIRED = {"name"}
DETAIL_COLS = ("vlan_or_subnet", "backup_type", "rto", "rpo")


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        unparsed = {"verdict": "unparsed", "missing": miss, "total": 0, "covered": 0}
        return {"per_item": {"1.1": unparsed, "1.2": unparsed}}

    named = [r for r in rows if (r.get("name") or "").strip()]

    # 1.1 — naam + eigenaar gevuld
    total_11 = len(named)
    covered_11 = sum(1 for r in named
                     if (r.get("owner") or "").strip())
    v11 = "fail" if total_11 == 0 else ("pass" if covered_11 == total_11 else "fail")
    r11 = {"verdict": v11, "total": total_11, "covered": covered_11,
           "pct": pct(covered_11, total_11)}

    # 1.2 — alle detail-kolommen gevuld per rij
    total_12 = len(named)

    def all_detail_filled(row: dict) -> bool:
        return all((row.get(c) or "").strip() for c in DETAIL_COLS)

    _, covered_12 = count_covered(named, all_detail_filled)
    v12 = "fail" if total_12 == 0 else ("pass" if covered_12 == total_12 else "fail")
    r12 = {"verdict": v12, "total": total_12, "covered": covered_12,
           "pct": pct(covered_12, total_12),
           "detail_cols": list(DETAIL_COLS)}

    return {"per_item": {"1.1": r11, "1.2": r12}}
