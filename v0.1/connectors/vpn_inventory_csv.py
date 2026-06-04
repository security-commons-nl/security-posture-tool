"""Vendor-VPN expliciet scoped (2.5). CSV: peer, dst_subnet.

Row OK als dst_subnet niet 0.0.0.0/0 en niet leeg.
"""
from __future__ import annotations
from ._csv_helpers import read_rows, missing_cols, count_covered, pct

REQUIRED = {"peer", "dst_subnet"}
FORBIDDEN_SUBNETS = {"0.0.0.0/0", "::/0", "any", ""}


def _ok(r: dict) -> bool:
    dst = (r.get("dst_subnet") or "").strip().lower()
    return dst not in FORBIDDEN_SUBNETS


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        return {"verdict": "unparsed", "missing": miss}
    total, covered = count_covered(rows, _ok)
    verdict = "pass" if total and covered == total else "fail"
    return {"verdict": verdict, "total": total, "covered": covered,
            "pct": pct(covered, total)}
