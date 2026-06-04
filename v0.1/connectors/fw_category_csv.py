"""AI-egress policy + logging (8.4). CSV: category, action, logged.

Pass als er ≥1 rij is met category containing 'ai' (case-insensitive),
action != allow-all, én logged=true.
"""
from __future__ import annotations
from ._csv_helpers import read_rows, missing_cols, truthy

REQUIRED = {"category", "action", "logged"}


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        return {"verdict": "unparsed", "missing": miss}
    ai_rows = [r for r in rows if "ai" in (r.get("category") or "").lower()]
    logged_ai = [r for r in ai_rows if truthy(r.get("logged"))]
    verdict = "pass" if logged_ai else "fail"
    return {"verdict": verdict, "total": len(rows), "ai_rows": len(ai_rows),
            "logged_ai": len(logged_ai)}
