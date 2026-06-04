"""Behavior-detectie rules (8.2). JSON: list met 'type' veld.

Pass als ≥3 rules met type='behavior'.
"""
from __future__ import annotations
import json


def parse(raw_bytes: bytes) -> dict:
    try:
        data = json.loads(raw_bytes.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        return {"verdict": "unparsed", "error": f"JSON-parse: {e}"}

    rules = data if isinstance(data, list) else data.get("rules", [])
    if not isinstance(rules, list):
        return {"verdict": "unparsed", "error": "rules-veld is geen lijst"}

    behavior = [r for r in rules if isinstance(r, dict)
                and (r.get("type") or "").lower() == "behavior"]
    verdict = "pass" if len(behavior) >= 3 else "fail"
    return {"verdict": verdict, "total_rules": len(rules),
            "behavior_rules": len(behavior), "threshold": 3}
