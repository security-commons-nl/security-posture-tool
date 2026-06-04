"""SIEM rules-export (4.5). JSON: list of rule-dicts met 'tags' veld.

Pass als ≥10 rules met tag 'gemeente' (of substring).
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

    gemeente_rules = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        tags = r.get("tags") or []
        if any("gemeente" in str(t).lower() for t in tags):
            gemeente_rules.append(r.get("id") or r.get("name") or "?")
    verdict = "pass" if len(gemeente_rules) >= 10 else "fail"
    return {"verdict": verdict, "total_rules": len(rules),
            "gemeente_rules": len(gemeente_rules),
            "threshold": 10,
            "sample_ids": gemeente_rules[:5]}
