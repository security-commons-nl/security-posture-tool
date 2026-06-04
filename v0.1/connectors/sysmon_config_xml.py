"""Sysmon config XML parser (4.2): herkent Hartong / SwiftOnSecurity fingerprints.

Pass als één van de bekende publieke configs herkend wordt ÉN er ≥5 RuleGroups
actief zijn (niet een lege stub).
"""
from __future__ import annotations
import re
import xml.etree.ElementTree as ET


FINGERPRINTS = (
    "swiftonsecurity",
    "sysmon-modular",
    "olaf hartong",
    "hartong",
    "sysmonconfig-export",
)


def parse(raw_bytes: bytes) -> dict:
    text = raw_bytes.decode("utf-8", errors="replace").lower()
    try:
        root = ET.fromstring(raw_bytes)
    except ET.ParseError as e:
        return {"verdict": "unparsed", "error": f"XML-parse: {e}"}

    rule_groups = len(list(root.iter("RuleGroup")))
    fp_hits = [fp for fp in FINGERPRINTS if fp in text]

    if rule_groups < 5:
        verdict = "fail"
    elif fp_hits:
        verdict = "pass"
    else:
        verdict = "unparsed"  # onbekende config, review nodig

    return {"verdict": verdict,
            "rule_groups": rule_groups,
            "fingerprints_matched": fp_hits}
