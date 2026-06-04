"""WDAC/AppLocker policy XML parser (7.1).

Pass als WDAC-policy in Enforce-mode staat (niet alleen Audit).
"""
from __future__ import annotations
import xml.etree.ElementTree as ET


def parse(raw_bytes: bytes) -> dict:
    try:
        root = ET.fromstring(raw_bytes)
    except ET.ParseError as e:
        return {"verdict": "unparsed", "error": f"XML-parse: {e}"}

    text = raw_bytes.decode("utf-8", errors="replace")

    # WDAC-policy kent <Rules> met <Rule><Option>Enabled:Audit Mode</Option></Rule>
    audit_mode = ("Enabled:Audit Mode" in text)
    enforce_mode = ("Enabled:Unsigned System Integrity Policy" in text
                    or "Enabled:Managed Installer" in text
                    or not audit_mode)

    # AppLocker fallback: <AppLockerPolicy> met <RuleCollection EnforcementMode="Enabled">
    applocker_enforced = False
    for rc in root.iter("RuleCollection"):
        if rc.attrib.get("EnforcementMode", "").lower() == "enabled":
            applocker_enforced = True
            break

    # Count rules (deny/allow) voor sanity
    rule_count = 0
    for tag in ("Allow", "Deny", "FileRule", "FileAttrib", "Signer",
                "FilePathRule", "FilePublisherRule", "FileHashRule"):
        rule_count += sum(1 for _ in root.iter(tag))

    if audit_mode and not applocker_enforced:
        verdict = "fail"
    elif applocker_enforced:
        verdict = "pass" if rule_count > 0 else "fail"
    elif enforce_mode:
        verdict = "pass" if rule_count > 0 else "fail"
    else:
        verdict = "unparsed"

    return {"verdict": verdict,
            "audit_mode": audit_mode,
            "enforce_mode": enforce_mode or applocker_enforced,
            "rule_count": rule_count}
