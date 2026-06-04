"""Palo Alto set-format parser → verdicts voor 2.1..2.4.

Ondersteund format: 'set rulebase security rules "NAME" from X to Y
source Z destination W service S action A'.
"""
from __future__ import annotations
import re


RULE_RE = re.compile(
    r'set rulebase security rules (?:"([^"]+)"|(\S+))\s+(.*)', re.IGNORECASE
)


def _fields(body: str) -> dict:
    """Extract simple k v / k "[...]"-multi-values from the rule body."""
    out: dict[str, str] = {}
    # Combine patterns: 'from X' / 'from [ A B ]'
    pattern = re.compile(
        r'(from|to|source|destination|service|application|action)\s+'
        r'(\[[^\]]+\]|"[^"]+"|\S+)', re.IGNORECASE
    )
    for m in pattern.finditer(body):
        key = m.group(1).lower()
        val = m.group(2).strip()
        if val.startswith("[") and val.endswith("]"):
            val = val[1:-1].strip()
        val = val.strip('"').lower()
        out[key] = val
    return out


def _tokens(v: str) -> list[str]:
    return [t.strip().strip('"').lower() for t in v.split() if t.strip()]


def parse(raw_bytes: bytes) -> dict:
    text = raw_bytes.decode("utf-8", errors="replace")
    rules = []
    for m in RULE_RE.finditer(text):
        name = m.group(1) or m.group(2)
        body = m.group(3)
        fields = _fields(body)
        rules.append({"name": name, **fields})

    any_any_in_mgmt = 0
    guest_to_internal = 0
    has_jump_ilo = False
    has_direct_rdp = False

    for r in rules:
        src_zone = r.get("from", "")
        dst_zone = r.get("to", "")
        src = _tokens(r.get("source", ""))
        dst = _tokens(r.get("destination", ""))
        svc = r.get("service", "")
        action = r.get("action", "allow")

        zones = f"{src_zone} {dst_zone}"
        is_mgmt = any(k in zones for k in ("mgmt", "oob", "tooling", "aaa"))
        if (action == "allow" and is_mgmt
                and ("any" in src or "all" in src)
                and ("any" in dst or "all" in dst)):
            any_any_in_mgmt += 1

        if ("guest" in src_zone
                and ("internal" in dst_zone or "trust" in dst_zone)
                and action == "allow"):
            guest_to_internal += 1

        if "jump" in src_zone and ("ilo" in dst_zone or "ipmi" in dst_zone):
            has_jump_ilo = True

        if ("user" in src_zone and "server" in dst_zone
                and ("rdp" in svc or "3389" in svc)
                and action == "allow"):
            has_direct_rdp = True

    verdicts = {
        "2.1": "pass" if has_jump_ilo else "fail",
        "2.2": "fail" if has_direct_rdp else "pass",
        "2.3": "fail" if any_any_in_mgmt > 0 else "pass",
        "2.4": "fail" if guest_to_internal > 0 else "pass",
    }
    return {
        "policy_count": len(rules),
        "any_any_in_mgmt": any_any_in_mgmt,
        "guest_to_internal": guest_to_internal,
        "has_jump_ilo": has_jump_ilo,
        "has_direct_rdp_user_to_server": has_direct_rdp,
        "verdicts": verdicts,
    }
