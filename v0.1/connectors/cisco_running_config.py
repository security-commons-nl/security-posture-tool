"""Cisco ASA/IOS running-config parser → verdicts voor 2.1..2.4.

Ondersteunde regels:
  access-list <ACL_NAAM> extended permit|deny <proto> <src> <dst> [<svc>]
  object-group, etc. worden niet diep uitgepluisd.

Heuristiek per item:
  2.3 — permit ip any any in ACL met 'mgmt' in naam → fail
  2.4 — permit in ACL 'guest' met dst niet 'any' extern → fail
  2.2 — permit ... eq 3389 van user-ACL naar server-ACL → fail
  2.1 — permit in 'jump' → 'ilo' expliciet → pass
"""
from __future__ import annotations
import re

ACL_RE = re.compile(
    r'access-list\s+(\S+)\s+(?:extended\s+)?(permit|deny)\s+(\S+)\s+(.+)',
    re.IGNORECASE,
)


def parse(raw_bytes: bytes) -> dict:
    text = raw_bytes.decode("utf-8", errors="replace")
    entries = []
    for m in ACL_RE.finditer(text):
        entries.append({
            "acl": m.group(1).lower(),
            "action": m.group(2).lower(),
            "proto": m.group(3).lower(),
            "rest": m.group(4).lower(),
        })

    any_any_in_mgmt = 0
    guest_to_internal = 0
    has_jump_ilo = False
    has_direct_rdp = False

    for e in entries:
        if e["action"] != "permit":
            continue
        rest = e["rest"]
        acl = e["acl"]

        if "mgmt" in acl and "any any" in rest and e["proto"] in ("ip", "any"):
            any_any_in_mgmt += 1

        if "guest" in acl and "any any" not in rest and "permit" == e["action"]:
            # gast-ACL mag niet permitten naar specifieke internal subnets
            if any(tok in rest for tok in ("10.", "172.16.", "192.168.", "internal")):
                guest_to_internal += 1

        if "jump" in acl and "ilo" in rest:
            has_jump_ilo = True

        if "user" in acl and ("eq 3389" in rest or "rdp" in rest):
            has_direct_rdp = True

    verdicts = {
        "2.1": "pass" if has_jump_ilo else "fail",
        "2.2": "fail" if has_direct_rdp else "pass",
        "2.3": "fail" if any_any_in_mgmt > 0 else "pass",
        "2.4": "fail" if guest_to_internal > 0 else "pass",
    }
    return {
        "policy_count": len(entries),
        "any_any_in_mgmt": any_any_in_mgmt,
        "guest_to_internal": guest_to_internal,
        "has_jump_ilo": has_jump_ilo,
        "has_direct_rdp_user_to_server": has_direct_rdp,
        "verdicts": verdicts,
    }
