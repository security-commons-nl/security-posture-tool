"""FortiGate running-config parser → verdicts voor 2.1, 2.2, 2.3, 2.4."""
from __future__ import annotations
import re


# Match 'edit <n>' tot 'next' binnen config firewall policy-blokken
POLICY_BLOCK = re.compile(r"edit\s+\d+\s*\n(.*?)\n\s*next", re.DOTALL)


def _fields(block: str) -> dict:
    out: dict[str, str] = {}
    for m in re.finditer(r'set\s+(\S+)\s+(.+)', block):
        out[m.group(1)] = m.group(2).strip().strip('"').strip()
    return out


def _tokens(val: str) -> list[str]:
    return [t.strip().strip('"').lower() for t in val.split() if t.strip()]


def parse(raw_bytes: bytes) -> dict:
    text = raw_bytes.decode("utf-8", errors="replace")
    blocks = [_fields(b) for b in POLICY_BLOCK.findall(text)]

    any_any_in_mgmt = 0
    guest_to_internal = 0
    has_jump_ilo = False
    has_direct_rdp_user_to_server = False

    for b in blocks:
        src_intf = b.get("srcintf", "").lower()
        dst_intf = b.get("dstintf", "").lower()
        src_addr = _tokens(b.get("srcaddr", ""))
        dst_addr = _tokens(b.get("dstaddr", ""))
        service = b.get("service", "").lower()
        action = b.get("action", "accept").lower()

        zones_combined = f"{src_intf} {dst_intf}"
        is_mgmt = any(k in zones_combined for k in ("mgmt", "oob", "tooling", "aaa"))
        if (action == "accept" and is_mgmt
                and "all" in src_addr and "all" in dst_addr):
            any_any_in_mgmt += 1

        if ("guest" in src_intf
                and ("internal" in dst_intf
                     or any("internal" in a for a in dst_addr))
                and action == "accept"):
            guest_to_internal += 1

        if "jump" in src_intf and ("ilo" in dst_intf or "ipmi" in dst_intf):
            has_jump_ilo = True

        if ("user" in src_intf and "server" in dst_intf
                and ("rdp" in service or "3389" in service)
                and action == "accept"):
            has_direct_rdp_user_to_server = True

    verdicts = {
        "2.1": "pass" if has_jump_ilo else "fail",
        "2.2": "fail" if has_direct_rdp_user_to_server else "pass",
        "2.3": "fail" if any_any_in_mgmt > 0 else "pass",
        "2.4": "fail" if guest_to_internal > 0 else "pass",
    }
    return {
        "policy_count": len(blocks),
        "any_any_in_mgmt": any_any_in_mgmt,
        "guest_to_internal": guest_to_internal,
        "has_jump_ilo": has_jump_ilo,
        "has_direct_rdp_user_to_server": has_direct_rdp_user_to_server,
        "verdicts": verdicts,
    }
