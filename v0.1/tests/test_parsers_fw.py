"""Tests voor FW-config parsers (FortiGate, Palo, Cisco)."""
from __future__ import annotations


FORTI_CLEAN = b"""config firewall policy
    edit 1
        set srcintf "jump-zone"
        set dstintf "ilo-zone"
        set srcaddr "JumpHosts"
        set dstaddr "iLO-VLAN"
        set service "HTTPS" "IPMI"
        set action accept
    next
    edit 2
        set srcintf "guest-wifi"
        set dstintf "wan"
        set srcaddr "GuestPool"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
"""

FORTI_ANYANY_MGMT = b"""config firewall policy
    edit 10
        set srcintf "mgmt"
        set dstintf "mgmt"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
"""

FORTI_GUEST_LEAK = b"""config firewall policy
    edit 20
        set srcintf "guest-wifi"
        set dstintf "internal"
        set srcaddr "GuestPool"
        set dstaddr "InternalSubnets"
        set service "ALL"
        set action accept
    next
end
"""

FORTI_DIRECT_RDP = b"""config firewall policy
    edit 30
        set srcintf "user-lan"
        set dstintf "server-lan"
        set srcaddr "Users"
        set dstaddr "Servers"
        set service "RDP"
        set action accept
    next
end
"""


def test_fortigate_clean_passes_23_24():
    from connectors.fortigate_config import parse
    out = parse(FORTI_CLEAN)
    assert out["any_any_in_mgmt"] == 0
    assert out["guest_to_internal"] == 0
    assert out["has_jump_ilo"] is True
    assert out["verdicts"]["2.3"] == "pass"
    assert out["verdicts"]["2.4"] == "pass"
    assert out["verdicts"]["2.1"] == "pass"


def test_fortigate_anyany_mgmt_fails_23():
    from connectors.fortigate_config import parse
    out = parse(FORTI_ANYANY_MGMT)
    assert out["any_any_in_mgmt"] >= 1
    assert out["verdicts"]["2.3"] == "fail"


def test_fortigate_guest_leak_fails_24():
    from connectors.fortigate_config import parse
    out = parse(FORTI_GUEST_LEAK)
    assert out["guest_to_internal"] >= 1
    assert out["verdicts"]["2.4"] == "fail"


def test_fortigate_direct_rdp_fails_22():
    from connectors.fortigate_config import parse
    out = parse(FORTI_DIRECT_RDP)
    assert out["has_direct_rdp_user_to_server"] is True
    assert out["verdicts"]["2.2"] == "fail"


# ---------------------------------------------------------------------------
# Palo Alto set-format
# ---------------------------------------------------------------------------

PALO_CLEAN = (
    b'set rulebase security rules "jump-to-ilo" from jump-zone to ilo-zone '
    b'source JumpHosts destination iLO-VLAN service [ https ipmi ] action allow\n'
    b'set rulebase security rules "guest-out" from guest to wan '
    b'source GuestPool destination any service any action allow\n'
)

PALO_ANYANY_MGMT = (
    b'set rulebase security rules "mgmt-anyany" from mgmt to mgmt '
    b'source any destination any service any action allow\n'
)

PALO_GUEST_LEAK = (
    b'set rulebase security rules "guest-leak" from guest to trust '
    b'source GuestPool destination InternalSubnets service any action allow\n'
)

PALO_DIRECT_RDP = (
    b'set rulebase security rules "rdp-direct" from user-zone to server-zone '
    b'source Users destination Servers service "tcp-3389" action allow\n'
)


def test_palo_clean_passes():
    from connectors.palo_config import parse
    out = parse(PALO_CLEAN)
    assert out["verdicts"]["2.3"] == "pass"
    assert out["verdicts"]["2.1"] == "pass"


def test_palo_anyany_fails_23():
    from connectors.palo_config import parse
    assert parse(PALO_ANYANY_MGMT)["verdicts"]["2.3"] == "fail"


def test_palo_guest_leak_fails_24():
    from connectors.palo_config import parse
    assert parse(PALO_GUEST_LEAK)["verdicts"]["2.4"] == "fail"


def test_palo_direct_rdp_fails_22():
    from connectors.palo_config import parse
    assert parse(PALO_DIRECT_RDP)["verdicts"]["2.2"] == "fail"


# ---------------------------------------------------------------------------
# Cisco ASA/IOS
# ---------------------------------------------------------------------------

CISCO_CLEAN = (
    b"access-list JUMP-TO-ILO extended permit tcp host 10.0.0.1 host 10.1.1.1 eq 443\n"
    b"access-list JUMP-TO-ILO extended permit tcp host 10.0.0.1 host 10.1.1.1 eq 623\n"
    b"access-list GUEST extended deny ip any 10.0.0.0 255.0.0.0\n"
)

CISCO_ANYANY_MGMT = (
    b"access-list MGMT-ANY extended permit ip any any\n"
)

CISCO_GUEST_LEAK = (
    b"access-list GUEST extended permit ip 192.168.50.0 255.255.255.0 10.0.0.0 255.0.0.0\n"
)

CISCO_DIRECT_RDP = (
    b"access-list USER-TO-SERVER extended permit tcp any any eq 3389\n"
)


def test_cisco_clean_passes_23():
    from connectors.cisco_running_config import parse
    out = parse(CISCO_CLEAN)
    assert out["verdicts"]["2.3"] == "pass"


def test_cisco_anyany_fails_23():
    from connectors.cisco_running_config import parse
    assert parse(CISCO_ANYANY_MGMT)["verdicts"]["2.3"] == "fail"


def test_cisco_guest_leak_fails_24():
    from connectors.cisco_running_config import parse
    assert parse(CISCO_GUEST_LEAK)["verdicts"]["2.4"] == "fail"


def test_cisco_direct_rdp_fails_22():
    from connectors.cisco_running_config import parse
    assert parse(CISCO_DIRECT_RDP)["verdicts"]["2.2"] == "fail"
