"""Parser-tests voor simpele CSV-parsers (pass / fail / edge)."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# 3.2 — ad_tier0_csv
# ---------------------------------------------------------------------------

def test_ad_tier0_pass():
    from connectors import ad_tier0_csv
    raw = b"account,logon_workstations_set\nsvc-admin,true\njane.doe,yes\n"
    out = ad_tier0_csv.parse(raw)
    assert out["verdict"] == "pass"
    assert out["total"] == 2 and out["covered"] == 2


def test_ad_tier0_fail():
    from connectors import ad_tier0_csv
    raw = b"account,logon_workstations_set\nsvc-admin,true\njane.doe,false\n"
    out = ad_tier0_csv.parse(raw)
    assert out["verdict"] == "fail"


def test_ad_tier0_unparsed_missing_col():
    from connectors import ad_tier0_csv
    raw = b"account\nx\n"
    out = ad_tier0_csv.parse(raw)
    assert out["verdict"] == "unparsed"
    assert "logon_workstations_set" in out["missing"]


# ---------------------------------------------------------------------------
# 3.3 — ad_svc_accounts_csv
# ---------------------------------------------------------------------------

def test_ad_svc_accounts_pass_gmsa():
    from connectors import ad_svc_accounts_csv
    raw = b"sam,in_da,auth_type,pw_len\nsvc-a,false,gmsa,0\nsvc-b,false,pw,30\n"
    out = ad_svc_accounts_csv.parse(raw)
    assert out["verdict"] == "pass"
    assert out["in_da_count"] == 0


def test_ad_svc_accounts_fail_in_da():
    from connectors import ad_svc_accounts_csv
    raw = b"sam,in_da,auth_type,pw_len\nsvc-a,true,gmsa,0\n"
    out = ad_svc_accounts_csv.parse(raw)
    assert out["verdict"] == "fail"
    assert out["in_da_count"] == 1


def test_ad_svc_accounts_fail_short_pw():
    from connectors import ad_svc_accounts_csv
    raw = b"sam,in_da,auth_type,pw_len\nsvc-a,false,pw,10\n"
    out = ad_svc_accounts_csv.parse(raw)
    assert out["verdict"] == "fail"


# ---------------------------------------------------------------------------
# 7.3 — local_admins_csv
# ---------------------------------------------------------------------------

def test_local_admins_pass():
    from connectors import local_admins_csv
    raw = b"device,user_count_in_admins\npc1,0\npc2,0\n"
    assert local_admins_csv.parse(raw)["verdict"] == "pass"


def test_local_admins_fail():
    from connectors import local_admins_csv
    raw = b"device,user_count_in_admins\npc1,0\npc2,2\n"
    out = local_admins_csv.parse(raw)
    assert out["verdict"] == "fail"
    assert out["covered"] == 1


def test_local_admins_unparsed():
    from connectors import local_admins_csv
    assert local_admins_csv.parse(b"device\npc1\n")["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# 7.4 — intune_usb_csv
# ---------------------------------------------------------------------------

def test_intune_usb_pass():
    from connectors import intune_usb_csv
    raw = b"device,usb_blocked_default\npc1,true\npc2,yes\n"
    assert intune_usb_csv.parse(raw)["verdict"] == "pass"


def test_intune_usb_fail():
    from connectors import intune_usb_csv
    raw = b"device,usb_blocked_default\npc1,true\npc2,false\n"
    assert intune_usb_csv.parse(raw)["verdict"] == "fail"


def test_intune_usb_unparsed():
    from connectors import intune_usb_csv
    assert intune_usb_csv.parse(b"x,y\n1,2\n")["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# 5.2 — edge_devices_csv
# ---------------------------------------------------------------------------

def test_edge_devices_pass_recent():
    from connectors import edge_devices_csv
    recent = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    raw = f"device,last_patched_at\nfw1,{recent}\n".encode()
    assert edge_devices_csv.parse(raw)["verdict"] == "pass"


def test_edge_devices_fail_old():
    from connectors import edge_devices_csv
    old = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    raw = f"device,last_patched_at\nfw1,{old}\n".encode()
    assert edge_devices_csv.parse(raw)["verdict"] == "fail"


def test_edge_devices_unparsed():
    from connectors import edge_devices_csv
    assert edge_devices_csv.parse(b"device\nfw1\n")["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# 5.3 — eol_inventory_csv
# ---------------------------------------------------------------------------

def test_eol_pass():
    from connectors import eol_inventory_csv
    raw = (b"system,eol_date,migration_date\n"
           b"Exch2013,2023-04-11,2025-10-01\n"
           b"Win2012,2023-10-10,2025-12-31\n")
    assert eol_inventory_csv.parse(raw)["verdict"] == "pass"


def test_eol_fail_missing_date():
    from connectors import eol_inventory_csv
    raw = b"system,eol_date,migration_date\nExch2013,2023-04-11,\n"
    assert eol_inventory_csv.parse(raw)["verdict"] == "fail"


def test_eol_unparsed():
    from connectors import eol_inventory_csv
    assert eol_inventory_csv.parse(b"system,eol_date\nA,B\n")["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# 2.5 — vpn_inventory_csv
# ---------------------------------------------------------------------------

def test_vpn_inventory_pass():
    from connectors import vpn_inventory_csv
    raw = b"peer,dst_subnet\nvendor-a,10.1.2.0/24\nvendor-b,172.20.0.0/16\n"
    assert vpn_inventory_csv.parse(raw)["verdict"] == "pass"


def test_vpn_inventory_fail_default_route():
    from connectors import vpn_inventory_csv
    raw = b"peer,dst_subnet\nvendor-a,10.1.2.0/24\nvendor-b,0.0.0.0/0\n"
    assert vpn_inventory_csv.parse(raw)["verdict"] == "fail"


def test_vpn_inventory_unparsed():
    from connectors import vpn_inventory_csv
    assert vpn_inventory_csv.parse(b"peer\na\n")["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# 6.2 — backup_ad_audit_csv
# ---------------------------------------------------------------------------

def test_backup_ad_audit_pass():
    from connectors import backup_ad_audit_csv
    raw = b"backup_system,prod_ad_trust\nveeam,false\n"
    assert backup_ad_audit_csv.parse(raw)["verdict"] == "pass"


def test_backup_ad_audit_fail():
    from connectors import backup_ad_audit_csv
    raw = b"backup_system,prod_ad_trust\nveeam,true\n"
    assert backup_ad_audit_csv.parse(raw)["verdict"] == "fail"


def test_backup_ad_audit_unparsed():
    from connectors import backup_ad_audit_csv
    assert backup_ad_audit_csv.parse(b"x\n1\n")["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# 8.4 — fw_category_csv
# ---------------------------------------------------------------------------

def test_fw_category_pass():
    from connectors import fw_category_csv
    raw = b"category,action,logged\nai-tools,block,true\nweb,allow,true\n"
    out = fw_category_csv.parse(raw)
    assert out["verdict"] == "pass"
    assert out["ai_rows"] == 1


def test_fw_category_fail_not_logged():
    from connectors import fw_category_csv
    raw = b"category,action,logged\nai-tools,block,false\n"
    out = fw_category_csv.parse(raw)
    assert out["verdict"] == "fail"


def test_fw_category_fail_no_ai_row():
    from connectors import fw_category_csv
    raw = b"category,action,logged\nweb,allow,true\n"
    assert fw_category_csv.parse(raw)["verdict"] == "fail"


def test_fw_category_unparsed():
    from connectors import fw_category_csv
    assert fw_category_csv.parse(b"category\nweb\n")["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# Kroonjuwelen (1.1 + 1.2)
# ---------------------------------------------------------------------------

def test_crown_jewels_full_pass():
    from connectors import crown_jewels_csv
    raw = (b"name,owner,vlan_or_subnet,backup_type,rto,rpo\n"
           b"BRP,Jan,VLAN10,veeam,4h,1h\n"
           b"Suwinet,Piet,VLAN12,rubrik,2h,15m\n")
    out = crown_jewels_csv.parse(raw)
    assert out["per_item"]["1.1"]["verdict"] == "pass"
    assert out["per_item"]["1.2"]["verdict"] == "pass"


def test_crown_jewels_11_fail_missing_owner():
    from connectors import crown_jewels_csv
    raw = (b"name,owner,vlan_or_subnet,backup_type,rto,rpo\n"
           b"BRP,,VLAN10,veeam,4h,1h\n")
    out = crown_jewels_csv.parse(raw)
    assert out["per_item"]["1.1"]["verdict"] == "fail"


def test_crown_jewels_12_fail_missing_detail():
    from connectors import crown_jewels_csv
    raw = (b"name,owner,vlan_or_subnet,backup_type,rto,rpo\n"
           b"BRP,Jan,VLAN10,,4h,1h\n")
    out = crown_jewels_csv.parse(raw)
    assert out["per_item"]["1.1"]["verdict"] == "pass"
    assert out["per_item"]["1.2"]["verdict"] == "fail"


def test_crown_jewels_unparsed():
    from connectors import crown_jewels_csv
    out = crown_jewels_csv.parse(b"owner\nJan\n")
    assert out["per_item"]["1.1"]["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# LAPS + ASR
# ---------------------------------------------------------------------------

def test_laps_pass():
    from connectors import laps_csv
    raw = b"device_name,laps_configured\npc1,true\npc2,yes\n"
    assert laps_csv.parse(raw)["verdict"] == "pass"


def test_laps_fail():
    from connectors import laps_csv
    raw = b"device_name,laps_configured\npc1,true\npc2,false\n"
    out = laps_csv.parse(raw)
    assert out["verdict"] == "fail"
    assert out["pct"] == 50


def test_laps_unparsed():
    from connectors import laps_csv
    assert laps_csv.parse(b"device\npc1\n")["verdict"] == "unparsed"


def test_asr_pass():
    from connectors import asr_csv
    raw = b"device_name,asr_office_macros_blocked\npc1,true\n"
    assert asr_csv.parse(raw)["verdict"] == "pass"


def test_asr_fail():
    from connectors import asr_csv
    raw = b"device_name,asr_office_macros_blocked\npc1,false\n"
    assert asr_csv.parse(raw)["verdict"] == "fail"


def test_asr_unparsed():
    from connectors import asr_csv
    assert asr_csv.parse(b"device_name\npc1\n")["verdict"] == "unparsed"
