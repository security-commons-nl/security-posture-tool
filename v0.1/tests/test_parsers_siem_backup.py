"""Tests voor SIEM/flow/backup/JSON parsers."""
from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# 4.1 + 4.6 — siem_flow_csv (gecombineerd)
# ---------------------------------------------------------------------------

def test_siem_flow_both_pass():
    from connectors import siem_flow_csv
    now = datetime.now(timezone.utc).isoformat()
    raw = (
        b"timestamp,src_ip,dst_ip,src_vlan,dst_vlan\n"
        + f"{now},10.1.1.1,10.2.2.2,user,server\n".encode()
        + f"{now},10.2.2.2,10.3.3.3,server,db\n".encode()
    )
    out = siem_flow_csv.parse(raw)
    assert out["per_item"]["4.1"]["verdict"] == "pass"
    assert out["per_item"]["4.6"]["verdict"] == "pass"


def test_siem_flow_41_fail_no_recent():
    from connectors import siem_flow_csv
    old = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    raw = (b"timestamp,src_ip,dst_ip,src_vlan,dst_vlan\n"
           + f"{old},10.1.1.1,10.2.2.2,user,server\n".encode())
    out = siem_flow_csv.parse(raw)
    assert out["per_item"]["4.1"]["verdict"] == "fail"


def test_siem_flow_46_fail_only_external():
    from connectors import siem_flow_csv
    now = datetime.now(timezone.utc).isoformat()
    raw = (b"timestamp,src_ip,dst_ip,src_vlan,dst_vlan\n"
           + f"{now},10.1.1.1,8.8.8.8,user,wan\n".encode())
    out = siem_flow_csv.parse(raw)
    assert out["per_item"]["4.6"]["verdict"] == "fail"


def test_siem_flow_unparsed():
    from connectors import siem_flow_csv
    out = siem_flow_csv.parse(b"src,dst\n1,2\n")
    assert out["per_item"]["4.1"]["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# 4.4 — fw_flow_csv (FQDN egress)
# ---------------------------------------------------------------------------

def test_fw_flow_pass():
    from connectors import fw_flow_csv
    raw = b"fqdn,bytes\nexample.com,1000\nfoo.bar,50\n"
    assert fw_flow_csv.parse(raw)["verdict"] == "pass"


def test_fw_flow_fail_low_coverage():
    from connectors import fw_flow_csv
    raw = b"fqdn,bytes\n-,1000\n-,500\nexample.com,100\n"
    out = fw_flow_csv.parse(raw)
    assert out["verdict"] == "fail"
    assert out["pct"] < 95


def test_fw_flow_unparsed():
    from connectors import fw_flow_csv
    assert fw_flow_csv.parse(b"ip\n1.2.3.4\n")["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# 6.1 — veeam_report
# ---------------------------------------------------------------------------

def test_veeam_pass():
    from connectors import veeam_report
    now = datetime.now(timezone.utc).isoformat()
    raw = (b"job_name,last_success,immutable,errors\n"
           + f"daily,{now},true,0\n".encode())
    out = veeam_report.parse(raw)
    assert out["verdict"] == "pass"


def test_veeam_fail_no_immutable():
    from connectors import veeam_report
    now = datetime.now(timezone.utc).isoformat()
    raw = (b"job_name,last_success,immutable,errors\n"
           + f"daily,{now},false,0\n".encode())
    assert veeam_report.parse(raw)["verdict"] == "fail"


def test_veeam_fail_errors_present():
    from connectors import veeam_report
    now = datetime.now(timezone.utc).isoformat()
    raw = (b"job_name,last_success,immutable,errors\n"
           + f"daily,{now},true,3\n".encode())
    assert veeam_report.parse(raw)["verdict"] == "fail"


def test_veeam_fail_old():
    from connectors import veeam_report
    old = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    raw = (b"job_name,last_success,immutable,errors\n"
           + f"daily,{old},true,0\n".encode())
    assert veeam_report.parse(raw)["verdict"] == "fail"


def test_veeam_unparsed():
    from connectors import veeam_report
    assert veeam_report.parse(b"job\nd\n")["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# 4.5 — siem_rules_json
# ---------------------------------------------------------------------------

def test_siem_rules_pass():
    from connectors import siem_rules_json
    rules = [{"id": f"r{i}", "tags": ["gemeente", "suwinet"]} for i in range(10)]
    raw = json.dumps(rules).encode()
    out = siem_rules_json.parse(raw)
    assert out["verdict"] == "pass"
    assert out["gemeente_rules"] == 10


def test_siem_rules_fail_less_than_10():
    from connectors import siem_rules_json
    rules = [{"id": f"r{i}", "tags": ["gemeente"]} for i in range(5)]
    assert siem_rules_json.parse(json.dumps(rules).encode())["verdict"] == "fail"


def test_siem_rules_unparsed():
    from connectors import siem_rules_json
    assert siem_rules_json.parse(b"not-json")["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# 8.2 — siem_behavior_rules_json
# ---------------------------------------------------------------------------

def test_behavior_pass():
    from connectors import siem_behavior_rules_json
    rules = [{"id": f"b{i}", "type": "behavior"} for i in range(3)]
    assert siem_behavior_rules_json.parse(json.dumps(rules).encode())["verdict"] == "pass"


def test_behavior_fail():
    from connectors import siem_behavior_rules_json
    rules = [{"id": "b1", "type": "behavior"}, {"id": "b2", "type": "signature"}]
    assert siem_behavior_rules_json.parse(json.dumps(rules).encode())["verdict"] == "fail"


def test_behavior_unparsed():
    from connectors import siem_behavior_rules_json
    assert siem_behavior_rules_json.parse(b"nope")["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# 1.3 — asset_inventory
# ---------------------------------------------------------------------------

def test_asset_inventory_pass():
    from connectors import asset_inventory
    lines = ["source,ip,mac,hostname"]
    # 10 IPs, allemaal in 3 bronnen
    for i in range(1, 11):
        ip = f"10.0.0.{i}"
        for src in ("ad", "dhcp", "fw_arp"):
            lines.append(f"{src},{ip},aa:bb:cc:dd:ee:{i:02x},h{i}")
    raw = ("\n".join(lines) + "\n").encode()
    out = asset_inventory.parse(raw)
    assert out["verdict"] == "pass"
    assert out["multi_source_pct"] >= 90


def test_asset_inventory_fail_missing_source():
    from connectors import asset_inventory
    raw = b"source,ip,mac,hostname\nad,10.0.0.1,x,h1\ndhcp,10.0.0.1,x,h1\n"
    # fw_arp bron ontbreekt
    assert asset_inventory.parse(raw)["verdict"] == "fail"


def test_asset_inventory_unparsed():
    from connectors import asset_inventory
    assert asset_inventory.parse(b"ip\n1.2.3.4\n")["verdict"] == "unparsed"
