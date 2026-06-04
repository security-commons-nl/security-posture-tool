"""FastAPI TestClient integratie-tests: upload-route → evidence-rij → verdict."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest


@pytest.fixture
def client(tmp_db, drops_tmp, monkeypatch):
    """FastAPI TestClient met fresh DB en drops."""
    # Forceer re-import van app zodat Startup-event niet eerdere DB gebruikt
    for name in list(sys.modules):
        if name in ("app",) or name.startswith("connectors"):
            sys.modules.pop(name, None)
    from fastapi.testclient import TestClient
    import app as app_mod
    importlib.reload(app_mod)
    with TestClient(app_mod.app) as c:
        yield c


# ---------------------------------------------------------------------------
# GET-routes renderen zonder error
# ---------------------------------------------------------------------------

def test_index_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Overzicht" in r.text or "overzicht" in r.text.lower()


def test_checklist_shows_37_items(client):
    r = client.get("/checklist")
    assert r.status_code == 200
    # Spot-check: hoogste ID 9.3 moet in de pagina
    assert ">9.3<" in r.text or "9.3" in r.text


def test_uploads_page_renders(client):
    r = client.get("/uploads")
    assert r.status_code == 200
    assert "LAPS" in r.text
    assert "Kroonjuwelen" in r.text


def test_evidence_detail_no_evidence(client):
    r = client.get("/evidence/3.1")
    assert r.status_code == 200
    assert "niets ingeladen" in r.text.lower() or "geen evidence" in r.text.lower()


# ---------------------------------------------------------------------------
# Upload → evidence flow
# ---------------------------------------------------------------------------

def test_crown_jewels_upload_writes_evidence(client):
    csv = (b"name,owner,vlan_or_subnet,backup_type,rto,rpo\n"
           b"BRP,Jan,VLAN10,veeam,4h,1h\n")
    r = client.post("/crown-jewels/upload",
                    files={"file": ("cj.csv", csv, "text/csv")})
    assert r.status_code in (200, 303)
    from evidence import latest_for
    assert latest_for("1.1")["verdict"] == "pass"
    assert latest_for("1.2")["verdict"] == "pass"


def test_laps_upload_writes_evidence(client):
    csv = b"device_name,laps_configured\npc1,true\npc2,false\n"
    r = client.post("/uploads/laps",
                    files={"file": ("laps.csv", csv, "text/csv")})
    assert r.status_code in (200, 303)
    from evidence import latest_for
    ev = latest_for("3.4")
    assert ev is not None
    assert ev["verdict"] == "fail"  # 50% dekking


def test_asr_upload_writes_evidence(client):
    csv = b"device_name,asr_office_macros_blocked\npc1,true\n"
    r = client.post("/uploads/asr",
                    files={"file": ("asr.csv", csv, "text/csv")})
    assert r.status_code in (200, 303)
    from evidence import latest_for
    assert latest_for("7.2")["verdict"] == "pass"


def test_simple_csv_route(client):
    csv = b"device,usb_blocked_default\npc1,true\n"
    r = client.post("/uploads/csv/7.4",
                    files={"file": ("usb.csv", csv, "text/csv")})
    assert r.status_code in (200, 303)
    from evidence import latest_for
    assert latest_for("7.4")["verdict"] == "pass"


def test_simple_csv_invalid_id(client):
    r = client.post("/uploads/csv/99.99",
                    files={"file": ("x.csv", b"a,b\n1,2\n", "text/csv")})
    assert r.status_code == 400


def test_fw_config_upload_forti(client):
    forti = b"""config firewall policy
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
    r = client.post(
        "/uploads/fw-config",
        data={"device_type": "fortigate"},
        files={"file": ("fw.conf", forti, "text/plain")},
    )
    assert r.status_code in (200, 303)
    from evidence import latest_for
    ev_23 = latest_for("2.3")
    assert ev_23 is not None
    assert ev_23["verdict"] == "fail"


def test_shallow_pentest_upload(client, fixtures_dir):
    with open(fixtures_dir / "pentest_valid.pdf", "rb") as f:
        pdf_bytes = f.read()
    r = client.post(
        "/uploads/shallow/9.3",
        files={"file": ("pentest.pdf", pdf_bytes, "application/pdf")},
    )
    assert r.status_code in (200, 303)
    from evidence import latest_for
    assert latest_for("9.3")["verdict"] == "pass"


def test_shallow_invalid_checklist_id(client, fixtures_dir):
    with open(fixtures_dir / "pentest_valid.pdf", "rb") as f:
        pdf = f.read()
    r = client.post(
        "/uploads/shallow/1.1",
        files={"file": ("x.pdf", pdf, "application/pdf")},
    )
    assert r.status_code == 400


def test_siem_flow_writes_both_41_46(client):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    csv = (
        b"timestamp,src_ip,dst_ip,src_vlan,dst_vlan\n"
        + f"{now},10.1.1.1,10.2.2.2,user,server\n".encode()
    )
    r = client.post("/uploads/siem-flow",
                    files={"file": ("flow.csv", csv, "text/csv")})
    assert r.status_code in (200, 303)
    from evidence import latest_for
    assert latest_for("4.1")["verdict"] == "pass"
    assert latest_for("4.6")["verdict"] == "pass"


def test_siem_rules_json_upload(client):
    import json
    rules = [{"id": f"r{i}", "tags": ["gemeente"]} for i in range(10)]
    body = json.dumps(rules).encode()
    r = client.post("/uploads/siem-rules",
                    files={"file": ("rules.json", body, "application/json")})
    assert r.status_code in (200, 303)
    from evidence import latest_for
    assert latest_for("4.5")["verdict"] == "pass"
