"""FastAPI app voor v0.1 — evidence-only checklist-tool.

Routes:
- /                overzicht (tellers + checklist)
- /checklist       alle 37 items met verdict
- /evidence/{id}   history van evidence-rijen per item
- /mfa             privileged accounts
- /inactive        inactieve accounts
- /crown-jewels    kroonjuweel-lijst
- /uploads         upload-formulieren per bron-type
- /drops           read-only drops-folder
- /entra/refresh   Graph-API pull (3.1, 3.5, 4.3, 8.1)

Uploads schrijven altijd een evidence-rij via `evidence.write_evidence()`.
`checklist_state` wordt afgeleid; nooit rechtstreeks gezet door routes.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import checklist
import db
import drops
import entra
import evidence
from connectors import shallow_pdf
from connectors import (
    fortigate_config, palo_config, cisco_running_config,
    nmap_xml, nessus_xml, sysmon_config_xml, wdac_policy_xml, gpo_export_xml,
    siem_flow_csv, siem_rules_json, fw_flow_csv, siem_behavior_rules_json,
    veeam_report, ad_tier0_csv, ad_svc_accounts_csv, local_admins_csv,
    intune_usb_csv, edge_devices_csv, eol_inventory_csv, vpn_inventory_csv,
    backup_ad_audit_csv, fw_category_csv, asset_inventory,
    crown_jewels_csv, laps_csv, asr_csv,
)

app = FastAPI(title="security-posture-tool v0.1 (evidence-only)")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@app.on_event("startup")
def _startup():
    if not db._db_path().exists():
        db.init()
    checklist.seed_if_empty()


# ---------------------------------------------------------------------------
# Overzicht / detail
# ---------------------------------------------------------------------------


def _enriched_checklist() -> list[dict]:
    """Checklist-rijen + evidence-state (verdict, artefact_date) + kill-chain-fases."""
    out = []
    for row in db.fetch_checklist():
        state = evidence.derive_state(row["checklist_id"])
        phases = checklist.phases_for(row["checklist_id"])
        out.append({
            **row,
            "category": checklist.category_for(row["checklist_id"]),
            "verdict": state["verdict"],
            "artefact_date": state["artefact_date"],
            "parser_name": state["parser_name"],
            "kill_chain_phases": phases,
            "kill_chain_labels": [checklist.KILL_CHAIN_LABELS[p] for p in phases],
        })
    return out


def _category_counters(items: list[dict]) -> list[dict]:
    cats: dict[str, dict] = {}
    for r in items:
        cat = r.get("category") or "onbekend"
        c = cats.setdefault(cat, {"name": cat, "pass": 0, "fail": 0,
                                  "stale": 0, "unparsed": 0, "none": 0, "total": 0})
        c["total"] += 1
        v = r["verdict"]
        if v == "pass": c["pass"] += 1
        elif v == "fail": c["fail"] += 1
        elif v == "stale": c["stale"] += 1
        elif v == "unparsed": c["unparsed"] += 1
        else: c["none"] += 1
    return sorted(cats.values(), key=lambda x: x["name"])


def _phase_counters(items: list[dict]) -> list[dict]:
    """Per kill-chain-fase tellen hoeveel items met welk verdict er zijn.

    Een item dat meerdere fases raakt, telt in elke fase mee (bewust:
    de mapping zegt dat de control in die fases iets doet). Items zonder
    fases (governance/inventaris) vallen in bucket 'meta'.
    """
    order = list(checklist.KILL_CHAIN_PHASES) + ["meta"]
    counters: dict[str, dict] = {
        key: {"key": key, "label": checklist.KILL_CHAIN_LABELS[key],
              "pass": 0, "fail": 0, "stale": 0, "unparsed": 0,
              "none": 0, "total": 0}
        for key in order
    }
    for r in items:
        phases = r.get("kill_chain_phases") or []
        buckets = phases if phases else ["meta"]
        v = r.get("verdict")
        for p in buckets:
            c = counters[p]
            c["total"] += 1
            if v == "pass": c["pass"] += 1
            elif v == "fail": c["fail"] += 1
            elif v == "stale": c["stale"] += 1
            elif v == "unparsed": c["unparsed"] += 1
            else: c["none"] += 1
    return [counters[k] for k in order]


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    items = _enriched_checklist()
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "checklist": items,
            "categories": _category_counters(items),
            "phases": _phase_counters(items),
            "total_accounts": len(db.fetch_accounts()),
            "total_privileged": len(db.fetch_accounts(privileged_only=True)),
            "total_crown_jewels": len(db.fetch_crown_jewels()),
        },
    )


@app.get("/checklist", response_class=HTMLResponse)
def checklist_page(request: Request):
    items = _enriched_checklist()
    return templates.TemplateResponse(
        request,
        "checklist.html",
        {"checklist": items,
         "categories": _category_counters(items),
         "phases": _phase_counters(items)},
    )


@app.get("/evidence/{checklist_id}", response_class=HTMLResponse)
def evidence_page(request: Request, checklist_id: str):
    rows = db.fetch_evidence_for(checklist_id, limit=50)
    import json
    for r in rows:
        if r.get("parsed_summary"):
            try:
                r["summary_parsed"] = json.loads(r["parsed_summary"])
            except json.JSONDecodeError:
                r["summary_parsed"] = {}
        else:
            r["summary_parsed"] = {}
    label = checklist.label_for(checklist_id)
    target = checklist.target_for(checklist_id)
    return templates.TemplateResponse(
        request,
        "evidence_detail.html",
        {"checklist_id": checklist_id,
         "label": label, "target": target, "rows": rows},
    )


@app.get("/mfa", response_class=HTMLResponse)
def mfa_page(request: Request):
    return templates.TemplateResponse(
        request,
        "mfa.html",
        {"accounts": db.fetch_accounts(privileged_only=True)},
    )


@app.get("/inactive", response_class=HTMLResponse)
def inactive_page(request: Request):
    return templates.TemplateResponse(
        request,
        "inactive.html",
        {"accounts": db.fetch_inactive_accounts(90)},
    )


@app.get("/crown-jewels", response_class=HTMLResponse)
def crown_jewels_page(request: Request):
    return templates.TemplateResponse(
        request,
        "crown_jewels.html",
        {"items": db.fetch_crown_jewels()},
    )


@app.get("/uploads", response_class=HTMLResponse)
def uploads_page(request: Request):
    return templates.TemplateResponse(request, "uploads.html")


@app.get("/drops", response_class=HTMLResponse)
def drops_page(request: Request):
    return templates.TemplateResponse(
        request,
        "drops.html",
        {
            "files": drops.list_drops(),
            "drops_path": str(drops._drops_path()),
        },
    )


@app.get("/drops/view/{path:path}", response_class=HTMLResponse)
def drops_view(request: Request, path: str):
    try:
        result = drops.read_drop(path)
    except ValueError:
        raise HTTPException(400, "Ongeldig pad")
    if result is None:
        raise HTTPException(404, "Bestand niet gevonden")
    return templates.TemplateResponse(
        request,
        "drop_detail.html",
        {"request": request, "file": result, "path": path},
    )


# ---------------------------------------------------------------------------
# Upload-helpers
# ---------------------------------------------------------------------------


def _write_parser_evidence(*, checklist_id: str, source_type: str,
                           source_ref: str, raw_bytes: bytes,
                           result: dict, parser_name: str,
                           artefact_date: str | None = None) -> None:
    """Vertaal parser-result → evidence-rij met verdict-fallback."""
    verdict = result.get("verdict", "unparsed")
    evidence.write_evidence(
        checklist_id=checklist_id,
        source_type=source_type,
        source_ref=source_ref,
        raw_bytes=raw_bytes,
        artefact_date=artefact_date or result.get("artefact_date"),
        parsed_summary=result,
        parser_name=parser_name,
        verdict=verdict,
    )


async def _read_upload(file: UploadFile, *, required_ext: tuple[str, ...]) -> bytes:
    name = (file.filename or "").lower()
    if not any(name.endswith(ext) for ext in required_ext):
        raise HTTPException(400, f"Ondersteunde extensies: {required_ext}")
    return await file.read()


# ---------------------------------------------------------------------------
# Uploads per bron-type
# ---------------------------------------------------------------------------


@app.post("/crown-jewels/upload")
async def crown_jewels_upload(file: UploadFile = File(...)):
    content = await _read_upload(file, required_ext=(".csv",))
    # CSV-rijen worden ook in de crown_jewels-tabel gezet zodat /crown-jewels
    # de lijst blijft tonen — evidence (1.1 + 1.2) komt uit de parser.
    import csv, io
    db.reset_crown_jewels()
    reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
    for row in reader:
        if not row.get("name", "").strip():
            continue
        db.insert_crown_jewel({
            "name": row["name"].strip(),
            "owner": (row.get("owner") or "").strip() or None,
            "vlan_or_subnet": (row.get("vlan_or_subnet") or "").strip() or None,
            "backup_type": (row.get("backup_type") or "").strip() or None,
            "rto": (row.get("rto") or "").strip() or None,
            "rpo": (row.get("rpo") or "").strip() or None,
        })
    # Parser beoordeelt 1.1 en 1.2
    result = crown_jewels_csv.parse(content)
    for cid in ("1.1", "1.2"):
        sub = result["per_item"][cid]
        _write_parser_evidence(
            checklist_id=cid, source_type="crown_jewels_csv",
            source_ref=f"uploads/{file.filename}", raw_bytes=content,
            result=sub, parser_name=f"crown_jewels_{cid.replace('.','_')}_v1",
        )
    return RedirectResponse("/crown-jewels", status_code=303)


@app.post("/uploads/laps")
async def uploads_laps(file: UploadFile = File(...)):
    content = await _read_upload(file, required_ext=(".csv",))
    result = laps_csv.parse(content)
    _write_parser_evidence(
        checklist_id="3.4", source_type="intune_csv",
        source_ref=f"uploads/{file.filename}", raw_bytes=content,
        result=result, parser_name="laps_csv_v1",
    )
    return RedirectResponse("/checklist", status_code=303)


@app.post("/uploads/asr")
async def uploads_asr(file: UploadFile = File(...)):
    content = await _read_upload(file, required_ext=(".csv",))
    result = asr_csv.parse(content)
    _write_parser_evidence(
        checklist_id="7.2", source_type="intune_csv",
        source_ref=f"uploads/{file.filename}", raw_bytes=content,
        result=result, parser_name="asr_csv_v1",
    )
    return RedirectResponse("/checklist", status_code=303)


# --- Simple CSV-parsers ----------------------------------------------------


SIMPLE_CSV_ROUTES = {
    "3.2": ("ad_tier0_csv", ad_tier0_csv, "ad_tier0_csv_v1"),
    "3.3": ("ad_svc_accounts_csv", ad_svc_accounts_csv, "ad_svc_accounts_csv_v1"),
    "7.3": ("local_admins_csv", local_admins_csv, "local_admins_csv_v1"),
    "7.4": ("intune_usb_csv", intune_usb_csv, "intune_usb_csv_v1"),
    "5.2": ("edge_devices_csv", edge_devices_csv, "edge_devices_csv_v1"),
    "5.3": ("eol_inventory_csv", eol_inventory_csv, "eol_inventory_csv_v1"),
    "2.5": ("vpn_inventory_csv", vpn_inventory_csv, "vpn_inventory_csv_v1"),
    "6.2": ("backup_ad_audit_csv", backup_ad_audit_csv, "backup_ad_audit_csv_v1"),
    "8.4": ("fw_category_csv", fw_category_csv, "fw_category_csv_v1"),
}


@app.post("/uploads/csv/{checklist_id}")
async def uploads_simple_csv(checklist_id: str, file: UploadFile = File(...)):
    if checklist_id not in SIMPLE_CSV_ROUTES:
        raise HTTPException(400, f"Geen CSV-parser voor {checklist_id}")
    source_type, module, parser_name = SIMPLE_CSV_ROUTES[checklist_id]
    content = await _read_upload(file, required_ext=(".csv",))
    result = module.parse(content)
    _write_parser_evidence(
        checklist_id=checklist_id, source_type=source_type,
        source_ref=f"uploads/{file.filename}", raw_bytes=content,
        result=result, parser_name=parser_name,
    )
    return RedirectResponse("/checklist", status_code=303)


# --- JSON-parsers ----------------------------------------------------------


@app.post("/uploads/siem-rules")
async def uploads_siem_rules(file: UploadFile = File(...)):
    content = await _read_upload(file, required_ext=(".json",))
    result = siem_rules_json.parse(content)
    _write_parser_evidence(
        checklist_id="4.5", source_type="siem_rules_json",
        source_ref=f"uploads/{file.filename}", raw_bytes=content,
        result=result, parser_name="siem_rules_v1",
    )
    return RedirectResponse("/checklist", status_code=303)


@app.post("/uploads/siem-behavior")
async def uploads_siem_behavior(file: UploadFile = File(...)):
    content = await _read_upload(file, required_ext=(".json",))
    result = siem_behavior_rules_json.parse(content)
    _write_parser_evidence(
        checklist_id="8.2", source_type="siem_rules_json",
        source_ref=f"uploads/{file.filename}", raw_bytes=content,
        result=result, parser_name="siem_behavior_v1",
    )
    return RedirectResponse("/checklist", status_code=303)


# --- SIEM flow CSV (schrijft evidence voor 4.1 + 4.6) ---------------------


@app.post("/uploads/siem-flow")
async def uploads_siem_flow(file: UploadFile = File(...)):
    content = await _read_upload(file, required_ext=(".csv",))
    result = siem_flow_csv.parse(content)
    for cid in ("4.1", "4.6"):
        sub = result["per_item"][cid]
        _write_parser_evidence(
            checklist_id=cid, source_type="siem_flow_csv",
            source_ref=f"uploads/{file.filename}", raw_bytes=content,
            result=sub, parser_name=f"siem_flow_{cid.replace('.','_')}_v1",
        )
    return RedirectResponse("/checklist", status_code=303)


@app.post("/uploads/fw-flow")
async def uploads_fw_flow(file: UploadFile = File(...)):
    content = await _read_upload(file, required_ext=(".csv",))
    result = fw_flow_csv.parse(content)
    _write_parser_evidence(
        checklist_id="4.4", source_type="fw_flow_csv",
        source_ref=f"uploads/{file.filename}", raw_bytes=content,
        result=result, parser_name="fw_flow_v1",
    )
    return RedirectResponse("/checklist", status_code=303)


@app.post("/uploads/veeam")
async def uploads_veeam(file: UploadFile = File(...)):
    content = await _read_upload(file, required_ext=(".csv",))
    result = veeam_report.parse(content)
    _write_parser_evidence(
        checklist_id="6.1", source_type="backup_report",
        source_ref=f"uploads/{file.filename}", raw_bytes=content,
        result=result, parser_name="veeam_report_v1",
    )
    return RedirectResponse("/checklist", status_code=303)


# --- FW-configs (fortigate/palo/cisco) → evidence voor 2.1..2.4 -----------


FW_PARSERS = {
    "fortigate": (fortigate_config, "fortigate_config_v1"),
    "palo": (palo_config, "palo_config_v1"),
    "cisco": (cisco_running_config, "cisco_config_v1"),
}


@app.post("/uploads/fw-config")
async def uploads_fw_config(
    device_type: str = Form(...), file: UploadFile = File(...)
):
    if device_type not in FW_PARSERS:
        raise HTTPException(400, f"Onbekend device_type: {device_type}")
    module, parser_name = FW_PARSERS[device_type]
    content = await _read_upload(file, required_ext=(".conf", ".cfg", ".txt", ".xml"))
    result = module.parse(content)
    for cid, verdict in result["verdicts"].items():
        sub = {**result, "verdict": verdict}
        evidence.write_evidence(
            checklist_id=cid, source_type="fw_config",
            source_ref=f"uploads/{device_type}_{file.filename}",
            raw_bytes=content, artefact_date=None,
            parsed_summary=sub, parser_name=parser_name, verdict=verdict,
        )
    return RedirectResponse("/checklist", status_code=303)


# --- XML uploads (nmap, nessus, sysmon, wdac, gpo) ------------------------


@app.post("/uploads/nmap")
async def uploads_nmap(file: UploadFile = File(...)):
    content = await _read_upload(file, required_ext=(".xml",))
    result = nmap_xml.parse(content)
    _write_parser_evidence(
        checklist_id="5.4", source_type="nmap_xml",
        source_ref=f"uploads/{file.filename}", raw_bytes=content,
        result=result, parser_name="nmap_xml_v1",
    )
    return RedirectResponse("/checklist", status_code=303)


@app.post("/uploads/nessus")
async def uploads_nessus(file: UploadFile = File(...)):
    content = await _read_upload(file, required_ext=(".xml", ".nessus"))
    result = nessus_xml.parse(content)
    _write_parser_evidence(
        checklist_id="5.1", source_type="vuln_scan_xml",
        source_ref=f"uploads/{file.filename}", raw_bytes=content,
        result=result, parser_name="nessus_xml_v1",
    )
    return RedirectResponse("/checklist", status_code=303)


@app.post("/uploads/sysmon")
async def uploads_sysmon(file: UploadFile = File(...)):
    content = await _read_upload(file, required_ext=(".xml",))
    result = sysmon_config_xml.parse(content)
    _write_parser_evidence(
        checklist_id="4.2", source_type="sysmon_config_xml",
        source_ref=f"uploads/{file.filename}", raw_bytes=content,
        result=result, parser_name="sysmon_config_v1",
    )
    return RedirectResponse("/checklist", status_code=303)


@app.post("/uploads/wdac")
async def uploads_wdac(file: UploadFile = File(...)):
    content = await _read_upload(file, required_ext=(".xml",))
    result = wdac_policy_xml.parse(content)
    _write_parser_evidence(
        checklist_id="7.1", source_type="wdac_xml",
        source_ref=f"uploads/{file.filename}", raw_bytes=content,
        result=result, parser_name="wdac_policy_v1",
    )
    return RedirectResponse("/checklist", status_code=303)


@app.post("/uploads/gpo")
async def uploads_gpo(file: UploadFile = File(...)):
    content = await _read_upload(file, required_ext=(".xml",))
    result = gpo_export_xml.parse(content)
    _write_parser_evidence(
        checklist_id="3.2", source_type="gpo_export_xml",
        source_ref=f"uploads/{file.filename}", raw_bytes=content,
        result=result, parser_name="gpo_export_v1",
    )
    return RedirectResponse("/checklist", status_code=303)


# --- Asset-inventaris (1.3) -----------------------------------------------


@app.post("/uploads/asset-inventory")
async def uploads_asset_inventory(file: UploadFile = File(...)):
    content = await _read_upload(file, required_ext=(".csv",))
    result = asset_inventory.parse(content)
    _write_parser_evidence(
        checklist_id="1.3", source_type="ad_export",
        source_ref=f"uploads/{file.filename}", raw_bytes=content,
        result=result, parser_name="asset_inventory_v1",
    )
    return RedirectResponse("/checklist", status_code=303)


# --- Shallow PDF-uploads (6.3, 8.3, 9.1, 9.2, 9.3) ------------------------


SHALLOW_RULES = {
    "9.3": {"must_match": [r"scope", r"finding|bevinding", r"cvss|severity|risico"],
            "max_age_months": 12, "parser": "shallow_pentest_v1"},
    "8.3": {"must_match": [r"scenario", r"respons", r"verbeter|lessons"],
            "max_age_months": 6, "parser": "shallow_tabletop_v1"},
    "9.2": {"must_match": [r"bio\s*2", r"gap", r"remediat|aanbeveling"],
            "max_age_months": 12, "parser": "shallow_bio2_v1"},
    "6.3": {"must_match": [r"restore", r"rto", r"rpo"],
            "max_age_months": 12, "parser": "shallow_restoretest_v1"},
    "9.1": {"must_match": [r"patch", r"mfa", r"incident"],
            "max_age_months": 1, "parser": "shallow_kpi_v1"},
}


@app.post("/uploads/shallow/{checklist_id}")
async def uploads_shallow(checklist_id: str, file: UploadFile = File(...)):
    if checklist_id not in SHALLOW_RULES:
        raise HTTPException(400, f"Geen shallow-rule voor {checklist_id}")
    rule = SHALLOW_RULES[checklist_id]
    content = await _read_upload(file, required_ext=(".pdf",))
    # Schrijf PDF naar drops/shallow/<cid>/<filename> zodat hij terug te vinden is
    dest_dir = drops._drops_path() / "shallow" / checklist_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / (file.filename or "upload.pdf")
    dest.write_bytes(content)
    result = shallow_pdf.evaluate(dest, rule)
    evidence.write_evidence(
        checklist_id=checklist_id, source_type="report_pdf",
        source_ref=f"drops/shallow/{checklist_id}/{dest.name}",
        raw_bytes=content,
        artefact_date=result.get("artefact_date"),
        parsed_summary=result, parser_name=rule["parser"],
        verdict=result["verdict"],
    )
    return RedirectResponse("/checklist", status_code=303)


# --- Entra refresh ---------------------------------------------------------


@app.post("/entra/refresh")
def entra_refresh():
    try:
        entra.refresh()
    except Exception as e:
        raise HTTPException(500, f"Refresh mislukt: {e}")
    return RedirectResponse("/", status_code=303)
