"""FastAPI app voor v0.1 — overzicht + CSV-upload + Entra-refresh."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import checklist
import db
import drops
import entra

app = FastAPI(title="security-posture-tool v0.1")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@app.on_event("startup")
def _startup():
    if not Path(db.DB_PATH).exists():
        db.init()
    checklist.seed_if_empty()


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "checklist": db.fetch_checklist(),
            "total_accounts": len(db.fetch_accounts()),
            "total_privileged": len(db.fetch_accounts(privileged_only=True)),
            "total_crown_jewels": len(db.fetch_crown_jewels()),
        },
    )


@app.get("/mfa", response_class=HTMLResponse)
def mfa_page(request: Request):
    return templates.TemplateResponse(
        "mfa.html",
        {"request": request, "accounts": db.fetch_accounts(privileged_only=True)},
    )


@app.get("/inactive", response_class=HTMLResponse)
def inactive_page(request: Request):
    return templates.TemplateResponse(
        "inactive.html",
        {"request": request, "accounts": db.fetch_inactive_accounts(90)},
    )


@app.get("/crown-jewels", response_class=HTMLResponse)
def crown_jewels_page(request: Request):
    return templates.TemplateResponse(
        "crown_jewels.html",
        {"request": request, "items": db.fetch_crown_jewels()},
    )


@app.post("/crown-jewels/upload")
async def crown_jewels_upload(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Alleen CSV-upload")
    content = (await file.read()).decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(content))
    required = {"name"}
    if not required.issubset(reader.fieldnames or []):
        raise HTTPException(400, f"CSV mist verplichte kolom: {required}")
    count = 0
    for row in reader:
        db.insert_crown_jewel({
            "name": row.get("name", "").strip(),
            "owner": row.get("owner", "").strip() or None,
            "vlan_or_subnet": row.get("vlan_or_subnet", "").strip() or None,
            "backup_type": row.get("backup_type", "").strip() or None,
            "rto": row.get("rto", "").strip() or None,
            "rpo": row.get("rpo", "").strip() or None,
        })
        count += 1
    db.set_checklist_state(
        "1.1",
        "Kroonjuwelenlijst (max 20, met eigenaar)",
        measured_value=f"{len(db.fetch_crown_jewels())} items",
        target="≥ 1 item, 100% heeft naam + eigenaar",
        notes=f"Laatste upload voegde {count} items toe.",
    )
    return RedirectResponse("/crown-jewels", status_code=303)


@app.post("/entra/refresh")
def entra_refresh():
    try:
        entra.refresh()
    except Exception as e:
        raise HTTPException(500, f"Refresh mislukt: {e}")
    return RedirectResponse("/", status_code=303)


@app.get("/checklist", response_class=HTMLResponse)
def checklist_page(request: Request):
    return templates.TemplateResponse(
        "checklist.html",
        {"request": request, "checklist": db.fetch_checklist()},
    )


@app.get("/uploads", response_class=HTMLResponse)
def uploads_page(request: Request):
    return templates.TemplateResponse("uploads.html", {"request": request})


@app.get("/drops", response_class=HTMLResponse)
def drops_page(request: Request):
    return templates.TemplateResponse(
        "drops.html",
        {
            "request": request,
            "files": drops.list_drops(),
            "drops_path": str(drops.DROPS_PATH),
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
        "drop_detail.html",
        {"request": request, "file": result, "path": path},
    )


def _truthy(val: str) -> bool:
    return str(val).strip().lower() in {"true", "yes", "ja", "1", "enabled", "on"}


@app.post("/uploads/laps")
async def uploads_laps(file: UploadFile = File(...)):
    """CSV met minimaal kolommen: device_name, laps_configured.

    Checklist 3.4 — LAPS op werkplekken + servers.
    """
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Alleen CSV-upload")
    content = (await file.read()).decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(content))
    required = {"device_name", "laps_configured"}
    if not required.issubset(reader.fieldnames or []):
        raise HTTPException(400, f"CSV mist verplichte kolommen: {required}")
    total = 0
    covered = 0
    for row in reader:
        total += 1
        if _truthy(row.get("laps_configured", "")):
            covered += 1
    pct = f"{(covered / total * 100):.0f}%" if total else "n.v.t."
    db.set_checklist_state(
        "3.4",
        "LAPS op werkplekken + servers",
        measured_value=f"{covered}/{total} ({pct})",
        target="100%",
        notes=f"Upload {file.filename}; bron: Intune/AD-export.",
    )
    return RedirectResponse("/checklist", status_code=303)


@app.post("/uploads/asr")
async def uploads_asr(file: UploadFile = File(...)):
    """CSV met minimaal kolommen: device_name, asr_office_macros_blocked.

    Checklist 7.2 — Office-macros uit voor internet-bestanden (ASR-rule).
    """
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Alleen CSV-upload")
    content = (await file.read()).decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(content))
    required = {"device_name", "asr_office_macros_blocked"}
    if not required.issubset(reader.fieldnames or []):
        raise HTTPException(400, f"CSV mist verplichte kolommen: {required}")
    total = 0
    covered = 0
    for row in reader:
        total += 1
        if _truthy(row.get("asr_office_macros_blocked", "")):
            covered += 1
    pct = f"{(covered / total * 100):.0f}%" if total else "n.v.t."
    db.set_checklist_state(
        "7.2",
        "Office-macros uit voor internet-bestanden (ASR)",
        measured_value=f"{covered}/{total} ({pct})",
        target="100%",
        notes=f"Upload {file.filename}; bron: Intune-export.",
    )
    return RedirectResponse("/checklist", status_code=303)
