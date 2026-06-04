"""Evidence-only schrijflaag voor checklist-metingen.

Elke meting = een artefact (API-response-body, CSV, config, log, rapport-PDF).
We slaan hash + datum + parsed_summary + verdict op. `checklist_state` wordt
afgeleid uit de nieuwste evidence-rij — nooit rechtstreeks door routes gezet.

Geen attestaties, geen "status=done"-checkbox. Wat er niet als artefact is,
is niet gemeten.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

VALID_VERDICTS = {"pass", "fail", "stale", "unparsed"}


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_evidence(*, checklist_id: str, source_type: str, source_ref: str,
                   raw_bytes: bytes, artefact_date: str | None,
                   parsed_summary: dict | None, parser_name: str | None,
                   verdict: str) -> str:
    """Schrijf een evidence-rij en sync `checklist_state`.

    Returns: sha256-hex van raw_bytes.
    """
    if verdict not in VALID_VERDICTS:
        raise ValueError(f"Ongeldig verdict: {verdict!r}")

    import db  # late import: laat tests DB_PATH overriden

    h = sha256_bytes(raw_bytes)
    db.insert_evidence({
        "checklist_id": checklist_id,
        "source_type": source_type,
        "source_ref": source_ref,
        "sha256": h,
        "collected_at": datetime.utcnow().isoformat(timespec="seconds"),
        "artefact_date": artefact_date,
        "parsed_summary": json.dumps(parsed_summary, default=str)
                          if parsed_summary is not None else None,
        "parser_name": parser_name,
        "verdict": verdict,
    })
    _update_checklist_state(checklist_id)
    return h


def latest_for(checklist_id: str) -> dict | None:
    import db
    return db.fetch_latest_evidence(checklist_id)


def history_for(checklist_id: str, limit: int = 20) -> list[dict]:
    import db
    return db.fetch_evidence_for(checklist_id, limit=limit)


def derive_state(checklist_id: str) -> dict:
    """Vertaal de nieuwste evidence-rij naar een UI-state-record."""
    latest = latest_for(checklist_id)
    if latest is None:
        return {
            "measured_value": "geen bewijs",
            "verdict": None,
            "last_measured_at": None,
            "artefact_date": None,
            "parser_name": None,
            "summary": {},
        }
    summary: dict[str, Any] = {}
    if latest.get("parsed_summary"):
        try:
            summary = json.loads(latest["parsed_summary"])
        except json.JSONDecodeError:
            summary = {}
    return {
        "measured_value": _format_measured(latest["verdict"], summary),
        "verdict": latest["verdict"],
        "last_measured_at": latest["collected_at"],
        "artefact_date": latest.get("artefact_date"),
        "parser_name": latest.get("parser_name"),
        "summary": summary,
    }


def _format_measured(verdict: str, summary: dict) -> str:
    if not isinstance(summary, dict):
        return verdict
    if "pct" in summary and "total" in summary and "covered" in summary:
        return f"{summary['covered']}/{summary['total']} ({summary['pct']}%)"
    if "total" in summary and "covered" in summary:
        t = summary["total"] or 0
        c = summary["covered"] or 0
        pct = round(c / t * 100) if t else 0
        return f"{c}/{t} ({pct}%)"
    if "age_days" in summary:
        return f"artefact {summary['age_days']} dagen oud"
    if "risky_count" in summary:
        return f"{summary['risky_count']} risky sign-ins"
    if "findings" in summary:
        return f"{summary['findings']} findings"
    return verdict


def _update_checklist_state(checklist_id: str):
    """Sync checklist_state met nieuwste evidence (idempotent)."""
    import db
    try:
        from checklist import label_for, target_for
    except ImportError:  # pragma: no cover — fallback bij bootstrap
        def label_for(cid): return cid
        def target_for(cid): return ""

    state = derive_state(checklist_id)
    notes = (
        f"parser={state.get('parser_name') or '-'}; "
        f"artefact_date={state.get('artefact_date') or '-'}; "
        f"verdict={state.get('verdict') or '-'}"
    )
    db.set_checklist_state(
        checklist_id,
        label_for(checklist_id),
        measured_value=state["measured_value"],
        target=target_for(checklist_id),
        notes=notes,
    )
