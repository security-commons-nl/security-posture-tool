"""Shallow check voor rapport-PDFs: tekst-extractie + regex-set + datum-window.

Gebruik: `evaluate(pdf_path, rule)` met rule = {must_match: [regex,...],
max_age_months: int}. Retourneert dict met verdict + metadata.

Verdicts:
  - pass      — alle regexen matchen én artefact_date binnen window
  - stale     — regexen matchen maar artefact te oud
  - unparsed  — regex-set mist: handmatige review nodig
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from pypdf import PdfReader


DATE_RE = re.compile(r"\b(20\d{2})[-/](0?[1-9]|1[0-2])[-/](0?[1-9]|[12]\d|3[01])\b")


def _extract_text(path: Path) -> str:
    reader = PdfReader(str(path))
    parts = []
    for page in reader.pages:
        try:
            parts.append(page.extract_text() or "")
        except Exception:  # pragma: no cover — corrupte pagina
            parts.append("")
    return "\n".join(parts)


def _extract_date(text: str, fallback_mtime_ts: float) -> tuple[datetime, str]:
    m = DATE_RE.search(text)
    if m:
        y, mo, d = m.groups()
        try:
            return datetime(int(y), int(mo), int(d), tzinfo=timezone.utc), "text"
        except ValueError:
            pass
    return datetime.fromtimestamp(fallback_mtime_ts, tz=timezone.utc), "mtime"


def evaluate(path: Path | str, rule: dict) -> dict:
    """rule = {"must_match": [regex,...], "max_age_months": int}"""
    path = Path(path)
    text = _extract_text(path)
    date, date_source = _extract_date(text, path.stat().st_mtime)
    now = datetime.now(timezone.utc)
    age_days = max(0, (now - date).days)
    max_age_days = rule["max_age_months"] * 31

    missing = []
    for rx in rule["must_match"]:
        if not re.search(rx, text, re.IGNORECASE | re.DOTALL):
            missing.append(rx)

    base = {
        "age_days": age_days,
        "max_age_months": rule["max_age_months"],
        "artefact_date": date.isoformat(),
        "date_source": date_source,
        "must_match": list(rule["must_match"]),
    }

    if missing:
        return {**base, "verdict": "unparsed", "missing_regex": missing}
    if age_days > max_age_days:
        return {**base, "verdict": "stale"}
    return {**base, "verdict": "pass"}
