"""Nessus .nessus / XML parser (5.1): telt criticals en ouderdom.

Pass als 0 critical-findings (severity=4) aanwezig. Stale als scan-datum >14d.
"""
from __future__ import annotations
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def parse(raw_bytes: bytes) -> dict:
    try:
        root = ET.fromstring(raw_bytes)
    except ET.ParseError as e:
        return {"verdict": "unparsed", "error": f"XML-parse: {e}"}

    criticals = []
    highs = []
    for item in root.iter("ReportItem"):
        sev = item.attrib.get("severity", "0")
        try:
            sev_int = int(sev)
        except ValueError:
            continue
        info = {
            "pluginName": item.attrib.get("pluginName", ""),
            "host": (item.getparent().attrib.get("name")
                     if hasattr(item, "getparent") else None),
            "port": item.attrib.get("port"),
        }
        if sev_int >= 4:
            criticals.append(info)
        elif sev_int == 3:
            highs.append(info)

    # Scan-datum uit <tag name="HOST_END"> of top-level policy; best-effort
    scan_dt = None
    for tag in root.iter("tag"):
        if tag.attrib.get("name") in ("HOST_END", "SCAN_END"):
            try:
                scan_dt = datetime.strptime(
                    tag.text.strip(), "%a %b %d %H:%M:%S %Y"
                ).replace(tzinfo=timezone.utc)
                break
            except (ValueError, AttributeError):
                continue

    age_days = None
    if scan_dt:
        age_days = max(0, (datetime.now(timezone.utc) - scan_dt).days)

    if age_days is not None and age_days > 14:
        verdict = "stale"
    elif len(criticals) == 0:
        verdict = "pass"
    else:
        verdict = "fail"

    return {"verdict": verdict,
            "critical_count": len(criticals),
            "high_count": len(highs),
            "scan_date": scan_dt.isoformat() if scan_dt else None,
            "artefact_date": scan_dt.isoformat() if scan_dt else None,
            "age_days": age_days}
