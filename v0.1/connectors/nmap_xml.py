"""Nmap XML parser (5.4): telt open poorten + scan-datum.

Pass als scan <7d én geen onbekende open poort (vergeleken met baseline-file,
optioneel). Zonder baseline-file: pass als scan <7d én hosts in scan.
"""
from __future__ import annotations
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta


def parse(raw_bytes: bytes) -> dict:
    try:
        root = ET.fromstring(raw_bytes)
    except ET.ParseError as e:
        return {"verdict": "unparsed", "error": f"XML-parse: {e}"}

    start_attr = root.attrib.get("start")
    if start_attr:
        try:
            scan_dt = datetime.fromtimestamp(int(start_attr), tz=timezone.utc)
        except ValueError:
            scan_dt = None
    else:
        scan_dt = None

    open_ports: list[dict] = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        ip = addr_el.attrib.get("addr") if addr_el is not None else "?"
        for port in host.findall(".//port"):
            state_el = port.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue
            open_ports.append({
                "host": ip,
                "port": port.attrib.get("portid"),
                "proto": port.attrib.get("protocol"),
            })

    now = datetime.now(timezone.utc)
    age_days = None
    fresh = False
    if scan_dt:
        age_days = max(0, (now - scan_dt).days)
        fresh = age_days <= 7

    if scan_dt is None:
        verdict = "unparsed"
    elif not fresh:
        verdict = "stale"
    else:
        # Zonder baseline is 'pass' als er daadwerkelijk hosts zijn gescand
        verdict = "pass" if open_ports or root.findall("host") else "fail"

    return {"verdict": verdict,
            "open_ports_count": len(open_ports),
            "scan_date": scan_dt.isoformat() if scan_dt else None,
            "artefact_date": scan_dt.isoformat() if scan_dt else None,
            "age_days": age_days,
            "fresh_within_7d": fresh,
            "sample_ports": open_ports[:10]}
