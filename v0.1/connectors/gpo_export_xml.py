"""GPO export XML parser (alternatieve bron voor 3.2).

Pass als de GPO een `LogonWorkstations`-setting met waarde bevat.
"""
from __future__ import annotations
import xml.etree.ElementTree as ET


def parse(raw_bytes: bytes) -> dict:
    text = raw_bytes.decode("utf-8", errors="replace")
    try:
        ET.fromstring(raw_bytes)
    except ET.ParseError as e:
        return {"verdict": "unparsed", "error": f"XML-parse: {e}"}

    has_logon_workstations = "LogonWorkstations" in text
    # Tellen voor indicatie
    occurrences = text.count("LogonWorkstations")
    verdict = "pass" if has_logon_workstations else "fail"
    return {"verdict": verdict,
            "logon_workstations_found": has_logon_workstations,
            "occurrences": occurrences}
