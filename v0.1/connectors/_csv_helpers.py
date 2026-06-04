"""Gedeelde helpers voor CSV-parsers: rijen tellen, true/false-waarden.

Elke parser implementeert `parse(raw_bytes) -> dict` met tenminste:
  {"verdict": "pass"|"fail"|"unparsed", ...}

De helpers hier nemen het saaie werk weg: utf-8-bom-strippen, header-check,
truthy-interpretatie.
"""
from __future__ import annotations

import csv
import io


TRUTHY = {"true", "yes", "ja", "1", "enabled", "on", "y", "t"}
FALSY = {"false", "no", "nee", "0", "disabled", "off", "n", "f"}


def truthy(val: str | None) -> bool:
    if val is None:
        return False
    return str(val).strip().lower() in TRUTHY


def falsy(val: str | None) -> bool:
    if val is None:
        return False
    return str(val).strip().lower() in FALSY


def read_rows(raw_bytes: bytes) -> tuple[list[str], list[dict[str, str]]]:
    """Decodeer bytes naar (fieldnames, rows). Robuust tegen BOM + encoding-fouten."""
    text = raw_bytes.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    headers = list(reader.fieldnames or [])
    rows = [dict(r) for r in reader]
    return headers, rows


def missing_cols(required: set[str], headers: list[str]) -> list[str]:
    return sorted(required - set(headers))


def count_covered(rows: list[dict], predicate) -> tuple[int, int]:
    total = len(rows)
    covered = sum(1 for r in rows if predicate(r))
    return total, covered


def verdict_from_coverage(total: int, covered: int, *, require_nonzero: bool = True) -> str:
    if total == 0:
        return "fail" if require_nonzero else "pass"
    return "pass" if covered == total else "fail"


def pct(covered: int, total: int) -> int:
    return round(covered / total * 100) if total else 0
