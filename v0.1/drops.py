"""Drops-folder — lees bestanden die buiten de tool leven.

De tool beschouwt `DROPS_PATH` (default `./drops/`) als een lees-folder. Alles
wat daarin staat — CSV's van firewall-logs, textfile-dumps van router-configs,
JSON-exports — kan via de UI worden ingezien zonder upload-ritueel. Het team
dumpt bestanden daar; de tool lijst en opent ze.

Geen DB-opslag: files zijn de bron van waarheid, tool leest on-demand.
"""

from __future__ import annotations

import csv
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

DROPS_PATH = Path(os.environ.get("DROPS_PATH", "drops")).resolve()

TEXT_EXT = {".txt", ".log", ".conf", ".cfg", ".md", ".json", ".xml", ".yaml", ".yml", ".ini"}
CSV_EXT = {".csv", ".tsv"}
PREVIEW_BYTES = 500_000    # max 500 KB text preview
PREVIEW_ROWS = 200         # max 200 CSV rows preview


def list_drops() -> list[dict]:
    """Lijst alle bestanden (recursief) onder DROPS_PATH, sorteren op mtime desc."""
    if not DROPS_PATH.exists():
        return []
    out: list[dict] = []
    for p in DROPS_PATH.rglob("*"):
        if p.is_dir():
            continue
        if p.name.lower() == "readme.md":
            continue
        if p.name.startswith("."):
            continue
        try:
            stat = p.stat()
        except OSError:
            continue
        out.append({
            "path": str(p.relative_to(DROPS_PATH)).replace("\\", "/"),
            "name": p.name,
            "size": stat.st_size,
            "size_human": _human_size(stat.st_size),
            "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            "ext": p.suffix.lower(),
            "kind": _kind(p),
        })
    out.sort(key=lambda r: r["mtime"], reverse=True)
    return out


def read_drop(relpath: str) -> dict | None:
    """Lees een bestand veilig binnen DROPS_PATH. Retourneert None als onbekend."""
    target = (DROPS_PATH / relpath).resolve()
    # Voorkom path-traversal
    try:
        target.relative_to(DROPS_PATH)
    except ValueError:
        raise ValueError("Path buiten DROPS_PATH")
    if not target.exists() or not target.is_file():
        return None

    ext = target.suffix.lower()
    stat = target.stat()

    if ext in CSV_EXT:
        return _read_csv(target, ext)
    if ext in TEXT_EXT or not ext:
        return _read_text(target)
    return {
        "type": "binary",
        "filename": target.name,
        "size": stat.st_size,
        "size_human": _human_size(stat.st_size),
    }


def _read_csv(p: Path, ext: str) -> dict:
    delim = "\t" if ext == ".tsv" else ","
    rows: list[list[str]] = []
    total = 0
    with open(p, encoding="utf-8-sig", newline="", errors="replace") as f:
        reader = csv.reader(f, delimiter=delim)
        for i, row in enumerate(reader):
            total = i + 1
            if i <= PREVIEW_ROWS:
                rows.append(row)
    headers = rows[0] if rows else []
    data = rows[1:PREVIEW_ROWS + 1]
    return {
        "type": "csv",
        "filename": p.name,
        "headers": headers,
        "rows": data,
        "total_rows": max(0, total - 1),
        "truncated": total > PREVIEW_ROWS + 1,
    }


def _read_text(p: Path) -> dict:
    with open(p, encoding="utf-8", errors="replace") as f:
        content = f.read(PREVIEW_BYTES + 1)
    truncated = len(content) > PREVIEW_BYTES
    if truncated:
        content = content[:PREVIEW_BYTES]
    return {
        "type": "text",
        "filename": p.name,
        "content": content,
        "truncated": truncated,
    }


def _kind(p: Path) -> str:
    ext = p.suffix.lower()
    if ext in CSV_EXT:
        return "csv"
    if ext in TEXT_EXT or not ext:
        return "text"
    return "binary"


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n = n / 1024
    return f"{n:.1f} TB"
