"""Genereer test-PDF's met fpdf2 voor shallow-PDF-tests.

Draai eenmalig:  python tests/fixtures/_generate_pdfs.py
De gegenereerde .pdf-bestanden komen naast dit script te staan en worden
door de testsuite gelezen.
"""
from __future__ import annotations
import os
import time
from pathlib import Path
from fpdf import FPDF

HERE = Path(__file__).parent


def _pdf(text: str, path: Path, mtime: float | None = None):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)
    for line in text.splitlines():
        pdf.cell(0, 8, line, ln=True)
    pdf.output(str(path))
    if mtime is not None:
        os.utime(path, (mtime, mtime))


YEAR_NOW = time.strftime("%Y")
RECENT = f"{YEAR_NOW}-03-14"
STALE = "2023-01-01"
OLD = "2024-01-01"


def main():
    # Pentest — valid (regex + datum)
    _pdf(f"Pentest rapport {RECENT}\nScope: infra\nFindings: 5\nCVSS hoogste 9.1\n",
         HERE / "pentest_valid.pdf")
    # Pentest — stale (te oud)
    _pdf(f"Pentest rapport {STALE}\nScope: old\nFindings: 3\nSeverity hoog\n",
         HERE / "pentest_stale.pdf")
    # Pentest — incomplete (mist 'findings'-regex)
    _pdf(f"Pentest sumvatting {RECENT}\nAlgemene observaties zonder detail.\n",
         HERE / "pentest_incomplete.pdf")
    # Tabletop — valid
    _pdf(f"Tabletop oefening {RECENT}\nScenario ransomware\nRespons geoefend\nVerbeterpunten 3\n",
         HERE / "tabletop_valid.pdf")
    # BIO 2.0 gap — valid
    _pdf(f"BIO 2.0 gap-analyse {RECENT}\nGap bevindingen op toegangscontrole\nAanbeveling 12\n",
         HERE / "bio2_valid.pdf")
    # Restore-test — valid
    _pdf(f"Restore test {RECENT}\nRTO 4 uur RPO 1 uur\nRestore succesvol afgerond\n",
         HERE / "restore_valid.pdf")
    # KPI maandrapport — valid (regex OK, maar oud → stale)
    _pdf(f"Maandrapport {RECENT}\nPatchstand 92%\nMFA 98%\nIncidents 2\n",
         HERE / "kpi_valid.pdf")
    print(f"Generated PDFs in {HERE}")


if __name__ == "__main__":
    main()
