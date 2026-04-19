"""Mapping van v0.1-metingen naar checklist-ID's.

Een cyber-hygiene-checklist voor gemeenten (BIO 2.0 / IBD-geïnspireerd) kent
per maatregel een ID. v0.1 dekt een subset. Deze module bevat de labels en
targets zodat de UI ze kan tonen — de meetwaarden worden door entra.py + CSV-
upload gevuld in tabel `checklist_state`.
"""

from __future__ import annotations

# De subset die v0.1 bedient. Niet hardcoden wat er wel en niet te meten is —
# de meting-functies zelf bepalen of er een waarde komt. Deze dict is alleen
# voor het initialiseren van de checklist-rijen bij een lege database.
V0_1_ITEMS: list[dict] = [
    {
        "id": "1.1",
        "label": "Kroonjuwelenlijst (max 20, met eigenaar)",
        "target": "≥ 1 item, 100% heeft naam + eigenaar",
        "bron": "CSV-upload",
    },
    {
        "id": "3.1",
        "label": "MFA verplicht op externe toegang + admin-accounts",
        "target": "100% dekking privileged accounts",
        "bron": "Entra (Graph API)",
    },
    {
        "id": "3.4",
        "label": "LAPS op alle werkplekken + servers",
        "target": "100% heeft recente LAPS-timestamp",
        "bron": "CSV-upload (Intune-export) — in v0.1",
    },
    {
        "id": "3.5",
        "label": "Inactieve accounts >90 dagen auto-disabled",
        "target": "0 inactief + niet-disabled",
        "bron": "Entra (sign-in activity)",
    },
    {
        "id": "7.2",
        "label": "Office-macros uit voor internet-bestanden (ASR)",
        "target": "Intune-policy actief op 100% werkplekken",
        "bron": "CSV-upload (Intune-export) — in v0.1",
    },
]


def seed_if_empty():
    """Zet initiële rijen in checklist_state als ze nog niet bestaan.

    Idempotent: herhaaldelijk aanroepen overschrijft geen metingen.
    """
    import db
    bestaand = {c["checklist_id"] for c in db.fetch_checklist()}
    for item in V0_1_ITEMS:
        if item["id"] not in bestaand:
            db.set_checklist_state(
                item["id"],
                item["label"],
                measured_value="nog niet gemeten",
                target=item["target"],
                notes=f"Bron: {item['bron']}",
            )
