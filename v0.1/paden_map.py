"""Koppeling van checklist-items naar een aanvalspad en chokepoint uit paden.json.

Dit is de brug tussen de meting (diepte 2) en de zelfcheck en methode (diepte 0 en 1): een gemeten item
hier is het bewijs voor een cel daar. Niet elk item hoort bij een pad; governance-items zoals de
maandelijkse KPI blijven bewust ongekoppeld. Dat is geen fout, wel een uitnodiging om de tabel aan te
vullen als een pad erbij komt.

De sleutel is het checklist-id uit checklist.py, de waarde is (pad, chokepoint) uit paden.json.
"""
from __future__ import annotations

KOPPELING: dict[str, tuple[str, str]] = {
    # 1 Inventaris en kroonjuwelen
    "1.1": ("AP18", "AP18-1"),   # kroonjuwelenlijst = kritieke processen en herstelprioriteiten
    "1.2": ("AP18", "AP18-2"),   # per juweel VLAN, backup, RTO/RPO = systemen in samenhang
    "1.3": ("AP13", "AP13-1"),   # asset-inventaris = het aanvalsoppervlak kennen
    # 2 Segmentatie
    "2.1": ("AP11", "AP11-3"),   # iLO/BMC in eigen VLAN
    "2.2": ("AP05", "AP05-2"),   # RDP/WinRM naar kroonjuwelen alleen via jump
    "2.3": ("AP11", "AP11-3"),   # mgmt-zone gesplitst
    "2.4": ("AP11", "AP11-3"),   # gast-wifi gescheiden
    "2.5": ("AP11", "AP11-3"),   # vendor-VPN's scoped
    # 3 Identity
    "3.1": ("AP02", "AP02-1"),   # MFA verplicht tegen gestolen inloggegevens
    "3.2": ("AP05", "AP05-1"),   # tier-0 isolatie, PAW
    "3.3": ("AP05", "AP05-1"),   # service-accounts gescheiden van dagelijks gebruik
    "3.4": ("AP11", "AP11-3"),   # LAPS stopt hergebruik van lokale beheerwachtwoorden
    "3.5": ("AP02", "AP02-2"),   # slapende accounts zijn een herstelroute
    # 4 Zicht
    "4.1": ("AP12", "AP12-4"),   # flow-logs maken externe exploitatie zichtbaar
    "4.2": ("AP11", "AP11-4"),   # event-IDs en Sysmon op de endpoint- en DC-laag
    "4.3": ("AP01", "AP01-3"),   # sign-in logs en risky sign-ins
    "4.4": ("AP10", "AP10-4"),   # egress met FQDN toont infostealer-verkeer
    "4.5": ("AP12", "AP12-4"),   # eigen use-case alerts
    "4.6": ("AP11", "AP11-3"),   # east-west zichtbaar
    # 5 Kwetsbaarheden
    "5.1": ("AP12", "AP12-1"),   # internet-facing patch-SLA
    "5.2": ("AP12", "AP12-1"),   # edge en VPN spoedpatching
    "5.3": ("AP10", "AP10-3"),   # EOL-lijst hoort bij dekking van patching
    "5.4": ("AP13", "AP13-1"),   # wekelijkse externe scan
    # 6 Back-up
    "6.1": ("AP17", "AP17-9"),   # 3-2-1-1-0 immutable
    "6.2": ("AP17", "AP17-9"),   # backup in eigen security-domein
    "6.3": ("AP17", "AP17-10"),  # restore-test tegen RTO en RPO
    # 7 Werkplek
    "7.1": ("AP09", "AP09-1"),   # application control
    "7.2": ("AP09", "AP09-1"),   # macro's uit via ASR
    "7.3": ("AP09", "AP09-3"),   # geen lokale admin
    "7.4": ("AP09", "AP09-2"),   # USB-policy = gegevensdragers beperken
    # 8 Volwassenheid
    "8.1": ("AP01", "AP01-1"),   # phishingbestendige MFA voor beheerders
    "8.2": ("AP11", "AP11-4"),   # gedragsdetectie op de endpoint
    "8.3": ("AP17", "AP17-11"),  # tabletop = het crisisherstelplan oefenen
    # 9 Verantwoording
    "9.3": ("AP12", "AP12-3"),   # externe pentest en herstel verifieren
}

# Bewust ongekoppeld: 8.4 (AI-egress), 9.1 (KPI naar het bestuur) en 9.2 (BIO 2.0 gap-analyse).
# Dat zijn beleids- en verantwoordingsmaatregelen, geen chokepoint in een aanvalspad.
ONGEKOPPELD_MET_REDEN: dict[str, str] = {
    "8.4": "beleidsmaatregel op AI-gebruik, raakt geen enkel chokepoint direct",
    "9.1": "verantwoording aan het bestuur, geen technische of procesbarriere in een pad",
    "9.2": "normconformiteit, geen barriere in een aanvalspad",
}


def koppel(checklist_id: str) -> tuple[str, str] | None:
    """Het pad en chokepoint bij een checklist-item, of None als het item nergens op landt."""
    return KOPPELING.get(checklist_id)


def items_voor(chokepoint_id: str) -> list[str]:
    """Welke checklist-items meten dit chokepoint? Leeg betekent: hier is nog geen meting voor."""
    return sorted(k for k, (_pad, cp) in KOPPELING.items() if cp == chokepoint_id)
