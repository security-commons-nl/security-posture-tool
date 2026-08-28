"""Checklist-definitie voor security-posture-tool-aegis.

Bevat alle 37 maatregelen uit de gemeente-cyber-hygiene-checklist. Elke rij
krijgt bij eerste start een rij in `checklist_state` (measured_value="geen
bewijs"). Metingen komen langs via `evidence.write_evidence()`, die
`checklist_state` bijwerkt op basis van de nieuwste evidence-rij.

Kill-chain-mapping: elk item heeft `kill_chain_phases` (Lockheed 7-fase).
Leeg = meta (governance/inventaris, geen kill-chain-fase). De mapping is een
DRAFT-voorzet — team reviewt bij de eerstvolgende tweewekelijkse sessie.
"""

from __future__ import annotations


# Lockheed Cyber Kill Chain — 7 fases, in aanvalsvolgorde.
KILL_CHAIN_PHASES: list[str] = [
    "recon", "weaponization", "delivery", "exploitation",
    "installation", "c2", "actions",
]

KILL_CHAIN_LABELS: dict[str, str] = {
    "recon": "Reconnaissance",
    "weaponization": "Weaponization",
    "delivery": "Delivery",
    "exploitation": "Exploitation",
    "installation": "Installation",
    "c2": "Command & Control",
    "actions": "Actions on Objectives",
    "meta": "Meta / governance",
}


ALL_ITEMS: list[dict] = [
    # Categorie 1 — Inventaris & kroonjuwelen
    {"id": "1.1", "category": "1 Inventaris & kroonjuwelen",
     "label": "Kroonjuwelenlijst (max 20, met eigenaar)",
     "target": "≥1 item, 100% heeft naam + eigenaar",
     "bron": "CSV-upload",
     "kill_chain_phases": []},
    {"id": "1.2", "category": "1 Inventaris & kroonjuwelen",
     "label": "Per kroonjuweel: VLAN, backup-type, RTO/RPO",
     "target": "100% van juwelen heeft alle kolommen gevuld",
     "bron": "CSV-upload (uitgebreide kolommen op 1.1)",
     "kill_chain_phases": []},
    {"id": "1.3", "category": "1 Inventaris & kroonjuwelen",
     "label": "Asset-inventaris bijgewerkt (AD+DHCP+FW-dump)",
     "target": "Totale count binnen 5% van werkelijkheid",
     "bron": "Drops: AD+DHCP+FW-dump",
     "kill_chain_phases": ["recon"]},

    # Categorie 2 — Segmentatie
    {"id": "2.1", "category": "2 Segmentatie",
     "label": "iLO/IPMI/DRAC/BMC eigen VLAN, alleen via jump",
     "target": "Policy: JumpHosts→iLO expliciet, elders deny",
     "bron": "Drops: fw_config",
     "kill_chain_phases": ["installation", "c2", "actions"]},
    {"id": "2.2", "category": "2 Segmentatie",
     "label": "RDP/WinRM naar kroonjuwelen alleen via jump",
     "target": "0 directe RDP user-VLAN→server-VLAN",
     "bron": "Drops: fw_config",
     "kill_chain_phases": ["installation", "actions"]},
    {"id": "2.3", "category": "2 Segmentatie",
     "label": "Mgmt-zone gesplitst (OOB/jump/tooling/AAA), geen any-any",
     "target": "0 any-any in mgmt-regels",
     "bron": "Drops: fw_config",
     "kill_chain_phases": ["installation", "c2", "actions"]},
    {"id": "2.4", "category": "2 Segmentatie",
     "label": "Gast-WiFi volledig gescheiden (geen route intern)",
     "target": "Traceroute gast→intern: drop",
     "bron": "Drops: fw_config",
     "kill_chain_phases": ["delivery", "installation"]},
    {"id": "2.5", "category": "2 Segmentatie",
     "label": "Vendor-VPN's expliciet src/dst scoped",
     "target": "Geen 0.0.0.0/0 per peer",
     "bron": "CSV-upload: vpn_inventory",
     "kill_chain_phases": ["delivery", "installation"]},

    # Categorie 3 — Identity & toegang
    {"id": "3.1", "category": "3 Identity & toegang",
     "label": "MFA verplicht: admin + externe + kroonjuweel-toegang",
     "target": "100% CA-dekking",
     "bron": "Graph API",
     "kill_chain_phases": ["delivery", "exploitation"]},
    {"id": "3.2", "category": "3 Identity & toegang",
     "label": "Tier-0 isolatie / PAW / LogonWorkstations",
     "target": "LogonWorkstations gezet op 100% Tier-0",
     "bron": "CSV-upload: ad_tier0_export",
     "kill_chain_phases": ["exploitation", "installation", "actions"]},
    {"id": "3.3", "category": "3 Identity & toegang",
     "label": "Service-accounts eigen OU / gMSA of ≥25 char",
     "target": "0 svc in DA; 100% gMSA of pwlen≥25",
     "bron": "CSV-upload: ad_svc_accounts",
     "kill_chain_phases": ["exploitation", "installation"]},
    {"id": "3.4", "category": "3 Identity & toegang",
     "label": "LAPS op alle werkplekken + servers",
     "target": "100% heeft recente LAPS-timestamp",
     "bron": "CSV-upload: Intune-export",
     "kill_chain_phases": ["installation"]},
    {"id": "3.5", "category": "3 Identity & toegang",
     "label": "Inactieve accounts >90 dagen auto-disabled",
     "target": "0 inactief én niet-disabled",
     "bron": "Graph API",
     "kill_chain_phases": ["delivery", "exploitation"]},

    # Categorie 4 — Monitoring & logging
    {"id": "4.1", "category": "4 Monitoring & logging",
     "label": "FW flow-logs centraal, 90+ dagen retentie",
     "target": "Rows aanwezig in 24u venster",
     "bron": "Drops: siem_flow_export.csv",
     "kill_chain_phases": ["c2", "actions"]},
    {"id": "4.2", "category": "4 Monitoring & logging",
     "label": "Windows Event IDs op DC + Sysmon (Hartong/SOS)",
     "target": "Herkenbare Sysmon-config-fingerprint",
     "bron": "Drops: sysmon_config.xml",
     "kill_chain_phases": ["exploitation", "installation", "c2"]},
    {"id": "4.3", "category": "4 Monitoring & logging",
     "label": "Entra + AD sign-in logs + risky sign-ins",
     "target": "Risky-count zichtbaar, 0 uitstaand",
     "bron": "Graph API",
     "kill_chain_phases": ["delivery", "exploitation"]},
    {"id": "4.4", "category": "4 Monitoring & logging",
     "label": "Egress-logging met FQDN",
     "target": "FQDN-kolom gevuld in flow-sample",
     "bron": "Drops: fw_flow_sample.csv",
     "kill_chain_phases": ["c2", "actions"]},
    {"id": "4.5", "category": "4 Monitoring & logging",
     "label": "≥10 gemeente-specifieke use-case alerts",
     "target": "≥10 rules met tag 'gemeente'",
     "bron": "Drops: siem_rules_export.json",
     "kill_chain_phases": ["exploitation", "installation", "c2", "actions"]},
    {"id": "4.6", "category": "4 Monitoring & logging",
     "label": "East-west traffic zichtbaar (inter-VLAN)",
     "target": "≥1 flow tussen 2 interne subnets",
     "bron": "Drops: siem_flow_export.csv",
     "kill_chain_phases": ["installation", "c2"]},

    # Categorie 5 — Patching & vulnerability
    {"id": "5.1", "category": "5 Patching & vulnerability",
     "label": "Internet-facing critical <7d / high <30d",
     "target": "0 crit ouder dan 7d",
     "bron": "Drops: nessus_xml / qualys_xml",
     "kill_chain_phases": ["delivery", "exploitation"]},
    {"id": "5.2", "category": "5 Patching & vulnerability",
     "label": "VPN/edge/Exchange patch-SLA 48-72u",
     "target": "100% gepatched binnen 72u bij critical",
     "bron": "CSV-upload: edge_devices",
     "kill_chain_phases": ["delivery", "exploitation"]},
    {"id": "5.3", "category": "5 Patching & vulnerability",
     "label": "EOL-lijst met migratie-datum",
     "target": "100% heeft migration_date",
     "bron": "CSV-upload: eol_inventory",
     "kill_chain_phases": ["exploitation"]},
    {"id": "5.4", "category": "5 Patching & vulnerability",
     "label": "Wekelijkse externe scan, onbekende poort <72u",
     "target": "Scan <7d, 0 onbekende nieuwe poorten",
     "bron": "Drops: nmap_xml",
     "kill_chain_phases": ["recon"]},

    # Categorie 6 — Backup & recovery
    {"id": "6.1", "category": "6 Backup & recovery",
     "label": "3-2-1-1-0 immutable + 0 fouten",
     "target": "immutable=true, errors=0",
     "bron": "Drops: veeam/rubrik_report.csv",
     "kill_chain_phases": ["actions"]},
    {"id": "6.2", "category": "6 Backup & recovery",
     "label": "Backup in eigen security-domein (eigen AD+MFA)",
     "target": "prod_ad_trust=false",
     "bron": "CSV-upload: backup_ad_audit",
     "kill_chain_phases": ["actions"]},
    {"id": "6.3", "category": "6 Backup & recovery",
     "label": "Jaarlijkse restore-test kroonjuweel",
     "target": "Rapport <12 mnd met RTO/RPO",
     "bron": "Drops: report_pdf",
     "kill_chain_phases": ["actions"]},

    # Categorie 7 — Werkplek-hardening
    {"id": "7.1", "category": "7 Werkplek-hardening",
     "label": "App-allowlisting (WDAC/AppLocker)",
     "target": "EnforceMode actief",
     "bron": "Drops: wdac_policy.xml",
     "kill_chain_phases": ["exploitation", "installation"]},
    {"id": "7.2", "category": "7 Werkplek-hardening",
     "label": "Office-macros uit voor internet-bestanden (ASR)",
     "target": "100% werkplekken",
     "bron": "CSV-upload: Intune-export",
     "kill_chain_phases": ["delivery", "exploitation"]},
    {"id": "7.3", "category": "7 Werkplek-hardening",
     "label": "Geen lokale admin voor users",
     "target": "0 users in lokale Administrators",
     "bron": "CSV-upload: local_admins",
     "kill_chain_phases": ["exploitation", "installation"]},
    {"id": "7.4", "category": "7 Werkplek-hardening",
     "label": "USB-policy default block/read-only",
     "target": "usb_blocked_default=true op alle devices",
     "bron": "CSV-upload: intune_usb_policy",
     "kill_chain_phases": ["delivery", "installation"]},

    # Categorie 8 — AI-specifiek (feitelijk)
    {"id": "8.1", "category": "8 AI-specifiek (feitelijk)",
     "label": "Phishing-resistant MFA voor admins (FIDO2/WHfB)",
     "target": "100% FIDO2/WHfB onder admins",
     "bron": "Graph API",
     "kill_chain_phases": ["delivery", "exploitation"]},
    {"id": "8.2", "category": "8 AI-specifiek (feitelijk)",
     "label": "Behavior-detectie-alerts (≥3)",
     "target": "≥3 rules type=behavior",
     "bron": "Drops: siem_behavior_rules.json",
     "kill_chain_phases": ["exploitation", "installation", "c2", "actions"]},
    {"id": "8.3", "category": "8 AI-specifiek (feitelijk)",
     "label": "Tabletop-oefening 2×/jaar",
     "target": "Verslag <6 mnd met scenario+respons",
     "bron": "Drops: report_pdf",
     "kill_chain_phases": []},
    {"id": "8.4", "category": "8 AI-specifiek (feitelijk)",
     "label": "AI-egress policy + logging",
     "target": "category ai-tools actief én gelogd",
     "bron": "CSV-upload: fw_category",
     "kill_chain_phases": ["c2", "actions"]},

    # Categorie 9 — Governance
    {"id": "9.1", "category": "9 Governance",
     "label": "Maandelijkse KPI naar B&W",
     "target": "Rapport <1 mnd met patch+mfa+incidents",
     "bron": "Drops: report_pdf",
     "kill_chain_phases": []},
    {"id": "9.2", "category": "9 Governance",
     "label": "BIO 2.0 gap-analyse",
     "target": "Rapport <12 mnd met gap+aanbevelingen",
     "bron": "Drops: report_pdf",
     "kill_chain_phases": []},
    {"id": "9.3", "category": "9 Governance",
     "label": "Jaarlijkse externe pentest",
     "target": "Rapport <12 mnd met scope+findings+CVSS",
     "bron": "Drops: report_pdf",
     "kill_chain_phases": []},
]

# Backwards-compat alias
V0_1_ITEMS = ALL_ITEMS

# Elk item draagt het aanvalspad en chokepoint waar het bewijs voor is (diepte 2 van de keten
# aanvalspaden). De koppeling staat in paden_map.py, zodat er maar een plek is om bij te werken;
# hier komen alleen de velden op de items te staan. None betekent: dit item hoort bij geen pad.
from paden_map import koppel as _koppel

for _item in ALL_ITEMS:
    _pad, _cp = _koppel(_item["id"]) or (None, None)
    _item["pad"], _item["chokepoint"] = _pad, _cp
del _item, _pad, _cp


def label_for(checklist_id: str) -> str:
    for it in ALL_ITEMS:
        if it["id"] == checklist_id:
            return it["label"]
    return checklist_id


def target_for(checklist_id: str) -> str:
    for it in ALL_ITEMS:
        if it["id"] == checklist_id:
            return it["target"]
    return ""


def category_for(checklist_id: str) -> str:
    for it in ALL_ITEMS:
        if it["id"] == checklist_id:
            return it["category"]
    return ""


def phases_for(checklist_id: str) -> list[str]:
    for it in ALL_ITEMS:
        if it["id"] == checklist_id:
            return list(it.get("kill_chain_phases") or [])
    return []


def pad_for(checklist_id: str) -> str | None:
    """Het aanvalspad waar dit item bewijs voor levert, of None."""
    for it in ALL_ITEMS:
        if it["id"] == checklist_id:
            return it.get("pad")
    return None


def chokepoint_for(checklist_id: str) -> str | None:
    """Het chokepoint waar dit item bewijs voor levert, of None."""
    for it in ALL_ITEMS:
        if it["id"] == checklist_id:
            return it.get("chokepoint")
    return None


def seed_if_empty():
    """Zet initiële rijen in checklist_state als ze nog niet bestaan.

    Idempotent: overschrijft geen bestaande metingen. Seed-waarde is
    "geen bewijs" totdat een evidence-rij de state bijwerkt.
    """
    import db
    bestaand = {c["checklist_id"] for c in db.fetch_checklist()}
    for item in ALL_ITEMS:
        if item["id"] not in bestaand:
            db.set_checklist_state(
                item["id"],
                item["label"],
                measured_value="geen bewijs",
                target=item["target"],
                notes=f"Bron: {item['bron']}",
            )
