# Security Posture Tool

**Evidence-based security posture assessment — Defense in Depth**

> Not "do you have a firewall?" → checkbox
> But "here are your firewall logs" → the tool proves what your score actually is.

## Wat is dit?
Een open-source oplossing ontworpen om de daadwerkelijke technische beveiligingswerkelijkheid, in plaats van papieren compliance, inzichtelijk te maken. In navolging van het Defense in Depth principe werkt de tool per laag om de kwetsbaarheden te verifiëren door ruwe brondata te interpreteren. 

In plaats van handmatige invuloefeningen over het configuratiemanagement, koppelt deze infrastructuur zich aan logs en de output van open-source tools (zoals Nmap, Wazuh, OpenSCAP, Prowler, OSINT of BloodHound CE). Aan de hand van regels bepaalt het de maturity/veiligheidsstatus van organisatorische activa en rolt dit uit in een overzichtelijke gelaagde visuele radiografie (Perimeter → Netwerk → Endpoint → Applicatie → Data → Kroonjuwelen).

## Architectuur en Concept
Drie fundamentele mechanismes sturen deze applicatie:
1. **Connectors**: Onttrekken de "actuele werkelijkheid" middels firewall logs, Microsoft Graph API (voor Entra ID / MFA dekking) en ingeladen network scans.
2. **Definitie & Rule Engine**: Vertaalt specifieke log-entries en scan-vondsten naar geautomatiseerde scoring voor concrete controls (e.g. IAM, patching, segmentatie).  
3. **Hybride AI Security Analyst**: Een op context (van de verzamelde logs) werkend taalmodel waarmee je in natuurlijke taal kunt redeneren.
   - *"Welke diensten kunnen vanaf werkplekken bij het datacenter (Any/Any regels)?"*
   - *"Met onze huidige posture (assumed breach), hoe ver komt een aanvaller?"*

## Opbouw Repository
- `frontend/` - De interactieve D3.js cirkel/fan interface (D3 radar).
- `backend/` - APIs en processing componenten voor de logs (aankomend).
- `connectors/` - Integraties met o.a. Entra ID, Firewall log-parsers en netwerk scanners.
- `controls/` - YAML/JSON gedreven security control definities die door de verwerkingsengine als metrics worden geclassificeerd.
- `docs/` - Achterliggende onderzoek en architectuurdocumentatie inzake Defense in Depth.
