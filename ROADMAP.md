# ROADMAP

## Fase 1 — Fundament en UI Concept (Nu bezig)
- [x] Initialisatie Defense in Depth (DiD) lagen diagram in D3.js.
- [x] Uitwerking evidence-based control model theorie (docs/defense-in-depth-research.md).
- [x] Demo UI framework met dummy scores gebaseerd op realistische bedreigingspatronen.
- [ ] Implementatie backend setup en het rule engine raamwerk (Control → Connector → Regel → Bewijs).

## Fase 2 — Eerste Live Connectors (Q3 2026)
- [ ] **Netwerk Scan Connector**: Analyseren van inkomende NMAP exports (service discovery, open ports, legacy systemen).
- [ ] **Identity Connector**: Integratie met Entra ID via Graph API voor het bevragen van MFA-dekking, LAPS aanwezigheid en de hoeveelheid permanently-elevated accounts zoals Domain Admins.
- [ ] **AI-Chat interface (Hybride)**: Opzetten van een RAG-achtige structuur of context injector voor de actieve "AI Security Analyst". Ervoor zorgen dat brondata alleen voor context wordt benut en niet op het internet wordt geworpen ongefilterd.

## Fase 3 — Uitbreiding & Volwassenheid (Q4 2026)
- [ ] **Firewall & Netwerk Connectors**: Evaluatie van "any/any" configuraties om laterale network movement direct te scoren en risico op te bouwen.
- [ ] Opschakeling naar het scannen van OT systemen en ingebouwde connectiviteit met andere third-party analysetools (BloodHound CE routes, Wazuh endpoint agent output, OpenSCAP).
- [ ] Rapportage generator (bestuurlijke export modus) voor besluitvorming, waardoor CISO risico's adequaat bij beslissers terecht komen als bewijsmateriaal in plaats van themazakjes.
