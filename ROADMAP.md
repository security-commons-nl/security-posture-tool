# ROADMAP

## Fase 1 — Architectuur & MVP (Nu bezig)
- [x] Initialisatie Defense in Depth (DiD) lagen diagram visualisatiestructuur.
- [x] Uitwerking evidence-based theorie (`docs/defense-in-depth-research.md`).
- [x] Architectuur vastgelegd en domeinmodel afgebakend (`Evidence → Observation → Finding`).
- [x] Dashboard UI / Mockup iteratie op de actiegerichte weergave, ontdaan van audit-termen.
- [ ] Backend setup: Postgres migraties en Object Models.
- [ ] Implementatie Intake pijler: base connector abstractie, runbook-loader, en bewijs upload flow.

## Fase 2 — Data Engine (Q3 2026)
- [ ] **Analysis Engine**: Verwerking van Observations naar Findings op basis van de YAML-checks in `controls/`. 
- [ ] **Eerste Connectors**: `entra_id` (MFA/LAPS API status) en `nmap` (XML parser).
- [ ] **Automated Prioritization**: Opleveren van de dynamische herberekenbare formule (Criticality x Severity x Exploitability).

## Fase 3 — AI & Integratie (Q4 2026)
- [ ] **AI-Interpreter**: Opzetten van de AI fallback module. Schakelt LLM *(Ollama lokaal of Azure cloud)* in om ongestructureerd bewijs te analyseren. Altijd icm een menselijke "Pending Review" poort om inzetbaar te zijn binnen soevereine standaarden.
- [ ] Real-time updates (Websockets / Event-bus) richting de Frontend fan.
- [ ] Webhook outbound API ten behoeve van SOAR en ticketing flows.
- [ ] CMDB-connector voor de geautomatiseerde import van asset criticaliteit in het scoremodel.
