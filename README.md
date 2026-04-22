# Security Posture Tool

**Operationele, evidence-based security posture registratie voor interventieteams.**

> Geen audit-wizards ("Heb je een firewall? [x] Ja").
> Wel operationeel inzicht ("Hier is bewijs van NMAP en Entra; uit 14.000 logs blijken nú 3 gapende gaten in je Perimeter en IAM.")


[![Bijdragen](https://img.shields.io/badge/📝_Open_een_bericht-238636?style=for-the-badge)](../../issues/new/choose)&nbsp;&nbsp;&nbsp;&nbsp;[![Discussions](https://img.shields.io/badge/💬_Meepraten_in_discussions-0969da?style=for-the-badge)](../../discussions)

👉 **Iets delen, feedback geven of een vraag stellen?** Klik op een van de knoppen hierboven — geen Git-ervaring nodig. Zie [CONTRIBUTING.md](CONTRIBUTING.md) voor meer opties.

## Wat is dit?
Een open-source operationele applicatie ontworpen voor het blauwe team of interventieteams die snel tot de kern moeten komen. Waar trajecten zoals BIO, ISO of NIS2 vaak leiden tot theoretische compliance, maakt deze tool de *daadwerkelijke* technische werkelijkheid inzichtelijk per verdedigingslaag (Defense-in-Depth).

Drie fundamentele pijlers:
1. **Intake**: Haalt feiten (Observations) op via API connectors (Entra ID, Nessus) óf mens-gedreven runbooks (voert script-commando's uit op on-prem systemen). Elk feit is onlosmakelijk gekoppeld aan onveranderlijk bewijs (Evidence).
2. **Analysis**: Groepeert duizenden losse scan-records met behulp van autonome regels (en optioneel AI-interpretatie) tot een klein dashboard van bruikbare bevindingen (Findings).
3. **Presentation**: Toont een actiegerichte Findings-list voorzien van een dynamische Priority Score gericht op de operator, gevisualiseerd op een 7-laags Defense-in-Depth model.

## Opbouw Repository
- `backend/` - Intake, Analysis en Prioriterings-engine (Python).
- `frontend/` - Het operationele dashboard gericht op security analisten (Next.js/React).
- `controls/` - YAML configuraties ("Checks") die bepalen hoe verzamelde feiten moeten worden beoordeeld.
- `docs/` - Architectuur blauwdruk, domeinmodel en design.
- `runbooks/` - Markdown gedreven documenten die teams stap-voor-stap vertellen hoe ze lokaal data moeten winnen.

## Beginnen — v0.1 MVP

De hierboven beschreven pijlers zijn de *horizon*, niet de startlijn. Om direct met data verzamelen aan de slag te kunnen, bevat de repo een **v0.1**-skelet: één Entra-connector, SQLite, mini FastAPI-webpagina, CSV-upload voor handmatige data. Geen AI, geen D3-fan, geen YAML-framework — eerst waarde, dan complexiteit.

- **Scope, datamodel, acceptatie-criteria:** `docs/v0.1-mvp.md`
- **Code-skelet:** `v0.1/` — zie de README daarin om lokaal te draaien
- **Meet-subset:** vijf items uit Week 1 van een cyber-hygiene-checklist voor gemeenten (3.1 MFA, 3.4 LAPS, 3.5 inactieve accounts, 7.2 ASR, 1.1 kroonjuwelen)

De volwassen architectuur in `docs/architecture.md` en `docs/overview.html` komt stapsgewijs, op basis van werkelijk gebruik.

## Relatie met Bestuur & Compliance
Voor beleid, risicomanagement en bestuurlijke compliance-rapportage is nadrukkelijk het afzonderlijke `grc-platform` bedoeld. Deze tool is bedoeld voor *handelen* in de operatie.

## Bijdragen

Zie [CONTRIBUTING.md](CONTRIBUTING.md) voor hoe je iets kan delen, melden of verbeteren — met of zonder Git-ervaring.
