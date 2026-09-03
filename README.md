# security-posture-tool

> **Gearchiveerd op 03-09-2026. Opgegaan in [aanvalspaden/meting](https://security-commons-nl.github.io/aanvalspaden/meting/).**
>
> De 37 checklistitems, de 27 connectors en hun drempels zijn overgenomen op tag `v0-applicatie` en
> staan nu als data in [`meting/regels.json`](https://github.com/security-commons-nl/aanvalspaden/blob/main/meting/regels.json),
> met een referentie in `meting/reken.py` en dezelfde toetsen in de browser. Dit was een applicatie
> met een installatie en een eigen kopie van `paden.json`; de commons publiceert instrumenten, en de
> meting is er een: een pagina die je opent, die je exports in je eigen browser leest.
>
> Deze repo blijft leesbaar staan als herkomst. De tag `v0-applicatie` is bevroren: `meting/overname.py`
> leest hem, en wie hem verplaatst, verandert de bron onder het instrument vandaan.

Evidence-based security posture registratie voor interventieteams, en diepte 2 van de aanvalspaden-keten.

Status: prototype. Werkt en heeft groene tests; geen product.

**Operationele, evidence-based security posture registratie voor interventieteams.**

> Geen audit-wizards ("Heb je een firewall? [x] Ja").
> Wel operationeel inzicht ("Hier is bewijs van NMAP en Entra; uit 14.000 logs blijken nú 3 gapende gaten in je Perimeter en IAM.")

[![Bijdragen](https://img.shields.io/badge/📝_Bijdragen-238636?style=for-the-badge)](../../issues/new/choose)&nbsp;&nbsp;&nbsp;&nbsp;[![Meepraten](https://img.shields.io/badge/💬_Meepraten-0969da?style=for-the-badge)](../../discussions)

👉 **Iets delen, feedback geven of een vraag stellen?** Klik op een van de knoppen hierboven - geen Git-ervaring nodig. Zie [CONTRIBUTING.md](CONTRIBUTING.md) voor meer opties.

## Voor wie

Blue teams en interventieteams.

## Snel starten

Beginnen

## Bijdragen

Zie de [CONTRIBUTING](https://github.com/security-commons-nl/.github/blob/main/CONTRIBUTING.md) van de organisatie: daar staat per project een formulier, ook zonder Git-ervaring.

Zie [CONTRIBUTING.md](CONTRIBUTING.md) voor hoe je iets kan delen, melden of verbeteren - met of zonder Git-ervaring.

## Licentie

EUPL-1.2, zie [LICENSE](LICENSE).

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

## Beginnen - v0.1 MVP
De hierboven beschreven pijlers zijn de *horizon*, niet de startlijn. Wat er nu draait, staat in `v0.1/`: een FastAPI-webpagina op SQLite, een Entra-connector en ruim twintig parsers voor exports die je al hebt (nmap, Nessus, Fortigate, Palo Alto, GPO, LAPS, SIEM-regels, back-uprapporten), met een testsuite van 127 tests. Geen AI, geen D3, geen YAML-framework: eerst waarde, dan complexiteit.

**Let op de mappen:** `backend/`, `frontend/` en `controls/` hierboven beschrijven de doelarchitectuur en zijn nog leeg. Alles wat werkt, zit in `v0.1/`.

- **Scope, datamodel, acceptatie-criteria:** `docs/v0.1-mvp.md`
- **Werkende code:** `v0.1/` - zie de README daarin om lokaal te draaien
- **Meet-subset:** vijf items uit Week 1 van een cyber-hygiene-checklist voor gemeenten (3.1 MFA, 3.4 LAPS, 3.5 inactieve accounts, 7.2 ASR, 1.1 kroonjuwelen)

De volwassen architectuur in `docs/architecture.md` en `docs/overview.html` komt stapsgewijs, op basis van werkelijk gebruik.

## Relatie met Bestuur & Compliance
Beleid, risicomanagement en bestuurlijke compliance-rapportage horen in het managementsysteem van de eigen organisatie; deze tool levert daar bevindingen voor aan en is bedoeld voor *handelen* in de operatie.
