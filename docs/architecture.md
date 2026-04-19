# Architectuur — security-posture-tool

> **Status: vision-document (v1.0+).**
> Dit document beschrijft de architectuur waar we naartoe werken. Het is *niet* wat we vanaf dag 1 bouwen. De eerste release (v0.1) is een flat Python-script met Entra-pull, SQLite en een mini-webpagina — zie **`v0.1-mvp.md`** voor wat er daadwerkelijk gebouwd wordt. Architectuur hieronder groeit pas zichtbaar als de tool empirisch daadwerkelijk gebruikt wordt en knelpunten blijken.

*Versie 0.1 van dit document · 19 april 2026 · status: vision-concept, open voor review*

Dit document legt de architectuur van de `security-posture-tool` vast: welke componenten er zijn, hoe ze communiceren, en welke afspraken tussen modules hard zijn. Het is het anker voor implementatie en bijdragen *zodra daar aanleiding voor is* — niet de blueprint voor de allereerste release.

Begeleidende documenten in deze folder:
- `defense-in-depth-research.md` — theoretische onderbouwing en control-taxonomie
- `open-source-tool-selectie.md` — tool-selectiematrix per DiD-laag

---

## 1. Doel van de tool

Een operationele tool voor security-teams en interventieteams. Haalt data op uit de systemen waar ze zitten, trekt daar bevindingen uit die je *kunt* opvolgen, en laat zien waar je nu aan moet werken. Geen audit-wizard, geen vinkjes-verhaal — dat is wat `grc-platform` is.

Concreet:
- **14.000 losse scan-records** worden teruggebracht tot een handvol bruikbare bevindingen, gegroepeerd op onderwerp
- **Bij elke bevinding** is het onderliggende bewijs één klik weg (het CSV-bestand, de API-response, de log-regel)
- **Prioritering gebeurt automatisch** op basis van asset-kritiek, ernst, uitbuitbaarheid en recentheid — met uitlegbare rationale
- **Runbook-gestuurd werken** — de tool vertelt je hoe je data verzamelt voor systemen die geen API hebben

Drie fundamentele pijlers:

1. **Intake** — data binnenhalen, automatisch én via runbook-gestuurde handmatige oplevering
2. **Analysis** — regels (en waar nodig AI) die de data groeperen tot bevindingen per onderwerp
3. **Presentation** — actiegerichte top-N + verdedigingslaag-overzicht

De tool is ontworpen voor **soevereine, on-premise inzet**, conform de principes in `open-source-tool-selectie.md`.

### 1.1 Woordgebruik: "Control" versus "Check"

In de YAML-configuratie en de codebase gebruiken we de term **Control** — dat is de industriestandaard-term en aligneert met `defense-in-depth-research.md` en `open-source-tool-selectie.md`. Een Control is **geen beleidsstuk**, maar een geautomatiseerde test ("check of privileged accounts MFA hebben"). In de UI en in gebruikersgerichte teksten noemen we het **Check** of **Security Check** om die operationele aard te benadrukken en verwarring met compliance-controls uit grc-platform te voorkomen.

In dit architectuurdocument blijft de term Control dominant, omdat dit document het technische ontwerp beschrijft.

---

## 2. Architectuur op hoofdlijnen

```
┌─────────────────────────────────────────────────────────────┐
│                       Frontend (web)                        │
│   Dashboard · Findings-list · Finding-detail                │
│   Runbook-runner · Controls-overzicht · Instellingen        │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP/JSON
┌──────────────────────────────┴──────────────────────────────┐
│                      Backend (API)                          │
│                                                             │
│   Intake          Analysis           Presentation           │
│   ──────          ────────           ────────────           │
│   connectors/     rules/             prioritizer/           │
│   instructions/   ai_interpreter/    reporter/              │
│   normalizer/     aggregator/                               │
│                                                             │
│   ─────────────── gedeeld domein ─────────────────          │
│   Evidence · Observation · Finding · Control · Asset        │
└──────────────────────────────┬──────────────────────────────┘
                               │
                    ┌──────────┴──────────┐
                    │  Postgres + blob    │
                    └─────────────────────┘
```

**Fundamentele afspraak:** modules praten *uitsluitend* via gedeelde domeintabellen in Postgres. Geen directe cross-module function-calls. Intake schrijft `Observation`; Analysis leest `Observation` en schrijft `Finding`; Presentation leest `Finding`. Elk module los testbaar, los vervangbaar.

---

## 3. Domeinmodel

Vijf kernentiteiten vormen de lingua franca tussen alle modules.

### 3.1 Evidence
Het ruwe bewijsmateriaal: een log-export, een CSV van een scan, een JSON-dump van een API-call. Evidence is onveranderlijk — zodra opgeslagen, wordt het nooit gewijzigd. Integriteit wordt geborgd met SHA-256 hash bij upload en hercontrole bij elke uitlezing.

**Velden (logisch):**
```
evidence_id         uniek, bv. EVD-2026-00042
blob_ref            pointer naar file store
sha256              integriteitshash
mime_type
uploaded_at
uploaded_by         actor (human of connector)
runbook_ref         optioneel: als evidence via instruction-pijler kwam
```

### 3.2 Observation
Een bron-specifiek, ruw feit. Afgeleid uit één of meer Evidence-items door een connector of een normalizer. Een observation heeft geen prioriteit, geen oordeel.

```
observation_id
asset_ref           → Asset
evidence_refs       → [Evidence], veel-op-veel
observed_at         wanneer was het zo in de werkelijkheid
created_at          wanneer kwam het in het systeem
source_type         api_connector | human_input | script_upload | ai_normalizer
source_name         bv. "Entra ID Connector" of "PowerShell AD Script"
description         leesbare tekst: "Account admin_user heeft geen MFA"
ai_confidence       optioneel: alleen als source_type = ai_normalizer
```

**Ontwerpkeuze:** Observations worden *alleen* door Intake geproduceerd. Analysis en Presentation creëren nooit observations. Dat houdt de herkomst van feiten schoon.

**SourceType-betekenis:**
- `api_connector` — automatische pull door een connector (`entra_id`, `nmap`, …)
- `script_upload` — uitvoer van een runbook, geüpload door een operator
- `human_input` — analist voert direct een observatie in via de UI
- `ai_normalizer` — AI-component binnen Intake extraheert facts uit unstructured evidence (bv. ruwe config-dumps). Blijft Intake — Analysis produceert nooit Observations.

### 3.3 Finding
Een onderwerp-gecentreerde aggregatie van observations, gekoppeld aan een Control. Eén Finding kan tientallen of honderden Observations omvatten, mogelijk uit verschillende bronnen. Omgekeerd kan één Observation aan meerdere Findings bijdragen (veel-op-veel).

```
finding_id
control_id          → Control (YAML-def)
control_version     semver, vastgeklikt op moment van scoren
did_layer           afgeleid van control
title               bv. "Privileged accounts missen phishing-resistente MFA"
severity            stable: intrinsieke ernst (info/low/medium/high/critical)
status              draft | pending_review | published | mitigated | dismissed
observation_refs    → [Observation], veel-op-veel

# AI-gegenereerd, met provenance
ai_business_impact  {text, model, prompt_id, prompt_version, generated_at, input_hash}
ai_recommended_action  idem

# Output van Prioritizer, apart van severity
priority_score      float, herberekenbaar
priority_rationale  tekst, één-regel-uitleg

# Lifecycle
created_at, created_by
published_at, published_by
last_verified_at
```

**Ontwerpkeuze — severity ≠ priority:** severity is een *eigenschap van de vondst zelf* (stabiel). Priority is *contextuele urgentie nu, voor deze organisatie* (herberekenbaar). Twee velden, twee verantwoordelijken. De Prioritizer muteert nooit de severity.

**Ontwerpkeuze — manual_assertion:** een Finding mag bestaan zonder Observations, mits het veld `manual_assertion_motivation` is ingevuld. Wordt in de UI expliciet gemarkeerd als niet-data-gedreven.

### 3.4 Control
Een testbare definitie van een beveiligingsmaatregel, vastgelegd als YAML in `controls/`. Elke control:
- Heeft een stabiele ID (bv. `IAM-MFA-01`)
- Hoort bij één DiD-laag
- Bevat N rules die observations → findings vertalen
- Verwijst naar M runbooks (instructions) die evidence opleveren
- Heeft optionele mapping naar externe frameworks

```yaml
# voorbeeld: controls/iam/IAM-MFA-01.yaml
id: IAM-MFA-01
version: 1.0.0
did_layer: iam
title: "MFA verplicht voor privileged accounts"
description: |
  Alle accounts met verhoogde rechten (admin, operator, functioneel beheerder)
  moeten phishing-resistente MFA geconfigureerd hebben.
verification:
  evidence: "Entra ID sign-in logs + conditional access policies"
  threshold: "100% dekking"
connectors:
  - entra_id
runbooks:
  - IAM-MFA-01-ad-admin-query
frameworks:                 # optioneel, future-proof
  cis: ["6.3", "6.4"]
  iso27001: ["A.8.5"]
  nist_csf: ["PR.AA-03"]
rules:
  - if: "observation.fact == 'account_without_mfa' AND asset.type == 'privileged_account'"
    then:
      severity: critical
      title: "Privileged account zonder MFA"
```

**Control-versioning:** semver. Findings bewaren de `control_version` waarmee ze gescoord zijn — essentieel voor audit ("volgens welke definitie scoorden we op 20 april?").

**Implementatienote — YAML als bron van waarheid + DB-cache:** de YAML-bestanden in `controls/` en `overlay/controls/` zijn de enige bron van waarheid voor control-definities. Bij app-startup en bij elke `/reload-rules`-aanroep worden ze ingelezen en gespiegeld naar een read-only cache-tabel in Postgres (bv. `controls_cache`). Die cache maakt relationele joins mogelijk (bv. "aantal findings per DiD-laag" in één query) zonder dat YAML runtime hoeft te worden geparsed. De cache is dispos­able — hij wordt bij elke reload overschreven.

### 3.5 Asset
Het object waar een observation over gaat.

```
asset_id            bv. "ad://example.local/admin_user"
type                user | host | network_segment | application | data_store | service
criticality         1-5 (schaal met definitie per niveau)
owner               optioneel: verantwoordelijk team of persoon
tags                vrije tags voor groepering
```

**Asset als eigen entity, niet string:** zonder gestructureerde asset-eigenschappen is de priority-formule (criticaliteit × severity × …) niet uit te rekenen. Voor integratie met bestaande CMDB's komt een `cmdb` connector later.

### 3.6 Relaties — diagram

```
 Evidence  ◄─── opgeslagen, integriteitsgehasht
     │
     │ 1..N
     ▼
 Observation ────────►  Asset
     │                   (gestructureerd)
     │ N..N
     ▼
  Finding ───────────►  Control (YAML, versioned)
     │                   │
     │                   └──► DiD-laag (1 van 7)
     │
     ├──► priority_score (van Prioritizer)
     └──► status (lifecycle)
```

---

## 4. Defense-in-Depth-lagen

Zeven lagen, conform `defense-in-depth-research.md`:

1. **Perimeter** — VPN, NGFW, IPS, DDoS-mitigatie, DNS-filtering
2. **Netwerk & Segmentatie** — segmentatie, NAC, SMB-signing, ZTNA
3. **Endpoint** — EDR/XDR, patching, applicatiewhitelisting, LAPS
4. **IAM** — MFA, PAM, JIT, sessiemonitoring
5. **Applicatie & Data** — WAF, API-gateway, encryptie, DLP, immutable backups
6. **Monitoring & IR** — SIEM, UEBA, SOAR
7. **EMSEC** — zonering, TEMPEST, kabelscheiding, lijnfilters

Vast in MVP, extensible in v2. De frontend-visualisatie (D3-fan) mapt direct op deze zeven.

**EMSEC en de instruction-pijler:** laag 7 is fysiek en facility-gedreven; evidence komt niet uit API's. Dit is precies waarom de instruction-pijler bestaat — een runbook beschrijft wat een operator moet inspecteren en hoe hij het resultaat terugbrengt.

---

## 5. Modules

### 5.1 Intake

Meerdere inkomende paden, één uitgang: alle data eindigt als Observation-rijen in de database.

**Connectors** — automated pull. Elke connector implementeert een abstract interface:
```
class BaseConnector:
    name: str
    def fetch() -> list[Observation]
```

MVP-connectors (naamconventie conform `defense-in-depth-research.md`):
- `entra_id` — Microsoft Graph API voor MFA-status, privileged accounts, sign-ins
- `nmap` — XML-export parser voor service discovery en open ports
- `vuln_scanner` — XML/JSON van OpenVAS / Greenbone

Externe scanners kunnen ook rechtstreeks posten naar een HTTP-callback endpoint — "bring your own scanner" zonder connector te hoeven schrijven.

**Instructions** — human-in-the-loop voor alles wat niet (of niet nu) geautomatiseerd is: legacy systemen zonder API, on-prem queries, facility-audits, observaties in gesprek. Elk runbook is een Markdown-bestand met YAML-frontmatter:

```markdown
---
id: IAM-MFA-01-ad-admin-query
version: 1.0.0
title: "MFA-status uitlezen on-prem AD"
control: IAM-MFA-01
required_privileges: "Domain Admin read-only"
expected_output: csv
normalizer: schema_driven
column_mapping:
  samAccountName: asset_ref
  mfaEnabled: fact_mfa
---

## Doel
Bepalen welke privileged accounts in AD geen MFA hebben.

## Uit te voeren
Draai op een DC:
```powershell
Get-ADUser -Filter {AdminCount -eq 1} -Properties msDS-...
```

## Output uploaden
Upload de resulterende CSV via de web-UI onder dit runbook.
```

**Normalizer** — schema-gedreven (kolom → domeinveld mapping via YAML-frontmatter) voor het merendeel. Voor complexe gevallen mag een `runbooks/<id>/normalizer.py` bestand bestaan als escape-hatch.

**Deduplicatie** van observations via idempotency-key: `hash(source_name, asset_ref, fact_type, observed_at)`. Zonder dedup explodeert de tabel.

**Asset-upsert** — in MVP is er nog geen CMDB-connector die Assets pre-populeert. Elke connector en normalizer voert daarom een *create-if-not-exists* uit op Asset bij aanlevering van een observation: bestaat de asset nog niet, dan wordt hij aangemaakt met default `criticality=3` (middelschaal) en `type` afgeleid uit de context (bv. `user` bij Entra-accounts). Analisten kunnen criticaliteit en eigenaar achteraf bijstellen in de UI. Zo faalt de priority-formule nooit op een missing integer, en hoeft niemand handmatig assets te registreren vóór een scan.

**Async verwerking** — uploads worden via een taakwachtrij verwerkt, niet synchroon. Operator krijgt direct bevestiging; resultaat verschijnt als observations zodra verwerking klaar is.

### 5.2 Analysis

Leest Observations, schrijft Findings. Drie sub-componenten.

**Rule engine** — primaire, deterministische weg. YAML-regels binnen controls (zie §3.4). Eén regel = één match-expressie over observations + resulterend finding-template. Regels produceren **alleen** Findings, geen Observations (die principe-lijn houdt herkomst schoon).

- Format: YAML met simpele match-DSL (geen Rego, geen losse Python — niet-ontwikkelaars moeten controls kunnen auteuren)
- Regels horen bij een Control (geen losstaande rules; weesdata voorkomen)
- Hot-reload via expliciet `/reload-rules` endpoint (geen filesystem-watcher; voorspelbaarheid wint)
- Unit-test-framework: per rule input-fixture → verwacht finding

**AI-interpreter** — fallback voor gevallen waar geen regel past: unstructured configs, vrije tekst, onbekende patronen. De AI leest Evidence + gerelateerde Observations en stelt een Finding voor. AI-gegenereerde Findings starten altijd in status `pending_review` en worden pas `published` na menselijke OK. De AI-interpreter creëert géén Observations — dat blijft de exclusieve verantwoordelijkheid van Intake.

**Aggregator** — binder tussen observations en findings. Voor elke control-scope evalueert de aggregator de bijbehorende rules op de observation-set en muteert/creëert Findings. Rules eerst, AI als fallback.

**Aggregator-trigger:** event-gedreven én scheduled. Elke voltooide Intake-run (connector-pull of runbook-upload) publiceert een event op de task-queue dat de aggregator voor de geraakte controls activeert. Daarnaast draait een periodiek schema (default elk uur) dat de volledige aggregatie heruitvoert — als vangnet voor gemiste events en om recentheid-gevoelige findings (zie priority-formule) actueel te houden.

### 5.3 Presentation

Leest Findings, toont en rangschikt.

**Prioritizer** — hybride. Transparante baseline-formule:

```
priority_score = w1·asset_criticality × w2·severity × w3·exploitability × w4·recency
```

Gewichten `w1..w4` zijn configureerbaar in settings (globaal in MVP). AI voegt *na* de formule een `priority_rationale` toe en mag een rangorde maximaal ±1 positie corrigeren met motivatie. Dit houdt de rangschikking uitlegbaar en audit-stand: elke positie heeft een traceerbare onderbouwing.

**Dashboard** — D3 DiD-fan (zeven segmenten) + findings-list naast elkaar. Fan voor de snelle posture-blik, lijst voor de analist. Filters op laag, severity, status, asset-type, datum.

**Reporter** — export van findings (JSON, CSV, PDF). Reporting-logica leeft hier; geen hard gecoupled aan dashboard-rendering.

---

## 6. Tech stack

Architectuur-laag keuzes (contractueel):

| Laag | Keuze | Waarom |
|---|---|---|
| Backend | Python-API (FastAPI-familie) | Aligneert met grc-platform, mature ecosysteem voor security-tooling |
| Frontend | Next.js (moderne React) | Aligneert met grc-platform, ondersteunt bestaande D3-fan |
| Database | PostgreSQL 16+ | Relationeel met goede JSONB-ondersteuning voor flexibele evidence-metadata |
| Blob-store | Lokale disk of S3-compatible (MinIO) | Configureerbaar; disk voor dev, MinIO voor productie |
| Task queue | Async job-runner (keuze bij implementatie) | Celery/RQ/APScheduler — contractueel abstracted achter een `enqueue(task)` interface |
| LLM | Ollama (lokaal, default) of externe API (Anthropic/Azure EU, opt-in) | Soevereiniteit first, met expliciete configuratie-keuze |

**Agnostisch gehouden** (keuzes bij implementatie-tijd):
- ORM (SQLAlchemy, SQLModel, enz.)
- Test-framework setup
- Specifieke LLM-wrapper library
- Specifieke blob-SDK

---

## 7. Directory-layout

```
security-posture-tool/
├── backend/
│   ├── domain/              # Evidence, Observation, Finding, Control, Asset schemas
│   ├── intake/
│   │   ├── connectors/      # entra_id, nmap, vuln_scanner, ...
│   │   ├── instructions/    # runbook loader + upload endpoint
│   │   └── normalizer/      # schema-driven + escape-hatch
│   ├── analysis/
│   │   ├── rules/           # rule-engine + DSL parser
│   │   ├── ai_interpreter/  # LLM-call, provenance, redactie
│   │   └── aggregator/
│   ├── presentation/
│   │   ├── prioritizer/     # baseline-formule + AI rationale
│   │   └── reporter/        # export (JSON, CSV, PDF)
│   └── storage/             # Postgres repo + blob-store abstractie
│
├── frontend/                # Next.js + D3 DiD-fan
│
├── controls/                # YAML control-definities
│   ├── perimeter/
│   ├── network/
│   ├── endpoint/
│   ├── iam/
│   ├── application_data/
│   ├── monitoring_ir/
│   ├── emsec/
│   └── redaction/           # PII/hostname redactie-regels
│
├── runbooks/                # bundled instruction-runbooks (Markdown + YAML)
│
├── overlay/                 # lokale uitbreiding — overlay wint bij naam-collisie
│   ├── controls/
│   └── runbooks/
│
├── ai/
│   └── prompts/             # YAML, versioned
│
├── docs/
│   ├── architecture.md      # dit document
│   ├── defense-in-depth-research.md
│   ├── open-source-tool-selectie.md
│   ├── getting-started.md
│   └── extending.md
│
├── docker-compose.yml
├── ARCHITECTURE.md          # korte samenvatting + link naar docs/architecture.md
├── README.md
├── ROADMAP.md
└── LICENSE                  # EUPL-1.2
```

---

## 8. AI — plaatsing en governance

### 8.1 Waar AI zit
- **Rule engine** = deterministisch, primair. Zoveel mogelijk via rules.
- **AI-interpreter** = fallback waar rules niet werken (unstructured, onbekende patronen).
- **Prioritizer** = AI voegt rationale en kleine rang-correctie toe *na* de baseline-formule.

### 8.2 Provider en soevereiniteit
Twee modi, configureerbaar via `llm_provider`:
- `ollama` (default) — lokaal LLM, data verlaat de omgeving niet
- `external` — Anthropic of Azure EU; expliciete opt-in met waarschuwing

### 8.3 Redactie vóór externe AI-call
Wanneer `llm_provider=external`:
- **PII** (namen, e-mails) → pseudoniemen; ook bij lokale provider toegepast als hygiëne
- **Hostnames / FQDN's** → stabiele pseudoniemen (`DC01.example.local` → `host-42`) binnen één analyse-sessie, zodat AI relaties behoudt ("drie observations over host-42")
- **Role-tags behouden** — `host-42` krijgt `role: domain_controller` meeliftend, zodat de AI functionele context heeft
- **Mapping-tabel blijft lokaal** — bij terugpresentatie aan de mens worden pseudoniemen vervangen door echte namen

Redactie-regels als YAML onder `controls/redaction/`, auditeerbaar, uitbreidbaar.

### 8.4 Output-discipline
- Beslissingen: structured output (JSON-schema-forced)
- Uitleg: vrije tekst toegestaan
- Confidence-score onder 0.6 → flag voor extra review (niet reject)

### 8.5 Menselijke review
AI-gegenereerde findings starten in `pending_review`. Publicatie vereist menselijke OK. Dashboard toont default `published`; toggle voor `pending`.

### 8.6 Provenance
Elk AI-gegenereerd veld wordt opgeslagen met `{text, model, prompt_id, prompt_version, generated_at, input_hash}`. Reproduceerbaarheid en audit.

### 8.7 Prompt-governance
Prompts leven als YAML onder `ai/prompts/`, versioned. Wijzigingen via PR — zelfde regime als controls.

### 8.8 Agentic AI
**Niet in MVP.** Pure LLM-call, mens triggert. Agentic (AI kiest runbooks, roept connectors) pas overwegen in v3, na uitgebreide audit-voorzieningen.

---

## 9. Scope en deployment

### 9.1 MVP-uitgangspunten
- **Geen login** — standalone tool, start-and-use
- **Geen multi-tenancy** — één install, één data-namespace
- **On-premise** — docker-compose start-and-use
- **Modulair** — contractueel afgebakend via §2

Authenticatie, rol-model en scope/tenancy zijn bewust uit MVP gelaten. Ze zijn toe te voegen in latere versies zonder het domeinmodel te breken (scope_id wordt dan een nullable veld met default).

### 9.2 Deployment
- MVP: docker-compose
- OS: Ubuntu/Debian + RHEL
- Observability: Prometheus-metrics endpoint + structured JSON logs
- Secrets: `.env`-file in MVP; Vault-hook voorbereid
- Backup: begeleidend `backup.sh` script (pg_dump + blob-sync); geen ingebouwde backup-manager

---

## 10. Uitbreidbaarheid en overlays

De tool is ontworpen voor **lokale uitbreiding zonder fork**. Twee mechanismen:

### 10.1 Overlay-directories
`overlay/controls/` en `overlay/runbooks/` worden bovenop de bundled defaults geladen. Naam-collisie: overlay wint. Zo kan een organisatie eigen controls toevoegen of bundled controls vervangen zonder de tool-code te raken.

### 10.2 Bring-your-own-scanner
Externe tools kunnen observations posten via een HTTP-callback endpoint. Je hoeft dus niet per se een Python-connector te schrijven — elk script dat JSON kan POSTen werkt.

### 10.3 Community-overlays
Op termijn mogelijk als apart repo (`security-posture-controls-community`). In MVP blijven alle controls in de main repo om schaalkosten te vermijden.

---

## 11. MVP — scope en Definition of Done

### 11.1 MVP-scope
End-to-end werkend pad: **1 connector + 1 runbook + 1 control + 1 rule → findings in de fan.**

Concreet:
- Connector: `entra_id` met basale MFA-status query
- Runbook: `IAM-MFA-01-ad-admin-query` voor on-prem AD
- Control: `IAM-MFA-01` met één rule ("account_without_mfa op privileged_account → critical finding")
- UI: D3-fan met zeven segmenten, findings-list, finding-detail met evidence-drilldown

### 11.2 DoD per module

**Intake**
- Observation-CRUD via API
- `entra_id` connector werkend
- Eén runbook via UI uitvoerbaar + upload-flow werkend
- Evidence-upload met SHA-256 integriteitscontrole
- Deduplicatie werkend
- Audit-log van schrijf-acties

**Analysis**
- YAML-control geladen vanuit `controls/`
- Rule matcht observation-patroon → Finding aangemaakt
- Status `pending_review` voor AI-findings, `published` voor rule-findings
- AI-provenance vastgelegd per AI-gegenereerd veld
- Menselijke review-publishen via UI werkend

**Presentation**
- D3-fan toont `published` findings per DiD-laag
- Findings-list met filter/zoek/sort
- Finding-detail met observation-drilldown + evidence-link (download met sha-check)
- Priority-formule werkend + rationale zichtbaar
- Export naar JSON + CSV + PDF

**Cross-cutting**
- `docker compose up` start werkende tool
- Health-check endpoints
- Prometheus metrics-endpoint
- NL in UI, EN in code
- `docs/`: `architecture.md` (dit), `getting-started.md`, `extending.md`

---

## 12. Wat later komt (niet MVP)

- Authenticatie (OIDC via Authentik) en rol-model
- Multi-scope / multi-tenancy
- Extra connectors: firewall-logs, BloodHound, SIEM, EDR-API
- Framework-mapping vullen (CIS / ISO27001 / NIST CSF)
- Agentic AI-modus
- Websocket-gedreven live updates
- Webhook-out voor SOAR-integratie
- Helm-chart voor Kubernetes
- Koppeling met grc-platform (export findings → risicoregister)
- CMDB-connectoren voor asset-metadata
- Community-overlay-repo voor controls en runbooks
- Data-retentie en garbage collection: archivering of verwijdering van verouderde evidence en observations, naast de reeds genoemde AVG-retentie (7 jaar default). Bij frequent ingeplande scans groeit de opslag snel; een retention-job die op basis van beleid evidence archiveert naar koude opslag of verwijdert, is wenselijk.

---

## 13. Licentie en governance

- **Licentie:** EUPL-1.2 (Europese publieke licentie, passend bij publieke sector)
- **Bijdragen:** public PRs welkom, `CONTRIBUTING.md` en `CODEOWNERS` aanwezig
- **Versiebeheer:** Semver
- **Releases:** ad-hoc in MVP-fase; tweewekelijks vanaf v1.0
- **Taal:** Nederlands voor documentatie en UI; Engels in code-identifiers

---

*Einde architectuurbeschrijving v0.1. Feedback welkom via issue of PR.*
