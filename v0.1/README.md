# security-posture-tool — v0.1 MVP

**Status:** skelet, klaar om in te vullen tijdens de eerste werksessie.

Minimale tool die data uit Entra haalt, CSV-upload accepteert, en meetwaarden toont tegen een subset van Week 1-items uit de cyber-hygiene-checklist.

Zie `docs/v0.1-mvp.md` (één niveau hoger) voor de scope, datamodel en acceptatie-criteria.

## Lokaal draaien

### 1. Python-omgeving

```bash
cd v0.1
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Entra app-registration

In de Azure-tenant van de organisatie een app-registration aanmaken met de volgende Microsoft Graph *application* permissions (read-only):

- `User.Read.All`
- `Directory.Read.All`
- `AuditLog.Read.All`
- `Policy.Read.All`
- `DeviceManagementConfiguration.Read.All` (alleen als Intune-policies uitgelezen worden)

Na "Grant admin consent" noteer: `Tenant ID`, `Client ID`, en genereer een `Client Secret`.

### 3. Environment

```bash
cp .env.example .env
# Vul in: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
```

### 4. Database initialiseren

```bash
python db.py init
```

Dit maakt `posture.sqlite` aan met de tabellen uit `docs/v0.1-mvp.md`.

### 5. Starten

```bash
uvicorn app:app --reload --port 8000
```

Open <http://localhost:8000>.

## Wat de UI toont

- **Overzicht** — status per Week 1-checklist-item (3.1, 3.4, 3.5, 7.2, 1.1)
- **MFA** — lijst admins / privileged accounts met MFA-status
- **Inactief** — accounts zonder sign-in in de afgelopen 90 dagen
- **Kroonjuwelen** — tabel + CSV-upload
- **Checklist** — voortgang + export

## Data verversen

Klik op de knop **Refresh Entra** op de overzichtspagina, of:

```bash
python entra.py refresh
```

Dit pullt alle relevante data en overschrijft de Entra-bron-tabellen in SQLite. De kroonjuwelen- en handmatige-upload-tabellen blijven onaangeraakt.

## Wat werkt er in dit skelet, en wat nog niet

- Dataflow, routes, templates, DB-schema: **klaar**, draait out-of-the-box met dummy data
- Graph API-calls in `entra.py`: **TODO-markers** — invullen tijdens eerste werksessie
- Checklist-mappings in `checklist.py`: structuur klaar, meetlogica stubs

Zoek op `# TODO` voor alle invulpunten.

## Geen compliance-tool

Dit is geen audit-wizard en geen GRC-systeem. Dat is `grc-platform`. Deze tool bestaat om een security-team data te laten verzamelen, zien, en op te volgen.
