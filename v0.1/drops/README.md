# Drops-folder

Deze folder is de **"gooi-hier-je-bestanden"-plek** voor de tool. Wat je hier dropt, verschijnt in de UI op `/drops` — direct leesbaar, zonder upload-knop of schema-verplichting.

## Gebruik

- Dump elke CSV, text-dump of config-file in deze folder (sub-folders mogen)
- Ga naar de tool → **Drops** → bestand is er
- Klik op een bestand voor preview (CSV als tabel, text als preformatted)

## Voorbeelden

- Palo Alto firewall-log export: `drops/firewall/palo-egress-2026-04-19.csv`
- Cisco router running-config: `drops/network/sw-core-01-running-config.txt`
- BloodHound CE JSON-export: `drops/bloodhound/computers.json`
- NMAP scan-output: `drops/scans/external-scan-2026-04-19.xml`

## Wat de tool leest

| Type | Wat er gebeurt |
|---|---|
| `.csv` / `.tsv` | Tabel, eerste 200 rijen |
| `.txt` / `.log` / `.conf` / `.cfg` / `.json` / `.xml` / `.yaml` / `.yml` / `.ini` | Tekst-preview, eerste 500 KB |
| Bestanden zonder extensie | Als tekst behandeld |
| Andere formaten (PDF, docx, binary) | Alleen bestandsnaam + grootte |

## Custom pad

Default-pad is `./drops/` relatief aan `app.py`. Wil je een andere locatie, zet dan `DROPS_PATH` in `.env`:

```
DROPS_PATH=/path/to/shared/evidence
```

Handig als jullie een netwerkschijf hebben waar iedereen dumpt.

## Privacy

Bestanden in deze folder worden **niet** gecommit — de map staat in `.gitignore` (behalve deze README en `.gitkeep`). Wat jullie hier dumpen blijft lokaal.
