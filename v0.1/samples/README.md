# Sample CSV-bestanden

Voorbeelden van CSV-input voor v0.1. Pas aan met echte data en upload via de UI of gebruik ze als template.

## `crown-jewels.csv`

Voor checklist-item **1.1** — lijst kroonjuwelen.

| Kolom | Verplicht | Voorbeeld |
|---|---|---|
| `name` | ja | "Voorbeeld-applicatie A" |
| `owner` | nee | "Team Burgerzaken" |
| `vlan_or_subnet` | nee | "VLAN 42 / 10.20.42.0/24" |
| `backup_type` | nee | "immutable Borg + offsite" |
| `rto` | nee | "4 uur" |
| `rpo` | nee | "1 uur" |

Upload via de pagina **Kroonjuwelen** in de UI.

## `intune-laps.csv`

Voor checklist-item **3.4** — LAPS op werkplekken + servers.

| Kolom | Verplicht | Voorbeeld |
|---|---|---|
| `device_name` | ja | "WKS-001" |
| `laps_configured` | ja | true / false |
| `os` | nee | "Windows 11" |
| `laps_last_rotation` | nee | "2026-04-17T08:12:00Z" |

Upload via de pagina **Uploads** in de UI.

## `intune-asr.csv`

Voor checklist-item **7.2** — Office-macros uit (ASR-rule).

| Kolom | Verplicht | Voorbeeld |
|---|---|---|
| `device_name` | ja | "WKS-001" |
| `asr_office_macros_blocked` | ja | true / false |
| `os` | nee | "Windows 11" |

Upload via de pagina **Uploads** in de UI.

## Na v0.1

Zodra een Intune-connector er is, zijn deze uploads niet meer nodig — de tool pullt dan zelf.
