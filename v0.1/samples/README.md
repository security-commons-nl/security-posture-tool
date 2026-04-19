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

## Later toe te voegen

- `intune-laps-status.csv` — voor 3.4 (LAPS-dekking per device)
- `intune-asr-rules.csv` — voor 7.2 (Office-macros ASR-status)

Zodra de Intune-connector er is, zijn deze uploads niet meer nodig.
