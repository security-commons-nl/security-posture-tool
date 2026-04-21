# Bijdragen aan security-posture-tool

Evidence-based security posture voor blue teams en interventieteams.

Raadpleeg de organisatiebrede richtlijnen van security-commons-nl:

- [CONTRIBUTING.md (org-wide)](https://github.com/security-commons-nl/.github/blob/main/CONTRIBUTING.md)
- [DOCUMENTATION-STANDARD.md](https://github.com/security-commons-nl/.github/blob/main/DOCUMENTATION-STANDARD.md)
- [PRINCIPLES.md](https://github.com/security-commons-nl/.github/blob/main/PRINCIPLES.md)

## Project-specifieke werkwijze

Zie [docs/](docs/) voor architectuur, gebruik en configuratie.

### Structuur

- `backend/` — API en data-verwerking
- `frontend/` — UI voor interventieteams
- `connectors/` — koppelingen met evidence-bronnen
- `controls/` — control-catalogus en evaluaties

### PRs

- Nieuwe connector? Voeg testdata en een minimale validatie toe.
- Nieuwe control? Documenteer het evidence-model en acceptatiecriteria.
- Gedragswijzigingen: update `docs/gebruik.md` of `docs/architectuur.md`.
