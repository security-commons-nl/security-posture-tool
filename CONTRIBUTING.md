# Bijdragen aan security-posture-tool

Evidence-based security posture voor blue teams en interventieteams.

## 1. Iets aanbieden of melden — geen Git-ervaring nodig

→ [**Bijdrage aanbieden**](https://github.com/security-commons-nl/security-posture-tool/issues/new?template=bijdrage-aanbieden.md)
  Een evidence-bron, control-evaluatie of ervaring uit een interventie.

→ [**Fout of verbetering**](https://github.com/security-commons-nl/security-posture-tool/issues/new?template=fout-of-verbetering.md)
  Iets klopt niet, kan beter, of mist.

Vul alleen de vragen in die voor jou relevant zijn — we helpen je met de rest.

**Geen GitHub-account?** [Maak er gratis een](https://github.com/signup) (2 minuten), of vraag iemand in je netwerk om namens jou te posten.

## 2. Meediscussiëren

→ [**Discussions**](https://github.com/orgs/security-commons-nl/discussions)

Voor vragen, ervaringen en ideeën zonder directe actie.

## 3. Voor ontwikkelaars — code aanleveren

### Structuur

- `backend/` — API en data-verwerking
- `frontend/` — UI voor interventieteams
- `connectors/` — koppelingen met evidence-bronnen
- `controls/` — control-catalogus en evaluaties

Zie [docs/](docs/) voor architectuur, gebruik en configuratie.

### PRs

- **Nieuwe connector**: voeg testdata en een minimale validatie toe
- **Nieuwe control**: documenteer het evidence-model en acceptatiecriteria
- **Gedragswijzigingen**: update `docs/gebruik.md` of `docs/architectuur.md`

---

**Organisatiebrede richtlijnen**: [security-commons-nl/.github](https://github.com/security-commons-nl/.github/blob/main/CONTRIBUTING.md)
