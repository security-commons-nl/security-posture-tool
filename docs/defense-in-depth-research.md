# Strategische Architectuur en Technische Verificatie van Defense-in-Depth

De evolutie van het digitale dreigingslandschap heeft de traditionele opvatting van een statische netwerkperimeter definitief achterhaald. Waar beveiliging voorheen vaak werd vergeleken met een kasteelmuur, dwingen de opkomst van hybride werken, cloud-native infrastructuren en geavanceerde persistente dreigingen (APT's) tot een paradigmaverschuiving naar defense-in-depth, ook wel gelaagde beveiliging genoemd. Deze strategie is gebaseerd op het principe dat geen enkele individuele beveiligingsmaatregel onfeilbaar is. In plaats daarvan worden redundante en overlappende technische controles geïmplementeerd over meerdere lagen—van de fysieke perimeter tot de diepste datastructuren—zodat het falen van één controlepunt niet leidt tot een volledige systeemcompromis. 

Dit rapport biedt de uitputtende definities van de technische maatregelen binnen deze gelaagde architectuur en stelt het verificatiekader voor waarmee de effectiviteit in de `security-posture-tool` kan worden getest.

## Theoretische Grondslagen en Raamwerkaliniëring
Een effectieve defense-in-depth strategie begint bij de selectie en implementatie van robuuste beveiligingsraamwerken die de architectonische keuzes sturen. Raamwerken zoals het NIST Cybersecurity Framework (CSF), de ISO/IEC 27001-standaard en de CIS Critical Security Controls bieden de noodzakelijke governance en technische richtlijnen om een coherente beveiligingshouding op te bouwen. 

### Vergelijking van Toonaangevende Beveiligingsraamwerken
| Kenmerk | NIST CSF 2.0 | CIS Controls v8.1 | ISO/IEC 27001:2022 |
|---|---|---|---|
| Primaire Focus | Risicomanagement uitkomsten | Geprioriteerde technische maatregelen | Beheersysteem voor informatiebeveiliging (ISMS) |
| Structuur | 6 Functies, 22 Categorieën | 18 Controls, 153 Safeguards | 4 Domeinen, 93 Controles |
| Toepassing | Strategisch en resultaatgericht | Tactisch en voorschrijvend | Compliance en risicogebaseerd |
| Audit-mechanisme | Maturity Tiers | Implementation Groups (IG1, IG2, IG3) | Formele certificering |

De synergie tussen deze raamwerken is essentieel voor een diepgaande verdediging. NIST 800-53 biedt bijvoorbeeld de fijnmazige technische specificaties die nodig zijn voor federale systemen, terwijl de CIS Benchmarks de configuratierichtlijnen leveren voor het harden van specifieke systemen en software.

---

## Defense-in-Depth Lagen en Control-Definities

Hieronder zijn alle kritieke maatregelen omgezet in toetsbare Control-Blokken ten behoeve van de *security-posture-tool* configuratie en rule-engine.

### 1. Perimeterbeveiliging
De traditionele netwerkperimeter getransformeerd tot een gedistribueerde 'edge'. Deze laag stopt dreigingen vóórdat ze het interne netwerk bereiken.

| Control ID | Beveiligingsdoel | Technische Maatregel | Toetsbare Verificatie (Bewijs) | Mogelijke Connector |
|---|---|---|---|---|
| PER-VPN-01 | Toegangskanaal | VPN met sterke encryptie en MFA | Gebruik van TLS 1.2+; afdwingen van MFA voor alle sessies. | `entra_id` / `vpn_logs` |
| PER-FW-01 | Verkeersfiltering | NGFW met actieve DPI en SSL-inspectie | Correcte classificatie van applicatieverkeer en detectie in versleutelde stromen. Actieve blokkade van "Any/Any" regels. | `firewall_logs` |
| PER-IPS-01 | Inbraakpreventie | IPS met real-time signature updates | Succesvolle blokkade van bekende exploits en minimale latency-impact. | `firewall_logs` / `ips_logs` |
| PER-DDoS-01 | Beschikbaarheid beschermen | DDoS-mitigatie | Diversiesnelheid naar scrubbing-infra en behoud van service-beschikbaarheid. | `ext_metrics` |
| PER-DNS-01 | Malafide links blokkeren | DNS-filtering op C2 of phishing | C2-blokkade actief, DGA-detectie aan. | `dns_logs` |

### 2. Netwerkbeveiliging en Segmentatie
Voorkomen van zijwaartse verplaatsing (lateral movement) van aanvallers zodra ze binnen de perimeter zijn.

| Control ID | Beveiligingsdoel | Technische Maatregel | Toetsbare Verificatie (Bewijs) | Mogelijke Connector |
|---|---|---|---|---|
| NET-SEG-01 | Netwerksegmentatie | Fysieke of VLAN-technische scheiding | Controleren van firewallregels op "any/any" tussen werkplekken en datacenter (geen onbeperkt SMB/RDP verkeer). | `firewall_logs` |
| NET-NAC-01 | Onbeheerde apparaten weren | NAC 802.1X op netwerkpoorten | Bekabeld en draadloos netwerk weigert verbinding zonder certificaat/device authenticatie. | `nmap` / `nac_logs` |
| NET-SMB-01 | Relay-aanvallen stoppen | SMB Signing / SMBv1 uitschakelen | Verplicht SMB signing op zowel client als server (100% dekking). | `nmap` |
| NET-ZTNA-01 | Identiteitgebonden toegang | Zero Trust Network Access | Toegang uitsluitend via validatie (context, identiteit, apparaatgezondheid). Geen impliciet vertrouwen voor intern netwerk IP. | `ztna_logs` |

### 3. Endpoint Security en Systeemharding
De apparaten zelf beveiligen tegen infiltratie, malware executie en misbruik.

| Control ID | Beveiligingsdoel | Technische Maatregel | Toetsbare Verificatie (Bewijs) | Mogelijke Connector |
|---|---|---|---|---|
| END-EDR-01 | Geavanceerde detectie | EDR / XDR Tooling | Endpoint agent is actief op >95% van systemen. Detectiedekking MITRE ATT&CK. | `edr_api` |
| END-PTC-01 | OS en App patching | Patch Management Proces | Kwetsbaarheden gepatcht binnen SLA (bijv. 30 dagen). Geen EOL systemen. | `nmap` / `vuln_scanner` |
| END-APP-01 | Unauthorized executie stuiten | Applicatiewhitelisting / ASR | Alleen gesigneerde/goedgekeurde binaries kunnen draaien. LSASS dump blokkade (ASR) actief. | `edr_api` |
| END-PRV-01 | Rechten inperken | Verwijderen lokale admin rechten | Gebruikers werken zonder Administrator rechten op het werkstation. | `entra_id` / `edr_api` |
| END-LAPS-01 | Lateral movement stoppen | LAPS implementatie | Lokaal admin wachtwoord is uniek per apparaat en roteert automatisch na uitgifte. | `entra_id` |

### 4. Identity and Access Management (Core / IAM)
Identiteit is de nieuwe perimeter in de gedistribueerde cloud/on-prem wereld.

| Control ID | Beveiligingsdoel | Technische Maatregel | Toetsbare Verificatie (Bewijs) | Mogelijke Connector |
|---|---|---|---|---|
| IAM-MFA-01 | Diefstal credentials stoppen | Multifactor Authentication (MFA) | Phishing-resistente MFA verplicht voor alle externe en beheerders-toegang (100% dekking). | `entra_id` |
| IAM-PAM-01 | Accounts met hoge rechten beschermen | Privileged Access Management | Wachtwoordkluis, automatische credential rotatie na gebruik, geen hardcoded admins. | `entra_id` / `pam_logs` |
| IAM-JIT-01 | Standing privileges inperken | Just-In-Time Access (JIT) | Geen permanente Domain Admins. Beheerrechten worden enkel toegekend op goedkeuring voor maximaal enkele uren. | `entra_id` |
| IAM-MON-01 | Sessies bewaken | Privileged Session Monitoring | Actieve sessieverhogingen worden opgenomen. Alerting actief bij afwijkend admin-gedrag. | `siem_logs` |

### 5. Applicatie- en Data Beveiliging
Zorgen dat de webapplicaties geen entry points zijn en de opgeslagen data niet verloren kan gaan of gelezen kan worden.

| Control ID | Beveiligingsdoel | Technische Maatregel | Toetsbare Verificatie (Bewijs) | Mogelijke Connector |
|---|---|---|---|---|
| APP-WAF-01 | Web endpoints bewaken | Web Application Firewall / RASP | Actieve HTTP inspectie op applicatieniveau; blokkeren van SQLi en XSS payloads. | `waf_logs` |
| APP-API-01 | API endpoints beveiligen | API Gateway / Schema Validatie | Volledige API inventarisatie, schema-validatie op inkomend verkeer, rate limiting. | `api_logs` |
| DAT-ENC-01 | Diefstal van fysieke opslag | Encryptie in rust (Bitlocker/AES-256) | Encryptie op disk geactiveerd bij werkplekken en servers. | `entra_id` |
| DAT-DLP-01 | Exfiltratie voorkomen | Data Loss Prevention (DLP) | Inspectie en blokkade bij overdracht van gevoelige persoonsgegevens of creditcarddata. | `dlp_logs` |
| DAT-BKP-01 | Herstelvermogen garanderen | Immutable en geteste Backups | Backups zijn geïsoleerd; RTO en RPO worden gehaald tijdens formele hersteltesten. | `backup_api` |

### 6. Monitoring, Detectie en Incident Response
Inzicht in incidenten en de vermindering van impact via geautomatiseerde respons.

| Control ID | Beveiligingsdoel | Technische Maatregel | Toetsbare Verificatie (Bewijs) | Mogelijke Connector |
|---|---|---|---|---|
| MON-SIEM-01 | Centrale zichtbaarheid | SIEM / Log Correlatie | Log integriteit gegarandeerd; firewalls, EDR en identiteitslogs stromen continu binnen. | `siem_status` |
| MON-UEBA-01 | Afwijkend gedrag zien | User & Entity Behavior Analytics | Melding op account login gedrag afkomstig uit vreemde landen of onbekende devices vlak na brute-force pogingen. | `siem_logs` |
| MON-SOAR-01 | MTTR verlagen | Geautomatiseerde Respons (SOAR) | Incidenten zoals ransomware of malafide bijlages leveren geautomatiseerd isolatie van hosts op, betrouwbaar en zonder business impact. | `soar_logs` |

### 7. Emission Security (EMSEC)
Emissiebeveiliging is een fysieke barrière tegen onbedoelde elektromagnetische emanaties, gedefinieerd op het raakvlak van de fysieke en elektronische wereld (zoals in NAVO SDIP-27/28 en ABDO 2019 structurering).

| Control ID | Beveiligingsdoel | Technische Maatregel | Toetsbare Verificatie (Bewijs) | Mogelijke Connector |
|---|---|---|---|---|
| EMS-ZON-01 | Afstandsbeveiliging | Facilitaire Zonering | Afstand tussen systemen en niet-inspecteerbare zones voldoet aan norm (>20 meter in Zone 1), RF-demping geverifieerd. | `facility_audit` |
| EMS-HRD-01 | Radiostraling dempen | TEMPEST gecertificeerde hardware | SDIP-27 Level A hardware certificaat aanwezig. Ongebruikte fysieke poorten fysiek afgeblokt. | `asset_db` |
| EMS-ISO-01 | Signalen gescheiden houden | Red/Black kabel management | Aantoonbare fysieke afstand (>50mm) tussen versleutelde (black) en onversleutelde (red) netwerkkabels. Glasvezel in Red-zones. | `facility_audit` |
| EMS-FLT-01 | Via stroom lekken stoppen | Lijnfilters (Signal & Power) | Correct geaarde filters geplaatst bij in/uitgang van secure zones op power en signal lines. | `facility_audit` |