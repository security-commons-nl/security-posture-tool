# Open Source Tooling Selectiematrix & Specificaties

Dit document vormt de technische ruggengraat voor implementaties en sluit aan bij de referentiearchitectuur zoals opgesteld in het Defense-in-Depth onderzoek. Het koppelt elke abstracte maatregel aan de minimale software-eisen en voorziet in een rangorde van beschikbare, bewezen, publieke open-source software (OSS).

## Principes en Minimale Specificaties
Onze tool-selectie baseert zich sterk op digitale soevereiniteit voor de Nederlandse overheid:
1. **On-Premise / Self-Hosted Capabel:** Tools moeten in onze eigen datacenters (of binnen EU sovereign cloud) kunnen draaien zonder call-homes naar niet-EU parent/US cloud controle-omgevingen. De voorkeur gaat uit naar air-gapped support.
2. **Open Source & Verifieerbaar:** Volledig open source (FOSS) heeft voorrang boven "open-core". De code moet onafhankelijk auditeerbaar zijn.
3. **API-first Design:** De tool moet telemetrie/logs kunnen uitspuwen conform open standaarden of voorzien in rijke REST/GraphQL of stroomgebaseerde API-koppelingen waaraan de geprogrammeerde `security-posture-tool` connectoren naadloos kunnen aanhaken.

---

## 1. Perimeterbeveiliging

| Control ID & Doel | Minimale OS Eisen & Specificaties | Voorgestelde Systemen (Best ➔ Fallback) |
|---|---|---|
| **PER-VPN-01** (Remote Access TLS/IPSec) | Geen cloud-afhankelijke gateways, sterke cryptografie audits (zoals Linux kernel integration), naadloze MFA OIDC/SAML integratie. | **WireGuard** ➔ OpenVPN ➔ StrongSwan |
| **PER-FW-01 / PER-IPS-01** (NGFW / Inbraakpreventie) | Moet line-rate deep packet inspection (DPI) ondersteunen en TLS-inspectie aankunnen. Actief beheerde threat-intelligence rulesets vereist. GUI moet niet verplicht via cloud. | **OPNsense** *met* **Suricata** ➔ pfSense ➔ Zeek (IDS only) ➔ IPFire |
| **PER-DNS-01** (DNS Filtering/C2) | Ondersteunt blocklists, RPZ (Response Policy Zones), lokaal cached, versleutelde upstreams (DoH/DoT). | **Pi-hole / AdGuard Home** (Enterprise use) ➔ BIND9 / Unbound (Custom RPZ) |

## 2. Netwerkbeveiliging en Segmentatie

| Control ID & Doel | Minimale OS Eisen & Specificaties | Voorgestelde Systemen (Best ➔ Fallback) |
|---|---|---|
| **NET-NAC-01** (NAC 802.1X / Apparaat authorisatie) | 802.1X functionaliteit verplicht, dynamische VLAN-toewijzing, gasten/IoT portal features. Ondersteunt MAC-auth fallback. | **PacketFence** ➔ FreeRADIUS |
| **NET-ZTNA-01** (Zero Trust / Context based toegang) | Volledig on-prem broker en controllers, applicatie-microsegmentatie op basis van identiteit en context ("no inbound peering"). | **OpenZiti** ➔ Nebula ➔ Headscale (Minder ZTNA, meer mesh) |

## 3. Endpoint Security en Systeemharding

| Control ID & Doel | Minimale OS Eisen & Specificaties | Voorgestelde Systemen (Best ➔ Fallback) |
|---|---|---|
| **END-EDR-01** (Agent based XDR / Detection) | Cross-platform (Win/Linux/Mac), lage kernel footprint, geavanceerde MITRE ATT&CK mapping, active response scripts integratie, SIEM-integratie. | **Wazuh** ➔ OSSEC / OpenEDR ➔ Velociraptor (puur Forensics) |
| **END-PTC-01** (Vulnerability / Patch Scans) | Lokaal te hosten database, regelmatige CVE feed updates, diepe credentials-based OS audits, SCAP (Security Content Automation Protocol) compliance. | **Greenbone (OpenVAS)** ➔ OpenSCAP |
| **END-LAPS-01 / END-APP-01** (Hardening/LAPS) | Geen third-party agents voor Windows Core functies, beheerd via inheemse tooling/Policies. OS-native of sovereign enterprise tooling. | **Native Microsoft LAPS (On-Prem/AD)** / **Samba AD Policies** |

## 4. Identity and Access Management (IAM)

| Control ID & Doel | Minimale OS Eisen & Specificaties | Voorgestelde Systemen (Best ➔ Fallback) |
|---|---|---|
| **IAM-MFA-01** (Authentication Authority / SSO) | Moet SAML/OIDC praten, on-prem federatie, FIDO2/WebAuthn phishing-resistant tokens ondersteunen, conditional access policy engine bezitten. | **Authentik** ➔ Keycloak ➔ Zitadel |
| **IAM-PAM-01 / IAM-JIT-01 / IAM-MON-01** (Privileged Access & JIT) | Moet Zero-Trust RDP/SSH portal bieden *zonder* direct de keys/credentials tonen. Audit logging van sessies en JIT-approval workflows, inclusief screencasts van sessies. | **Teleport** ➔ Apache Guacamole + Hashicorp Vault (Secret broker) ➔ Lokaal Jump Host Linux |

## 5. Applicatie- en Data Beveiliging

| Control ID & Doel | Minimale OS Eisen & Specificaties | Voorgestelde Systemen (Best ➔ Fallback) |
|---|---|---|
| **APP-WAF-01** (Web Application Firewall) | Modulair in te haken op reverse proxy of Ingress controller, compatibel met OWASP CRS (Core Rule Set). | **Coraza (OWASP)** ➔ ModSecurity (End-of-Life juli '24) |
| **APP-API-01** (API Gateway) | Lichte foot-print, OIDC integratie, JWT validatie en harde rate-limiting per identiteit, Cloud-native support (K8S/Docker). | **KrakenD** ➔ Kong (OS layer) ➔ Tyk |
| **DAT-DLP-01** (Data Loss Prevention) | Geen echt "pure OS DLP". Min. Eis: Fijnmazige File Access Control logs via platform, File Integrity Monitoring op Endpoint, Custom yara/regex scanning. | **Nextcloud (File Access Control / DLP Plugin)** / **Wazuh (FIM + RegEx rules op endpoint data in motion)** |
| **DAT-BKP-01** (Immutable Backups) | Zoveel mogelijk storage-agnostisch (S3, lokale disk), de-duplicerende en off-site encryptie mogelijkheden. Immutable repo lock ondersteuning. | **BorgBackup / Restic** ➔ Proxmox Backup Server (Indien PVE clusters gebruikt worden) |

## 6. Monitoring, Detectie en Incident Response

| Control ID & Doel | Minimale OS Eisen & Specificaties | Voorgestelde Systemen (Best ➔ Fallback) |
|---|---|---|
| **MON-SIEM-01 / MON-UEBA-01** (Data aggregatie & correlatie) | Gigantisch datavolume aankunnen zonder licentie per gigabyte (GB/day), open API voor custom rule injectie, native dashboarding met ML/UEBA support. | **Elastic Security / ELK (Open-core)** / **OpenSearch (AWS/Linux Foundation fork)** ➔ Graylog (Free edition) |
| **MON-SOAR-01** (Automatisering en Incident flow) | Visuele drag-n-drop playbook editor of "low code", naadloze hooks via webhooks met SIEM/EDR, case management systeem ingebouwd. | **Shuffle** ➔ n8n ➔ TheHive / Cortex (Met name gericht op Incident management) |

## 7. Emission Security (EMSEC) en Auditing

| Control ID & Doel | Minimale OS Eisen & Specificaties | Voorgestelde Systemen (Best ➔ Fallback) |
|---|---|---|
| **Meerdere** (Fysieke security vs Attack path theorie) | Fysieke beveiliging kan niet gemeten worden met software. Echter, *attack path / identity drift* wat EMSEC raakt kan met auditing tools visueel inzichtelijk worden gemaakt met Open Source graph-analyse van Identity/ADCS. | **BloodHound CE** ➔ PingCastle ➔ Linux auditd |

---
*Note: Deze selectie vormt de 'Best Practice' sturing. Voor de bouw van de `security-posture-tool` connectoren zullen dit de applicaties zijn waartegen de eerste API integraties en log-parsers worden geschreven ten behoeve van het uitlezen van 'Bewijs'.*
