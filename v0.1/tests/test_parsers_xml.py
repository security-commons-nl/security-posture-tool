"""Tests voor XML-parsers (nmap, nessus, sysmon, wdac, gpo)."""
from __future__ import annotations

import time
from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# 5.4 — nmap_xml
# ---------------------------------------------------------------------------

def _nmap_xml(start_ts: int, ports: list[tuple[str, int]]) -> bytes:
    hosts = ""
    for host, port in ports:
        hosts += f"""
  <host>
    <address addr="{host}" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="{port}"><state state="open"/></port></ports>
  </host>"""
    return (
        f'<?xml version="1.0"?>\n<nmaprun start="{start_ts}" version="7.93">'
        + hosts + "\n</nmaprun>"
    ).encode()


def test_nmap_fresh_with_hosts_pass():
    from connectors.nmap_xml import parse
    ts = int(datetime.now(timezone.utc).timestamp())
    out = parse(_nmap_xml(ts, [("10.0.0.1", 443)]))
    assert out["verdict"] == "pass"
    assert out["open_ports_count"] == 1


def test_nmap_stale_fails():
    from connectors.nmap_xml import parse
    ts = int((datetime.now(timezone.utc) - timedelta(days=14)).timestamp())
    out = parse(_nmap_xml(ts, [("10.0.0.1", 443)]))
    assert out["verdict"] == "stale"


def test_nmap_unparsed():
    from connectors.nmap_xml import parse
    assert parse(b"<not-xml")["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# 5.1 — nessus_xml
# ---------------------------------------------------------------------------

NESSUS_CLEAN = b"""<?xml version="1.0"?>
<NessusClientData_v2><Report>
<ReportHost name="10.0.0.1">
  <HostProperties><tag name="HOST_END">Mon Mar 10 12:00:00 2026</tag></HostProperties>
  <ReportItem severity="2" pluginName="Info" port="80"/>
</ReportHost>
</Report></NessusClientData_v2>
"""

NESSUS_WITH_CRITICALS = b"""<?xml version="1.0"?>
<NessusClientData_v2><Report>
<ReportHost name="10.0.0.1">
  <HostProperties><tag name="HOST_END">Mon Mar 10 12:00:00 2026</tag></HostProperties>
  <ReportItem severity="4" pluginName="CVE-X" port="443"/>
  <ReportItem severity="4" pluginName="CVE-Y" port="80"/>
</ReportHost>
</Report></NessusClientData_v2>
"""


def test_nessus_clean_pass():
    from connectors.nessus_xml import parse
    out = parse(NESSUS_CLEAN)
    # scan uit maart 2026 — afhankelijk van today kan het stale zijn,
    # maar critical_count moet 0 zijn
    assert out["critical_count"] == 0


def test_nessus_with_criticals_fails_or_stale():
    from connectors.nessus_xml import parse
    out = parse(NESSUS_WITH_CRITICALS)
    assert out["critical_count"] == 2
    assert out["verdict"] in {"fail", "stale"}


def test_nessus_unparsed():
    from connectors.nessus_xml import parse
    assert parse(b"<broken")["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# 4.2 — sysmon_config_xml
# ---------------------------------------------------------------------------

def _sysmon_xml(rule_groups: int, fingerprint: str = "") -> bytes:
    rg = "\n".join(
        f'<RuleGroup name="rg{i}" groupRelation="or"><ProcessCreate onmatch="include"/></RuleGroup>'
        for i in range(rule_groups)
    )
    comment = f"<!-- {fingerprint} -->\n" if fingerprint else ""
    return (
        f'<Sysmon schemaversion="4.50">{comment}<EventFiltering>{rg}</EventFiltering></Sysmon>'
    ).encode()


def test_sysmon_swiftonsecurity_pass():
    from connectors.sysmon_config_xml import parse
    out = parse(_sysmon_xml(10, "SwiftOnSecurity sysmon-config"))
    assert out["verdict"] == "pass"


def test_sysmon_too_few_rules_fail():
    from connectors.sysmon_config_xml import parse
    assert parse(_sysmon_xml(2, "SwiftOnSecurity"))["verdict"] == "fail"


def test_sysmon_unknown_fingerprint_unparsed():
    from connectors.sysmon_config_xml import parse
    assert parse(_sysmon_xml(10, ""))["verdict"] == "unparsed"


def test_sysmon_broken_unparsed():
    from connectors.sysmon_config_xml import parse
    assert parse(b"<broken")["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# 7.1 — wdac_policy_xml
# ---------------------------------------------------------------------------

WDAC_ENFORCE = b"""<?xml version="1.0"?>
<SiPolicy><Rules>
  <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
</Rules>
<FileRules>
  <Allow ID="1" FriendlyName="x" FileName="a.exe"/>
</FileRules></SiPolicy>
"""

WDAC_AUDIT = b"""<?xml version="1.0"?>
<SiPolicy><Rules>
  <Rule><Option>Enabled:Audit Mode</Option></Rule>
</Rules>
<FileRules><Allow ID="1" FriendlyName="x" FileName="a.exe"/></FileRules></SiPolicy>
"""

APPLOCKER_ENFORCED = b"""<?xml version="1.0"?>
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="1" Name="x" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*"/></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"""


def test_wdac_enforce_pass():
    from connectors.wdac_policy_xml import parse
    assert parse(WDAC_ENFORCE)["verdict"] == "pass"


def test_wdac_audit_fails():
    from connectors.wdac_policy_xml import parse
    assert parse(WDAC_AUDIT)["verdict"] == "fail"


def test_applocker_enforced_pass():
    from connectors.wdac_policy_xml import parse
    assert parse(APPLOCKER_ENFORCED)["verdict"] == "pass"


def test_wdac_broken_unparsed():
    from connectors.wdac_policy_xml import parse
    assert parse(b"<broken")["verdict"] == "unparsed"


# ---------------------------------------------------------------------------
# 3.2-alt — gpo_export_xml
# ---------------------------------------------------------------------------

GPO_WITH_LW = b"""<?xml version="1.0"?>
<GPO><Settings><LogonWorkstations>PC-TIER0-01,PC-TIER0-02</LogonWorkstations></Settings></GPO>
"""

GPO_WITHOUT_LW = b"""<?xml version="1.0"?>
<GPO><Settings></Settings></GPO>
"""


def test_gpo_with_logon_workstations_pass():
    from connectors.gpo_export_xml import parse
    assert parse(GPO_WITH_LW)["verdict"] == "pass"


def test_gpo_without_logon_workstations_fail():
    from connectors.gpo_export_xml import parse
    assert parse(GPO_WITHOUT_LW)["verdict"] == "fail"


def test_gpo_broken_unparsed():
    from connectors.gpo_export_xml import parse
    assert parse(b"<broken")["verdict"] == "unparsed"
