"""Microsoft Graph API client — evidence-only refactor.

Haalt privileged accounts, MFA-status, sign-in activity, risky sign-ins en
authentication-methods op uit Entra ID. Elke pull schrijft een evidence-rij
voor het corresponderende checklist-item:
  3.1 — MFA privileged
  3.5 — Inactieve accounts
  4.3 — Risky sign-ins
  8.1 — Phishing-resistant MFA onder admins
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Iterable

import httpx
from dotenv import load_dotenv
from msal import ConfidentialClientApplication

import db
import evidence

load_dotenv()

AUTHORITY_TEMPLATE = "https://login.microsoftonline.com/{tenant}"
SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH = "https://graph.microsoft.com/v1.0"

PHISHING_RESISTANT_TYPES = {
    "#microsoft.graph.fido2AuthenticationMethod",
    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod",
    "#microsoft.graph.x509CertificateAuthenticationMethod",
}


def _env() -> tuple[str, str, str]:
    tenant = os.environ.get("AZURE_TENANT_ID", "")
    client = os.environ.get("AZURE_CLIENT_ID", "")
    secret = os.environ.get("AZURE_CLIENT_SECRET", "")
    if not all([tenant, client, secret]):
        raise RuntimeError(
            "Missing AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET — "
            "zie .env.example"
        )
    return tenant, client, secret


def _token() -> str:
    tenant, client, secret = _env()
    app = ConfidentialClientApplication(
        client,
        authority=AUTHORITY_TEMPLATE.format(tenant=tenant),
        client_credential=secret,
    )
    res = app.acquire_token_for_client(scopes=SCOPE)
    if "access_token" not in res:
        raise RuntimeError(f"Graph auth failed: {res.get('error_description')}")
    return res["access_token"]


def _graph_get(path: str, params: dict | None = None, token: str | None = None) -> dict:
    token = token or _token()
    with httpx.Client(timeout=30) as client:
        r = client.get(
            f"{GRAPH}{path}",
            params=params or {},
            headers={"Authorization": f"Bearer {token}"},
        )
        r.raise_for_status()
        return r.json()


def _graph_paged(path: str, params: dict | None = None,
                 token: str | None = None) -> Iterable[dict]:
    token = token or _token()
    url = f"{GRAPH}{path}"
    with httpx.Client(timeout=30) as client:
        first = True
        while url:
            r = client.get(
                url,
                params=params if first else None,
                headers={"Authorization": f"Bearer {token}"},
            )
            r.raise_for_status()
            data = r.json()
            for item in data.get("value", []):
                yield item
            url = data.get("@odata.nextLink")
            first = False


# ---------------------------------------------------------------------------
# Pulls
# ---------------------------------------------------------------------------


def fetch_privileged_accounts() -> list[dict]:
    seen: dict[str, dict] = {}
    for role in _graph_paged("/directoryRoles"):
        role_id = role["id"]
        try:
            for member in _graph_paged(f"/directoryRoles/{role_id}/members"):
                if member.get("@odata.type") != "#microsoft.graph.user":
                    continue
                uid = member["id"]
                if uid in seen:
                    continue
                seen[uid] = {
                    "id": uid,
                    "upn": member.get("userPrincipalName"),
                    "display_name": member.get("displayName"),
                }
        except httpx.HTTPError as e:
            print(f"  waarschuwing: role {role.get('displayName')}: {e}")
    return list(seen.values())


def fetch_mfa_registrations() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for rec in _graph_paged(
        "/reports/authenticationMethods/userRegistrationDetails"
    ):
        uid = rec.get("id")
        if not uid:
            continue
        out[uid] = {
            "mfa_registered": bool(rec.get("isMfaRegistered")),
            "methods": rec.get("methodsRegistered") or [],
        }
    return out


def fetch_last_signin(user_ids: Iterable[str]) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    token = _token()
    for uid in user_ids:
        try:
            data = _graph_get(
                f"/users/{uid}",
                params={"$select": "id,signInActivity"},
                token=token,
            )
        except httpx.HTTPError as e:
            print(f"  waarschuwing: sign-in van {uid}: {e}")
            out[uid] = None
            continue
        activity = data.get("signInActivity") or {}
        out[uid] = activity.get("lastSignInDateTime")
    return out


def fetch_risky_signins(window_days: int = 7) -> list[dict]:
    """Alle sign-ins met riskLevelAggregated != 'none' in laatste N dagen."""
    from datetime import timedelta
    since = (datetime.now(timezone.utc) - timedelta(days=window_days)).isoformat()
    filt = f"riskLevelAggregated ne 'none' and createdDateTime ge {since}"
    return list(_graph_paged("/auditLogs/signIns",
                             params={"$filter": filt, "$top": 100}))


def fetch_auth_methods(user_id: str) -> list[dict]:
    data = _graph_get(f"/users/{user_id}/authentication/methods")
    return data.get("value", [])


# ---------------------------------------------------------------------------
# Orchestrator — schrijft evidence-rijen
# ---------------------------------------------------------------------------


def refresh():
    """Volledige pull: accounts + MFA + sign-ins + risky + authmethods-admins."""
    now_iso = datetime.now(timezone.utc).isoformat()

    print("Privileged accounts ophalen...")
    privileged = fetch_privileged_accounts()

    print("MFA-registraties ophalen...")
    mfa = fetch_mfa_registrations()

    print("Laatste sign-ins ophalen...")
    user_ids = [a["id"] for a in privileged]
    signins = fetch_last_signin(user_ids)

    for acc in privileged:
        mfa_info = mfa.get(acc["id"], {})
        db.upsert_account({
            "id": acc["id"],
            "upn": acc.get("upn"),
            "display_name": acc.get("display_name"),
            "is_privileged": 1,
            "mfa_registered": 1 if mfa_info.get("mfa_registered") else 0,
            "mfa_methods": ",".join(mfa_info.get("methods", [])),
            "last_signin_at": signins.get(acc["id"]),
            "source": "entra",
        })

    # 3.1 — MFA privileged
    total_priv = len(privileged)
    mfa_covered = sum(1 for a in privileged
                      if mfa.get(a["id"], {}).get("mfa_registered"))
    body_31 = json.dumps({"privileged": privileged, "mfa": mfa},
                         sort_keys=True, default=str).encode("utf-8")
    evidence.write_evidence(
        checklist_id="3.1", source_type="graph_api",
        source_ref=f"graph:mfa-privileged:{now_iso}",
        raw_bytes=body_31, artefact_date=now_iso,
        parsed_summary={"total": total_priv, "covered": mfa_covered,
                        "pct": round(mfa_covered/total_priv*100) if total_priv else 0},
        parser_name="graph_mfa_privileged_v1",
        verdict="pass" if total_priv and mfa_covered == total_priv else "fail",
    )

    # 3.5 — Inactieve accounts (>90d) + enabled
    inactive = db.fetch_inactive_accounts(90)
    body_35 = json.dumps({"inactive_count": len(inactive)},
                         sort_keys=True, default=str).encode("utf-8")
    evidence.write_evidence(
        checklist_id="3.5", source_type="graph_api",
        source_ref=f"graph:inactive-accounts:{now_iso}",
        raw_bytes=body_35, artefact_date=now_iso,
        parsed_summary={"total": len(db.fetch_accounts()),
                        "inactive_over_90d": len(inactive)},
        parser_name="graph_inactive_v1",
        verdict="pass" if len(inactive) == 0 else "fail",
    )

    # 4.3 — Risky sign-ins laatste 7d
    try:
        risky = fetch_risky_signins(window_days=7)
    except httpx.HTTPError as e:
        print(f"  waarschuwing: risky sign-ins: {e}")
        risky = []
    body_43 = json.dumps(risky, sort_keys=True, default=str).encode("utf-8")
    evidence.write_evidence(
        checklist_id="4.3", source_type="graph_api",
        source_ref=f"graph:risky-signins:{now_iso}",
        raw_bytes=body_43, artefact_date=now_iso,
        parsed_summary={"risky_count": len(risky), "window_days": 7},
        parser_name="graph_risky_signins_v1",
        verdict="pass" if len(risky) == 0 else "fail",
    )

    # 8.1 — Phishing-resistant MFA onder admins
    resistant = 0
    total_admins = len(privileged)
    for uid in user_ids:
        try:
            methods = fetch_auth_methods(uid)
        except httpx.HTTPError:
            continue
        if any(m.get("@odata.type") in PHISHING_RESISTANT_TYPES for m in methods):
            resistant += 1
    body_81 = json.dumps({"admins": total_admins, "resistant": resistant},
                         sort_keys=True).encode("utf-8")
    evidence.write_evidence(
        checklist_id="8.1", source_type="graph_api",
        source_ref=f"graph:authmethods-admins:{now_iso}",
        raw_bytes=body_81, artefact_date=now_iso,
        parsed_summary={"total": total_admins, "covered": resistant,
                        "pct": round(resistant/total_admins*100) if total_admins else 0},
        parser_name="graph_phishing_resistant_v1",
        verdict="pass" if total_admins and resistant == total_admins else "fail",
    )

    print("Klaar.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "refresh":
        refresh()
    else:
        print("Usage: python entra.py refresh")
