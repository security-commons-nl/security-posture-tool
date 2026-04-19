"""Microsoft Graph API client — v0.1 skelet.

Haalt privileged accounts, MFA-status en sign-in activity op uit Entra ID.
De Graph-calls zijn gestubt met TODO-markers; invullen tijdens eerste werksessie.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime
from typing import Iterable

import httpx
from dotenv import load_dotenv
from msal import ConfidentialClientApplication

import db

load_dotenv()

TENANT_ID = os.environ.get("AZURE_TENANT_ID", "")
CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH = "https://graph.microsoft.com/v1.0"


def _token() -> str:
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        raise RuntimeError(
            "Missing AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET — "
            "zie .env.example"
        )
    app = ConfidentialClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
        client_credential=CLIENT_SECRET,
    )
    res = app.acquire_token_for_client(scopes=SCOPE)
    if "access_token" not in res:
        raise RuntimeError(f"Graph auth failed: {res.get('error_description')}")
    return res["access_token"]


def _graph_get(path: str, params: dict | None = None) -> dict:
    with httpx.Client(timeout=30) as client:
        r = client.get(
            f"{GRAPH}{path}",
            params=params or {},
            headers={"Authorization": f"Bearer {_token()}"},
        )
        r.raise_for_status()
        return r.json()


def _graph_paged(path: str, params: dict | None = None) -> Iterable[dict]:
    """Iterate over alle pagina's van een Graph-list-response."""
    url = f"{GRAPH}{path}"
    token = _token()
    with httpx.Client(timeout=30) as client:
        while url:
            r = client.get(
                url,
                params=params if url == f"{GRAPH}{path}" else None,
                headers={"Authorization": f"Bearer {token}"},
            )
            r.raise_for_status()
            data = r.json()
            for item in data.get("value", []):
                yield item
            url = data.get("@odata.nextLink")


# ---------------------------------------------------------------------------
# De eigenlijke pulls — TODO tijdens eerste werksessie invullen
# ---------------------------------------------------------------------------


def fetch_privileged_accounts() -> list[dict]:
    """Haal accounts op die lid zijn van één of meer directory-roles.

    Strategie: GET /directoryRoles → per role GET /members → dedupliceer op
    user-id. Dit pakt alle accounts die ten minste één admin-role hebben
    (Global Admin, Security Admin, User Admin, enz.). Als een strakkere
    definitie gewenst is, filter hier op role-template-id.

    NOTE: niet getest tegen live tenant; ronde dit af bij eerste run.
    """
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
    """Per user-id de MFA-registratiestatus.

    Graph endpoint: /reports/authenticationMethods/userRegistrationDetails
    Levert per user o.a. isMfaRegistered + methodsRegistered.

    NOTE: vereist Reports.Read.All in app-registration.
    """
    out: dict[str, dict] = {}
    for rec in _graph_paged("/reports/authenticationMethods/userRegistrationDetails"):
        uid = rec.get("id")
        if not uid:
            continue
        out[uid] = {
            "mfa_registered": bool(rec.get("isMfaRegistered")),
            "methods": rec.get("methodsRegistered") or [],
        }
    return out


def fetch_last_signin(user_ids: Iterable[str]) -> dict[str, str | None]:
    """Per user-id de ISO-timestamp van de laatste sign-in.

    Graph endpoint: /users/{id}?$select=signInActivity
    Vereist Entra ID P1/P2 (anders is signInActivity leeg).
    """
    out: dict[str, str | None] = {}
    for uid in user_ids:
        try:
            data = _graph_get(
                f"/users/{uid}",
                params={"$select": "id,signInActivity"},
            )
        except httpx.HTTPError as e:
            print(f"  waarschuwing: sign-in van {uid}: {e}")
            out[uid] = None
            continue
        activity = data.get("signInActivity") or {}
        out[uid] = activity.get("lastSignInDateTime")
    return out


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def refresh():
    """Pull alles, schrijf naar SQLite, update checklist-state."""
    print("Privileged accounts ophalen...")
    privileged = fetch_privileged_accounts()
    print(f"  → {len(privileged)} privileged accounts")

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

    _update_checklist_state(privileged, mfa)
    print("Klaar.")


def _update_checklist_state(privileged: list[dict], mfa: dict[str, dict]):
    total = len(privileged)
    covered = sum(1 for a in privileged if mfa.get(a["id"], {}).get("mfa_registered"))
    pct = f"{(covered / total * 100):.0f}%" if total else "n.v.t."
    db.set_checklist_state(
        "3.1",
        "MFA verplicht op admin-accounts",
        measured_value=f"{covered}/{total} ({pct})",
        target="100%",
        notes="Gemeten op privileged accounts (directory-role members).",
    )

    inactive = db.fetch_inactive_accounts(90)
    db.set_checklist_state(
        "3.5",
        "Inactieve accounts >90 dagen",
        measured_value=f"{len(inactive)} accounts",
        target="0 (of auto-disabled)",
        notes="Gebaseerd op signInActivity.lastSignInDateTime.",
    )

    # 3.4 (LAPS) en 7.2 (Office-macros) worden in v0.1 via CSV-upload gevuld
    # (Intune-export). Hier niet overschrijven als de waarde al bestaat.


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "refresh":
        refresh()
    else:
        print("Usage: python entra.py refresh")
