"""Entra-refactor: mock Graph-API, verify evidence-rijen voor 3.1, 3.5, 4.3, 8.1."""
from __future__ import annotations

import pytest


@pytest.fixture
def entra_env(monkeypatch):
    # MSAL valideert tenant-format — gebruik 'common' of een UUID
    monkeypatch.setenv("AZURE_TENANT_ID", "common")
    monkeypatch.setenv("AZURE_CLIENT_ID", "11111111-1111-1111-1111-111111111111")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-x")


def test_entra_refresh_writes_all_four_evidence(tmp_db, entra_env, monkeypatch):
    """Mock msal + httpx.Client zodat refresh() end-to-end draait op fakes."""
    import importlib, sys

    # Stub msal ConfidentialClientApplication.acquire_token_for_client
    from msal import ConfidentialClientApplication

    def _fake_token(self, scopes):
        return {"access_token": "fake-token"}

    monkeypatch.setattr(ConfidentialClientApplication,
                        "acquire_token_for_client", _fake_token)

    # Fake httpx.Client — aantal endpoints moet consistent resolven
    import httpx

    class _Resp:
        def __init__(self, data):
            self._data = data
        def raise_for_status(self): pass
        def json(self): return self._data

    class _FakeClient:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False

        def get(self, url, params=None, headers=None):
            if "/directoryRoles/" in url and "/members" in url:
                return _Resp({"value": [
                    {"@odata.type": "#microsoft.graph.user",
                     "id": "user-1", "userPrincipalName": "a@x",
                     "displayName": "Admin A"},
                ]})
            if url.endswith("/directoryRoles") or "/directoryRoles?" in url:
                return _Resp({"value": [{"id": "role-1",
                                          "displayName": "Global Admin"}]})
            if "/reports/authenticationMethods/userRegistrationDetails" in url:
                return _Resp({"value": [
                    {"id": "user-1", "isMfaRegistered": True,
                     "methodsRegistered": ["fido2"]}
                ]})
            if "/users/user-1" in url and "signInActivity" in str(params or {}):
                return _Resp({"id": "user-1",
                              "signInActivity": {
                                  "lastSignInDateTime": "2026-04-18T10:00:00Z"}})
            if "/users/user-1/authentication/methods" in url:
                return _Resp({"value": [
                    {"@odata.type": "#microsoft.graph.fido2AuthenticationMethod"}
                ]})
            if "/auditLogs/signIns" in url:
                return _Resp({"value": []})  # 0 risky
            raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "Client", _FakeClient)

    # Herlaad entra met schone env
    for name in ("entra",):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
    import entra
    entra.refresh()

    from evidence import latest_for
    assert latest_for("3.1")["verdict"] == "pass"
    assert latest_for("3.5") is not None
    assert latest_for("4.3")["verdict"] == "pass"  # 0 risky
    assert latest_for("8.1")["verdict"] == "pass"  # fido2 aanwezig
