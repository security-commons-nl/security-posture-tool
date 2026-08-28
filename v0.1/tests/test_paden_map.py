"""Bevindingen van de meting landen op dezelfde paden en chokepoints als zelfcheck en methode."""
import hashlib
import json
import pathlib

import checklist
import paden_map

V01 = pathlib.Path(__file__).resolve().parent.parent


def _bron() -> dict:
    return json.loads((V01 / "paden.json").read_text(encoding="utf-8"))


def test_kopie_paden_json_matcht_hash():
    h = hashlib.sha256((V01 / "paden.json").read_bytes()).hexdigest()
    assert h == (V01 / "paden.sha256").read_text().strip(), (
        "paden.json loopt achter op de bron in de aanvalspaden-repo"
    )


def test_elke_koppeling_wijst_naar_bestaand_chokepoint():
    data = _bron()
    cps = {cp["id"] for b in data["bladeren"] for cp in b["chokepoints"]}
    bladeren = {b["id"] for b in data["bladeren"]}
    for checklist_id, (pad, cp) in paden_map.KOPPELING.items():
        assert pad in bladeren, f"{checklist_id}: onbekend pad {pad}"
        assert cp in cps, f"{checklist_id}: onbekend chokepoint {cp}"
        assert cp.startswith(pad + "-"), f"{checklist_id}: {cp} hoort niet bij {pad}"


def test_elke_koppeling_verwijst_naar_een_bestaand_checklist_item():
    ids = {i["id"] for i in checklist.ALL_ITEMS}
    onbekend = set(paden_map.KOPPELING) - ids
    assert not onbekend, f"koppeling voor niet-bestaande items: {sorted(onbekend)}"


def test_elk_checklist_item_is_gekoppeld_of_heeft_een_reden():
    ids = {i["id"] for i in checklist.ALL_ITEMS}
    los = ids - set(paden_map.KOPPELING) - set(paden_map.ONGEKOPPELD_MET_REDEN)
    assert not los, f"items zonder koppeling en zonder reden: {sorted(los)}"


def test_koppel_geeft_none_voor_onbekende_bevinding():
    assert paden_map.koppel("bestaat-niet") is None


def test_de_mfa_en_backup_items_zijn_gekoppeld():
    assert paden_map.koppel("3.1") is not None, "MFA hoort op een pad te landen"
    assert paden_map.koppel("8.1") == ("AP01", "AP01-1")
    assert paden_map.koppel("6.1") == ("AP17", "AP17-9")


def test_items_voor_geeft_de_metingen_bij_een_chokepoint():
    assert paden_map.items_voor("AP09-1") == ["7.1", "7.2"]
    assert paden_map.items_voor("AP01-1") == ["8.1"]
    assert paden_map.items_voor("AP15-1") == []


def test_checklist_items_dragen_hun_pad_en_chokepoint():
    per_id = {i["id"]: i for i in checklist.ALL_ITEMS}
    assert per_id["8.1"]["pad"] == "AP01"
    assert per_id["8.1"]["chokepoint"] == "AP01-1"
    assert per_id["9.1"]["pad"] is None and per_id["9.1"]["chokepoint"] is None
    for item in checklist.ALL_ITEMS:
        assert "pad" in item and "chokepoint" in item
