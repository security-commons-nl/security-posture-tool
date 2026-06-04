"""Validatie van de kill-chain-mapping uit checklist.py."""
from __future__ import annotations

import checklist


def test_all_items_have_phases_field():
    for item in checklist.ALL_ITEMS:
        assert "kill_chain_phases" in item, f"{item['id']} mist kill_chain_phases"
        assert isinstance(item["kill_chain_phases"], list), f"{item['id']} phases is geen list"


def test_phases_zijn_bekend():
    geldig = set(checklist.KILL_CHAIN_PHASES)
    for item in checklist.ALL_ITEMS:
        for p in item["kill_chain_phases"]:
            assert p in geldig, f"{item['id']}: onbekende fase {p!r}"


def test_phase_labels_dekt_alle_fases_plus_meta():
    for p in checklist.KILL_CHAIN_PHASES:
        assert p in checklist.KILL_CHAIN_LABELS
    assert "meta" in checklist.KILL_CHAIN_LABELS


def test_phases_for_helper_werkt():
    # 3.1 MFA raakt delivery + exploitation
    assert "delivery" in checklist.phases_for("3.1")
    assert "exploitation" in checklist.phases_for("3.1")
    # 9.3 pentest is meta — leeg
    assert checklist.phases_for("9.3") == []
    # Onbekend id → lege lijst, geen exception
    assert checklist.phases_for("99.9") == []


def test_governance_en_kroonjuweel_items_zijn_meta():
    """Governance-rapporten en kroonjuwelen-inventaris mappen niet op kill-chain."""
    for cid in ("1.1", "1.2", "8.3", "9.1", "9.2", "9.3"):
        assert checklist.phases_for(cid) == [], f"{cid} hoort meta (leeg) te zijn"


def test_kill_chain_phases_zijn_in_aanvalsvolgorde():
    expected = ["recon", "weaponization", "delivery", "exploitation",
                "installation", "c2", "actions"]
    assert checklist.KILL_CHAIN_PHASES == expected
