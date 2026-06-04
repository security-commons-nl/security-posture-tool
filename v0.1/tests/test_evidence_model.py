"""Tests voor evidence-schrijflaag en state-afleiding."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone


def test_sha256_bytes_is_deterministic():
    from evidence import sha256_bytes
    assert sha256_bytes(b"hello") == sha256_bytes(b"hello")
    assert sha256_bytes(b"hello") != sha256_bytes(b"world")


def test_write_and_fetch_evidence(tmp_db):
    from evidence import write_evidence, latest_for, sha256_bytes
    raw = b"graph-response-body"
    h = write_evidence(
        checklist_id="3.1",
        source_type="graph_api",
        source_ref="graph:users:2026-04-19T10:00:00Z",
        raw_bytes=raw,
        artefact_date="2026-04-19T10:00:00Z",
        parsed_summary={"total": 10, "covered": 10, "pct": 100},
        parser_name="graph_mfa_v1",
        verdict="pass",
    )
    assert h == sha256_bytes(raw)
    row = latest_for("3.1")
    assert row is not None
    assert row["sha256"] == h
    assert row["verdict"] == "pass"
    assert row["parser_name"] == "graph_mfa_v1"
    summary = json.loads(row["parsed_summary"])
    assert summary["pct"] == 100


def test_derive_state_no_evidence(tmp_db):
    from evidence import derive_state
    state = derive_state("9.3")
    assert state["measured_value"] == "geen bewijs"
    assert state["verdict"] is None


def test_derive_state_fail_with_pct(tmp_db):
    from evidence import write_evidence, derive_state
    write_evidence(
        checklist_id="3.4", source_type="intune_csv",
        source_ref="uploads/laps.csv", raw_bytes=b"x",
        artefact_date=None,
        parsed_summary={"total": 10, "covered": 6, "pct": 60},
        parser_name="laps_csv_v1", verdict="fail",
    )
    state = derive_state("3.4")
    assert state["verdict"] == "fail"
    assert "6/10" in state["measured_value"]
    assert "60%" in state["measured_value"]


def test_derive_state_stale(tmp_db):
    from evidence import write_evidence, derive_state
    write_evidence(
        checklist_id="9.3", source_type="report_pdf",
        source_ref="drops/pentest_2024.pdf", raw_bytes=b"x",
        artefact_date="2024-01-01T00:00:00+00:00",
        parsed_summary={"age_days": 720, "max_age_months": 12},
        parser_name="shallow_pentest_v1",
        verdict="stale",
    )
    state = derive_state("9.3")
    assert state["verdict"] == "stale"


def test_write_evidence_rejects_unknown_verdict(tmp_db):
    import pytest
    from evidence import write_evidence
    with pytest.raises(ValueError):
        write_evidence(
            checklist_id="1.1", source_type="x", source_ref="y",
            raw_bytes=b"", artefact_date=None, parsed_summary=None,
            parser_name=None, verdict="green",
        )


def test_write_evidence_syncs_checklist_state(tmp_db):
    from evidence import write_evidence
    write_evidence(
        checklist_id="3.1", source_type="graph_api",
        source_ref="graph:users:now", raw_bytes=b"data",
        artefact_date=None,
        parsed_summary={"total": 5, "covered": 5, "pct": 100},
        parser_name="graph_mfa_v1", verdict="pass",
    )
    rows = tmp_db.fetch_checklist()
    # checklist_state moet ook zijn bijgewerkt
    row31 = next(r for r in rows if r["checklist_id"] == "3.1")
    assert "5/5" in row31["measured_value"]
    assert "100%" in row31["measured_value"]
    assert "verdict=pass" in row31["notes"]


def test_multiple_evidence_rows_latest_wins(tmp_db):
    from evidence import write_evidence, latest_for
    write_evidence(
        checklist_id="3.4", source_type="intune_csv", source_ref="u1",
        raw_bytes=b"1", artefact_date=None,
        parsed_summary={"total": 2, "covered": 1, "pct": 50},
        parser_name="laps_csv_v1", verdict="fail",
    )
    write_evidence(
        checklist_id="3.4", source_type="intune_csv", source_ref="u2",
        raw_bytes=b"2", artefact_date=None,
        parsed_summary={"total": 2, "covered": 2, "pct": 100},
        parser_name="laps_csv_v1", verdict="pass",
    )
    latest = latest_for("3.4")
    assert latest["source_ref"] == "u2"
    assert latest["verdict"] == "pass"


def test_all_37_items_seeded(tmp_db):
    import checklist
    checklist.seed_if_empty()
    rows = tmp_db.fetch_checklist()
    assert len(rows) == 37
    ids = {r["checklist_id"] for r in rows}
    # Spot-checks per categorie
    assert "1.1" in ids and "1.2" in ids and "1.3" in ids
    assert "2.1" in ids and "2.5" in ids
    assert "3.1" in ids and "3.5" in ids
    assert "4.1" in ids and "4.6" in ids
    assert "5.1" in ids and "5.4" in ids
    assert "6.1" in ids and "6.3" in ids
    assert "7.1" in ids and "7.4" in ids
    assert "8.1" in ids and "8.4" in ids
    assert "9.1" in ids and "9.3" in ids


def test_seed_idempotent(tmp_db):
    import checklist
    checklist.seed_if_empty()
    checklist.seed_if_empty()
    rows = tmp_db.fetch_checklist()
    assert len(rows) == 37


def test_seed_does_not_overwrite_evidence(tmp_db):
    from evidence import write_evidence
    import checklist
    checklist.seed_if_empty()
    write_evidence(
        checklist_id="3.1", source_type="graph_api", source_ref="x",
        raw_bytes=b"x", artefact_date=None,
        parsed_summary={"total": 3, "covered": 3, "pct": 100},
        parser_name="graph_mfa_v1", verdict="pass",
    )
    checklist.seed_if_empty()  # opnieuw seeden mag niet terugzetten
    rows = tmp_db.fetch_checklist()
    row31 = next(r for r in rows if r["checklist_id"] == "3.1")
    assert "3/3" in row31["measured_value"]
