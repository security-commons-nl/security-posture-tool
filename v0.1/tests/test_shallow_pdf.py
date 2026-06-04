"""Tests voor shallow-PDF module (regex + datum-window)."""
from __future__ import annotations


RULES = {
    "9.3": {"must_match": [r"scope", r"finding|bevinding",
                           r"cvss|severity|risico"], "max_age_months": 12},
    "8.3": {"must_match": [r"scenario", r"respons",
                           r"verbeter|lessons"], "max_age_months": 6},
    "9.2": {"must_match": [r"bio\s*2", r"gap",
                           r"remediat|aanbeveling"], "max_age_months": 12},
    "6.3": {"must_match": [r"restore", r"rto", r"rpo"], "max_age_months": 12},
    "9.1": {"must_match": [r"patch", r"mfa", r"incident"], "max_age_months": 1},
}


def test_pentest_valid_pass(fixtures_dir):
    from connectors.shallow_pdf import evaluate
    out = evaluate(fixtures_dir / "pentest_valid.pdf", RULES["9.3"])
    assert out["verdict"] == "pass"


def test_pentest_stale(fixtures_dir):
    from connectors.shallow_pdf import evaluate
    out = evaluate(fixtures_dir / "pentest_stale.pdf", RULES["9.3"])
    assert out["verdict"] == "stale"


def test_pentest_incomplete_unparsed(fixtures_dir):
    from connectors.shallow_pdf import evaluate
    out = evaluate(fixtures_dir / "pentest_incomplete.pdf", RULES["9.3"])
    assert out["verdict"] == "unparsed"
    # specifiek: 'finding|bevinding' mist
    assert any("finding" in m for m in out["missing_regex"])


def test_tabletop_valid(fixtures_dir):
    from connectors.shallow_pdf import evaluate
    out = evaluate(fixtures_dir / "tabletop_valid.pdf", RULES["8.3"])
    assert out["verdict"] == "pass"


def test_bio2_valid(fixtures_dir):
    from connectors.shallow_pdf import evaluate
    out = evaluate(fixtures_dir / "bio2_valid.pdf", RULES["9.2"])
    assert out["verdict"] == "pass"


def test_restore_valid(fixtures_dir):
    from connectors.shallow_pdf import evaluate
    out = evaluate(fixtures_dir / "restore_valid.pdf", RULES["6.3"])
    assert out["verdict"] == "pass"


def test_kpi_regex_matches(fixtures_dir):
    """KPI-rapport heeft regex-match maar 1-mnd-window is streng;
    we testen dat óf pass óf stale, maar nooit unparsed."""
    from connectors.shallow_pdf import evaluate
    out = evaluate(fixtures_dir / "kpi_valid.pdf", RULES["9.1"])
    assert out["verdict"] in {"pass", "stale"}
