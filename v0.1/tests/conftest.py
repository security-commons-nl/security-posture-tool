"""Pytest configuration: zorg dat modules in v0.1/ importeerbaar zijn + tmp-DB-fixture."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Geef elke test een eigen lege SQLite-DB + verse module-imports."""
    db_path = tmp_path / "test.sqlite"
    monkeypatch.setenv("DB_PATH", str(db_path))
    # Forceer herlaad zodat DB_PATH-constante opnieuw wordt gelezen
    for name in ("db", "evidence", "checklist"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
    import db as dbmod
    dbmod.init()
    return dbmod


@pytest.fixture
def fixtures_dir():
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def drops_tmp(tmp_path, monkeypatch):
    """Geef drops.py een tijdelijke DROPS_PATH."""
    monkeypatch.setenv("DROPS_PATH", str(tmp_path / "drops"))
    (tmp_path / "drops").mkdir(exist_ok=True)
    import importlib, sys
    if "drops" in sys.modules:
        importlib.reload(sys.modules["drops"])
    return tmp_path / "drops"
