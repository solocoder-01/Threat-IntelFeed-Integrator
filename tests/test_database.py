
import pytest

import core.database as database


@pytest.fixture
def temporary_database(tmp_path, monkeypatch):
    """Give each test its own temporary SQLite database."""
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(
        database,
        "DB_PATH",
        tmp_path / "test_threat_intel.db",
    )
    database.initialize_database()
    return database.DB_PATH


def make_record():
    return {
        "indicator": "203.0.113.10",
        "type": "ipv4",
        "sources": ["FeedA", "FeedB"],
        "source_count": 2,
        "average_confidence": 60,
        "source_bonus": 10,
        "risk_score": 70,
        "risk_level": "HIGH",
        "reasons": ["Test scoring reason"],
    }


def test_database_file_created(temporary_database):
    assert temporary_database.is_file()


def test_insert_indicator(temporary_database):
    database.upsert_indicator(make_record())

    records = database.list_indicators()

    assert len(records) == 1
    assert records[0]["indicator"] == "203.0.113.10"
    assert records[0]["risk_score"] == 70
    assert records[0]["risk_level"] == "HIGH"


def test_duplicate_indicator_updates_existing_record(temporary_database):
    record = make_record()
    database.upsert_indicator(record)

    updated_record = {
        **record,
        "sources": ["FeedA"],
        "source_count": 1,
        "average_confidence": 75,
        "source_bonus": 0,
        "risk_score": 75,
        "risk_level": "HIGH",
    }
    database.upsert_indicator(updated_record)

    records = database.list_indicators()

    assert len(records) == 1
    assert records[0]["source_count"] == 1
    assert records[0]["risk_score"] == 75


def test_invalid_score_is_rejected(temporary_database):
    record = make_record()
    record["risk_score"] = 20

    with pytest.raises(ValueError):
        database.upsert_indicator(record)

    assert database.list_indicators() == []


def test_invalid_indicator_type_is_rejected(temporary_database):
    record = make_record()
    record["type"] = "email"

    with pytest.raises(ValueError):
        database.upsert_indicator(record)

    assert database.list_indicators() == []


def test_invalid_limit_is_rejected(temporary_database):
    with pytest.raises(ValueError):
        database.list_indicators(limit=0)
