
"""SQLite storage for the Threat IntelFeed Integrator."""

import json
import os
import sqlite3
from pathlib import Path
from contextlib import contextmanager

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "threat_intel.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY,
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL
        CHECK (indicator_type IN ('ipv4', 'domain', 'url', 'sha256')),
    sources_json TEXT NOT NULL,
    source_count INTEGER NOT NULL CHECK (source_count >= 1),
    average_confidence INTEGER NOT NULL
        CHECK (average_confidence BETWEEN 0 AND 100),
    source_bonus INTEGER NOT NULL CHECK (source_bonus BETWEEN 0 AND 20),
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL
        CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
    reasons_json TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (indicator_type, indicator)
);

CREATE INDEX IF NOT EXISTS idx_indicators_risk
ON indicators (risk_level);

CREATE INDEX IF NOT EXISTS idx_indicators_type
ON indicators (indicator_type);
"""


def connect_db():
    """Open a local SQLite connection with safe defaults."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        DB_PATH,
        timeout=5,
    )
    connection.row_factory = sqlite3.Row

    # Enforce foreign key checks if relationships are added later.
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")

    return connection


@contextmanager
def db_session():
    """Manage a SQLite connection and always close it."""
    connection = connect_db()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database():
    """Create schema and restrict the DB file where supported."""
    with db_session() as connection:
        connection.executescript(SCHEMA)

    # Best-effort local file permission restriction.
    # Windows uses ACLs; chmod is not a full Windows ACL manager.
    if os.name != "nt":
        try:
            DB_PATH.chmod(0o600)
        except OSError:
            pass


def upsert_indicator(record):
    """Insert an indicator or update its existing record safely."""
    required = {
        "indicator",
        "type",
        "sources",
        "source_count",
        "average_confidence",
        "source_bonus",
        "risk_score",
        "risk_level",
        "reasons",
    }

    if set(record) != required:
        raise ValueError("Unexpected database record fields")

    indicator = record["indicator"]
    indicator_type = record["type"]
    sources = record["sources"]
    reasons = record["reasons"]

    if not isinstance(indicator, str) or not indicator or len(indicator) > 2048:
        raise ValueError("Invalid indicator")

    if indicator_type not in {"ipv4", "domain", "url", "sha256"}:
        raise ValueError("Unsupported indicator type")

    if not isinstance(sources, list) or not sources:
        raise ValueError("Sources must be a non-empty list")

    if not all(isinstance(s, str) and s.strip() for s in sources):
        raise ValueError("Invalid source name")

    sources = sorted(set(s.strip() for s in sources))

    if not isinstance(reasons, list) or not all(
        isinstance(reason, str) for reason in reasons
    ):
        raise ValueError("Reasons must be a list of strings")

    source_count = record["source_count"]
    average_confidence = record["average_confidence"]
    source_bonus = record["source_bonus"]
    risk_score = record["risk_score"]
    risk_level = record["risk_level"]

    numeric_values = (
        source_count,
        average_confidence,
        source_bonus,
        risk_score,
    )

    if any(type(value) is not int for value in numeric_values):
        raise ValueError("Numeric fields must be integers")

    if source_count != len(sources) or source_count < 1:
        raise ValueError("Source count mismatch")

    if not 0 <= average_confidence <= 100:
        raise ValueError("Invalid average confidence")

    if not 0 <= source_bonus <= 20:
        raise ValueError("Invalid source bonus")

    if not 0 <= risk_score <= 100:
        raise ValueError("Invalid risk score")

    if risk_level not in {"LOW", "MEDIUM", "HIGH"}:
        raise ValueError("Invalid risk level")

    expected_score = min(average_confidence + source_bonus, 100)
    expected_level = (
        "HIGH" if expected_score >= 70
        else "MEDIUM" if expected_score >= 40
        else "LOW"
    )

    if risk_score != expected_score or risk_level != expected_level:
        raise ValueError("Risk score or level does not match scoring rules")

    # JSON serialization avoids ambiguous custom separators.
    sources_json = json.dumps(sources, ensure_ascii=True)
    reasons_json = json.dumps(reasons, ensure_ascii=True)

    with db_session() as connection:
        connection.execute(
            """
            INSERT INTO indicators (
                indicator, indicator_type, sources_json, source_count,
                average_confidence, source_bonus, risk_score, risk_level,
                reasons_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(indicator_type, indicator) DO UPDATE SET
                sources_json = excluded.sources_json,
                source_count = excluded.source_count,
                average_confidence = excluded.average_confidence,
                source_bonus = excluded.source_bonus,
                risk_score = excluded.risk_score,
                risk_level = excluded.risk_level,
                reasons_json = excluded.reasons_json,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                indicator,
                indicator_type,
                sources_json,
                source_count,
                average_confidence,
                source_bonus,
                risk_score,
                risk_level,
                reasons_json,
            ),
        )


def list_indicators(limit=100):
    """Return recent indicators with a bounded result size."""
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("Limit must be an integer between 1 and 1000")

    with db_session() as connection:
        rows = connection.execute(
            """
            SELECT indicator, indicator_type, source_count,
                   risk_score, risk_level, updated_at
            FROM indicators
            ORDER BY risk_score DESC, indicator ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]
