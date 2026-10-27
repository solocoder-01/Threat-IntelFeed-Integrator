
"""Store and load threat-feed fetch status and freshness."""

import json
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STATUS_FILE = BASE_DIR / "data" / "feed_status.json"


def load_feed_status() -> dict:
    """Load the latest feed status."""
    default = {
        "feed": "URLhaus",
        "status": "UNKNOWN",
        "message": "No feed-fetch attempt recorded yet.",
        "indicator_count": 0,
        "last_attempt_utc": None,
        "last_success_utc": None,
    }

    if not STATUS_FILE.exists():
        return default

    try:
        record = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            return default
        return {**default, **record}
    except (json.JSONDecodeError, OSError):
        return {
            **default,
            "message": "Could not read feed status file.",
        }


def save_feed_status(
    status: str,
    message: str = "",
    indicator_count: int = 0,
) -> None:
    """Save fetch status while preserving the last successful fetch."""
    previous = load_feed_status()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    last_success = previous.get("last_success_utc")

    if status == "SUCCESS":
        last_success = now

    record = {
        "feed": "URLhaus",
        "status": status,
        "message": message,
        "indicator_count": indicator_count,
        "last_attempt_utc": now,
        "last_success_utc": last_success,
    }

    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATUS_FILE.write_text(
        json.dumps(record, indent=4),
        encoding="utf-8",
    )


def get_feed_freshness(max_age_hours: int = 24) -> dict:
    """Calculate age since the last successful fetch."""
    status = load_feed_status()
    last_success = status.get("last_success_utc")

    if not last_success:
        return {
            "state": "UNKNOWN",
            "age_hours": None,
            "message": "No successful fetch has been recorded yet.",
        }

    try:
        timestamp = datetime.fromisoformat(last_success)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        age_seconds = (
            datetime.now(timezone.utc) - timestamp.astimezone(timezone.utc)
        ).total_seconds()

        if age_seconds < 0:
            return {
                "state": "UNKNOWN",
                "age_hours": None,
                "message": "Successful-fetch timestamp is in the future.",
            }

        age_hours = age_seconds / 3600

    except (ValueError, TypeError):
        return {
            "state": "UNKNOWN",
            "age_hours": None,
            "message": "Successful-fetch timestamp is invalid.",
        }

    if age_hours <= max_age_hours:
        state = "FRESH"
        message = f"Last successful fetch was within {max_age_hours} hours."
    else:
        state = "STALE"
        message = f"No successful fetch within the last {max_age_hours} hours."

    return {
        "state": state,
        "age_hours": round(age_hours, 2),
        "message": message,
    }
