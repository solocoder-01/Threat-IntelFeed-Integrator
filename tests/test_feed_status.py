
import json
from datetime import datetime, timedelta, timezone

import feed_status


def test_recent_success_is_fresh(tmp_path, monkeypatch):
    status_file = tmp_path / "feed_status.json"
    monkeypatch.setattr(feed_status, "STATUS_FILE", status_file)

    now = datetime.now(timezone.utc)
    status_file.write_text(
        json.dumps({
            "feed": "URLhaus",
            "status": "SUCCESS",
            "message": "Fetch successful",
            "indicator_count": 1000,
            "last_attempt_utc": now.isoformat(),
            "last_success_utc": now.isoformat(),
        }),
        encoding="utf-8",
    )

    result = feed_status.get_feed_freshness()

    assert result["state"] == "FRESH"
    assert result["age_hours"] < 24


def test_old_success_is_stale(tmp_path, monkeypatch):
    status_file = tmp_path / "feed_status.json"
    monkeypatch.setattr(feed_status, "STATUS_FILE", status_file)

    old_time = datetime.now(timezone.utc) - timedelta(hours=25)
    status_file.write_text(
        json.dumps({"last_success_utc": old_time.isoformat()}),
        encoding="utf-8",
    )

    result = feed_status.get_feed_freshness()

    assert result["state"] == "STALE"
    assert result["age_hours"] > 24


def test_missing_success_timestamp_is_unknown(tmp_path, monkeypatch):
    status_file = tmp_path / "feed_status.json"
    monkeypatch.setattr(feed_status, "STATUS_FILE", status_file)

    result = feed_status.get_feed_freshness()

    assert result["state"] == "UNKNOWN"
    assert result["age_hours"] is None


def test_invalid_timestamp_is_unknown(tmp_path, monkeypatch):
    status_file = tmp_path / "feed_status.json"
    monkeypatch.setattr(feed_status, "STATUS_FILE", status_file)

    status_file.write_text(
        json.dumps({"last_success_utc": "not-a-valid-timestamp"}),
        encoding="utf-8",
    )

    result = feed_status.get_feed_freshness()

    assert result["state"] == "UNKNOWN"
    assert result["age_hours"] is None



def test_failed_fetch_preserves_last_success(tmp_path, monkeypatch):
    status_file = tmp_path / "feed_status.json"
    monkeypatch.setattr(feed_status, "STATUS_FILE", status_file)

    previous_success = (
        datetime.now(timezone.utc) - timedelta(hours=1)
    ).isoformat()

    status_file.write_text(
        json.dumps({
            "feed": "URLhaus",
            "status": "SUCCESS",
            "message": "Fetch successful",
            "indicator_count": 1000,
            "last_attempt_utc": previous_success,
            "last_success_utc": previous_success,
        }),
        encoding="utf-8",
    )

    feed_status.save_feed_status(
        status="FAILED",
        message="Connection timeout",
        indicator_count=0,
    )

    result = feed_status.load_feed_status()

    assert result["status"] == "FAILED"
    assert result["message"] == "Connection timeout"
    assert result["last_success_utc"] == previous_success


def test_first_failed_fetch_has_no_last_success(
    tmp_path, monkeypatch
):
    status_file = tmp_path / "feed_status.json"
    monkeypatch.setattr(feed_status, "STATUS_FILE", status_file)

    feed_status.save_feed_status(
        status="FAILED",
        message="Connection timeout",
        indicator_count=0,
    )

    result = feed_status.load_feed_status()

    assert result["status"] == "FAILED"
    assert result["last_success_utc"] is None
