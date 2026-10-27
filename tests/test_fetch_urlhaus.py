
import csv
from datetime import datetime, timedelta, timezone

import pytest

import fetch_urlhaus
import feed_status


def test_fetch_failure_records_failed_status(
    tmp_path, monkeypatch
):
    output_file = tmp_path / "urlhaus_iocs.csv"
    status_file = tmp_path / "feed_status.json"

    monkeypatch.setattr(fetch_urlhaus, "OUTPUT_FILE", output_file)
    monkeypatch.setattr(feed_status, "STATUS_FILE", status_file)

    previous_success = (
        datetime.now(timezone.utc) - timedelta(hours=2)
    ).isoformat()

    feed_status.save_feed_status(
        status="SUCCESS",
        message="Previous fetch successful",
        indicator_count=50,
    )

    # Set a known previous successful timestamp.
    import json

    status_file.write_text(
        json.dumps({
            "feed": "URLhaus",
            "status": "SUCCESS",
            "message": "Previous fetch successful",
            "indicator_count": 50,
            "last_attempt_utc": previous_success,
            "last_success_utc": previous_success,
        }),
        encoding="utf-8",
    )

    def fail_fetch():
        raise RuntimeError("Simulated connection failure")

    monkeypatch.setattr(fetch_urlhaus, "fetch_feed", fail_fetch)

    with pytest.raises(RuntimeError, match="Simulated connection failure"):
        fetch_urlhaus.main()

    result = feed_status.load_feed_status()

    assert result["status"] == "FAILED"
    assert "Simulated connection failure" in result["message"]
    assert result["last_success_utc"] == previous_success


def test_failed_fetch_does_not_replace_existing_csv(
    tmp_path, monkeypatch
):
    output_file = tmp_path / "urlhaus_iocs.csv"
    status_file = tmp_path / "feed_status.json"

    original_content = (
        "indicator,type,source,confidence\n"
        "https://example.invalid/test,url,URLhaus,80\n"
    )
    output_file.write_text(original_content, encoding="utf-8")

    monkeypatch.setattr(fetch_urlhaus, "OUTPUT_FILE", output_file)
    monkeypatch.setattr(feed_status, "STATUS_FILE", status_file)

    def fail_fetch():
        raise RuntimeError("Simulated connection failure")

    monkeypatch.setattr(fetch_urlhaus, "fetch_feed", fail_fetch)

    with pytest.raises(RuntimeError, match="Simulated connection failure"):
        fetch_urlhaus.main()

    assert output_file.read_text(encoding="utf-8") == original_content
