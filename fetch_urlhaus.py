
"""Fetch and validate recent URLhaus indicators.

Downloads indicator text only. Never visits the reported URLs.
"""

import csv
import io
from pathlib import Path
import os

import requests
from feed_status import save_feed_status

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_FILE = BASE_DIR / "data" / "urlhaus_iocs.csv"

FEED_BASE_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
MAX_BYTES = 20 * 1024 * 1024  # 20 MB maximum
MAX_ROWS = 1000

# This is our project heuristic, not a confidence score supplied by URLhaus.
PROJECT_CONFIDENCE = 80




def fetch_feed():
    """Fetch recent URLhaus URL records through the API."""
    import os

    auth_key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    if not auth_key:
        raise RuntimeError("Set URLHAUS_AUTH_KEY in PowerShell first.")

    response = requests.get(
        "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        headers={
            "Auth-Key": auth_key,
            "User-Agent": "ThreatIntelFeedIntegrator/1.0",
        },
        timeout=(5, 20),
    )
    response.raise_for_status()

    try:
        data = response.json()
    except ValueError as error:
        raise ValueError("URLhaus returned invalid JSON.") from error

    if data.get("query_status") != "ok":
        raise ValueError(
            f"URLhaus API returned status: {data.get('query_status')}"
        )

    import json
    return json.dumps(data)





def parse_feed(text):
    """Parse URLhaus JSON and return normalized IOC rows."""
    import json
    from core.normalizer import normalize_indicator

    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError("Invalid JSON returned by URLhaus") from error

    if data.get("query_status") != "ok":
        raise ValueError(
            f"URLhaus query failed: {data.get('query_status')}"
        )

    rows = []
    seen = set()

    for item in data.get("urls", []):
        if len(rows) >= MAX_ROWS:
            break

        if not isinstance(item, dict):
            continue

        if item.get("threat") != "malware_download":
            continue

        url = item.get("url", "")
        if not isinstance(url, str) or len(url) > 2048:
            continue

        try:
            normalized = normalize_indicator(url, "url")
        except (ValueError, TypeError):
            continue

        if normalized in seen:
            continue

        seen.add(normalized)
        rows.append({
            "indicator": normalized,
            "type": "url",
            "source": "URLhaus",
            "confidence": PROJECT_CONFIDENCE,
        })

    return rows



def main():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    try:
        text = fetch_feed()
        rows = parse_feed(text)

        fieldnames = ["indicator", "type", "source", "confidence"]
        temp_file = OUTPUT_FILE.with_suffix(".tmp")

        try:
            with temp_file.open(
                "w", newline="", encoding="utf-8"
            ) as file:
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

            temp_file.replace(OUTPUT_FILE)
        finally:
            if temp_file.exists():
                temp_file.unlink()

        save_feed_status(
            status="SUCCESS",
            message="Feed fetched and saved successfully.",
            indicator_count=len(rows),
        )

        print("--- URLhaus Feed Summary ---")
        print(f"Valid unique URLs: {len(rows)}")
        print(f"Output: {OUTPUT_FILE}")
        print("Feed status saved: SUCCESS")
        print(
            "Note: confidence 80 is a project heuristic, "
            "not a score provided by URLhaus."
        )

        return len(rows)

    except Exception as error:
        try:
            save_feed_status(
                status="FAILED",
                message=f"{type(error).__name__}: {error}",
                indicator_count=0,
            )
        except OSError as status_error:
            print(f"Could not save feed status: {status_error}")

        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"\nURLhaus fetch failed: {error}")
        raise SystemExit(1)
