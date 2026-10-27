
import json
from datetime import datetime, timezone
from pathlib import Path

STATUS_FILE = Path(__file__).resolve().parent / "data" / "pipeline_status.json"


def save_pipeline_status(
    status: str,
    message: str = "",
    indicator_count: int = 0,
) -> None:
    """Save the latest pipeline execution status."""
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "status": status,
        "message": message,
        "indicator_count": indicator_count,
        "last_run_utc": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
    }

    STATUS_FILE.write_text(
        json.dumps(record, indent=4),
        encoding="utf-8",
    )


def load_pipeline_status() -> dict:
    """Read the latest saved pipeline status."""
    if not STATUS_FILE.exists():
        return {
            "status": "UNKNOWN",
            "message": "Pipeline has not recorded a run yet.",
            "indicator_count": 0,
            "last_run_utc": None,
        }

    try:
        return json.loads(STATUS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {
            "status": "UNKNOWN",
            "message": "Could not read pipeline status.",
            "indicator_count": 0,
            "last_run_utc": None,
        }
