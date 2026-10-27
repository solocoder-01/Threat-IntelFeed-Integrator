"""Combine threat feeds and run the IOC scoring/import pipeline."""

import csv
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from pipeline_status import save_pipeline_status
from core.normalizer import normalize_indicator


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

INPUT_FILES = [
    DATA_DIR / "sample_iocs.csv",
    DATA_DIR / "urlhaus_iocs.csv",
]

NORMALIZED_FILE = DATA_DIR / "normalized_iocs.csv"

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_TOTAL_ROWS = 100_000

REQUIRED_COLUMNS = {"indicator", "type", "source", "confidence"}


def read_feed(path):
    """Read a bounded CSV feed and validate its structure."""
    if not path.is_file():
        print(f"Feed not found; skipping: {path.name}")
        return []

    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"{path.name} exceeds the 5 MB limit")

    records = []

    with path.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError(f"{path.name} has no CSV headers")

        reader.fieldnames = [
            name.strip().lower() if name else ""
            for name in reader.fieldnames
        ]

        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError(f"{path.name} has duplicate headers")

        missing = REQUIRED_COLUMNS - set(reader.fieldnames)
        if missing:
            raise ValueError(
                f"{path.name} is missing columns: {sorted(missing)}"
            )

        for row_number, row in enumerate(reader, start=1):
            if row_number > MAX_TOTAL_ROWS:
                raise ValueError(
                    f"{path.name} exceeds the row limit"
                )

            if None in row or any(value is None for value in row.values()):
                print(f"Skipping malformed row {row_number} in {path.name}")
                continue

            try:
                raw_indicator = row["indicator"].strip()
                indicator_type = row["type"].strip().lower()
                source = row["source"].strip()
                confidence_text = row["confidence"].strip()

                if not source or len(source) > 200:
                    raise ValueError("Invalid source name")

                if (
                    not confidence_text.isascii()
                    or not confidence_text.isdecimal()
                ):
                    raise ValueError("Confidence must be an integer")

                confidence = int(confidence_text)

                if not 0 <= confidence <= 100:
                    raise ValueError("Confidence must be between 0 and 100")

                normalized = normalize_indicator(
                    raw_indicator, indicator_type
                )

                records.append({
                    "indicator": normalized,
                    "type": indicator_type,
                    "source": source,
                    "confidence": confidence,
                })

            except (ValueError, TypeError, AttributeError) as error:
                print(
                    f"Skipping {path.name} row {row_number}: {error}"
                )

    print(f"Loaded {len(records)} valid records from {path.name}")
    return records


def build_normalized(records):
    """Deduplicate indicators and retain confidence per source."""
    merged = defaultdict(dict)

    for record in records:
        key = (record["type"], record["indicator"])
        source = record["source"]
        confidence = record["confidence"]

        # If a source reports the same IOC more than once,
        # retain its highest supplied confidence value.
        previous = merged[key].get(source)
        if previous is None or confidence > previous:
            merged[key][source] = confidence

    output_rows = []

    for (indicator_type, indicator), source_scores in sorted(
        merged.items()
    ):
        output_rows.append({
            "indicator": indicator,
            "type": indicator_type,
            "sources": ";".join(sorted(source_scores)),
            "source_count": len(source_scores),
            "source_confidences": ";".join(
                f"{source}:{score}"
                for source, score in sorted(source_scores.items())
            ),
        })

    return output_rows


def write_normalized(rows):
    """Write the normalized CSV atomically."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "indicator",
        "type",
        "sources",
        "source_count",
        "source_confidences",
    ]

    temp_file = NORMALIZED_FILE.with_suffix(".tmp")

    try:
        with temp_file.open(
            "w", newline="", encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        temp_file.replace(NORMALIZED_FILE)

    finally:
        if temp_file.exists():
            temp_file.unlink()


def run_script(script_name):
    """Run a project stage and stop if it fails."""
    script_path = BASE_DIR / script_name

    print(f"\n--- Running {script_name} ---")

    result = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=BASE_DIR,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"{script_name} failed with exit code {result.returncode}"
        )


def main():
    all_records = []
    total_rows = 0

    for path in INPUT_FILES:
        if path.is_file() and path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"{path.name} exceeds the 5 MB limit")

        feed_records = read_feed(path)
        total_rows += len(feed_records)

        if total_rows > MAX_TOTAL_ROWS:
            raise ValueError("Combined feed row limit exceeded")

        all_records.extend(feed_records)

    if not all_records:
        raise RuntimeError(
            "No valid indicators found. Check your input feed files."
        )

    normalized_rows = build_normalized(all_records)
    write_normalized(normalized_rows)

    print("\n--- Feed Merge Summary ---")
    print(f"Valid input records: {len(all_records)}")
    print(f"Unique indicators: {len(normalized_rows)}")
    print(f"Normalized output: {NORMALIZED_FILE}")

    run_script("score_iocs.py")
    run_script("import_to_db.py")

    print("\nPipeline completed successfully.")
    print("Click Refresh dashboard to reload the latest database records.")
    return len(normalized_rows)



if __name__ == "__main__":
    try:
        indicator_count = main()

        save_pipeline_status(
            status="SUCCESS",
            message="Pipeline completed successfully.",
            indicator_count=indicator_count,
        )

        print("\nPipeline status saved: SUCCESS")

    except (OSError, ValueError, RuntimeError, csv.Error) as error:
        try:
            save_pipeline_status(
                status="FAILED",
                message=str(error),
                indicator_count=0,
            )
        except OSError as status_error:
            print(f"Could not save pipeline status: {status_error}")

        print(f"\nPIPELINE FAILED: {error}")
        sys.exit(1)
