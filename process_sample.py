
import csv
from pathlib import Path

from core.normalizer import normalize_indicator

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_FILE = DATA_DIR / "normalized_iocs.csv"

INPUT_FILES = [
    DATA_DIR / "sample_iocs.csv",
    DATA_DIR / "urlhaus_iocs.csv",
]

REQUIRED_COLUMNS = {
    "indicator",
    "type",
    "source",
    "confidence",
}


def process_feed():
    unique_iocs = {}
    invalid_count = 0
    input_count = 0

    for input_file in INPUT_FILES:
        if not input_file.is_file():
            print(f"Feed not found, skipping: {input_file.name}")
            continue

        print(f"\nReading: {input_file.name}")

        with input_file.open(
            "r", newline="", encoding="utf-8-sig"
        ) as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames:
                raise ValueError(
                    f"{input_file.name} is missing CSV headers"
                )

            reader.fieldnames = [
                name.strip().lower() if name else ""
                for name in reader.fieldnames
            ]

            if len(reader.fieldnames) != len(set(reader.fieldnames)):
                raise ValueError(
                    f"Duplicate headers in {input_file.name}"
                )

            missing = REQUIRED_COLUMNS - set(reader.fieldnames)
            if missing:
                raise ValueError(
                    f"{input_file.name} missing columns: "
                    f"{sorted(missing)}"
                )

            for row in reader:
                input_count += 1

                try:
                    if None in row or any(
                        value is None for value in row.values()
                    ):
                        raise ValueError("Malformed CSV row")

                    raw_indicator = row["indicator"]
                    indicator_type = row["type"].strip().lower()
                    source = row["source"].strip()
                    confidence_text = row["confidence"].strip()

                    if indicator_type not in {
                        "ipv4", "domain", "url", "sha256"
                    }:
                        raise ValueError("Unsupported IOC type")

                    if not source or len(source) > 200:
                        raise ValueError("Invalid source name")

                    if (
                        not confidence_text.isascii()
                        or not confidence_text.isdecimal()
                    ):
                        raise ValueError("Invalid confidence value")

                    confidence = int(confidence_text)
                    if not 0 <= confidence <= 100:
                        raise ValueError(
                            "Confidence must be between 0 and 100"
                        )

                    indicator = normalize_indicator(
                        raw_indicator, indicator_type
                    )

                    key = (indicator_type, indicator)

                    if key not in unique_iocs:
                        unique_iocs[key] = {
                            "indicator": indicator,
                            "type": indicator_type,
                            "sources": set(),
                            "confidence_values": {},
                        }

                    record = unique_iocs[key]
                    record["sources"].add(source)
                    record["confidence_values"][source] = confidence

                except (
                    ValueError, TypeError, KeyError, AttributeError
                ) as error:
                    invalid_count += 1
                    print(
                        f"Skipping {input_file.name}, "
                        f"row {input_count}: {error}"
                    )

    if input_count == 0:
        raise ValueError("No input rows were found in the available feeds")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temp_file = OUTPUT_FILE.with_suffix(".tmp")

    try:
        with temp_file.open(
            "w", newline="", encoding="utf-8"
        ) as file:
            fieldnames = [
                "indicator",
                "type",
                "sources",
                "source_count",
                "source_confidences",
            ]
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()

            for record in unique_iocs.values():
                confidence_text = ";".join(
                    f"{source}:{score}"
                    for source, score in sorted(
                        record["confidence_values"].items()
                    )
                )

                writer.writerow({
                    "indicator": record["indicator"],
                    "type": record["type"],
                    "sources": ";".join(sorted(record["sources"])),
                    "source_count": len(record["confidence_values"]),
                    "source_confidences": confidence_text,
                })

        temp_file.replace(OUTPUT_FILE)

    finally:
        if temp_file.exists():
            temp_file.unlink()

    print("\n--- Combined Feed Summary ---")
    print(f"Input rows: {input_count}")
    print(f"Unique indicators: {len(unique_iocs)}")
    print(f"Invalid rows skipped: {invalid_count}")
    print(f"Output saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    process_feed()
