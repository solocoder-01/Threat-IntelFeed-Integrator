
import csv
from pathlib import Path

from core.risk_scorer import calculate_risk


BASE_DIR = Path(__file__).resolve().parent
INPUT_FILE = BASE_DIR / "data" / "normalized_iocs.csv"
OUTPUT_FILE = BASE_DIR / "data" / "scored_iocs.csv"

MAX_INPUT_BYTES = 5 * 1024 * 1024
MAX_ROWS = 100_000

REQUIRED_COLUMNS = {
    "indicator",
    "type",
    "sources",
    "source_count",
    "source_confidences",
}


def safe_csv_cell(value: str) -> str:
    """Reduce spreadsheet formula-injection risk on CSV export."""
    value = str(value)

    # Prefix dangerous leading characters so spreadsheet apps are
    # less likely to interpret untrusted content as a formula.
    if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value

    return value


def parse_confidences(raw: str) -> dict[str, int]:
    """Parse source:confidence pairs and reject malformed entries."""
    result = {}

    if not raw or len(raw) > 10_000:
        raise ValueError("Missing or oversized confidence data")

    for item in raw.split(";"):
        if ":" not in item:
            raise ValueError("Malformed source confidence entry")

        source, score_text = item.rsplit(":", 1)
        source = source.strip()

        if not source or source in result:
            raise ValueError("Empty or duplicate source")

        if not score_text.isascii() or not score_text.isdecimal():
            raise ValueError("Confidence must be a decimal integer")

        result[source] = int(score_text)

    return result


def main():
    if not INPUT_FILE.is_file():
        raise FileNotFoundError(f"Input file not found: {INPUT_FILE}")

    if INPUT_FILE.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("Input CSV exceeds the 5 MB safety limit")

    scored_rows = []
    rejected_rows = 0

    with INPUT_FILE.open(
        "r", newline="", encoding="utf-8-sig"
    ) as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("Input CSV is missing headers")

        reader.fieldnames = [
            name.strip().lower() if name else ""
            for name in reader.fieldnames
        ]

        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("Duplicate column names are not allowed")

        missing = REQUIRED_COLUMNS - set(reader.fieldnames)
        if missing:
            raise ValueError(f"Missing required columns: {sorted(missing)}")

        for row_number, row in enumerate(reader, start=1):
            if row_number > MAX_ROWS:
                raise ValueError("Input CSV exceeds the row limit")

            try:
                if None in row or any(value is None for value in row.values()):
                    raise ValueError("Malformed CSV row")

                indicator = row["indicator"].strip()
                indicator_type = row["type"].strip().lower()

                if not indicator or len(indicator) > 2048:
                    raise ValueError("Invalid indicator length")

                if indicator_type not in {
                    "ipv4", "domain", "url", "sha256"
                }:
                    raise ValueError("Unsupported indicator type")

                confidences = parse_confidences(
                    row["source_confidences"]
                )

                source_count_text = row["source_count"].strip()
                if not source_count_text.isascii() or not source_count_text.isdecimal():
                    raise ValueError("Invalid source count")

                declared_count = int(source_count_text)
                if declared_count != len(confidences):
                    raise ValueError("Source count does not match confidence data")

                result = calculate_risk(confidences)

                scored_rows.append({
                    "indicator": indicator,
                    "type": indicator_type,
                    "sources": row["sources"].strip(),
                    "source_count": result["source_count"],
                    "average_confidence": result["average_confidence"],
                    "source_bonus": result["source_bonus"],
                    "risk_score": result["risk_score"],
                    "risk_level": result["risk_level"],
                    "reasons": " | ".join(result["reasons"]),
                })

            except (ValueError, TypeError, AttributeError) as error:
                rejected_rows += 1
                print(f"Skipping row {row_number}: {error}")

    fieldnames = [
        "indicator",
        "type",
        "sources",
        "source_count",
        "average_confidence",
        "source_bonus",
        "risk_score",
        "risk_level",
        "reasons",
    ]

    # Write to a temporary file first; replace the output after success.
    temp_file = OUTPUT_FILE.with_suffix(".tmp")

    try:
        with temp_file.open(
            "w", newline="", encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()

            for row in scored_rows:
                writer.writerow({
                    key: safe_csv_cell(value)
                    for key, value in row.items()
                })

        temp_file.replace(OUTPUT_FILE)

    finally:
        if temp_file.exists():
            temp_file.unlink()

    print("\n--- IOC Risk Scoring Summary ---")
    print(f"Scored indicators: {len(scored_rows)}")
    print(f"Rejected rows: {rejected_rows}")
    print(f"Output saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
