
"""Explainable, deterministic IOC risk scoring.

This is a triage heuristic, not proof that an IOC is malicious.
"""

from collections.abc import Mapping


def calculate_risk(confidence_values: Mapping[str, int]) -> dict:
    """Calculate an explainable score from per-source confidence.

    Confidence values must be integers from 0 to 100.
    Each source contributes once.
    """

    if not isinstance(confidence_values, Mapping):
        raise ValueError("Confidence data must be a mapping")

    if not confidence_values:
        raise ValueError("At least one source is required")

    validated = {}

    for source, confidence in confidence_values.items():
        if not isinstance(source, str) or not source.strip():
            raise ValueError("Source name must not be empty")

        # bool is a subclass of int in Python, so reject it explicitly.
        if isinstance(confidence, bool) or not isinstance(confidence, int):
            raise ValueError("Confidence must be an integer")

        if not 0 <= confidence <= 100:
            raise ValueError("Confidence must be between 0 and 100")

        validated[source.strip()] = confidence

    # Average confidence across unique sources.
    average_confidence = round(
        sum(validated.values()) / len(validated)
    )

    # Independent-source corroboration bonus, capped at 20.
    source_bonus = min((len(validated) - 1) * 10, 20)

    score = min(average_confidence + source_bonus, 100)

    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    reasons = [
        f"Average source confidence: {average_confidence}/100",
        f"Unique source count: {len(validated)}",
        f"Corroboration bonus: +{source_bonus}",
    ]

    if len(validated) == 1:
        reasons.append("Only one source; independent corroboration is limited")

    reasons.append(
        "Heuristic score only; verify before taking action"
    )

    return {
        "risk_score": score,
        "risk_level": level,
        "average_confidence": average_confidence,
        "source_count": len(validated),
        "source_bonus": source_bonus,
        "reasons": reasons,
    }
