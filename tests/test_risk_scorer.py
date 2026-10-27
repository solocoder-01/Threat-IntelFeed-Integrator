
import pytest

from core.risk_scorer import calculate_risk


def test_single_source_score():
    result = calculate_risk({"DemoFeed": 80})

    assert result["average_confidence"] == 80
    assert result["source_bonus"] == 0
    assert result["risk_score"] == 80
    assert result["risk_level"] == "HIGH"


def test_multiple_sources_add_bonus():
    result = calculate_risk({
        "FeedA": 60,
        "FeedB": 80,
    })

    assert result["average_confidence"] == 70
    assert result["source_bonus"] == 10
    assert result["risk_score"] == 80
    assert result["risk_level"] == "HIGH"


def test_source_bonus_is_capped():
    result = calculate_risk({
        "FeedA": 50,
        "FeedB": 50,
        "FeedC": 50,
        "FeedD": 50,
    })

    assert result["source_bonus"] == 20
    assert result["risk_score"] == 70


@pytest.mark.parametrize(
    ("confidence", "expected_level"),
    [
        (0, "LOW"),
        (39, "LOW"),
        (40, "MEDIUM"),
        (69, "MEDIUM"),
        (70, "HIGH"),
        (100, "HIGH"),
    ],
)
def test_risk_level_boundaries(confidence, expected_level):
    result = calculate_risk({"DemoFeed": confidence})
    assert result["risk_level"] == expected_level


def test_empty_sources_rejected():
    with pytest.raises(ValueError):
        calculate_risk({})


@pytest.mark.parametrize("confidence", [-1, 101, True, 50.5, "80"])
def test_invalid_confidence_rejected(confidence):
    with pytest.raises(ValueError):
        calculate_risk({"DemoFeed": confidence})
