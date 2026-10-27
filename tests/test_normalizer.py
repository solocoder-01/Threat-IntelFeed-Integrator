
import pytest

from core.normalizer import normalize_indicator


def test_ipv4_normalization():
    assert normalize_indicator("203.0.113.10", "ipv4") == "203.0.113.10"


def test_invalid_ipv4_rejected():
    with pytest.raises(ValueError):
        normalize_indicator("999.1.1.1", "ipv4")


def test_domain_lowercase_and_trailing_dot():
    assert normalize_indicator("EXAMPLE.TEST.", "domain") == "example.test"


def test_invalid_domain_rejected():
    with pytest.raises(ValueError):
        normalize_indicator("-bad.example", "domain")


def test_url_scheme_and_host_normalized():
    result = normalize_indicator(
        "HTTPS://Example.test/login",
        "url",
    )
    assert result == "https://example.test/login"


def test_url_with_credentials_rejected():
    with pytest.raises(ValueError):
        normalize_indicator(
            "https://user:password@example.test/",
            "url",
        )


def test_invalid_url_port_rejected():
    with pytest.raises(ValueError):
        normalize_indicator("https://example.test:99999/", "url")


def test_sha256_lowercase():
    digest = "A" * 64
    assert normalize_indicator(digest, "sha256") == "a" * 64


def test_invalid_sha256_rejected():
    with pytest.raises(ValueError):
        normalize_indicator("abc123", "sha256")


def test_unsupported_indicator_type_rejected():
    with pytest.raises(ValueError):
        normalize_indicator("example.test", "email")
