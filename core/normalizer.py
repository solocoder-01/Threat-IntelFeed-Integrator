
import ipaddress
import re
from urllib.parse import urlsplit


def normalize_indicator(value, indicator_type):
    """Validate and normalize a supported IOC."""

    value = value.strip()

    if indicator_type == "ipv4":
        return str(ipaddress.IPv4Address(value))

    if indicator_type == "domain":
        domain = value.rstrip(".").lower()

        if len(domain) > 253 or not domain:
            raise ValueError("Invalid domain length")

        labels = domain.split(".")

        for label in labels:
            if (
                not label
                or len(label) > 63
                or not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                    label,
                )
            ):
                raise ValueError("Invalid domain")

        return domain

    if indicator_type == "url":
        parts = urlsplit(value)

        if parts.scheme.lower() not in ("http", "https"):
            raise ValueError("Only HTTP/HTTPS URLs are supported")

        if not parts.hostname or parts.username or parts.password:
            raise ValueError("Invalid URL")

        if parts.port is not None and not (
            1 <= parts.port <= 65535
        ):
            raise ValueError("Invalid port")

        host = parts.hostname.lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"

        netloc = host
        if parts.port is not None:
            netloc = f"{host}:{parts.port}"

        return parts._replace(
            scheme=parts.scheme.lower(),
            netloc=netloc,
        ).geturl()

    if indicator_type == "sha256":
        if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError("SHA-256 must contain 64 hex characters")

        return value.lower()

    raise ValueError(f"Unsupported type: {indicator_type}")
