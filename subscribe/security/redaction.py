# -*- coding: utf-8 -*-
"""Secret redaction helpers shared by HTTP, config and logging code."""

from __future__ import annotations

import os
import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "access_token", "refresh_token",
    "cookie", "session", "sessionid", "authorization", "apikey", "api_key",
    "private_key", "cvv", "cardnumber", "expiry",
}

_REDACTED = "***"


def _looks_sensitive(key: str) -> bool:
    text = (key or "").strip().lower()
    return text in SENSITIVE_KEYS or any(word in text for word in ("token", "password", "secret", "cookie", "authorization"))


def redact_mapping(data: object, sensitive_keys: set[str] | None = None) -> object:
    keys = sensitive_keys or SENSITIVE_KEYS
    if isinstance(data, dict):
        return {str(key): _REDACTED if _looks_sensitive(str(key)) else redact_mapping(value, keys) for key, value in data.items()}
    if isinstance(data, list):
        return [redact_mapping(item, keys) for item in data]
    return data


def redact_url(url: str) -> str:
    if not url or not isinstance(url, str):
        return ""
    try:
        parts = urlsplit(url.strip())
        query = "&".join(f"{key}={_REDACTED if _looks_sensitive(key) else value}" for key, value in parse_qsl(parts.query, keep_blank_values=True))
        netloc = parts.netloc
        if "@" in netloc:
            _, _, host_part = netloc.rpartition("@")
            netloc = host_part
        return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))
    except Exception:
        return re.sub(r"([?&])([^=&]+)(=[^&]*)?", lambda match: f"{match.group(1)}{match.group(2)}={_REDACTED}", url)


def secret_from_env(env_name: str, default: str = "") -> str:
    if not env_name:
        return default
    value = os.environ.get(env_name.strip(), "")
    return value if isinstance(value, str) else default
