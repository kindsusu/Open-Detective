"""Secret-minimizing evidence helpers."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from urllib.parse import urlsplit


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def safe_url(url: str) -> str:
    """Return an origin-level display URL without userinfo, path data or query."""
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = parts.hostname
        port = parts.port
    except (TypeError, ValueError):
        return "<invalid-url>"
    if scheme not in {"http", "https"} or not host:
        return "<invalid-url>"
    try:
        host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return "<invalid-url>"
    shown_host = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    authority = shown_host if port in (None, default) else f"{shown_host}:{port}"
    suffix = "/<path-omitted>" if parts.path not in ("", "/") else "/"
    if parts.query:
        suffix += "?<query-omitted>"
    if parts.fragment:
        suffix += "#<fragment-omitted>"
    return _CONTROL.sub("", f"{scheme}://{authority}{suffix}")[:512]


def stable_ref(url: str, key: bytes | str | None = None) -> str:
    """Return a keyed stable reference, or a non-correlatable random reference."""
    raw = url.encode("utf-8", "surrogatepass")
    if key is None:
        return f"opaque:{secrets.token_hex(16)}"
    if isinstance(key, str):
        key = key.encode("utf-8")
    digest = hmac.new(key, raw, hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def clean_text(value: object, limit: int = 256) -> str:
    """Sanitize untrusted labels/header values for JSON and terminal output."""
    text = _CONTROL.sub(" ", str(value)).replace("\t", " ")
    return " ".join(text.split())[:limit]
