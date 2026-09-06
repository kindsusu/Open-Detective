"""Fail-closed authorization policy for anonymous exposure observations."""

from __future__ import annotations

import ipaddress
import json
import re
import threading
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, unquote_to_bytes, urlsplit, urlunsplit


class PolicyError(ValueError):
    """A safe, operator-facing policy rejection."""


class Budget:
    """Thread-safe request budget shared by all fetches for one scope."""

    def __init__(self, maximum: int):
        self.maximum = maximum
        self._used = 0
        self._lock = threading.Lock()

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    def consume(self) -> None:
        with self._lock:
            if self._used >= self.maximum:
                raise PolicyError("request budget exhausted")
            self._used += 1


@dataclass(frozen=True)
class _Target:
    origin: str
    owner: str
    ownership_evidence: str
    path_prefixes: tuple[str, ...]


_DANGEROUS_QUERY_KEY = re.compile(
    r"(?:^|[_\-.])(?:access[_-]?token|auth|authorization|bearer|capability|"
    r"credential|jwt|key|pass(?:word)?|secret|session|share|sig(?:nature)?|"
    r"signed|ticket|token)(?:$|[_\-.])",
    re.IGNORECASE,
)
_DANGEROUS_COMPACT_KEYS = {
    "accesskey", "accesstoken", "apikey", "api_key", "assertion", "auth",
    "authorization", "awsaccesskeyid", "bearer", "capability", "code",
    "credential", "expires", "googleaccessid", "idtoken", "jwt", "key",
    "keypairid", "password", "policy", "refreshtoken", "samlresponse", "secret",
    "securitytoken", "session", "sharetoken", "sig", "signature", "signedurl",
    "state", "ticket", "token", "xamzcredential", "xamzsecuritytoken",
    "xamzsignature", "xgoogcredential", "xgoogsignature",
}
_DANGEROUS_COMPACT_KEYS = frozenset(
    re.sub(r"[^a-z0-9]", "", item) for item in _DANGEROUS_COMPACT_KEYS
)
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")
_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise PolicyError(f"invalid {name}")
    return value


def _decode_path(raw_path: str) -> str:
    if _PERCENT.search(raw_path):
        raise PolicyError("invalid path encoding")
    current = raw_path or "/"
    for _ in range(4):
        try:
            decoded = unquote_to_bytes(current).decode("utf-8", "strict")
        except (UnicodeDecodeError, ValueError):
            raise PolicyError("invalid path encoding") from None
        if decoded == current:
            break
        current = decoded
    else:
        raise PolicyError("excessive path encoding")
    current = unicodedata.normalize("NFC", current)
    if "%" in current or "\\" in current or _CONTROL_OR_SPACE.search(current) or "//" in current:
        raise PolicyError("unsafe path")
    if not current.startswith("/"):
        raise PolicyError("invalid path")
    if any(part in {".", ".."} for part in current.split("/")):
        raise PolicyError("path traversal rejected")
    return current


def _canonical_origin(parts: Any) -> tuple[str, str, int]:
    if parts.scheme.lower() != "https":
        raise PolicyError("https is required")
    if parts.username is not None or parts.password is not None:
        raise PolicyError("credentials in URL rejected")
    try:
        host = parts.hostname
        port = parts.port or 443
    except ValueError:
        raise PolicyError("invalid authority") from None
    if not host or _CONTROL_OR_SPACE.search(host):
        raise PolicyError("invalid host")
    try:
        host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise PolicyError("invalid host") from None
    if not host or port < 1 or port > 65535:
        raise PolicyError("invalid authority")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        authority_host = host
    else:
        authority_host = f"[{literal.compressed}]" if literal.version == 6 else literal.compressed
        host = literal.compressed
    authority = authority_host if port == 443 else f"{authority_host}:{port}"
    return f"https://{authority}", host, port


def _normalize_url(raw: str, *, check_query: bool = True) -> tuple[str, str]:
    if not isinstance(raw, str) or not raw or _CONTROL_OR_SPACE.search(raw):
        raise PolicyError("invalid URL")
    try:
        parts = urlsplit(raw)
    except ValueError:
        raise PolicyError("invalid URL") from None
    if parts.fragment:
        raise PolicyError("URL fragment rejected")
    if _PERCENT.search(parts.query):
        raise PolicyError("invalid query")
    origin, _, _ = _canonical_origin(parts)
    decoded_path = _decode_path(parts.path)
    canonical_path = quote(decoded_path, safe="/~!$&'()*+,;=:@-")
    if check_query:
        try:
            pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=False)
        except ValueError:
            raise PolicyError("invalid query") from None
        for key, _ in pairs:
            decoded_key = key
            for _ in range(3):
                try:
                    next_key = unquote_to_bytes(decoded_key).decode("utf-8", "strict")
                except UnicodeDecodeError:
                    raise PolicyError("invalid query") from None
                if next_key == decoded_key:
                    break
                decoded_key = next_key
            compact_key = re.sub(r"[^a-z0-9]", "", decoded_key.casefold())
            suspicious_suffix = compact_key.endswith(("credential", "password", "secret", "signature", "token"))
            if _DANGEROUS_QUERY_KEY.search(decoded_key) or compact_key in _DANGEROUS_COMPACT_KEYS or suspicious_suffix:
                raise PolicyError("credential-like query rejected")
    normalized = urlunsplit(("https", origin.removeprefix("https://"), canonical_path, parts.query, ""))
    return normalized, decoded_path


@dataclass
class Scope:
    policy_id: str
    expires_at: datetime
    targets: tuple[_Target, ...]
    exclude_urls: frozenset[str]
    max_bytes: int = 262_144
    max_requests: int = 20
    timeout: int = 10
    max_redirects: int = 5
    allow_credentials_in_url: bool = False
    _budget: Budget = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._budget = Budget(self.max_requests)

    @property
    def budget(self) -> Budget:
        return self._budget

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        try:
            source = Path(path)
            if source.stat().st_size > 1_048_576:
                raise PolicyError("scope file is too large")
            data = json.loads(source.read_text(encoding="utf-8"))
        except PolicyError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
            raise PolicyError("scope file could not be loaded") from None
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Scope":
        if not isinstance(data, dict):
            raise PolicyError("scope must be an object")
        allowed_fields = {
            "policy_id", "expires_at", "targets", "exclude_urls", "max_bytes",
            "max_requests", "timeout", "max_redirects", "allow_credentials_in_url",
        }
        if set(data) - allowed_fields:
            raise PolicyError("unknown scope field")
        policy_id = data.get("policy_id")
        if not isinstance(policy_id, str) or not policy_id or len(policy_id) > 128 or _CONTROL_OR_SPACE.search(policy_id):
            raise PolicyError("invalid policy id")
        raw_expiry = data.get("expires_at")
        if not isinstance(raw_expiry, str):
            raise PolicyError("invalid expiry")
        try:
            expiry = datetime.fromisoformat(raw_expiry.replace("Z", "+00:00"))
        except ValueError:
            raise PolicyError("invalid expiry") from None
        if expiry.tzinfo is None or expiry.utcoffset() is None or expiry.utcoffset().total_seconds() != 0:
            raise PolicyError("expiry must include UTC timezone")
        expiry = expiry.astimezone(timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            raise PolicyError("scope expired")

        allow_credentials = data.get("allow_credentials_in_url", False)
        if allow_credentials is not False:
            # Anonymous probing never sends URL credentials. The field exists so an
            # unsafe policy cannot be silently accepted by a future caller.
            raise PolicyError("URL credentials cannot be enabled")

        raw_targets = data.get("targets")
        if not isinstance(raw_targets, list) or not raw_targets:
            raise PolicyError("targets are required")
        targets: list[_Target] = []
        for item in raw_targets:
            if not isinstance(item, dict):
                raise PolicyError("invalid target")
            if set(item) - {"origin", "owner", "ownership_evidence", "path_prefixes"}:
                raise PolicyError("unknown target field")
            raw_origin = item.get("origin")
            owner = item.get("owner")
            ownership = item.get("ownership_evidence")
            prefixes = item.get("path_prefixes")
            if not all(isinstance(value, str) and value for value in (raw_origin, owner, ownership)):
                raise PolicyError("target ownership is required")
            if len(owner) > 256 or len(ownership) > 256 or _CONTROL_OR_SPACE.search(owner) or _CONTROL_OR_SPACE.search(ownership):
                raise PolicyError("target ownership is invalid")
            normalized_origin, origin_path = _normalize_url(raw_origin)
            if origin_path != "/" or "?" in normalized_origin:
                raise PolicyError("target origin must not include a path or query")
            normalized_origin = normalized_origin.rstrip("/")
            if not isinstance(prefixes, list) or not prefixes:
                raise PolicyError("path prefixes are required")
            clean_prefixes = []
            for prefix in prefixes:
                if not isinstance(prefix, str) or "?" in prefix or "#" in prefix:
                    raise PolicyError("invalid path prefix")
                clean_prefixes.append(_decode_path(prefix))
            targets.append(_Target(normalized_origin, owner, ownership, tuple(clean_prefixes)))

        raw_excludes = data.get("exclude_urls", [])
        if not isinstance(raw_excludes, list) or not all(isinstance(v, str) for v in raw_excludes):
            raise PolicyError("invalid exclusions")
        excludes = frozenset(_normalize_url(value, check_query=False)[0] for value in raw_excludes)
        return cls(
            policy_id=policy_id,
            expires_at=expiry,
            targets=tuple(targets),
            exclude_urls=excludes,
            max_bytes=_integer(data.get("max_bytes", 262_144), "max bytes", 1, 16 * 1024 * 1024),
            max_requests=_integer(data.get("max_requests", 20), "max requests", 1, 10_000),
            timeout=_integer(data.get("timeout", 10), "timeout", 1, 120),
            max_redirects=_integer(data.get("max_redirects", 5), "max redirects", 0, 20),
            allow_credentials_in_url=False,
        )

    def authorize(self, url: str) -> str:
        if self.expires_at <= datetime.now(timezone.utc):
            raise PolicyError("scope expired")
        normalized, decoded_path = _normalize_url(url)
        if normalized in self.exclude_urls:
            raise PolicyError("URL is excluded")
        origin, _, _ = _canonical_origin(urlsplit(normalized))
        for target in self.targets:
            if origin == target.origin and any(
                prefix == "/" or decoded_path == prefix or decoded_path.startswith(prefix.rstrip("/") + "/")
                for prefix in target.path_prefixes
            ):
                return normalized
        raise PolicyError("URL is outside authorized scope")
