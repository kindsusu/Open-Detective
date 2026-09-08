"""Direct, DNS-pinned HTTPS transport for anonymous observations."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import socket
import ssl
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable
from urllib.parse import urljoin, urlsplit

from .evidence import clean_text, safe_url
from .policy import Budget, PolicyError, Scope


@dataclass
class FetchResult:
    observation: dict[str, object]
    body: bytes
    # Transient allowlisted response metadata. Callers must not serialize this.
    headers: dict[str, str] = field(default_factory=dict)


Resolver = Callable[[str, int], Iterable[str]]
ConnectionFactory = Callable[[str, int, str, float], http.client.HTTPSConnection]


def _default_resolver(host: str, port: int, timeout: float) -> list[str]:
    """Bound getaddrinfo wall time without leaving a process-blocking worker."""
    result: queue.Queue[object] = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            result.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM), block=False)
        except (OSError, queue.Full):
            try:
                result.put([], block=False)
            except queue.Full:
                pass

    threading.Thread(target=run, daemon=True, name="open-detective-dns").start()
    try:
        answer = result.get(timeout=max(0.001, timeout))
    except queue.Empty:
        raise PolicyError("DNS resolution timed out") from None
    return sorted({item[4][0] for item in answer})


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def _default_connection(host: str, port: int, ip: str, timeout: float) -> http.client.HTTPSConnection:
    return _PinnedHTTPSConnection(host, port, ip, timeout)


def _resolve_public(host: str, port: int, resolver: Resolver) -> list[str]:
    try:
        literal = ipaddress.ip_address(host)
        values = [literal.compressed]
    except ValueError:
        try:
            values = list(resolver(host, port))
        except Exception:
            values = []
    if not values:
        raise PolicyError("DNS resolution failed")
    parsed = []
    for value in values:
        if isinstance(value, tuple) and len(value) >= 5:
            value = value[4][0]
        try:
            address = ipaddress.ip_address(str(value))
        except ValueError:
            raise PolicyError("DNS returned an invalid address") from None
        forbidden = (
            not address.is_global
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
            or address.is_private
            or address.is_loopback
            or address.is_link_local
        )
        if isinstance(address, ipaddress.IPv6Address):
            # Transition encodings are needlessly ambiguous for this observer.
            # IPv4-mapped addresses are allowed only when the embedded address is
            # itself public unicast; 6to4 and Teredo are rejected outright.
            if address.ipv4_mapped is not None:
                mapped = address.ipv4_mapped
                forbidden = forbidden or any((
                    not mapped.is_global, mapped.is_multicast, mapped.is_unspecified,
                    mapped.is_reserved, mapped.is_private, mapped.is_loopback,
                    mapped.is_link_local,
                ))
            forbidden = forbidden or address.sixtofour is not None or address.teredo is not None
        if forbidden:
            raise PolicyError("DNS returned a non-public address")
        parsed.append(address.compressed)
    return sorted(set(parsed), key=lambda item: (ipaddress.ip_address(item).version, item))


def _observation(scope: Scope, url: str) -> dict[str, object]:
    return {
        "observation_id": str(uuid.uuid4()),
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "policy_id": clean_text(scope.policy_id, 128),
        "target_ref": safe_url(url),
        "access": "INDETERMINATE",
        "content": "NOT_INSPECTED",
        "http_status": None,
        "sha256": None,
        "capture_complete": False,
        "reason": "not_started",
        "redirects": [],
    }


def _classify_status(status: int) -> tuple[str, str]:
    if 200 <= status <= 299:
        return "BODY_SERVED", "response_observed"
    if status in (401, 403):
        return "ACCESS_DENIED_OBSERVED", "access_denied_status"
    if status in (404, 410):
        return "NOT_FOUND_OBSERVED", "not_found_status"
    return "INDETERMINATE", "http_status_inconclusive"


def _response_socket_timeout(response: http.client.HTTPResponse, timeout: float) -> None:
    try:
        response.fp.raw._sock.settimeout(max(0.001, timeout))
    except (AttributeError, OSError):
        pass


def _read_bounded(response: http.client.HTTPResponse, maximum: int, deadline: float) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    remaining = maximum
    while remaining:
        time_left = deadline - time.monotonic()
        if time_left <= 0:
            raise TimeoutError
        _response_socket_timeout(response, time_left)
        reader = getattr(response, "read1", response.read)
        chunk = reader(min(65_536, remaining))
        if not chunk:
            return b"".join(chunks), True
        chunks.append(chunk)
        remaining -= len(chunk)
    # At the exact boundary, one byte distinguishes complete from truncated while
    # the returned body remains bounded to maximum.
    time_left = deadline - time.monotonic()
    if time_left <= 0:
        raise TimeoutError
    _response_socket_timeout(response, time_left)
    reader = getattr(response, "read1", response.read)
    return b"".join(chunks), reader(1) == b""


def _safe_headers(response: http.client.HTTPResponse) -> dict[str, str]:
    result: dict[str, str] = {}
    for source, target in (
        ("Content-Type", "content-type"),
        ("Location", "location"),
        ("Cache-Control", "cache-control"),
        ("Access-Control-Allow-Origin", "access-control-allow-origin"),
        ("Content-Encoding", "content-encoding"),
        ("Content-Security-Policy", "content-security-policy"),
        ("Content-Disposition", "content-disposition"),
        ("X-Content-Type-Options", "x-content-type-options"),
        ("Vary", "vary"),
    ):
        value = response.getheader(source)
        if value is not None and len(value) <= 2048:
            result[target] = clean_text(value, 2048)
    return result


def fetch(
    url: str,
    scope: Scope,
    *,
    follow_redirects: bool = True,
    budget: Budget | None = None,
    resolver: Resolver | None = None,
    connection_factory: ConnectionFactory | None = None,
    max_bytes: int | None = None,
) -> FetchResult:
    """Fetch one authorized HTTPS URL with every network hop pre-authorized.

    Resolver and connection factory injection exist for deterministic offline tests;
    production defaults always resolve every address and connect to a validated pin.
    """
    injected_resolver = resolver
    connection_factory = connection_factory or _default_connection
    budget = budget or scope.budget
    if max_bytes is None:
        body_limit = scope.max_bytes
    elif isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("invalid max_bytes")
    else:
        body_limit = min(scope.max_bytes, max_bytes)
    observation = _observation(scope, url)
    redirects: list[dict[str, object]] = []
    current = url
    deadline = time.monotonic() + scope.timeout

    for redirect_number in range(scope.max_redirects + 1):
        try:
            current = scope.authorize(current)
            parts = urlsplit(current)
            host = parts.hostname or ""
            port = parts.port or 443
            time_left = deadline - time.monotonic()
            if time_left <= 0:
                raise PolicyError("request timed out")
            active_resolver = injected_resolver or (
                lambda resolve_host, resolve_port: _default_resolver(resolve_host, resolve_port, time_left)
            )
            budget.consume()
            pins = _resolve_public(host, port, active_resolver)
        except PolicyError as exc:
            observation["reason"] = clean_text(exc)
            observation["redirects"] = redirects
            return FetchResult(observation, b"", {})

        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        response_error = True
        for pin_number, pin in enumerate(pins):
            connection = None
            try:
                time_left = deadline - time.monotonic()
                if time_left <= 0:
                    raise TimeoutError
                if pin_number:
                    budget.consume()
                connection = connection_factory(host, port, pin, time_left)
                connection.request(
                    "GET",
                    target,
                    headers={
                        "Accept": "*/*",
                        "Accept-Encoding": "identity",
                        "Connection": "close",
                        "User-Agent": "open-detective/2 (authorized anonymous observation)",
                    },
                )
                response = connection.getresponse()
                status = int(response.status)
                headers = _safe_headers(response)
                body, complete = _read_bounded(response, body_limit, deadline)
                response_error = False
                break
            except PolicyError as exc:
                observation["reason"] = clean_text(exc)
                observation["redirects"] = redirects
                return FetchResult(observation, b"", {})
            except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError, ValueError):
                continue
            except Exception:
                # Test adapters and platform TLS stacks must not leak exception text.
                continue
            finally:
                if connection is not None:
                    try:
                        connection.close()
                    except Exception:
                        pass
        if response_error:
            observation["reason"] = "transport_error"
            observation["redirects"] = redirects
            return FetchResult(observation, b"", {})

        observation.update(
            {
                "target_ref": safe_url(current),
                "http_status": status,
                "capture_complete": complete,
                "sha256": hashlib.sha256(body).hexdigest() if complete else None,
                "bytes_captured": len(body),
                "reason": "response_observed" if complete else "response_truncated",
            }
        )
        if not complete:
            observation["prefix_sha256"] = hashlib.sha256(body).hexdigest()

        content_encoding = headers.get("content-encoding", "identity").casefold()
        if content_encoding not in ("", "identity"):
            observation["access"] = "INDETERMINATE"
            observation["sha256"] = None
            observation["prefix_sha256"] = hashlib.sha256(body).hexdigest()
            observation["reason"] = "unsupported_content_encoding"
            observation["redirects"] = redirects
            return FetchResult(observation, body, headers)
        if status == 206:
            observation["access"] = "BODY_SERVED"
            observation["capture_complete"] = False
            observation["sha256"] = None
            observation["prefix_sha256"] = hashlib.sha256(body).hexdigest()
            observation["reason"] = "partial_resource"
            observation["redirects"] = redirects
            return FetchResult(observation, body, headers)

        if status not in (301, 302, 303, 307, 308):
            access, reason = _classify_status(status)
            observation["access"] = access
            if complete:
                observation["reason"] = reason
            observation["redirects"] = redirects
            return FetchResult(observation, body, headers)

        location = headers.get("location")
        if not location:
            observation["reason"] = "redirect_missing_location"
            observation["redirects"] = redirects
            return FetchResult(observation, body, headers)
        candidate = urljoin(current, location)
        try:
            authorized_candidate = scope.authorize(candidate)
            candidate_parts = urlsplit(authorized_candidate)
            time_left = deadline - time.monotonic()
            if time_left <= 0:
                raise PolicyError("request timed out")
            active_resolver = injected_resolver or (
                lambda resolve_host, resolve_port: _default_resolver(resolve_host, resolve_port, time_left)
            )
            _resolve_public(candidate_parts.hostname or "", candidate_parts.port or 443, active_resolver)
        except PolicyError as exc:
            observation["reason"] = clean_text(exc)
            observation["redirects"] = redirects
            return FetchResult(observation, body, headers)
        redirects.append({"http_status": status, "target_ref": safe_url(authorized_candidate)})
        observation["redirects"] = redirects
        if not follow_redirects:
            observation["access"] = "INDETERMINATE"
            observation["reason"] = "authorized_redirect_observed"
            return FetchResult(observation, body, headers)
        if redirect_number >= scope.max_redirects:
            observation["reason"] = "redirect budget exhausted"
            return FetchResult(observation, body, headers)
        current = authorized_candidate

    observation["reason"] = "redirect budget exhausted"
    return FetchResult(observation, b"", {})
