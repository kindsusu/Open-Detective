"""Offline, scope-bound review of already delivered presentation gates.

Only one recognized fixed-value handler may run in a network-blocked inert
projection. This module never fetches URLs or executes arbitrary page scripts.
"""
from __future__ import annotations

import argparse
import hashlib
from html import escape
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
from datetime import datetime, timezone

from .dom_replay import _InertFixtureParser, _browser_replay, _read_bounded, _reject_symlink_path
from .classifiers import CLIENT_PASSWORD_ASSIGNMENT, CLIENT_PASSWORD_COMPARISON
from .policy import PolicyError, Scope

MAX_HTML = 4_194_304
MAX_PROJECTION_TEXT = 131_072
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FIXED_GATE = re.compile(
    r"^\s*"
    r"(?:const|let)\s+password\s*=\s*document\.getElementById\(['\"]password['\"]\)\.value\s*;\s*"
    r"if\s*\(\s*password\s*===\s*(['\"])([^'\"\r\n]{1,128})\1\s*\)\s*\{\s*"
    r"document\.getElementById\(['\"]login-screen['\"]\)\.remove\(\)\s*;\s*"
    r"document\.getElementById\(['\"]app['\"]\)\.style\.display\s*=\s*['\"]flex['\"]\s*;\s*"
    r"\}\s*$", re.S,
)
_SERVER_CALL = re.compile(r"\b(?:fetch|XMLHttpRequest|sendBeacon|WebSocket|axios|submit)\s*(?:\(|\.)", re.I)
_LOGIN_ENDPOINT = re.compile(r"(?:^|/)(?:login|log-in|signin|sign-in|authenticate|auth|session|token)(?:[/?#]|$)", re.I)
_REQUEST_URL = re.compile(r'''\b(?:fetch|axios(?:\.get|\.post)?|open)\s*\(\s*(["'`])([^"'`\s]{1,512})\1''', re.I)
_ENCRYPTION = re.compile(r"\b(?:staticrypt|crypto\.subtle\.decrypt|AES\.decrypt|ciphertext)\b", re.I)
_BUSINESS = {
    "commission": re.compile(r"수수료|commission", re.I),
    "cost": re.compile(r"원가|조달|cost.price|purchase.price", re.I),
    "interest": re.compile(r"금리|interest.rate", re.I),
    "depreciation": re.compile(r"감가|잔가|depreciation|residual", re.I),
    "deposit": re.compile(r"보증금|선납금|deposit", re.I),
    "inventory": re.compile(r"재고|inventory|stock", re.I),
    "customer_contract": re.compile(r"고객|계약|customer|contract", re.I),
}
_FILLED = re.compile(r"(?:\d[\d,.]*\s*(?:%|원|KRW|USD)|\"(?:cost_price|commission_rate|customer_name)\"\s*:\s*(?!null|\"\")[^,}]+)", re.I)


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.nodes = []
        self.scripts = []
        self._script = None
        self.password_inputs = 0
        self.hidden_payload = []
        self.visible_payload = []
        self.hidden_field_count = 0
        self.hidden_filled_field_count = 0
        self.hidden_field_categories = set()
        self._hidden = [False]
        self._tags = []
        self.active = False
        self.encrypted = False
        self._sanitized = []
        self.ids = {}
        self.form_actions = []

    def handle_starttag(self, tag, attrs):
        a = {key: value or "" for key, value in attrs}
        if len(a) != len(attrs):
            self.active = True
        if tag == "script":
            if attrs:
                self.active = True
            self._script = []
            return
        if self._script is not None:
            return
        hidden = self._hidden[-1] or "hidden" in a or bool(re.search(r"display\s*:\s*none|visibility\s*:\s*hidden", a.get("style") or "", re.I))
        if tag not in {"input", "img", "meta", "br", "hr"}:
            self._hidden.append(hidden)
            self._tags.append(tag)
        if tag == "input" and a.get("type", "").lower() == "password":
            self.password_inputs += 1
        if tag == "form":
            self.form_actions.append(a.get("action", ""))
        if tag in {"input", "textarea", "select"} and (hidden or a.get("type", "").lower() == "hidden"):
            self.hidden_field_count += 1
            value = a.get("value", "")
            if value and value.strip() and not re.fullmatch(r"(?:example|sample|placeholder|test|demo)", value.strip(), re.I):
                self.hidden_filled_field_count += 1
                label = " ".join((a.get("name", ""), a.get("id", "")))
                self.hidden_field_categories.update(name for name, pattern in _BUSINESS.items() if pattern.search(label))
        if "id" in a:
            self.ids[a["id"]] = self.ids.get(a["id"], 0) + 1
        if tag in {"iframe", "form", "object", "embed", "base", "link", "video", "audio", "svg", "math"}:
            self.active = True
        if any(k.startswith("on") or k in {"src", "href", "action", "formaction", "srcdoc", "ping"} for k in a):
            self.active = True
        if tag == "style":
            self.active = True  # CSS is omitted from the inert projection.
        if tag in {"html", "head", "body", "main", "section", "div", "p", "span", "table", "tbody", "thead", "tr", "td", "th", "input", "button", "h1", "h2", "h3", "ul", "li"}:
            safe = []
            for key in ("id", "type", "style"):
                if key in a:
                    safe.append(f' {key}="{escape(a[key], quote=True)}"')
            self._sanitized.append(f"<{tag}{''.join(safe)}>")
        else:
            self.active = True

    def handle_endtag(self, tag):
        if tag == "script":
            if self._script is not None:
                self.scripts.append("".join(self._script))
                self._script = None
            return
        if self._script is not None:
            return
        if self._tags and self._tags[-1] == tag:
            self._tags.pop()
            self._hidden.pop()
        if tag in {"html", "head", "body", "main", "section", "div", "p", "span", "table", "tbody", "thead", "tr", "td", "th", "button", "h1", "h2", "h3", "ul", "li"}:
            self._sanitized.append(f"</{tag}>")

    def handle_data(self, data):
        if self._script is not None:
            self._script.append(data)
        else:
            (self.hidden_payload if self._hidden[-1] else self.visible_payload).append(data)
            self._sanitized.append(escape(data))

    @property
    def projection(self):
        return "".join(self._sanitized)


def _run_fixed_gate(projection: str, script: str, literal: str) -> tuple[bool, int]:
    """Execute only the exact allowlisted handler once in an isolated browser."""
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise ValueError("browser_runtime_unavailable") from None
    requests = 0
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True, proxy={"server": "http://127.0.0.1:9", "bypass": "<-loopback>"},
                args=["--disable-background-networking", "--disable-quic", "--disable-extensions",
                      "--disable-sync", "--disable-default-apps", "--host-resolver-rules=MAP * ~NOTFOUND",
                      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"],
            )
            context = browser.new_context(service_workers="block", accept_downloads=False,
                                          java_script_enabled=True, permissions=[],
                                          storage_state={"cookies": [], "origins": []})
            def block(route):
                nonlocal requests
                requests += 1
                route.abort("blockedbyclient")

            context.route("**/*", block)
            page = context.new_page()
            page.on("popup", lambda popup: popup.close())
            page.on("download", lambda download: download.cancel())
            page.on("dialog", lambda dialog: dialog.dismiss())
            try:
                page.set_content(projection, wait_until="domcontentloaded", timeout=5_000)
                if page.locator("#password").count() != 1 or page.locator("#app").count() != 1:
                    raise ValueError("ambiguous_replay_targets")
                if page.locator("#app").is_visible():
                    raise ValueError("app_already_visible")
                page.locator("#password").fill(literal, timeout=2_000)
                page.evaluate("() => {" + script + "}")
                page.wait_for_timeout(100)
                opened = page.locator("#login-screen").count() == 0 and page.locator("#app").is_visible()
            finally:
                context.close()
                browser.close()
    except ValueError:
        raise
    except PlaywrightError:
        raise ValueError("browser_runtime_unavailable") from None
    return opened, requests


def _capability(capability: dict, scope: Scope, target: str, digest: str, now: datetime) -> str:
    legacy = {"capability_id", "policy_id", "action", "target_url", "owner_evidence_ref", "expires_at", "max_attempts", "response_sha256"}
    scoped = {"policy_id", "action", "valid_until", "authorization_ref"}
    if not isinstance(capability, dict) or set(capability) not in (legacy, scoped):
        return "invalid_capability"
    fields = ("capability_id", "policy_id", "owner_evidence_ref") if set(capability) == legacy else ("policy_id", "authorization_ref")
    if any(not isinstance(capability[k], str) or not _REF.fullmatch(capability[k]) for k in fields):
        return "invalid_capability"
    if capability["policy_id"] != scope.policy_id or capability["action"] not in {"reveal_delivered_content", "verify_fixed_client_gate"}:
        return "capability_mismatch"
    if set(capability) == legacy:
        if capability["target_url"] != target or capability["response_sha256"] != digest or not _SHA.fullmatch(capability["response_sha256"]):
            return "target_or_response_mismatch"
        if type(capability["max_attempts"]) is not int or capability["max_attempts"] != 1:
            return "invalid_attempt_limit"
    try:
        field = "expires_at" if set(capability) == legacy else "valid_until"
        if not isinstance(capability[field], str):
            return "invalid_capability"
        expiry = datetime.fromisoformat(capability[field].replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry.astimezone(timezone.utc) <= now:
            return "expired_capability"
    except (ValueError, TypeError):
        return "invalid_capability"
    return "authorized"


def review(response: bytes, target_url: str, scope: Scope, capability: dict | None, *, now: datetime | None = None, replay_browser: bool | None = None) -> dict:
    """Review an already captured HTML response; return only bounded non-value evidence.

    Authorized calls attempt isolated replay by default; callers can explicitly
    disable it for a static-only pass.
    """
    now = now or datetime.now(timezone.utc)
    digest = hashlib.sha256(response).hexdigest() if isinstance(response, bytes) else None
    result = {
        "schema_version": "1.0", "status": "pending", "reason": "not_started",
        "response_sha256": digest, "review_binding_sha256": None,
        "auth_ui_present": False,
        "client_secret_literal_present": False, "request_present": False,
        "login_request_present": False,
        "payload_in_initial_response": False, "payload_template_only": False,
        "encrypted_payload_observed": False, "client_gate_tested": False,
        "server_authorization_tested": False, "actual_data_access_result": "not_observed",
        "business_logic_evidence_refs": [], "content_evidence_refs": [],
        "replay": "not_attempted", "replay_source": "none",
        "original_dom_replayed": False, "original_active_content_stripped": False,
        "network_request_attempts": 0,
        "client_gate_attempts": 0, "hidden_field_count": 0,
        "hidden_filled_field_count": 0, "follow_up": [],
    }
    try:
        canonical = scope.authorize(target_url)
    except (PolicyError, TypeError, ValueError):
        result["reason"] = "scope_denied"
        return result
    if not digest or len(response) > min(MAX_HTML, scope.max_bytes):
        result["reason"] = "response_missing_or_oversize"
        return result
    result["review_binding_sha256"] = hashlib.sha256(
        (scope.policy_id + "\0" + canonical + "\0" + digest).encode("utf-8")).hexdigest()
    permission = _capability(capability, scope, canonical, digest, now) if capability is not None else "capability_required"
    try:
        html = response.decode("utf-8", "strict")
    except UnicodeError:
        result["reason"] = "unsupported_encoding"
        return result
    page = _Page()
    try:
        page.feed(html)
        page.close()
    except (ValueError, RecursionError):
        result["reason"] = "html_parse_incomplete"
        return result
    scripts = "\n".join(page.scripts)
    all_text = " ".join(page.hidden_payload + page.visible_payload)
    hidden_text = " ".join(page.hidden_payload)
    replay_canary = next((part.strip()[:128] for part in page.hidden_payload if part.strip()), "")
    result["auth_ui_present"] = page.password_inputs > 0
    result["hidden_field_count"] = page.hidden_field_count
    result["hidden_filled_field_count"] = page.hidden_filled_field_count
    result["request_present"] = bool(_SERVER_CALL.search(scripts)) or bool(page.form_actions)
    request_urls = [match.group(2) for match in _REQUEST_URL.finditer(scripts)]
    result["login_request_present"] = any(_LOGIN_ENDPOINT.search(url) for url in request_urls + page.form_actions)
    result["encrypted_payload_observed"] = bool(_ENCRYPTION.search(scripts) and re.search(r"[A-Za-z0-9+/]{48,}={0,2}", scripts))
    gate = _FIXED_GATE.fullmatch(scripts) if len(page.scripts) == 1 else None
    result["client_secret_literal_present"] = bool(
        CLIENT_PASSWORD_ASSIGNMENT.search(scripts) or CLIENT_PASSWORD_COMPARISON.search(scripts))
    categories = [name for name, pattern in _BUSINESS.items() if pattern.search(all_text)]
    categories = sorted(set(categories) | page.hidden_field_categories)
    filled = bool(_FILLED.search(all_text)) or page.hidden_filled_field_count > 0
    hidden_filled = bool(hidden_text.strip() and _FILLED.search(hidden_text)) or page.hidden_filled_field_count > 0
    result["payload_in_initial_response"] = filled
    result["payload_template_only"] = bool(categories and not filled)
    result["content_evidence_refs"] = [f"sha256:{digest}:html:{name}" for name in categories if filled]
    result["business_logic_evidence_refs"] = [f"sha256:{digest}:script:business-rule"] if re.search(r"(?:commission|margin|rate|수수료|원가)\s*[*+/=-]", scripts, re.I) else []
    if filled:
        result["actual_data_access_result"] = "delivered_in_initial_response"
    if permission != "authorized":
        result["reason"] = permission
        result["follow_up"].append("capability_or_scope_review")
        return result
    if result["encrypted_payload_observed"]:
        result["follow_up"].append("owner_key_or_plaintext_review")
    if result["request_present"]:
        result["follow_up"].append("server_authorization_review")
    if result["payload_template_only"]:
        result["follow_up"].append("data_delivery_review")
    if replay_browser is None:
        replay_browser = True
    has_reveal_text = bool(hidden_text.strip() and _FILLED.search(hidden_text))
    if capability["action"] == "verify_fixed_client_gate":
        if not gate or result["request_present"]:
            result["reason"] = "unsupported_client_gate"
            result["follow_up"].append("controlled_broker_or_manual_review")
            return result
        result["follow_up"].append("isolated_client_gate_run")
    if not has_reveal_text:
        result["reason"] = "replay_text_unavailable" if hidden_filled else "delivered_payload_not_revealable"
        result["follow_up"].append("bounded_replay_adapter_or_content_review")
        if filled:
            result["status"] = "partial"
        return result
    original_preset = (page.ids.get("login-screen") == 1 and page.ids.get("app") == 1
                       and not page.active and (not page.scripts or bool(gate)))
    if capability["action"] == "verify_fixed_client_gate":
        if not original_preset:
            result["reason"] = "active_markup_replay_unsupported"
            result["follow_up"].append("controlled_broker_or_manual_review")
            return result
        projection = page.projection
        result["replay_source"] = "sanitized_structure_projection"
    elif original_preset and not page.scripts:
        projection = page.projection
        result["replay_source"] = "sanitized_structure_projection"
    else:
        if len(hidden_text) > MAX_PROJECTION_TEXT:
            result["reason"] = "projection_text_limit"
            result["follow_up"].append("bounded_content_review")
            result["status"] = "partial"
            return result
        projection = ('<main id="login-screen"><input type="password"></main>'
                      '<section id="app" style="display:none"><p>'
                      + escape(hidden_text) + '</p></section>')
        result["replay_source"] = "sanitized_hidden_text_projection"
        result["original_active_content_stripped"] = bool(page.active or page.scripts)
    inert = _InertFixtureParser()
    try:
        inert.feed(projection)
        inert.close()
    except ValueError:
        result["reason"] = "active_markup_replay_unsupported"
        return result
    if inert.target_counts != {"login-screen": 1, "app": 1}:
        result["reason"] = "ambiguous_replay_targets"
        return result
    result["replay"] = "inert_projection_validated"
    if replay_browser:
        try:
            if capability["action"] == "verify_fixed_client_gate":
                result["client_gate_attempts"] = 1
                opened, attempts = _run_fixed_gate(projection, scripts, gate.group(2))
                result["network_request_attempts"] = attempts
                result["client_gate_tested"] = bool(opened and attempts == 0)
                if not result["client_gate_tested"]:
                    result["reason"] = "isolated_client_gate_failed"
                    return result
                result["follow_up"].remove("isolated_client_gate_run")
            else:
                before, after, attempts = _browser_replay(projection, replay_canary)
                if before["targets"]["app"]["visible"] or not after["targets"]["app"]["visible"]:
                    result["reason"] = "replay_boundary_failed"
                    return result
            result["network_request_attempts"] = attempts
            if attempts:
                result["reason"] = "replay_boundary_failed"
                return result
            result["replay"] = "local_display_confirmed"
        except Exception:
            result["reason"] = "replay_unavailable_or_failed"
            result["follow_up"].append("isolated_replay_retry")
            return result
    result["status"] = "reviewed" if replay_browser else "partial"
    result["reason"] = "local_display_confirmed" if replay_browser else "inert_projection_validated"
    result["actual_data_access_result"] = "delivered_in_initial_response"
    if not replay_browser:
        result["follow_up"].append("isolated_replay_optional")
    return result


def review_gate(body: bytes, content_type: str, url: str, scope: Scope,
                capability: dict | None = None, *, replay_browser: bool | None = None) -> dict:
    """Integration entry for already fetched bytes; unsupported media stays pending."""
    if not isinstance(content_type, str) or "html" not in content_type.casefold():
        return {"schema_version": "1.0", "status": "pending", "reason": "unsupported_content_type",
                "response_sha256": hashlib.sha256(body).hexdigest() if isinstance(body, bytes) else None,
                "review_binding_sha256": None,
                "auth_ui_present": False, "client_secret_literal_present": False,
                "request_present": False, "login_request_present": False,
                "payload_in_initial_response": False,
                "payload_template_only": False, "encrypted_payload_observed": False,
                "client_gate_tested": False, "server_authorization_tested": False,
                "actual_data_access_result": "not_observed", "business_logic_evidence_refs": [],
                "content_evidence_refs": [], "replay": "not_attempted",
                "replay_source": "none", "original_dom_replayed": False,
                "original_active_content_stripped": False, "network_request_attempts": 0,
                "client_gate_attempts": 0, "hidden_field_count": 0,
                "hidden_filled_field_count": 0, "follow_up": ["content_type_review"]}
    return review(body, url, scope, capability, replay_browser=replay_browser)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Offline review of already captured, scope-authorized HTML.")
    p.add_argument("--response", required=True)
    p.add_argument("--scope", required=True)
    p.add_argument("--capability", required=True)
    p.add_argument("--target-url", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--no-replay-browser", action="store_true", help="static-only review")
    args = p.parse_args(argv)
    try:
        output = _reject_symlink_path(Path(args.output))
        if output.exists() or not output.parent.is_dir():
            raise ValueError("unsafe_output")
        raw = _read_bounded(Path(args.response), MAX_HTML, invalid="invalid_response")
        scope = Scope.load(args.scope)
        cap = json.loads(_read_bounded(Path(args.capability), 16_384, invalid="invalid_capability").decode("utf-8"))
        result = review(raw, args.target_url, scope, cap, replay_browser=not args.no_replay_browser)
        with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=True, indent=2)
            stream.write("\n")
        return 0 if result["status"] in {"reviewed", "partial"} else 2
    except (OSError, ValueError, TypeError, PolicyError, UnicodeError, json.JSONDecodeError):
        print('{"error":"invalid_local_input"}', file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
