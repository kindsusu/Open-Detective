"""Bounded offline execution of hash-authorized, already captured HTML/JavaScript.

The original scripts run in a fresh Chromium process. All supported requests are
fulfilled from an exact, caller-supplied synthetic-origin resource map; anything
else is aborted. This is a browser-observer boundary, not an OS egress sandbox.
"""
from __future__ import annotations

from datetime import datetime, timezone
from html.parser import HTMLParser
import hashlib
import json
import multiprocessing as mp
import os
import re
import signal
import subprocess
import time
import unicodedata
from urllib.parse import unquote_to_bytes, urlsplit


ORIGIN = "https://captured.invalid"
ROOT_URL = ORIGIN + "/"
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_RESOURCES = 32
MAX_RESOURCE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_CASE = re.compile(r"case_[0-9a-f]{32}\Z")
_LOCAL_PATH = re.compile(r"/[A-Za-z0-9_./~%\-]+\Z")
_LOCAL_QUERY = re.compile(r"[A-Za-z0-9_./~!$&'()*+,;=:@?%\-]+\Z")
_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_MEDIA_TYPE = re.compile(r"[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+(?:;[ A-Za-z0-9=.+_-]+)?\Z")
_DOM_ID = re.compile(r"[A-Za-z][A-Za-z0-9_:.-]{0,99}\Z")
_CSP = ("default-src 'none'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; "
        "connect-src 'self'; frame-src 'none'; worker-src 'none'; object-src 'none'; "
        "base-uri 'none'; form-action 'none'")
_BOOTSTRAP = """(() => {
  const blocked = window.__sudetectBlockedTransport;
  for (const key of ['RTCPeerConnection','webkitRTCPeerConnection','Worker',
                     'SharedWorker','WebTransport','EventSource']) {
    try { Object.defineProperty(window, key, {value: undefined, configurable: false}); } catch (_) {}
  }
  try { Object.defineProperty(navigator, 'sendBeacon', {
    value: () => { blocked('beacon'); return false; }, configurable: false
  }); } catch (_) {}
})();"""
_SNAPSHOT = r"""(() => {
  const visible = el => {
    let node = el;
    let depth = 0;
    while (node && depth++ < 128) {
      const style = getComputedStyle(node);
      if (style.display === 'none' || style.visibility === 'hidden' ||
          style.opacity === '0') return false;
      node = node.parentElement;
    }
    if (node) return false;
    const box = el.getBoundingClientRect();
    return box.width > 0 && box.height > 0;
  };
  const limit = 10000;
  const counts = {visible_fields:0,filled_fields:0,visible_tables:0,
    visible_table_rows:0,visible_table_cells:0,category_hints:{pricing:0,
    customer_contact:0,vehicle:0,financial:0},email_like:0,phone_like:0};
  const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_ELEMENT);
  let el, examined = 0, visited = 0, nodeLimit = false;
  while ((el = walker.nextNode())) {
    if (++visited > 50000) { nodeLimit = true; break; }
    if (!/^(INPUT|TEXTAREA|SELECT|TABLE|TR|TD|TH)$/.test(el.tagName)) continue;
    if (++examined > limit) { nodeLimit = true; break; }
    if (!visible(el)) continue;
    const tag = el.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') {
      counts.visible_fields++;
      if (String(el.value || '').trim()) counts.filled_fields++;
      const label = [el.name,el.id,el.getAttribute('aria-label'),el.placeholder,
        el.labels && el.labels[0] && el.labels[0].textContent].join(' ').toLowerCase();
      if (/price|rate|fee|rent|pricing|가격|요금|렌트료/.test(label)) counts.category_hints.pricing++;
      if (/customer|client|phone|email|contact|고객|연락처|전화|이메일/.test(label)) counts.category_hints.customer_contact++;
      if (/vehicle|vin|plate|차량|차종/.test(label)) counts.category_hints.vehicle++;
      if (/revenue|profit|budget|매출|수익|예산/.test(label)) counts.category_hints.financial++;
    } else if (tag === 'TABLE') counts.visible_tables++;
    else if (tag === 'TR') counts.visible_table_rows++;
    else if (tag === 'TD' || tag === 'TH') counts.visible_table_cells++;
  }
  let text = '', textNodes = 0, textTruncated = false;
  const textWalker = document.createTreeWalker(document.body || document.documentElement,
                                              NodeFilter.SHOW_TEXT);
  let part;
  while ((part = textWalker.nextNode())) {
    if (++textNodes > limit) { textTruncated = true; break; }
    if (!part.parentElement || !visible(part.parentElement)) continue;
    const value = part.nodeValue || '';
    if (text.length + value.length > 1048576) {
      text += value.slice(0, 1048576 - text.length);
      textTruncated = true;
      break;
    }
    text += value;
  }
  counts.email_like = (text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi)||[]).length;
  counts.phone_like = (text.match(/(?:0\d{1,2}[- ]?)?\d{3,4}[- ]\d{4}/g)||[]).length;
  counts.visible_text_category_hints = {
    pricing:(text.match(/price|pricing|rate|fee|rent|가격|요금|렌트료/gi)||[]).length,
    customer_contact:(text.match(/customer|client|phone|email|contact|고객|연락처|전화|이메일/gi)||[]).length,
    vehicle:(text.match(/vehicle|vin|plate|차량|차종/gi)||[]).length,
    financial:(text.match(/revenue|profit|budget|매출|수익|예산/gi)||[]).length
  };
  return {counts,dom_nodes_examined:Math.min(examined,limit),
    dom_node_limit:nodeLimit,visible_text_chars:text.length,
    visible_text_truncated:textTruncated};
})()"""
_REVEAL = """((config) => {
  const targets = [...config.hide_ids, ...config.show_ids];
  const found = new Map();
  for (const id of targets) {
    const element = document.getElementById(id);
    if (!element) return 'target_missing';
    found.set(id, element);
  }
  // getElementById alone cannot detect duplicate IDs. Count exact IDs without
  // selector interpolation, then refuse ambiguous documents before mutation.
  const counts = new Map(targets.map(id => [id, 0]));
  const nodes = document.getElementsByTagName('*');
  if (nodes.length > 50000) return 'dom_limit';
  for (const node of nodes) {
    if (counts.has(node.id)) counts.set(node.id, counts.get(node.id) + 1);
  }
  if ([...counts.values()].some(count => count !== 1)) return 'duplicate_target';
  for (const hideId of config.hide_ids) {
    for (const showId of config.show_ids) {
      if (found.get(hideId).contains(found.get(showId))) return 'hidden_ancestor';
    }
  }
  for (const id of config.hide_ids) found.get(id).remove();
  for (const id of config.show_ids) found.get(id).style.display = config.display;
  return 'applied';
})(__CONFIG__)"""
_REVEAL_VISIBLE = """((ids) => {
  for (const id of ids) {
    const el = document.getElementById(id);
    if (!el) return false;
    let node = el, depth = 0;
    while (node && depth++ < 128) {
      const style = getComputedStyle(node);
      if (style.display === 'none' || style.visibility === 'hidden' ||
          style.visibility === 'collapse' || Number(style.opacity) === 0)
        return false;
      node = node.parentElement;
    }
    if (node) return false;
    const box = el.getBoundingClientRect();
    if (!(box.width > 0 && box.height > 0)) return false;
  }
  return true;
})(__SHOW_IDS__)"""


def _reveal_config(authorization: dict):
    """Validate only exact, bounded DOM IDs; the containing approval is source-hash bound."""
    if "client_ui_reveal" not in authorization:
        return None, {"hide_ids": ["login-screen"], "show_ids": ["app"],
                      "display": "flex"}
    config = authorization["client_ui_reveal"]
    if not isinstance(config, dict) or set(config) != {"hide_ids", "show_ids", "display"}:
        return "invalid_client_ui_reveal", None
    hide, show = config["hide_ids"], config["show_ids"]
    if (not isinstance(hide, list) or not isinstance(show, list)
            or not 1 <= len(hide) <= 4 or not 1 <= len(show) <= 4
            or not isinstance(config["display"], str)
            or config["display"] not in {"block", "flex", "grid"}):
        return "invalid_client_ui_reveal", None
    ids = hide + show
    if (any(not isinstance(value, str) or not _DOM_ID.fullmatch(value) for value in ids)
            or len(set(ids)) != len(ids)):
        return "invalid_client_ui_reveal", None
    return None, {"hide_ids": hide.copy(), "show_ids": show.copy(),
                  "display": config["display"]}


def _local_resource_key(key: str) -> str | None:
    """Return an ambiguity-check key; keep the supplied URL unchanged for replay."""
    if (not key.startswith("/") or len(key) > 2048 or not key.isascii()
            or key.startswith("//") or "#" in key):
        return None
    path, separator, query = key.partition("?")
    if (not _LOCAL_PATH.fullmatch(path) or path == "/" or "//" in path
            or (separator and not _LOCAL_QUERY.fullmatch(query))):
        return None
    for component in (path, query):
        # A bare/partial percent escape is not a URI byte and must not be
        # accepted as a second spelling of an approved captured request.
        if "%" in _PERCENT.sub("", component):
            return None
        if re.search(r"%(?:2[fFeE]|5[cC]|25|0[0-9a-fA-F]|1[0-9a-fA-F]|7[fF])", component):
            return None
        try:
            decoded = unquote_to_bytes(component).decode("utf-8", "strict")
        except UnicodeError:
            return None
        if (unicodedata.normalize("NFC", decoded) != decoded
                or any(unicodedata.category(char).startswith("C") for char in decoded)):
            return None
    if any(part in {".", ".."} for part in unquote_to_bytes(path).decode("utf-8").split("/")):
        return None
    def canonical(component: str) -> str:
        return _PERCENT.sub(lambda match: (
            chr(int(match.group()[1:], 16)) if chr(int(match.group()[1:], 16)) in _UNRESERVED
            else match.group().upper()), component)
    return canonical(path) + ("?" + canonical(query) if separator else "")


class _StaticHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.fields = self.tables = self.rows = self.scripts = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"input", "textarea", "select"}: self.fields += 1
        elif tag == "table": self.tables += 1
        elif tag == "tr": self.rows += 1
        elif tag == "script":
            kind = (dict(attrs).get("type") or "").casefold()
            if kind in {"", "module", "text/javascript", "application/javascript"}:
                self.scripts += 1


def _base_result(body: bytes, kind: str) -> dict:
    return {"schema_version": "1.0", "status": "blocked", "reason": "invalid_input",
            "source_sha256": hashlib.sha256(body).hexdigest(), "document_type": kind,
            "review_mode": "offline_original_javascript", "original_script_executed": False,
            "network_fetches_performed": 0, "runtime_observation_complete": False,
            "all_runtime_states_verified": False, "server_authorization_tested": False,
            "publication_approval_verified": False, "pending_reviews": [],
            "static_html": {"fields": 0, "tables": 0, "rows": 0, "scripts": 0},
            "initial_dom": None, "after_client_reveal": None,
            "client_reveal_applied": False,
            "client_reveal_visibility_verified": False,
            "client_reveal_action_digest": None,
            "client_reveal_failure": None, "script_parsed_count": 0,
            "script_executed_count": 0, "script_error_count": 0,
            "console_error_count": 0, "captured_resource_requests": 0,
            "blocked_request_count": 0, "failed_request_count": 0,
            "blocked_beacon_count": 0,
            "blocked_websocket_count": 0, "blocked_popup_count": 0,
            "blocked_download_count": 0, "blocked_frame_request_count": 0,
            "attached_frame_count": 0, "unexpected_navigation_count": 0,
            "observation_window_ms": 1000, "boundary": "browser_broker_only"}


def _validate(body, content_type, authorization, resources, max_seconds):
    if not isinstance(body, bytes) or len(body) > MAX_SOURCE_BYTES:
        return "invalid_source", None, None
    if not isinstance(content_type, str) or not _MEDIA_TYPE.fullmatch(content_type):
        return "invalid_content_type", None, None
    kind = "html" if "html" in content_type.casefold() else (
        "javascript" if "javascript" in content_type.casefold() else "other")
    if kind == "other":
        return "unsupported_content_type", kind, None
    if (isinstance(max_seconds, bool) or not isinstance(max_seconds, (int, float))
            or not 0 < max_seconds <= 30):
        return "invalid_time_limit", kind, None
    if not isinstance(authorization, dict):
        return "invalid_authorization", kind, None
    needed = {"case_id", "owner_ref", "action", "expires_at", "source_sha256", "resource_sha256"}
    if not needed <= authorization.keys():
        return "invalid_authorization", kind, None
    if (not isinstance(authorization["case_id"], str) or not _CASE.fullmatch(authorization["case_id"])
            or not isinstance(authorization["owner_ref"], str)
            or not 1 <= len(authorization["owner_ref"]) <= 256
            or authorization["action"] != "execute_captured_javascript"
            or not isinstance(authorization["source_sha256"], str)
            or not _SHA.fullmatch(authorization["source_sha256"])):
        return "invalid_authorization", kind, None
    if authorization["source_sha256"] != hashlib.sha256(body).hexdigest():
        return "source_hash_mismatch", kind, None
    try:
        expiry = datetime.fromisoformat(authorization["expires_at"].replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            return "authorization_expired", kind, None
    except (AttributeError, TypeError, ValueError, OverflowError):
        return "invalid_authorization", kind, None
    expected = authorization["resource_sha256"]
    if not isinstance(expected, dict) or not isinstance(resources, (dict, type(None))):
        return "invalid_resources", kind, None
    resources = resources or {}
    if len(resources) > MAX_RESOURCES or set(resources) != set(expected):
        return "resource_binding_mismatch", kind, None
    total = len(body)
    normalized = {}
    local_canonical_keys = set()
    for path, row in resources.items():
        if not isinstance(path, str) or not isinstance(row, dict):
            return "invalid_resources", kind, None
        if path.startswith("/"):
            canonical_key = _local_resource_key(path)
            valid_location = (canonical_key is not None
                              and canonical_key.split("?", 1)[0] != "/__main__.js")
            if valid_location:
                if canonical_key in local_canonical_keys:
                    return "invalid_resources", kind, None
                local_canonical_keys.add(canonical_key)
        else:
            try:
                parsed = urlsplit(path)
                valid_location = (len(path) <= 2048 and path.isascii()
                    and parsed.scheme == "https" and bool(parsed.hostname)
                    and bool(re.fullmatch(r"[A-Za-z0-9.-]+", parsed.hostname or ""))
                    and (parsed.port is None or 1 <= parsed.port <= 65535)
                    and not parsed.username and not parsed.password and not parsed.fragment
                    and not any(ord(char) < 33 or ord(char) == 127 for char in path)
                    and parsed.netloc != "captured.invalid")
            except ValueError:
                valid_location = False
        if not valid_location:
            return "invalid_resources", kind, None
        data, media_type = row.get("body"), row.get("content_type")
        digest = expected[path]
        if (not isinstance(data, bytes) or len(data) > MAX_RESOURCE_BYTES
                or not isinstance(media_type, str) or not _MEDIA_TYPE.fullmatch(media_type)
                or not isinstance(digest, str) or not _SHA.fullmatch(digest)):
            return "invalid_resources", kind, None
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            return "resource_byte_limit", kind, None
        if hashlib.sha256(data).hexdigest() != digest:
            return "resource_hash_mismatch", kind, None
        normalized[path] = (data, media_type)
    return None, kind, normalized


def _snapshot(cdp, frame_id):
    world = cdp.send("Page.createIsolatedWorld", {"frameId": frame_id,
                     "worldName": "sudetect-read-only", "grantUniveralAccess": False})
    result = cdp.send("Runtime.evaluate", {"expression": _SNAPSHOT,
                      "contextId": world["executionContextId"], "returnByValue": True})
    if "exceptionDetails" in result:
        raise RuntimeError("isolated_dom_snapshot_failed")
    value = result.get("result", {}).get("value")
    if not isinstance(value, dict):
        raise RuntimeError("isolated_dom_snapshot_failed")
    return value, world["executionContextId"]


def _review_worker(body, content_type, kind, resources, reveal_client_ui, reveal_config,
                   reveal_explicit, max_seconds):
    from playwright.sync_api import sync_playwright

    result = _base_result(body, kind)
    result.update(status="partial", reason="runtime_incomplete", pending_reviews=[],
                  static_html={"fields": 0, "tables": 0, "rows": 0, "scripts": 0},
                  initial_dom=None, after_client_reveal=None, client_reveal_applied=False,
                  script_parsed_count=0, script_error_count=0, console_error_count=0,
                  script_executed_count=0,
                  captured_resource_requests=0, blocked_request_count=0,
                  failed_request_count=0,
                  blocked_beacon_count=0,
                  blocked_websocket_count=0, blocked_popup_count=0,
                  blocked_download_count=0, blocked_frame_request_count=0,
                  attached_frame_count=0, unexpected_navigation_count=0,
                  observation_window_ms=1000, boundary="browser_broker_only")
    start = time.monotonic()
    if kind == "html":
        parser = _StaticHTML()
        parser.feed(body.decode("utf-8", "replace"))
        result["static_html"] = {"fields": parser.fields, "tables": parser.tables,
                                 "rows": parser.rows, "scripts": parser.scripts}
        root_body = body
        root_type = content_type
    else:
        root_body = b'<!doctype html><meta charset="utf-8"><script src="/__main__.js"></script>'
        root_type = "text/html; charset=utf-8"
        result["static_html"]["scripts"] = 1
    fulfilled = {ROOT_URL: (root_body, root_type)}
    external_origins = set()
    for key, value in resources.items():
        if key.startswith("/"):
            fulfilled[ORIGIN + key] = value
        else:
            fulfilled[key] = value
            parsed = urlsplit(key)
            external_origins.add(parsed.scheme + "://" + parsed.netloc)
    if kind == "javascript":
        fulfilled[ORIGIN + "/__main__.js"] = (body, content_type)
    script_urls = {ROOT_URL} | {url for url, (_data, mime) in fulfilled.items()
                                if "javascript" in mime.casefold()}
    if external_origins:
        # Captured response headers were not supplied: original CORS/CSP
        # semantics remain unverified even if offline script execution works.
        result["pending_reviews"].append("external_response_headers_unverified")
    source_list = " ".join(sorted(external_origins))
    csp = _CSP.replace("'self'", "'self' " + source_list) if source_list else _CSP
    root_served = False
    browser = context = None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True, chromium_sandbox=True,
                timeout=min(15000, int(max_seconds * 1000)),
                proxy={"server": "http://127.0.0.1:9", "bypass": "<-loopback>"},
                args=["--disable-background-networking", "--disable-quic",
                      "--disable-extensions", "--disable-sync", "--disable-default-apps",
                      "--host-resolver-rules=MAP * ~NOTFOUND",
                      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"])
            context = browser.new_context(service_workers="block", accept_downloads=False,
                                          permissions=[], storage_state={"cookies": [], "origins": []})
            if not hasattr(context, "route_web_socket"):
                result["pending_reviews"].append("websocket_interception_unavailable")
                return result
            context.expose_binding("__sudetectBlockedTransport", lambda _source, kind:
                result.__setitem__("blocked_beacon_count", result["blocked_beacon_count"]
                                   + (kind == "beacon")))
            context.add_init_script(_BOOTSTRAP)
            def websocket_sink(ws):
                result["blocked_websocket_count"] += 1
                ws.on_message(lambda _message: None)
            context.route_web_socket("**/*", websocket_sink)
            page = context.new_page()
            page.on("pageerror", lambda _error: result.__setitem__(
                "script_error_count", result["script_error_count"] + 1))
            page.on("requestfailed", lambda _request: result.__setitem__(
                "failed_request_count", result["failed_request_count"] + 1))
            page.on("console", lambda message: result.__setitem__(
                "console_error_count", result["console_error_count"] + (message.type == "error")))
            page.on("dialog", lambda dialog: dialog.dismiss())
            context.on("page", lambda popup: (result.__setitem__(
                "blocked_popup_count", result["blocked_popup_count"] + 1), popup.close())
                       if popup != page else None)
            page.on("download", lambda download: result.__setitem__(
                "blocked_download_count", result["blocked_download_count"] + 1))
            page.on("frameattached", lambda frame: result.__setitem__(
                "attached_frame_count", result["attached_frame_count"] + 1))
            page.on("framenavigated", lambda frame: result.__setitem__(
                "unexpected_navigation_count", result["unexpected_navigation_count"]
                + (frame == page.main_frame and frame.url != ROOT_URL)))
            cdp = context.new_cdp_session(page)
            cdp.send("Page.enable")
            cdp.send("Runtime.enable")
            cdp.send("Debugger.enable")
            cdp.send("Profiler.enable")
            cdp.send("Profiler.startPreciseCoverage", {"callCount": True, "detailed": True})
            def script_parsed(event):
                url = event.get("url", "")
                if url in script_urls:
                    result["script_parsed_count"] += 1
            cdp.on("Debugger.scriptParsed", script_parsed)
            def handle(route):
                nonlocal root_served
                request = route.request
                target_url = request.url
                allowed = request.method == "GET" and target_url in fulfilled
                if request.resource_type == "document":
                    try:
                        main_frame = request.frame == page.main_frame
                    except Exception:
                        main_frame = False
                    if not main_frame or target_url != ROOT_URL or root_served:
                        result["blocked_frame_request_count"] += 1
                        allowed = False
                    else:
                        root_served = True
                if not allowed:
                    result["blocked_request_count"] += 1
                    route.abort()
                    return
                data, mime = fulfilled[target_url]
                result["captured_resource_requests"] += 1
                headers = {"Content-Security-Policy": csp,
                           "X-Content-Type-Options": "nosniff"} if target_url == ROOT_URL else {
                           "X-Content-Type-Options": "nosniff"}
                route.fulfill(status=200, body=data, content_type=mime, headers=headers)
            context.route("**/*", handle)
            try:
                page.goto(ROOT_URL, wait_until="domcontentloaded",
                          timeout=max(1000, min(15000, int((max_seconds - (time.monotonic()-start))*1000))))
                page.wait_for_timeout(1000)
                frame_id = cdp.send("Page.getFrameTree")["frameTree"]["frame"]["id"]
                snapshot, world_id = _snapshot(cdp, frame_id)
                result["initial_dom"] = snapshot
                if reveal_client_ui:
                    expression = _REVEAL.replace("__CONFIG__", json.dumps(
                        reveal_config, ensure_ascii=True, separators=(",", ":")))
                    changed = cdp.send("Runtime.evaluate", {"expression": expression,
                                       "contextId": world_id, "returnByValue": True})
                    outcome = changed.get("result", {}).get("value")
                    if "exceptionDetails" in changed or outcome not in {
                            "applied", "target_missing", "duplicate_target", "dom_limit",
                            "hidden_ancestor"}:
                        outcome = "client_reveal_execution_failed"
                    applied = outcome == "applied"
                    result["client_reveal_applied"] = applied
                    result["client_reveal_action_digest"] = hashlib.sha256(
                        (result["source_sha256"] + "\n" + json.dumps(reveal_config,
                         ensure_ascii=True, sort_keys=True, separators=(",", ":"))).encode()
                    ).hexdigest()
                    if not applied:
                        result["client_reveal_failure"] = outcome
                        if reveal_explicit:
                            result["pending_reviews"].append("client_reveal_" + outcome)
                    if applied:
                        page.wait_for_timeout(1000)
                        result["after_client_reveal"], _ = _snapshot(cdp, frame_id)
                        visibility = cdp.send("Runtime.evaluate", {
                            "expression": _REVEAL_VISIBLE.replace("__SHOW_IDS__", json.dumps(
                                reveal_config["show_ids"], ensure_ascii=True)),
                            "contextId": world_id, "returnByValue": True})
                        visible = ("exceptionDetails" not in visibility and
                                   visibility.get("result", {}).get("value") is True)
                        result["client_reveal_visibility_verified"] = visible
                        if not visible:
                            result["client_reveal_failure"] = "target_not_visible"
                            result["pending_reviews"].append("client_reveal_target_not_visible")
            except Exception:
                result["pending_reviews"].append("runtime_navigation_or_snapshot_failed")
            finally:
                try:
                    coverage = cdp.send("Profiler.takePreciseCoverage")["result"]
                    result["script_executed_count"] = sum(
                        1 for script in coverage
                        if script.get("url") in script_urls
                        and any(span.get("count", 0) > 0
                                for function in script.get("functions", [])
                                for span in function.get("ranges", [])))
                except Exception:
                    result["pending_reviews"].append("script_coverage_unavailable")
                context.close()
                browser.close()
    except ImportError:
        result["pending_reviews"].append("playwright_unavailable")
    except Exception:
        result["pending_reviews"].append("runtime_worker_failure")
    finally:
        if context is not None:
            try: context.close()
            except Exception: pass
        if browser is not None:
            try: browser.close()
            except Exception: pass
    if result["script_executed_count"] == 0 and result["static_html"]["scripts"]:
        result["pending_reviews"].append("original_script_not_observed")
    result["original_script_executed"] = result["script_executed_count"] > 0
    if result["script_error_count"]: result["pending_reviews"].append("script_error_observed")
    if result["console_error_count"]: result["pending_reviews"].append("console_error_observed")
    if result["failed_request_count"]: result["pending_reviews"].append("request_failure_observed")
    if result["blocked_beacon_count"]: result["pending_reviews"].append("beacon_blocked")
    if result["blocked_request_count"]: result["pending_reviews"].append("uncaptured_dependency_blocked")
    if result["blocked_websocket_count"]: result["pending_reviews"].append("websocket_blocked")
    if result["blocked_popup_count"]: result["pending_reviews"].append("popup_blocked")
    if result["blocked_download_count"]: result["pending_reviews"].append("download_blocked")
    if result["blocked_frame_request_count"]: result["pending_reviews"].append("frame_or_navigation_blocked")
    if result["attached_frame_count"]: result["pending_reviews"].append("frame_attached")
    if result["unexpected_navigation_count"]: result["pending_reviews"].append("navigation_changed_document")
    for snapshot in (result["initial_dom"], result["after_client_reveal"]):
        if snapshot and (snapshot["dom_node_limit"] or snapshot["visible_text_truncated"]):
            result["pending_reviews"].append("dom_snapshot_limit")
    if kind == "javascript":
        result["pending_reviews"].append("original_html_unavailable")
    result["pending_reviews"] = sorted(set(result["pending_reviews"]))
    result["runtime_observation_complete"] = bool(result["initial_dom"] is not None
        and not result["pending_reviews"] and (result["original_script_executed"]
        or not result["static_html"]["scripts"]))
    result["status"] = "reviewed" if result["runtime_observation_complete"] else "partial"
    result["reason"] = "bounded_runtime_observed" if result["runtime_observation_complete"] else "runtime_incomplete"
    return result


def _entry(writer, body, content_type, kind, resources, reveal_client_ui, reveal_config,
           reveal_explicit, max_seconds):
    if os.name != "nt":
        os.setsid()
    try:
        writer.send(_review_worker(body, content_type, kind, resources,
                                   reveal_client_ui, reveal_config, reveal_explicit,
                                   max_seconds))
    except Exception:
        result = _base_result(body, kind)
        result.update(status="partial", reason="runtime_worker_failure",
                      pending_reviews=["runtime_worker_failure"])
        writer.send(result)
    finally:
        writer.close()
        # Keep the worker as the descendant-tree root until the parent has
        # received the result and terminated the whole process group/tree.
        time.sleep(5)


def _kill_tree(process):
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.is_alive():
        process.kill()
    process.join(timeout=2)


def review_runtime_source(body: bytes, content_type: str, *, authorization: dict,
                          resources: dict | None = None, reveal_client_ui: bool = True,
                          max_seconds: float = 30.0) -> dict:
    """Run only the hash-approved capture; return counts and controlled gaps."""
    safe_body = body if isinstance(body, bytes) else b""
    error, kind, normalized = _validate(body, content_type, authorization, resources, max_seconds)
    result = _base_result(safe_body, kind or "unknown")
    if error:
        result["reason"] = error
        result["pending_reviews"] = [error]
        return result
    if not isinstance(reveal_client_ui, bool):
        result["reason"] = "invalid_reveal_option"
        result["pending_reviews"] = ["invalid_reveal_option"]
        return result
    reveal_error, reveal_config = _reveal_config(authorization)
    if reveal_error:
        result["reason"] = reveal_error
        result["pending_reviews"] = [reveal_error]
        return result
    context = mp.get_context("spawn")
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(target=_entry, args=(writer, body, content_type, kind,
                              normalized, reveal_client_ui, reveal_config,
                              "client_ui_reveal" in authorization, max_seconds))
    deadline = time.monotonic() + max_seconds
    process.start()
    writer.close()
    try:
        if reader.poll(max(0.0, deadline - time.monotonic())):
            try:
                return reader.recv()
            except EOFError:
                pass
        result.update(status="partial", reason="runtime_time_limit",
                      pending_reviews=["runtime_time_limit"])
        return result
    finally:
        reader.close()
        if process.is_alive():
            _kill_tree(process)
        else:
            process.join(timeout=2)
