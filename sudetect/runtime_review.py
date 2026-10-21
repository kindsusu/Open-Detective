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
import tempfile
import time
import unicodedata
from urllib.parse import unquote_to_bytes, urlsplit

from .runtime_interactions import inspect_png_download, validate_steps


ORIGIN = "https://captured.invalid"
ROOT_URL = ORIGIN + "/"
MAX_PNG_DOWNLOADS = 4
MAX_DOWNLOAD_STORAGE_BYTES = 32 * 1024 * 1024
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
_TIMEZONE_ID = re.compile(r"[A-Za-z_+-]+(?:/[A-Za-z0-9_+.-]+)*\Z")
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
_ACTION_TARGET = """((id) => {
  const el = document.getElementById(id);
  if (!el) return 'target_missing';
  const nodes = document.getElementsByTagName('*');
  if (nodes.length > 50000) return 'dom_limit';
  let matches = 0;
  for (const node of nodes) if (node.id === id) matches++;
  if (matches !== 1) return 'duplicate_target';
  const tag = el.tagName.toLowerCase();
  const type = String(el.type || '').toLowerCase();
  const name = String(el.name || '').toLowerCase();
  if (/login|log-in|signin|sign-in|password|passwd|credential|auth|submit/i.test(name) ||
      type === 'password' || type === 'submit' ||
      (tag === 'button' && (type === 'submit' || !el.hasAttribute('type'))) ||
      (tag === 'a' && /^javascript:/i.test(el.getAttribute('href') || '')))
    return 'prohibited_target';
  const form = el.closest('form');
  if (form && form.querySelector('input[type=password]')) return 'prohibited_target';
  return tag + ':' + type;
})(__TARGET_ID__)"""
_ACTION_BUTTON_CLASS = r"""((selection) => {
  const nodes = document.getElementsByClassName(selection.token);
  if (nodes.length > 64) return 'dom_limit';
  if (!nodes.length || (selection.index !== null && selection.index >= nodes.length))
    return 'target_missing';
  if (selection.index === null && nodes.length !== 1) return 'duplicate_target';
  const el = nodes[selection.index === null ? 0 : selection.index];
  const name = String(el.name || '');
  const aria = String(el.getAttribute('aria-label') || '');
  const text = String(el.textContent || '');
  const authWords = /(?:\b(?:log[\s-]?in|sign[\s-]?in|sign[\s-]?up|password|passcode|credential|auth(?:enticate|orize|entication)?|submit)\b|로그인|로그아웃|비밀번호|인증|제출|가입)/i;
  if (el.tagName !== 'BUTTON' || el.id || el.form || el.closest('form') ||
      (el.hasAttribute('type') && el.type === 'submit') ||
      el.hasAttribute('form') || el.hasAttribute('formaction') ||
      name.length > 256 || aria.length > 256 || text.length > 256 ||
      /login|log-in|signin|sign-in|password|passwd|credential|auth|submit/i.test(name) ||
      authWords.test(aria) || authWords.test(text))
    return 'prohibited_target';
  return 'button:standalone';
})(__BUTTON_CLASS__)"""
_FORM_STATE = """(() => {
  const fields = document.querySelectorAll('input,textarea,select');
  if (fields.length > 10000) return null;
  const rows = [];
  let chars = 0;
  for (const el of fields) {
    const row = [String(el.value || ''), !!el.checked,
                 Number(el.selectedIndex || 0)];
    chars += row[0].length;
    if (chars > 1048576) return null;
    rows.push(row);
  }
  return JSON.stringify(rows);
})()"""
_TARGET_DIAGNOSTICS = r"""((selection) => {
  const elements = document.getElementsByTagName('*');
  const unknown = presence => ({presence,visible:false,hidden_reason:null,
    disabled:null,option_count:null,selected_index:null});
  if (elements.length > 50000)
    return selection.ids.map(() => unknown('limit'))
      .concat(selection.button_class ? [unknown('limit')] : []);
  const byId = new Map(selection.ids.map(id => [id, []]));
  for (const el of elements) if (byId.has(el.id)) byId.get(el.id).push(el);
  const describe = matches => {
    if (!matches.length) return unknown('missing');
    if (matches.length !== 1) return unknown('duplicate');
    const el = matches[0];
    let reason = null, node = el, depth = 0;
    while (node && depth++ < 128) {
      const own = node === el;
      const style = getComputedStyle(node);
      if (style.display === 'none') {
        reason = node.hidden ? (own ? 'self_hidden' : 'ancestor_hidden')
                             : (own ? 'self_display' : 'ancestor_display');
        break;
      }
      if (Number(style.opacity) === 0) {
        reason = own ? 'self_opacity' : 'ancestor_opacity'; break;
      }
      node = node.parentElement;
    }
    if (!reason && node) reason = 'ancestor_depth_limit';
    if (!reason) {
      const style = getComputedStyle(el);
      if (style.visibility === 'hidden' || style.visibility === 'collapse')
        reason = 'self_visibility';
    }
    if (!reason) {
      const rect = el.getBoundingClientRect();
      if (!(rect.width > 0 && rect.height > 0)) reason = 'zero_geometry';
    }
    return {presence:'unique',visible:reason === null,hidden_reason:reason,
      disabled:el.matches(':disabled'),
      option_count:el.tagName === 'SELECT' ? el.options.length : null,
      selected_index:el.tagName === 'SELECT' ? el.selectedIndex : null};
  };
  const output = selection.ids.map(id => describe(byId.get(id)));
  if (selection.button_class) {
    const matches = document.getElementsByClassName(selection.button_class);
    const count = Math.min(matches.length, 65);
    const selected = matches.length > 64 ? unknown('limit') :
      selection.button_index === null ? describe([...matches]) :
      describe(selection.button_index < matches.length ? [matches[selection.button_index]] : []);
    output.push({...selected, match_count:count});
  }
  return output;
})(__SELECTION__)"""


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
            "observed_targets_initial": [],
            "observed_target_ids": [],
            "client_reveal_applied": False,
            "client_reveal_visibility_verified": False,
            "client_reveal_action_digest": None,
            "client_reveal_failure": None, "script_parsed_count": 0,
            "ui_steps": [], "png_downloads": [],
            "ui_steps_requested": 0, "ui_steps_completed": 0,
            "script_coverage_observed": None,
            "script_executed_count": 0, "script_error_count": 0,
            "console_error_count": 0, "captured_resource_requests": 0,
            "blocked_request_count": 0, "failed_request_count": 0,
            "blocked_beacon_count": 0,
            "blocked_websocket_count": 0, "blocked_popup_count": 0,
            "blocked_download_count": 0, "blocked_frame_request_count": 0,
            "attached_frame_count": 0, "unexpected_navigation_count": 0,
            "local_render_frame_count": 0,
            "viewport": {"width": 1280, "height": 720},
            "simulated_clock_used": False, "clock_fixture_digest": None,
            "timezone_id": None,
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


def _isolated_value(cdp, world_id, expression):
    response = cdp.send("Runtime.evaluate", {"expression": expression,
                        "contextId": world_id, "returnByValue": True})
    if "exceptionDetails" in response:
        raise RuntimeError("isolated_dom_action_failed")
    return response.get("result", {}).get("value")


def _visible_ids(cdp, world_id, ids):
    return _isolated_value(cdp, world_id, _REVEAL_VISIBLE.replace(
        "__SHOW_IDS__", json.dumps(ids, ensure_ascii=True))) is True


def _target_diagnostics(cdp, world_id, ids, button_class=None, button_index=None):
    return _isolated_value(cdp, world_id, _TARGET_DIAGNOSTICS.replace(
        "__SELECTION__", json.dumps({"ids": ids, "button_class": button_class,
                                     "button_index": button_index},
                                     ensure_ascii=True)))


def _targets_visible(states):
    return bool(states) and all(row["presence"] == "unique" and row["visible"]
                                for row in states)


def _targets_hidden(states):
    return bool(states) and all(row["presence"] == "unique" and not row["visible"]
                                and row["hidden_reason"] not in {
                                    None, "ancestor_depth_limit"}
                                for row in states)


def _dom_fingerprint(page, cdp, world_id):
    markup = page.content().encode("utf-8")
    if len(markup) > 8 * 1024 * 1024:
        return None
    state = _isolated_value(cdp, world_id, _FORM_STATE)
    if not isinstance(state, str) or len(state) > 2 * 1024 * 1024:
        return None
    class _WithoutFormControls(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=False)
            self.parts = []
            self.skip = 0

        def handle_starttag(self, tag, attrs):
            if tag in {"select", "textarea"}:
                self.skip += 1
            elif not self.skip and tag != "input":
                self.parts.append(self.get_starttag_text())

        def handle_startendtag(self, tag, attrs):
            if not self.skip and tag not in {"input", "select", "textarea"}:
                self.parts.append(self.get_starttag_text())

        def handle_endtag(self, tag):
            if tag in {"select", "textarea"} and self.skip:
                self.skip -= 1
            elif not self.skip and tag != "input":
                self.parts.append("</" + tag + ">")

        def handle_data(self, data):
            if not self.skip:
                self.parts.append(data)

        def handle_entityref(self, name):
            if not self.skip:
                self.parts.append("&" + name + ";")

        def handle_charref(self, name):
            if not self.skip:
                self.parts.append("&#" + name + ";")

    scrubbed = _WithoutFormControls()
    scrubbed.feed(markup.decode("utf-8", "replace"))
    return {"app": hashlib.sha256("".join(scrubbed.parts).encode("utf-8")).digest(),
            "input": hashlib.sha256(state.encode("utf-8")).digest()}


def _execute_ui_step(page, cdp, frame_id, world_id, row, action_state=None):
    action = row["action"]
    status = "completed"
    if action == "wait":
        page.wait_for_timeout(row["milliseconds"])
    else:
        if action_state:
            presence = action_state["presence"]
            if presence != "unique":
                return ({"missing": "target_missing", "duplicate": "duplicate_target",
                         "limit": "dom_limit"}.get(presence, "target_inspection_failed"),
                        None, False)
        target_class = row.get("target_button_class")
        if target_class is not None:
            target = _isolated_value(cdp, world_id, _ACTION_BUTTON_CLASS.replace(
                "__BUTTON_CLASS__", json.dumps({"token": target_class,
                    "index": row.get("target_index")}, ensure_ascii=True)))
        else:
            target_id = row["target_id"]
            target = _isolated_value(cdp, world_id, _ACTION_TARGET.replace(
                "__TARGET_ID__", json.dumps(target_id, ensure_ascii=True)))
        if target in {"target_missing", "duplicate_target", "dom_limit", "prohibited_target"}:
            return target, None, False
        if not isinstance(target, str) or ":" not in target:
            return "target_inspection_failed", None, False
        tag, field_type = target.split(":", 1)
        if ((action == "select" and tag != "select")
                or (action == "check" and field_type not in {"checkbox", "radio"})
                or (action == "fill" and (tag not in {"input", "textarea"}
                    or field_type not in {"", "text", "search"}))):
            return "incompatible_target", None, False
        locator = (page.locator("." + target_class).nth(row.get("target_index", 0))
                   if target_class is not None
                   else page.locator('[id="' + target_id + '"]'))
        if action == "click":
            locator.click(timeout=2000)
        elif action == "select":
            locator.select_option(index=row["index"], timeout=2000)
        elif action == "check":
            if row["checked"]:
                locator.check(timeout=2000)
            else:
                locator.uncheck(timeout=2000)
        elif action == "fill":
            locator.fill(row["value"], timeout=2000)
        page.wait_for_timeout(200)
    snapshot, world_id = _snapshot(cdp, frame_id)
    expected_visible = (_targets_visible(_target_diagnostics(
        cdp, world_id, row["expect_visible_ids"]))
        if row["expect_visible_ids"] else True)
    if not expected_visible:
        status = "expected_target_not_visible"
    return status, snapshot, expected_visible


def _review_worker(body, content_type, kind, resources, reveal_client_ui, reveal_config,
                   reveal_explicit, ui_steps, observe_target_ids, observe_png_download,
                   allow_local_render_frames, viewport, clock_time,
                   timezone_id, download_dir, max_seconds,
                   progress=None):
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
    result["ui_steps_requested"] = len(ui_steps)
    result["observed_target_ids"] = observe_target_ids.copy()
    result["viewport"] = viewport.copy()
    result["timezone_id"] = timezone_id
    if clock_time is not None:
        result["clock_fixture_digest"] = hashlib.sha256(
            (result["source_sha256"] + "\n" + clock_time.isoformat() + "\n"
             + (timezone_id or "")).encode()).hexdigest()
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
    script_sources = {url: (hashlib.sha256(fulfilled[url][0]).hexdigest(),
                            "primary" if url == ROOT_URL or url == ORIGIN + "/__main__.js"
                            else "captured_external" if not url.startswith(ORIGIN + "/")
                            else "captured_local") for url in script_urls}
    if external_origins:
        # Captured response headers were not supplied: original CORS/CSP
        # semantics remain unverified even if offline script execution works.
        result["pending_reviews"].append("external_response_headers_unverified")
    source_list = " ".join(sorted(external_origins))
    csp = _CSP.replace("'self'", "'self' " + source_list) if source_list else _CSP
    if allow_local_render_frames:
        csp = csp.replace("frame-src 'none'", "frame-src 'self' about:")
    root_served = False
    browser = context = None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True, chromium_sandbox=True,
                downloads_path=download_dir,
                timeout=min(15000, int(max_seconds * 1000)),
                proxy={"server": "http://127.0.0.1:9", "bypass": "<-loopback>"},
                args=["--disable-background-networking", "--disable-quic",
                      "--disable-extensions", "--disable-sync", "--disable-default-apps",
                      "--host-resolver-rules=MAP * ~NOTFOUND",
                      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"])
            try:
                context = browser.new_context(service_workers="block",
                                              accept_downloads=observe_png_download,
                                              viewport=viewport, timezone_id=timezone_id,
                                              permissions=[], storage_state={"cookies": [], "origins": []})
            except Exception:
                if timezone_id is not None:
                    result["pending_reviews"].append("timezone_context_unavailable")
                    return result
                raise
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
            if clock_time is not None:
                try:
                    page.clock.set_fixed_time(clock_time)
                    result["simulated_clock_used"] = True
                except Exception:
                    result["pending_reviews"].append("clock_fixture_unavailable")
                    return result
            page.set_default_timeout(2000)
            downloads = []
            browser_downloads = None
            if observe_png_download:
                try:
                    browser_downloads = browser.new_browser_cdp_session()
                    browser_downloads.send("Browser.setDownloadBehavior", {
                        "behavior": "allow", "downloadPath": download_dir,
                        "eventsEnabled": True})
                    def on_progress(event):
                        if max(event.get("receivedBytes", 0), event.get("totalBytes", 0)) > 8 * 1024 * 1024:
                            result["pending_reviews"].append("png_progress_byte_limit")
                            try:
                                browser_downloads.send("Browser.cancelDownload", {
                                    "guid": event["guid"]})
                            except Exception:
                                pass
                    browser_downloads.on("Browser.downloadProgress", on_progress)
                except Exception:
                    result["pending_reviews"].append("png_progress_guard_unavailable")
                    return result
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
            def on_download(download):
                downloads.append(download)
                if len(downloads) > MAX_PNG_DOWNLOADS:
                    result["blocked_download_count"] += 1
                    result["pending_reviews"].append("png_download_count_limit")
                    try:
                        download.cancel()
                    except Exception:
                        pass
                elif not observe_png_download:
                    result["blocked_download_count"] += 1
                elif not (download.url.startswith("blob:https://captured.invalid/")
                          or download.url.startswith("data:image/png;base64,")):
                    result["blocked_download_count"] += 1
                    try:
                        download.cancel()
                    except Exception:
                        pass
            page.on("download", on_download)
            def frame_attached(frame):
                result["attached_frame_count"] += 1
                if allow_local_render_frames:
                    result["local_render_frame_count"] += 1
            page.on("frameattached", frame_attached)
            def frame_navigated(frame):
                if frame == page.main_frame:
                    result["unexpected_navigation_count"] += frame.url != ROOT_URL
                elif frame.url not in {"about:blank", "about:srcdoc"}:
                    result["pending_reviews"].append("frame_navigation_not_local")
            page.on("framenavigated", frame_navigated)
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
            executed_scripts = set()
            observed_functions = set()
            executed_functions = set()
            observed_ranges = set()
            executed_ranges = set()
            script_id_sources = {}
            def collect_coverage():
                coverage = cdp.send("Profiler.takePreciseCoverage")["result"]
                functions = ranges = 0
                for script in coverage:
                    url = script.get("url")
                    if url not in script_urls:
                        continue
                    script_id = script.get("scriptId", "")
                    script_id_sources[script_id] = url
                    found = False
                    for function_index, function in enumerate(script.get("functions", [])):
                        function_key = (script_id, function_index)
                        observed_functions.add(function_key)
                        active = 0
                        for span in function.get("ranges", []):
                            range_key = (script_id, function_index,
                                         span.get("startOffset"), span.get("endOffset"))
                            observed_ranges.add(range_key)
                            if span.get("count", 0) > 0:
                                executed_ranges.add(range_key)
                                active += 1
                        if active:
                            executed_functions.add(function_key)
                            functions += 1
                            ranges += active
                            found = True
                    if found:
                        executed_scripts.add(script_id)
                    if len(observed_ranges) > 250000:
                        raise RuntimeError("script_coverage_limit")
                result["script_executed_count"] = len(executed_scripts)
                source_summaries = []
                for url in sorted(script_urls):
                    digest, source_kind = script_sources[url]
                    ids = {script_id for script_id, location in script_id_sources.items()
                           if location == url}
                    source_summaries.append({"source_sha256": digest,
                                             "source_kind": source_kind,
                                             "parsed_script_count": len(ids),
                                             "executed_script_count": len(ids & executed_scripts),
                                             "observed_function_count": sum(
                                                 item[0] in ids for item in observed_functions),
                                             "ever_executed_function_count": sum(
                                                 item[0] in ids for item in executed_functions),
                                             "observed_range_count": sum(
                                                 item[0] in ids for item in observed_ranges),
                                             "ever_executed_range_count": sum(
                                                 item[0] in ids for item in executed_ranges)})
                summary = {"executed_script_count": len(executed_scripts),
                        "observed_function_count": functions,
                        "observed_range_count": ranges,
                        "observed_total_function_count": len(observed_functions),
                        "ever_executed_function_count": len(executed_functions),
                        "unexecuted_observed_function_count": (
                            len(observed_functions) - len(executed_functions)),
                        "observed_total_range_count": len(observed_ranges),
                        "ever_executed_range_count": len(executed_ranges),
                        "unexecuted_observed_range_count": (
                            len(observed_ranges) - len(executed_ranges)),
                        "sources": source_summaries,
                        "semantic_branch_coverage_verified": False}
                result["script_coverage_observed"] = summary
                return summary
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
                if observe_target_ids:
                    result["observed_targets_initial"] = _target_diagnostics(
                        cdp, world_id, observe_target_ids)
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
                collect_coverage()
                if progress:
                    progress(result)
                for index, row in enumerate(ui_steps):
                    if time.monotonic() + 2.0 >= start + max_seconds:
                        result["pending_reviews"].append("ui_step_time_limit")
                        break
                    before = {name: result[name] for name in (
                        "script_error_count", "console_error_count",
                        "blocked_request_count", "failed_request_count")}
                    first_download = len(downloads)
                    visible_before = (_targets_visible(_target_diagnostics(
                        cdp, world_id, row["expect_visible_ids"]))
                        if row["expect_visible_ids"] else None)
                    hidden_before = (_targets_visible(_target_diagnostics(
                        cdp, world_id, row["expect_hidden_ids"]))
                        if row["expect_hidden_ids"] else None)
                    target_ids = [row["target_id"]] if "target_id" in row else []
                    target_class = row.get("target_button_class")
                    target_index = row.get("target_index")
                    action_state_before = (_target_diagnostics(
                        cdp, world_id, target_ids, target_class, target_index)[0]
                        if target_ids or target_class else None)
                    before_dom = None
                    if row["expect_dom_change"]:
                        before_dom = _dom_fingerprint(page, cdp, world_id)
                        if before_dom is None:
                            result["pending_reviews"].append("ui_dom_comparison_limit")
                            break
                    step = {"index": index, "action": row["action"],
                            "action_applied": False, "branch_verified": False,
                            "status": "action_failed", "dom": None,
                            "expected_visible_verified": None,
                            "visible_transition_verified": None,
                            "expected_hidden_verified": None,
                            "hidden_transition_verified": None,
                            "dom_change_verified": None,
                            "input_state_changed": None,
                            "observed_targets_after": [],
                            "action_target_before": action_state_before,
                            "action_target_after": None,
                            "png_download_verified": None,
                            "download_count": 0, "verified_png_count": 0,
                            "script_coverage": None, "error_delta": 0,
                            "blocked_request_delta": 0}
                    try:
                        action_status, step_dom, expected_visible = _execute_ui_step(
                            page, cdp, frame_id, world_id, row, action_state_before)
                        if row["expect_png_download"] and len(downloads) == first_download:
                            wait_deadline = min(time.monotonic() + 5,
                                                start + max_seconds - 1)
                            while len(downloads) == first_download and time.monotonic() < wait_deadline:
                                page.wait_for_timeout(100)
                        step["action_applied"] = action_status in {
                            "completed", "expected_target_not_visible"}
                        step["status"] = action_status
                        step["dom"] = step_dom
                        if row["expect_visible_ids"]:
                            step["expected_visible_verified"] = _targets_visible(
                                _target_diagnostics(cdp, world_id,
                                                    row["expect_visible_ids"]))
                            step["visible_transition_verified"] = bool(
                                not visible_before and step["expected_visible_verified"])
                        if row["expect_hidden_ids"]:
                            step["expected_hidden_verified"] = _targets_hidden(
                                _target_diagnostics(cdp, world_id,
                                                    row["expect_hidden_ids"]))
                            step["hidden_transition_verified"] = bool(
                                hidden_before and step["expected_hidden_verified"])
                        if row["expect_dom_change"] and step["action_applied"]:
                            after_dom = _dom_fingerprint(page, cdp, world_id)
                            if after_dom is not None:
                                step["dom_change_verified"] = (
                                    after_dom["app"] != before_dom["app"])
                                step["input_state_changed"] = (
                                    after_dom["input"] != before_dom["input"])
                        if observe_png_download:
                            first_metadata = len(result["png_downloads"])
                            for download in downloads[first_download:MAX_PNG_DOWNLOADS]:
                                metadata = inspect_png_download(download, download_dir)
                                result["png_downloads"].append(metadata)
                                if metadata["status"] != "verified_png":
                                    result["pending_reviews"].append("png_download_unverified")
                            new_downloads = result["png_downloads"][first_metadata:]
                            step["download_count"] = len(downloads) - first_download
                            step["verified_png_count"] = sum(
                                item["status"] == "verified_png" for item in new_downloads)
                        if row["expect_png_download"]:
                            step["png_download_verified"] = step["verified_png_count"] > 0
                        asserted = bool(row["expect_visible_ids"] or row["expect_hidden_ids"]
                                        or row["expect_dom_change"]
                                        or row["expect_png_download"])
                        step["branch_verified"] = bool(step["action_applied"] and asserted
                            and step["expected_visible_verified"] is not False
                            and step["expected_hidden_verified"] is not False
                            and step["dom_change_verified"] is not False
                            and step["png_download_verified"] is not False
                            and (not row["expect_dom_change"]
                                 or step["dom_change_verified"] is True)
                            and any(value is True for value in (
                                step["visible_transition_verified"],
                                step["hidden_transition_verified"],
                                step["dom_change_verified"],
                                step["png_download_verified"])))
                        if not step["branch_verified"]:
                            result["pending_reviews"].append("ui_branch_unverified")
                    except Exception:
                        step["status"] = "action_or_snapshot_failed"
                    try:
                        if observe_target_ids:
                            step["observed_targets_after"] = _target_diagnostics(
                                cdp, world_id, observe_target_ids)
                        if target_ids or target_class:
                            step["action_target_after"] = _target_diagnostics(
                                cdp, world_id, target_ids, target_class, target_index)[0]
                    except Exception:
                        result["pending_reviews"].append("target_diagnostics_unavailable")
                    if step["status"] == "action_or_snapshot_failed":
                        state = step["action_target_after"]
                        if state is not None:
                            if state["presence"] == "missing":
                                step["status"] = "target_missing"
                            elif state["presence"] == "duplicate":
                                step["status"] = "duplicate_target"
                            elif state["presence"] == "unique" and state["disabled"]:
                                step["status"] = "target_disabled"
                            elif state["presence"] == "unique" and not state["visible"]:
                                step["status"] = "target_hidden"
                        if step["status"] == "action_or_snapshot_failed":
                            result["pending_reviews"].append("ui_action_or_snapshot_failed")
                    try:
                        step["script_coverage"] = collect_coverage()
                    except Exception:
                        result["pending_reviews"].append("script_coverage_unavailable")
                    step["error_delta"] = sum(result[name] - before[name] for name in (
                        "script_error_count", "console_error_count", "failed_request_count"))
                    step["blocked_request_delta"] = (
                        result["blocked_request_count"] - before["blocked_request_count"])
                    if step["error_delta"] or step["blocked_request_delta"]:
                        step["branch_verified"] = False
                        result["pending_reviews"].append("ui_branch_unverified")
                    result["ui_steps"].append(step)
                    if step["branch_verified"]:
                        result["ui_steps_completed"] += 1
                    if progress:
                        progress(result)
                    if not step["action_applied"]:
                        result["pending_reviews"].append("ui_action_not_applied")
                        break
                if len(result["ui_steps"]) < len(ui_steps):
                    result["pending_reviews"].append("ui_steps_incomplete")
            except Exception:
                result["pending_reviews"].append("runtime_navigation_or_snapshot_failed")
            finally:
                try:
                    collect_coverage()
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
    if result["attached_frame_count"] and not allow_local_render_frames:
        result["pending_reviews"].append("frame_attached")
    if result["local_render_frame_count"]:
        result["pending_reviews"].append("local_render_frame_content_unverified")
    if result["unexpected_navigation_count"]: result["pending_reviews"].append("navigation_changed_document")
    diagnostic_states = list(result["observed_targets_initial"])
    for step in result["ui_steps"]:
        diagnostic_states.extend(step["observed_targets_after"])
        diagnostic_states.extend(state for state in (
            step["action_target_before"], step["action_target_after"]) if state)
    if any(state["presence"] == "limit" or
           state["hidden_reason"] == "ancestor_depth_limit"
           for state in diagnostic_states):
        result["pending_reviews"].append("target_diagnostics_limit")
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
           reveal_explicit, ui_steps, observe_target_ids, observe_png_download,
           allow_local_render_frames, viewport, clock_time, timezone_id,
           download_dir, max_seconds):
    if os.name != "nt":
        os.setsid()
    try:
        final = _review_worker(body, content_type, kind, resources,
                               reveal_client_ui, reveal_config, reveal_explicit,
                               ui_steps, observe_target_ids, observe_png_download,
                               allow_local_render_frames, viewport, clock_time,
                               timezone_id, download_dir,
                               max_seconds,
                               progress=lambda current: writer.send(("progress", current)))
        writer.send(("final", final))
    except Exception:
        result = _base_result(body, kind)
        result.update(status="partial", reason="runtime_worker_failure",
                      pending_reviews=["runtime_worker_failure"])
        writer.send(("final", result))
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
    steps_error, steps_config = validate_steps(authorization)
    if steps_error:
        result["reason"] = steps_error
        result["pending_reviews"] = [steps_error]
        return result
    ui_steps, observe_png_download, observe_target_ids = steps_config
    allow_local_render_frames = authorization.get("allow_local_render_frames", False)
    if not isinstance(allow_local_render_frames, bool):
        result["reason"] = "invalid_local_frame_option"
        result["pending_reviews"] = ["invalid_local_frame_option"]
        return result
    viewport = authorization.get("viewport", {"width": 1280, "height": 720})
    if (not isinstance(viewport, dict) or set(viewport) != {"width", "height"}
            or any(isinstance(value, bool) or not isinstance(value, int)
                   for value in viewport.values())
            or not 320 <= viewport["width"] <= 1920
            or not 240 <= viewport["height"] <= 2160):
        result["reason"] = "invalid_viewport"
        result["pending_reviews"] = ["invalid_viewport"]
        return result
    raw_clock = authorization.get("clock_time")
    clock_time = None
    if raw_clock is not None:
        if not isinstance(raw_clock, str) or len(raw_clock) > 40:
            result["reason"] = "invalid_clock_time"
            result["pending_reviews"] = ["invalid_clock_time"]
            return result
        try:
            clock_time = datetime.fromisoformat(raw_clock.replace("Z", "+00:00"))
            if (clock_time.tzinfo is None or clock_time.utcoffset() is None
                    or not 1900 <= clock_time.year <= 2100):
                raise ValueError("invalid clock")
        except (TypeError, ValueError, OverflowError):
            result["reason"] = "invalid_clock_time"
            result["pending_reviews"] = ["invalid_clock_time"]
            return result
    timezone_id = authorization.get("timezone_id")
    if (timezone_id is not None and (not isinstance(timezone_id, str)
            or not 1 <= len(timezone_id) <= 64
            or not _TIMEZONE_ID.fullmatch(timezone_id))):
        result["reason"] = "invalid_timezone_id"
        result["pending_reviews"] = ["invalid_timezone_id"]
        return result
    context = mp.get_context("spawn")
    reader, writer = context.Pipe(duplex=False)
    download_temp = tempfile.TemporaryDirectory(prefix="sudetect-runtime-")
    process = context.Process(target=_entry, args=(writer, body, content_type, kind,
                              normalized, reveal_client_ui, reveal_config,
                              "client_ui_reveal" in authorization, ui_steps,
                              observe_target_ids, observe_png_download,
                              allow_local_render_frames,
                              viewport.copy(), clock_time, timezone_id,
                              download_temp.name, max_seconds))
    deadline = time.monotonic() + max_seconds
    try:
        process.start()
        writer.close()
        latest = result
        while time.monotonic() < deadline:
            try:
                stored_bytes = sum(entry.stat(follow_symlinks=False).st_size
                    for entry in os.scandir(download_temp.name)
                    if entry.is_file(follow_symlinks=False))
            except OSError:
                stored_bytes = MAX_DOWNLOAD_STORAGE_BYTES + 1
            if stored_bytes > MAX_DOWNLOAD_STORAGE_BYTES:
                latest.update(status="partial", reason="download_storage_limit",
                              runtime_observation_complete=False,
                              pending_reviews=sorted(set(latest["pending_reviews"])
                                                     | {"download_storage_limit"}))
                return latest
            if not reader.poll(min(0.1, max(0.0, deadline - time.monotonic()))):
                continue
            try:
                kind, value = reader.recv()
            except EOFError:
                break
            latest = value
            if kind == "final":
                return value
        latest.update(status="partial", reason="runtime_time_limit",
                      runtime_observation_complete=False,
                      pending_reviews=sorted(set(latest["pending_reviews"])
                                             | {"runtime_time_limit", "ui_steps_incomplete"}))
        return latest
    finally:
        reader.close()
        writer.close()
        if process.pid is not None:
            if process.is_alive():
                _kill_tree(process)
            else:
                process.join(timeout=2)
        download_temp.cleanup()
