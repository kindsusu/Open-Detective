"""Replay one approved DOM edit against a hash-pinned, inert local fixture."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

MAX_INPUT = 1_048_576
MAX_FIXTURE = 1_048_576
APPROVED_ACTION = "remove_login_show_app"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PLAIN_REF = re.compile(r"[^\x00-\x1f\x7f]{1,256}")
_OPAQUE_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
_VOID_ELEMENTS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
                  "meta", "param", "source", "track", "wbr"}
_FORBIDDEN_ELEMENTS = {"applet", "audio", "base", "embed", "frame", "frameset", "iframe", "link",
                       "object", "script", "source", "track", "video"}
_ALLOWED_ELEMENTS = {
    "address", "article", "aside", "b", "blockquote", "body", "br", "button", "caption", "code",
    "col", "colgroup", "dd", "details", "div", "dl", "dt", "em", "fieldset", "footer", "h1",
    "h2", "h3", "h4", "h5", "h6", "head", "header", "hr", "html", "i", "input", "label",
    "legend", "li", "main", "meta", "nav", "ol", "option", "p", "pre", "section", "select",
    "small", "span", "strong", "style", "summary", "table", "tbody", "td", "textarea", "tfoot",
    "th", "thead", "title", "tr", "ul",
}
_URL_ATTRIBUTES = {"action", "background", "cite", "data", "formaction", "href", "manifest", "ping",
                   "poster", "profile", "src", "srcdoc", "srcset", "usemap", "xlink:href"}
_ERROR_GROUPS = {
    "expired_scope": "expired_scope",
    "fixture_mismatch": "fixture_mismatch",
    "browser_runtime_unavailable": "missing_browser",
    "dom_mutation_failed": "mutation_failed",
    "control_canary_changed": "mutation_failed",
    "active_or_navigable_markup_rejected": "fixture_blocked",
    "duplicate_attribute_rejected": "fixture_blocked",
    "preset_targets_missing_or_ambiguous": "fixture_blocked",
    "control_canary_missing": "fixture_blocked",
    "network_capable_fixture_rejected": "fixture_blocked",
    "symlink_path_rejected": "fixture_blocked",
    "invalid_fixture": "fixture_blocked",
    "invalid_fixture_encoding": "fixture_blocked",
}


class _InertFixtureParser(HTMLParser):
    """Validate active surfaces while checking exact preset target counts."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.target_counts = {"login-screen": 0, "app": 0}
        self._open_tags: list[str] = []
        self._style_parts: list[str] = []

    @staticmethod
    def _check_css(value: str) -> None:
        # Backslash escapes, comments, and at-rules make URL-token validation
        # unnecessarily ambiguous. The synthetic fixture does not need them.
        if ("\\" in value or "@" in value or "/*" in value or "*/" in value
                or re.search(r"(?:url|image|image-set|expression|element)\s*\(|-moz-binding\b", value, re.I)):
            raise ValueError("active_or_navigable_markup_rejected")

    def handle_starttag(self, tag, attrs):
        tag = tag.casefold()
        pairs = [(name.casefold(), value or "") for name, value in attrs]
        names = [name for name, _ in pairs]
        if len(names) != len(set(names)):
            raise ValueError("duplicate_attribute_rejected")
        if tag in _FORBIDDEN_ELEMENTS or tag not in _ALLOWED_ELEMENTS:
            raise ValueError("active_or_navigable_markup_rejected")
        values = dict(pairs)
        if any(name.startswith("on") or name in _URL_ATTRIBUTES for name in names):
            raise ValueError("active_or_navigable_markup_rejected")
        if tag == "meta" and values.get("http-equiv", "").strip().casefold() == "refresh":
            raise ValueError("active_or_navigable_markup_rejected")
        if "style" in values:
            self._check_css(values["style"])
        identifier = values.get("id")
        if identifier in self.target_counts:
            self.target_counts[identifier] += 1
        if tag not in _VOID_ELEMENTS:
            self._open_tags.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.casefold() not in _VOID_ELEMENTS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        tag = tag.casefold()
        if tag == "style":
            self._check_css("".join(self._style_parts))
            self._style_parts.clear()
        if self._open_tags and self._open_tags[-1] == tag:
            self._open_tags.pop()

    def handle_data(self, data):
        if self._open_tags and self._open_tags[-1] == "style":
            self._style_parts.append(data)

    def handle_pi(self, data):
        raise ValueError("active_or_navigable_markup_rejected")

    def handle_decl(self, decl):
        if decl.strip().casefold() != "doctype html":
            raise ValueError("active_or_navigable_markup_rejected")

    def close(self):
        super().close()
        if self._style_parts:
            self._check_css("".join(self._style_parts))


def _nonempty(value, name: str, maximum: int = 256, *, opaque: bool = False) -> str:
    if not isinstance(value, str) or value != value.strip() or not value or len(value) > maximum:
        raise ValueError(f"invalid_{name}")
    if not _PLAIN_REF.fullmatch(value):
        raise ValueError(f"invalid_{name}")
    if opaque and not _OPAQUE_REF.fullmatch(value):
        raise ValueError(f"invalid_{name}")
    return value


def _utc_time(value) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ValueError("invalid_expiry") from None
    if parsed.tzinfo is None:
        raise ValueError("invalid_expiry")
    return parsed.astimezone(timezone.utc)


def _reject_symlink_path(path: Path) -> Path:
    """Reject a link at the path or in any existing ancestor before resolving it."""
    absolute = path.absolute()
    for candidate in (absolute, *absolute.parents):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        attributes = getattr(info, "st_file_attributes", 0)
        if candidate.is_symlink() or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            raise ValueError("symlink_path_rejected")
    return absolute


def _read_bounded(path: Path, maximum: int, *, invalid: str) -> bytes:
    path = _reject_symlink_path(path)
    if not path.is_file():
        raise ValueError(invalid)
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("input_too_large")
    return raw


def _validate_manifest(manifest) -> tuple[Path, str, str, str]:
    required = {"case_id", "fixture_path", "fixture_sha256", "expires_at", "owner_ref",
                "approved_action", "control_canary"}
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise ValueError("invalid_manifest")
    case_id = _nonempty(manifest["case_id"], "case_id", 128, opaque=True)
    owner_ref = _nonempty(manifest["owner_ref"], "owner_ref", opaque=True)
    canary = _nonempty(manifest["control_canary"], "control_canary", 512)
    if manifest["approved_action"] != APPROVED_ACTION:
        raise ValueError("action_not_approved")
    digest = manifest["fixture_sha256"]
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ValueError("invalid_fixture_sha256")
    if _utc_time(manifest["expires_at"]) <= datetime.now(timezone.utc):
        raise ValueError("expired_scope")
    fixture_value = manifest["fixture_path"]
    if not isinstance(fixture_value, str) or not fixture_value or "\x00" in fixture_value:
        raise ValueError("invalid_fixture")
    return Path(fixture_value), case_id, owner_ref, canary


def _browser_replay(text: str, canary: str) -> tuple[dict, dict, int]:
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise ValueError("browser_runtime_unavailable") from None

    request_attempts = 0

    def snapshot(page) -> dict:
        structure = page.evaluate("""
            () => {
              const elements = Array.from(document.querySelectorAll('*'));
              const visible = (el) => {
                const style = getComputedStyle(el);
                return style.display !== 'none' && style.visibility !== 'hidden' &&
                       style.visibility !== 'collapse' &&
                       el.getClientRects().length > 0;
              };
              const tags = {};
              for (const el of elements) {
                const tag = el.tagName.toLowerCase();
                tags[tag] = (tags[tag] || 0) + 1;
              }
              const walker = document.createTreeWalker(document, NodeFilter.SHOW_ALL);
              let nodes = 0;
              while (walker.nextNode()) nodes += 1;
              return {
                element_count: elements.length,
                node_count: nodes,
                visible_element_count: elements.filter(visible).length,
                form_control_count: document.querySelectorAll('input,select,textarea').length,
                tag_counts: tags
              };
            }
        """)
        targets = {}
        for name, selector in (("login_screen", "#login-screen"), ("app", "#app")):
            locator = page.locator(selector)
            count = locator.count()
            targets[name] = {
                "count": count,
                "visible": locator.is_visible() if count == 1 else False,
                "computed_display": locator.evaluate("el => getComputedStyle(el).display") if count == 1 else None,
            }
        structure["targets"] = targets
        structure["control_canary_present"] = page.evaluate(
            "needle => (document.body?.textContent || '').includes(needle)", canary)
        return structure

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                proxy={"server": "http://127.0.0.1:9", "bypass": "<-loopback>"},
                args=["--disable-background-networking", "--disable-quic", "--disable-extensions",
                      "--disable-sync", "--disable-default-apps",
                      "--host-resolver-rules=MAP * ~NOTFOUND",
                      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"],
            )
            context = browser.new_context(
                service_workers="block", accept_downloads=False, java_script_enabled=False,
                permissions=[], storage_state={"cookies": [], "origins": []})
            page = context.new_page()

            def block_request(route):
                nonlocal request_attempts
                request_attempts += 1
                route.abort("blockedbyclient")

            context.route("**/*", block_request)
            try:
                page.set_content(text, wait_until="domcontentloaded", timeout=5_000)
                if request_attempts:
                    raise ValueError("network_capable_fixture_rejected")
                baseline = snapshot(page)
                if any(target["count"] != 1 for target in baseline["targets"].values()):
                    raise ValueError("preset_targets_missing_or_ambiguous")
                if not baseline["control_canary_present"]:
                    raise ValueError("control_canary_missing")
                page.evaluate("""
                    () => {
                      const login = document.querySelector('#login-screen');
                      const app = document.querySelector('#app');
                      if (!login || !app) throw new Error('preset targets missing');
                      login.remove();
                      app.style.display = 'flex';
                    }
                """)
                after = snapshot(page)
                if request_attempts:
                    raise ValueError("network_capable_fixture_rejected")
            finally:
                context.close()
                browser.close()
    except ValueError:
        raise
    except PlaywrightError:
        raise ValueError("browser_runtime_unavailable") from None

    if after["targets"]["login_screen"]["count"] != 0:
        raise ValueError("dom_mutation_failed")
    if (after["targets"]["app"]["count"] != 1
            or after["targets"]["app"]["computed_display"] != "flex"
            or not after["targets"]["app"]["visible"]):
        raise ValueError("dom_mutation_failed")
    if not after["control_canary_present"]:
        raise ValueError("control_canary_changed")
    return baseline, after, request_attempts


def replay(manifest):
    fixture_path, case_id, owner_ref, canary = _validate_manifest(manifest)
    raw = _read_bounded(fixture_path, MAX_FIXTURE, invalid="invalid_fixture")
    if hashlib.sha256(raw).hexdigest() != manifest["fixture_sha256"]:
        raise ValueError("fixture_mismatch")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("invalid_fixture_encoding") from None

    parser = _InertFixtureParser()
    parser.feed(text)
    parser.close()
    if parser.target_counts != {"login-screen": 1, "app": 1}:
        raise ValueError("preset_targets_missing_or_ambiguous")

    baseline, after, requests = _browser_replay(text, canary)
    return {
        "schema_version": "1.0", "case_id": case_id, "owner_ref": owner_ref,
        "fixture_sha256": manifest["fixture_sha256"], "approved_action": APPROVED_ACTION,
        "baseline": baseline, "after": after, "network_request_attempts": requests,
        "control_canary": {"baseline_present": baseline["control_canary_present"],
                           "after_present": after["control_canary_present"], "finding_claim": False},
        "interpretation": {"preset_dom_edit_completed": True, "synthetic_fixture_only": True,
                           "server_exposure": "not_measured", "authentication": "not_measured",
                           "original_anonymous_proof": False},
        "limitations": ["offline_hash_pinned_inert_fixture", "preset_dom_edit_only",
                        "no_raw_html_or_screenshot_in_report", "live_target_server_and_auth_not_tested",
                        "synthetic_replay_is_not_a_server_finding"],
    }


def _public_error(exc: Exception) -> str:
    """Return a bounded error category without echoing input or library text."""
    if isinstance(exc, json.JSONDecodeError):
        return "invalid_manifest"
    code = str(exc)
    if code in _ERROR_GROUPS:
        return _ERROR_GROUPS[code]
    if (code == "invalid_manifest" or code == "action_not_approved" or code == "invalid_expiry"
            or code.startswith("invalid_case_id") or code.startswith("invalid_owner_ref")
            or code.startswith("invalid_control_canary") or code == "invalid_fixture_sha256"):
        return "invalid_manifest"
    return "local_input_error"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Replay one preset DOM edit against an approved inert local fixture.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        manifest_path = _reject_symlink_path(Path(args.manifest))
        raw = _read_bounded(manifest_path, MAX_INPUT, invalid="invalid_manifest")
        manifest = json.loads(raw.decode("utf-8"))
        if isinstance(manifest, dict) and isinstance(manifest.get("fixture_path"), str):
            fixture_path = Path(manifest["fixture_path"])
            if not fixture_path.is_absolute():
                manifest = dict(manifest)
                manifest["fixture_path"] = str(manifest_path.parent / fixture_path)
        output = _reject_symlink_path(Path(args.output))
        if output.exists() or not output.parent.is_dir():
            raise ValueError("unsafe_output")
        result = replay(manifest)
        with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                       "w", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=True, indent=2)
            stream.write("\n")
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": _public_error(exc)}, separators=(",", ":")), file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
