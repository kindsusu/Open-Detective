"""Bounded brokered browser observation, with no direct browser HTTP transport.

Every intercepted HTTP request is fetched through the anonymous policy transport,
then fulfilled from RAM. Cookies, user headers, POST, WS and service workers are
not replayed. This deliberately changes some applications: report limitations,
never call an inaccessible application safe. OS egress isolation is still needed
for hostile pages; Chromium flags are defense in depth, not an OS firewall.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import time
from urllib.parse import urljoin
import uuid

from .classifiers import analyze

LIMITATIONS = [
    "brokered_stateless_anonymous_not_full_browser_equivalence",
    "cookies_authorization_and_browser_referrer_not_forwarded",
    "service_workers_websockets_post_downloads_and_popups_disabled",
    "native_egress_requires_external_os_isolation_for_hostile_content",
    "no_automated_site_safety_or_sensitive_data_absence_claim",
    "canvas_shadow_dom_js_heap_and_post_interaction_content_not_inspected",
]

# Do not mutate DOM properties to expose a gate. Current form values differ from
# attributes in outerHTML. Bound both element traversal and data crossing into Python.
LIVE_STATE_SCRIPT = """({maxBytes,maxNodes}) => {
    const started = performance.now(), encoder = new TextEncoder();
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_ELEMENT);
    const values = []; let bytes=0, nodes=0, controls=0, truncated=false;
    let node=walker.currentNode;
    while (node) {
        if (++nodes > maxNodes || performance.now()-started > 100) { truncated=true; break; }
        const tag=node.tagName;
        if (tag==='INPUT' || tag==='TEXTAREA' || tag==='SELECT') {
            controls++;
            const proto=tag==='INPUT'?HTMLInputElement.prototype:tag==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLSelectElement.prototype;
            const value=Object.getOwnPropertyDescriptor(proto,'value').get.call(node);
            const left=maxBytes-bytes;
            // UTF-16 slicing first bounds work before UTF-8 encoding.
            const part=value.slice(0,left);
            const raw=encoder.encode(part);
            const clipped=raw.length>left || part.length<value.length;
            values.push(new TextDecoder().decode(raw.slice(0,left)));
            bytes+=Math.min(raw.length,left);
            if (clipped || bytes>=maxBytes) { truncated=true; break; }
        }
        node=walker.nextNode();
    }
    return {values,bytes,nodes:Math.min(nodes,maxNodes),controls,truncated};
}"""


def observe(url, scope, *, duration=3.0, max_total_bytes=None, fetcher=None,
            synthetic_markers=(), stop_on_sensitive=True, target_id=None):
    from .policy import PolicyError
    from .evidence import safe_url, stable_ref
    from .transport import fetch

    started = time.monotonic()
    result = {
        "schema_version": "2.0.0", "observation_id": str(uuid.uuid4()),
        "observed_at": datetime.now(timezone.utc).isoformat(), "policy_id": scope.policy_id,
        "target_ref": safe_url(url), "mode": "brokered_anonymous_browser",
        "access": "INDETERMINATE", "content": "NOT_INSPECTED", "complete": False,
        "capture_complete": False, "analysis_complete": False,
        "content_review_complete": False,
        "observations": [], "blocked": [], "limitations": list(LIMITATIONS),
        "requests": 0, "bytes_processed": 0, "reason": "not_started",
    }
    try:
        canonical = scope.authorize(url)
        result["target_id"] = target_id or stable_ref(canonical, os.environ.get("SUDETECT_LOCATOR_HMAC_KEY") or None)
    except (PolicyError, ValueError):
        result["reason"] = "scope_rejected"
        return result
    if not 0 < duration <= 30:
        result["reason"] = "invalid_duration"
        return result
    if max_total_bytes is not None and (isinstance(max_total_bytes, bool) or not isinstance(max_total_bytes, int) or max_total_bytes < 1):
        result["reason"] = "invalid_byte_budget"
        return result
    byte_budget = min(max_total_bytes if max_total_bytes is not None else scope.max_bytes * 4, 8 * 1024 * 1024)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        result["reason"] = "browser_dependency_unavailable"
        return result
    do_fetch = fetcher or fetch
    deadline = started + min(60, duration + scope.timeout)
    stop = False
    observed_main = False
    completed_navigation = False

    def block(reason, target):
        if len(result["blocked"]) < scope.max_requests:
            result["blocked"].append({"reason": reason, "target_ref": safe_url(target)})

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                proxy={"server": "http://127.0.0.1:9", "bypass": "<-loopback>"},
                args=["--disable-background-networking", "--disable-quic",
                      "--disable-extensions", "--disable-sync", "--disable-default-apps",
                      "--host-resolver-rules=MAP * ~NOTFOUND",
                      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"],
            )
            context = browser.new_context(service_workers="block", accept_downloads=False,
                                          permissions=[], storage_state={"cookies": [], "origins": []})
            try:
                if not hasattr(context, "route_web_socket"):
                    result["reason"] = "websocket_interception_unavailable"
                    return result
                # Never connect_to_server. Closing inside the synchronous route
                # callback can deadlock before Playwright marks the mock socket
                # open. Sink messages locally; context teardown closes it.
                def sink_websocket(ws):
                    block("websocket_not_observed", ws.url)
                    ws.on_message(lambda message: None)
                context.route_web_socket("**/*", sink_websocket)
                page = context.new_page()
                context.on("page", lambda popup: popup.close() if popup != page else None)
                page.on("dialog", lambda dialog: dialog.dismiss())

                def handle(route):
                    nonlocal stop, observed_main
                    request = route.request
                    target = request.url
                    if stop or time.monotonic() > deadline:
                        block("inspection_stopped", target)
                        route.abort()
                        return
                    if request.method != "GET":
                        block("method_not_allowed", target)
                        route.abort()
                        return
                    if request.resource_type not in ("document", "script", "stylesheet", "xhr", "fetch"):
                        block("resource_not_observed", target)
                        route.abort()
                        return
                    if result["requests"] >= scope.max_requests or result["bytes_processed"] >= byte_budget:
                        stop = True
                        result["reason"] = "budget_exhausted"
                        block("budget_exhausted", target)
                        route.abort()
                        return
                    try:
                        scope.authorize(target)
                    except (PolicyError, ValueError):
                        block("scope_rejected", target)
                        route.abort()
                        return
                    result["requests"] += 1
                    remaining = byte_budget - result["bytes_processed"]
                    try:
                        response = do_fetch(target, scope, follow_redirects=False, max_bytes=remaining)
                    except Exception:
                        block("broker_failed", target)
                        route.abort()
                        return
                    obs = dict(response.observation)
                    obs["resource_type"] = request.resource_type
                    obs["initiator"] = "anonymous_page_load"
                    body = response.body
                    if len(body) > remaining:
                        stop = True
                        result["reason"] = "budget_exhausted"
                        block("budget_exhausted", target)
                        route.abort()
                        return
                    result["bytes_processed"] += len(body)
                    headers = getattr(response, "headers", {})
                    if headers.get("content-encoding", "identity").casefold() not in ("", "identity"):
                        result["observations"].append(obs)
                        block("unsupported_content_encoding", target)
                        route.abort()
                        return
                    mime = headers.get("content-type", obs.get("content_type", "application/octet-stream"))
                    classification = analyze(body, mime, target, synthetic_markers=synthetic_markers)
                    obs.update(classification.report)
                    result["observations"].append(obs)
                    if request.is_navigation_request() and request.frame == page.main_frame:
                        result["access"] = obs.get("access", "INDETERMINATE")
                        result["http_status"] = obs.get("http_status")
                        obs["target_id"] = result["target_id"]
                        obs["is_main_document"] = True
                        observed_main = True
                    if classification.report["content"] in ("SENSITIVE_CANDIDATE", "SYNTHETIC_CONTENT_CONFIRMED"):
                        result["content"] = classification.report["content"]
                        if stop_on_sensitive:
                            stop = True
                            result["reason"] = "sensitive_candidate_stop"
                            route.abort()
                            return
                    elif result["content"] == "NOT_INSPECTED" and classification.report["content"] == "PUBLIC_UI":
                        result["content"] = "PUBLIC_UI"
                    status = obs.get("http_status")
                    if not isinstance(status, int) or not 200 <= status < 600 or not obs.get("capture_complete", False):
                        block("incomplete_response", target)
                        route.abort()
                        return
                    if "attachment" in headers.get("content-disposition", "").lower():
                        block("download_not_allowed", target)
                        route.abort()
                        return
                    # Only behavior-essential response headers; never cookies or arbitrary vendor headers.
                    allowed = ("content-type", "content-security-policy", "x-content-type-options",
                               "access-control-allow-origin", "vary")
                    output_headers = {key: headers[key] for key in allowed if key in headers}
                    output_headers["cache-control"] = "no-store"
                    if 300 <= status < 400:
                        location = headers.get("location")
                        try:
                            output_headers["location"] = scope.authorize(urljoin(target, location or ""))
                            if not location:
                                raise ValueError()
                        except (PolicyError, ValueError):
                            block("redirect_out_of_scope", target)
                            route.abort()
                            return
                    route.fulfill(status=status, headers=output_headers, body=body)

                context.route("**/*", handle)
                try:
                    page.goto(canonical, wait_until="domcontentloaded", timeout=min(60000, int((duration + scope.timeout) * 1000)))
                    completed_navigation = True
                except Exception:
                    if not stop:
                        result["reason"] = "navigation_incomplete"
                if completed_navigation and not stop:
                    end = min(deadline, time.monotonic() + duration)
                    while time.monotonic() < end and not stop:
                        page.wait_for_timeout(min(100, max(1, int((end - time.monotonic()) * 1000))))
                    # Read only DOM, capped in the browser before crossing the boundary.
                    snapshot = page.evaluate("limit => { const html = document.documentElement.outerHTML; return {prefix: html.slice(0, limit), truncated: html.length > limit}; }", scope.max_bytes)
                    encoded = snapshot["prefix"].encode("utf-8")
                    dom = analyze(encoded[:scope.max_bytes], "text/html", canonical,
                                  synthetic_markers=synthetic_markers)
                    dom.report["analysis_complete"] &= not snapshot["truncated"] and len(encoded) <= scope.max_bytes
                    result["dom"] = dom.report
                    if dom.report["content"] in ("SENSITIVE_CANDIDATE", "SYNTHETIC_CONTENT_CONFIRMED"):
                        result["content"] = dom.report["content"]
                    # Stop after minimum evidence; otherwise inspect live form properties.
                    state_complete = False
                    if result["content"] not in ("SENSITIVE_CANDIDATE", "SYNTHETIC_CONTENT_CONFIRMED"):
                        state = page.evaluate(LIVE_STATE_SCRIPT, {"maxBytes": scope.max_bytes, "maxNodes": 2048})
                        state_analysis = analyze("\n".join(state["values"]).encode("utf-8"), "text/plain",
                                                 synthetic_markers=synthetic_markers)
                        state_analysis.report["analysis_complete"] &= not state["truncated"]
                        state_analysis.report["nodes_examined"] = state["nodes"]
                        state_analysis.report["controls_examined"] = state["controls"]
                        result["live_state"] = state_analysis.report
                        state_complete = state_analysis.report["analysis_complete"]
                        if state_analysis.report["content"] in ("SENSITIVE_CANDIDATE", "SYNTHETIC_CONTENT_CONFIRMED"):
                            result["content"] = state_analysis.report["content"]
                        del state
                    result["reason"] = "bounded_observation_completed"
                    result["capture_complete"] = bool(observed_main and not result["blocked"] and not stop
                        and all(o.get("capture_complete", False) for o in result["observations"]))
                    result["analysis_complete"] = bool(dom.report["analysis_complete"] and state_complete
                        and all(o.get("analysis_complete", False) for o in result["observations"]))
                    result["complete"] = result["capture_complete"] and result["analysis_complete"]
                    if not dom.report["analysis_complete"]:
                        result["reason"] = "dom_capture_incomplete"
                    elif not state_complete:
                        result["reason"] = "live_state_incomplete"
                elif not observed_main and result["reason"] == "not_started":
                    result["reason"] = "no_main_response"
            finally:
                context.close()
                browser.close()
    except Exception:
        if result["reason"] == "not_started":
            result["reason"] = "browser_runtime_unavailable"
        result["complete"] = False
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result


def main(argv=None):
    from .policy import Scope, PolicyError
    p = argparse.ArgumentParser(description="Scope-bound, stateless anonymous browser capture; emits no raw DOM.")
    p.add_argument("url", nargs="?")
    p.add_argument("--scope", required=True)
    p.add_argument("--locator-store")
    p.add_argument("--locator-scope")
    p.add_argument("--locator-ref")
    p.add_argument("--duration", type=float, default=3.0)
    args = p.parse_args(argv)
    try:
        scope = Scope.load(args.scope)
        from .locators import resolve_target
        url, target_id = resolve_target(args.url, args.locator_store, args.locator_scope, args.locator_ref)
        report = observe(url, scope, duration=args.duration, target_id=target_id)
    except (PolicyError, ValueError, OSError):
        print(json.dumps({"access": "INDETERMINATE", "reason": "scope_invalid"}))
        return 2
    print(json.dumps(report, ensure_ascii=True))
    return 0 if report["observations"] else 2
