# Offline DOM replay

`dom-replay` measures one preset edit in a new headless Chromium context using an explicitly approved, hash-pinned synthetic HTML fixture. It removes the single `#login-screen` element and sets the single `#app` element's inline `display` property to `flex`. It never opens a live target, sends a request, authenticates, or establishes a server exposure finding.

## Approval manifest

Use a manifest with exactly these fields:

```json
{
  "case_id": "synthetic-dom-replay-example",
  "fixture_path": "dom-replay.fixture.html",
  "fixture_sha256": "d2cc4a2df5f40bda360533337a7f8c60e7389430c3ae663e771b293c07d6f979",
  "expires_at": "2020-01-01T00:00:00Z",
  "owner_ref": "fixture:repository-maintainer",
  "approved_action": "remove_login_show_app",
  "control_canary": "OPEN_DETECTIVE_DOM_REPLAY_CONTROL"
}
```

`case_id` and `owner_ref` are opaque identifiers. The checked-in example is intentionally expired and cannot approve a replay. Copy the example fixture and manifest into a private `_local/` case directory, then record the actual approval with a timezone-aware future expiry. `fixture_sha256` is the lowercase SHA-256 of the exact copied fixture bytes. A relative `fixture_path` is resolved from the manifest directory by the CLI. The control canary must be nonempty, present in the browser DOM before the edit, and remain present afterward. The canary value is never copied into the report.

The fixture and every existing ancestor must be ordinary filesystem entries, not symlinks, junctions, or other reparse points. The fixture is limited to 1 MiB of UTF-8 HTML and must contain exactly one `#login-screen` and one `#app`.

## Inert fixture boundary

The parser accepts a limited set of ordinary text, layout, table, and form-control elements. It rejects scripts, embedded content, media and resource elements, unknown elements such as SVG and MathML, event-handler attributes, duplicate attributes, URL-bearing attributes, navigation and form actions, meta refresh, CSS resource functions, CSS at-rules, CSS escapes, and CSS comments. This deliberately narrow format is for synthetic structural examples, not captured application pages.

Chromium runs with page JavaScript disabled, service workers blocked, no permissions or storage state, a dead proxy, hostname resolution disabled, and all browser requests aborted. Any attempted request fails the replay. The fixture is supplied directly with `set_content`; no local HTTP server or `file:` navigation is used.

## Run and interpret

Install the optional browser dependency and Chromium once. After copying both example files into `_local/dom-replay/`, update the copied manifest with the approval reference, expiry, and exact fixture hash, then write to a new private-local output path:

```bash
python -m pip install -e ".[browser]"
python -m playwright install chromium
open-detective dom-replay --manifest _local/dom-replay/manifest.json --output _local/dom-replay/report.json
```

The command refuses to overwrite an existing output and does not create a missing output directory. The report contains element and DOM-node counts, tag counts, form-control counts, computed target display values, Playwright visibility results, and canary-presence booleans before and after the edit. It contains no fixture HTML, control value, field values, screenshots, URLs, or browser captures.

The result only shows what this preset edit did to one frozen synthetic fixture. `server_exposure` and `authentication` remain `not_measured`, `original_anonymous_proof` is false, and `finding_claim` is false. Do not cite the result as evidence that a deployed application serves data, that authentication can be bypassed, or that any live target is affected.
