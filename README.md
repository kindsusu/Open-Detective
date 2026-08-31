# su-detect

**Find your organization's material and servers that are exposed on the public internet — and prove it
with measurements, not opinions.**

A skill for Claude Code. It does not ask *"can this be broken into."* It asks only **"is this open."**
Those are different questions with different methods. Whether something is open is settled at the door;
whether it can be broken into requires pushing. **This skill does not push.**

한국어 문서: [`ko/`](ko/) · [README.ko.md](README.ko.md)

---

## Why this exists

Most "we got audited" findings die the same way. Someone confirms an exposure, writes it up, and nothing
happens — because the report had no owner, no deadline, and no re-measurement date. In the case this
skill was built from, an exposure finding sat unremediated for **19 days**, and in that window the number
of exposed assets grew **from one to eight**.

So the procedure ends at re-measurement, not at "fixed."

## What it does

```
Scope -> Discover -> Measure -> Triage -> Remediate -> Re-measure
```

- **Anonymous measurement decides exposure.** Status code, `sha256`, `ETag`, final URI. Not opinions.
- **Nine exposure surfaces**, including the ones most inventories miss: AI output (conversation share
  links, meeting-note transcripts, agent config files), third-party supply chain, and file internals.
- **15 invariants** that no request overrides, with the legal boundary mapped for each action.
- **Only techniques that were actually run and confirmed working.** Tools that turned out to be blocked,
  retired, or paywalled are quarantined with the reason, because listing a dead tool produces false negatives.

## Install

```bash
git clone https://github.com/kindsusu/su-detect ~/.claude/skills/su-detect
```

For Codex, clone into `~/.codex/skills/su-detect` and restart. For desktop apps that take a package,
zip the folder so the archive contains `su-detect/SKILL.md` at its root and upload it.

## Use

Ask in plain language:

```
Check whether any of our company material is exposed on the internet
Find out if internal files ended up on a public code host
Run an exposure check on our domains
```

Or run the measurement directly:

```bash
bash tools/probe.sh "https://example.com/" "label"
bash tools/probe.sh --batch targets.tsv
```

```
LABEL      CODE  BYTES  SHA256(16)        VERDICT    ETAG  LAST-MODIFIED  FINAL-URI
control    200   33156  b1e07d4c9a6f2351  AUTH-GATE  -     -              https://<idp>/...?<query-omitted>
target     200   81926  3f9c1a7e5b2d4088  EXPOSED    "..."  Mon, 03 ...    https://<host>/<path>/
```

Those two lines prove "a login screen is not a security boundary" without any explanation. Same day, same
method, opposite results.

## What it will not do

This is the part that matters. The skill is deliberately constrained:

- No authentication bypass, brute force, or exploitation
- **No logging in with credentials it finds** — not even to check whether they still work
- **No enumerating sequential IDs.** If `?id=1001` is open, it records that and does not try `1002`.
  Each request is "unauthenticated and small," but strung together it becomes personal-data collection
- **No copying originals to local storage.** The moment you make a copy, the auditor's machine becomes a
  new leak point
- **No reading personal data.** If it appears, stop and escalate. The deliverable stops at
  "exposed / not exposed / how much"
- **No probing assets whose ownership is unconfirmed.** A similar name does not make an asset yours
- **No requests that return the contents of live systems.** If existence is establishable externally,
  it does not hit the system

Full text and the legal-boundary table: [`ops/scope.md`](ops/scope.md).

## Measurement rules worth stealing even if you skip the skill

These came out of getting them wrong first.

- **The invariant for reproducibility is a digest, not a byte count.** Identical bytes mean the content
  did not change, not that your technique reproduces.
- **Anonymous decides exposure; authenticated decides existence.** An authenticated search will mix your
  own private repositories into the results.
- **A negative from one channel is not evidence of absence.** Eight exposed sites were invisible to
  search-engine dorks because they were never indexed; account enumeration found them.
- **Attach a control to every negative.** In one run the target and the control both returned zero — the
  query format was wrong, and only the control caught it.
- **Do not trust status codes.** A retired cache endpoint still answers `200`. Eight such
  "failures that look like negatives" are catalogued in [`ops/verify.md`](ops/verify.md).
- **Cross-check external scan data by connecting directly.** A port list that omitted a live `443` proved
  its own staleness.
- **"No permanent residue" is not a claim you can make.** A host with zero web-archive snapshots was
  already mirrored byte-for-byte by a third-party CDN. What you can write is a point-in-time statement.
- **Header dumps leak tokens.** This tool filters `Set-Cookie` and strips the query string from redirect
  URIs, because both of those actually leaked during development.

## Layout

| Path | Contents |
|---|---|
| [`SKILL.md`](SKILL.md) | Invariants and Phase 0-6 |
| [`ops/scope.md`](ops/scope.md) | 15 invariants, legal boundaries, scope procedure |
| [`ops/discovery.md`](ops/discovery.md) | Execution layer — verified techniques only |
| [`ops/verify.md`](ops/verify.md) | Verdicts, failures that look like negatives, residue, bucket rules |
| [`ops/triage.md`](ops/triage.md) | Risk grades, file-internals inspection, confirmed vs unconfirmed |
| [`ops/evidence.md`](ops/evidence.md) | Masking, header hygiene, who receives what |
| [`ops/remediate.md`](ops/remediate.md) | Remediation order, zero-downtime migration, residue removal |
| [`surfaces/inventory.md`](surfaces/inventory.md) | 9 exposure axes, priority, exclusions with reasons |
| [`tools/probe.sh`](tools/probe.sh) | Anonymous measurement (no jq dependency) |
| [`assets/ledger-template.md`](assets/ledger-template.md) | Ledger, residue checklist, re-measurement history |

## Scope of authorization

This is for **assets you are authorized to audit** — your own organization's, or a client's with written
permission. Nothing in it is designed for unauthorized targets, and its constraints exist so that an
audit stays an audit.

Legal boundaries differ by jurisdiction. The table in `ops/scope.md` is written as practical judgment,
not legal advice; anything consequential is marked **requires legal review**.

## Contributors

- **kindsusu** — design, methodology, direction
- **Claude** — authoring, scripts, empirical verification of every technique
- Adversarial review across three axes (channel gaps, measurement errors, guardrail and legal boundaries)

## License

[PolyForm Noncommercial License 1.0.0](LICENSE) — free for personal, nonprofit, educational, and research
use. **Commercial and corporate use is not permitted** under this license; contact the author for other
arrangements.
