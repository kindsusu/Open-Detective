# Remediation — What Comes First

## Order

**Rotate and block in parallel. If only one can come first, rotate.**

```
1. Rotate credentials      <- assume bots already harvested any secret in a public repository
2. Block the exposure      <- make private / put an auth gate in front / remove the file
3. Check and request removal of residue  <- archives, CDN mirrors, search index. The whole table in ops/verify.md
4. Establish the exposure window  <- since when? obtain access logs if they exist
5. Close by re-measuring   <- run the same measurement again
```

**Blocking does not undo a leak.** What has already been copied does not disappear when you close the door.
The "stop sharing, then rotate keys" ordering used in awareness training is for comprehension;
**in execution, rotation comes first.**

> Revoking or rotating an exposed key is a **remote administrative action** and does not conflict with
> "never log in with discovered credentials" (invariant 3). Keep the two separate.

## Zero-downtime migration — closing is the last step for live assets

```
1. Stand up the new path first — publish to a host with authentication in front
2. Confirm real users can reach it
3. Only then close the old path
4. If authentication layers now overlap, remove one
```

**Doing step 3 first causes an incident.** A document in active use stops the business the moment you close it.
> Precedent: making a repository private killed its Pages site instantly, and the change was reverted
> within two minutes. **"Make the repository private" and "make the page private" are different operations.**

## Authentication belongs in front of the HTML

A login screen that runs in the browser executes **after the HTML has already been transmitted**.
That is not access control. Only a design where **the server refuses to transmit** is.

| Option | Authentication | Fits |
|---|---|---|
| Static host + identity-aware proxy | SSO, OTP, corporate identity | The simplest employee-only site |
| Cloud static hosting + enterprise identity | Corporate accounts | Organizations already on that identity provider (tenant restriction may need a paid tier) |
| Plain static hosting from a code host | None — **published pages are public by default** | Not suitable for internal material |

- On free tiers, making the repository private takes the published page down with it.
- On paid tiers you can publish from a private repository, but **the published page is still public.**
- Truly private published pages are typically an enterprise-only feature.
- **Do not stack authentication layers.** Once a front-door gate is in place, remove the app's own password.

## Residue removal

| Target | Method |
|---|---|
| Web archives | Request exclusion from the archive operator. **Fixing the server does not remove the archive** |
| Third-party CDN mirrors | Delete or privatize the origin repository, then confirm cache expiry. **Commit-pinned paths persist** |
| Search-engine index | Request removal from each engine. **Check index status before you close the asset** |
| Commit history | After history rewriting, direct SHA access **still works for a while**. Ask the host to garbage-collect if needed |
| Forks | Forked copies do not disappear when the original is deleted |
| AI search citations | A different removal channel from ordinary search — follow each service's process |

**Closing an asset can itself create residue.** Re-check the archives after closing.

## Owner routing — where remediation stalls

> Precedent: an audit confirmed the exposure but had **no path to request remediation because the owning
> employee and department were never identified**. It was still unresolved 19 days later, and in that
> window the exposed assets grew from one to eight.

```
asset -> account -> person -> department -> remediation request path
```

- Identifying the account: commit authors, repository description, deployment settings, contact metadata
- **If you cannot identify an owner, make that fact a reported item.** Never leave it as "unknown."
- Contact happens **only after per-case approval, through official channels** (invariant 14) — if word
  gets out that an audit is running, evidence can be destroyed and disputes can start

**Keep security action separate from HR action.** Takedown, key rotation, and scoping the exposure happen
immediately regardless of who is involved. Disciplinary judgment follows the normal employment procedure,
and **the same person does not do both** (invariant 15).

## Closure criteria

**A report that ends at "fixed" has failed.**

- Closure means re-running the same measurement and **seeing the verdict change**
- Write a **re-measurement date** in the ledger, and actually run it that day
- If the residue checks are not complete, mark it **partially closed**
