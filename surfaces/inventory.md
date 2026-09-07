# Exposure-surface inventory

Use this checklist to state bounded coverage. It is not a claim that every provider or asset was found.

| Surface | Owner inventory | Public supplement | Completion evidence |
|---|---|---|---|
| Source/deployment | GitHub organization/account repositories and optional trees; Vercel scoped projects, deployments, aliases, domains | Owner-provided normalized Pages/environment records; passive public repo/deployment records | Cursor/page end, permissions, truncation, time window |
| DNS/TLS | Managed zones, registrar and certificate inventory | CT and public DNS | Zone/scope list and observation time |
| Static/CDN hosting | Provider projects, origins, aliases | Public URLs and headers | Project/alias relationship complete |
| Object storage | Owner bucket/container inventory and policies | Exact public links; no name-only probing | Account scope and policy retrieval complete |
| Documents/shares | Admin-approved Drive/SharePoint/Box exports | Public search/share links | Tenant/export scope and retrieval time |
| SaaS/low-code | Workspace apps, published pages, integrations | Public app URLs | Workspace/project scope and permission gaps |
| AI/public collaboration | Owner/admin share inventory where available | Indexed public share URLs | Provider limitations and date |
| Packages/artifacts | Registries, releases, build artifacts, images | Public registry metadata | Namespace and pagination complete |
| Operations surfaces | CMDB/cloud inventory | Public metadata only; no port/service interaction without approval | Owner approval and exact endpoints |
| Archives/caches | Known snapshots/caches in approved channels | Archive indexes | Collections/time ranges queried |

Track owner type as organization, employee/former-employee personal, third party, or unknown. Organization ownership permits only policy-declared measurements. Personal and third-party material goes through approved takedown/notification; similarity never expands access.

Start with a local audit intake (`examples/audit-intake.example.json` and `schemas/audit-intake.schema.json`) before this inventory. Record the affiliate boundary and third parties as `provided`, `unknown`, or `none_declared`; `unknown` remains a gap and never becomes organization ownership by guesswork. Obtain administrator exports for contracts, assets, processors, and outsourcers before executable scope approval and candidate import. The intake is not scope and does not authorize a network request.

Prioritize with accountable evidence: confirmed ownership links, possible data impact, recent deployment/change, and expected information gain versus request/privacy cost. Do not hardcode organization-specific occurrence probabilities or describe any category as certain. Preserve budget for disconnected brands, affiliates, and non-developer tools.

For every row record `source`, `retrieved_at`, `owner_scope`, `relationship`, `ownership_evidence`, `completeness`, `gap_reason`, `source_record_id`, and `next_cursor`. A private source repository does not imply a private deployed site. A public UI does not imply sensitive content.

Excluded content needs an exact URL, documented publication intent, owner/evidence, and review date. Domain-wide exclusion can hide unintentional paths.
