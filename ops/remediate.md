# Containment, recovery, and recheck

Choose actions from the confirmed evidence and current harm. For an active personal-data or secret exposure, urgent isolation and log preservation can precede continuity work. For a planned migration without active harm, prepare the replacement path first. Record the reason rather than applying one fixed order.

## Action plan

1. Freeze evidence references and preserve required provider/application logs without copying exposed content.
2. Restrict/delete the exact public deployment, share, object, or alias; confirm which other aliases point to it.
3. Rotate confirmed private secrets through the owner-controlled system. Audit code does not test or use them.
4. Restore service through a reviewed private deployment when continuity is required.
5. Keep server-side user, role, tenant, and object authorization even behind SSO or an edge access gate. SSO authentication is not application authorization.
6. Inspect owner-side access logs for the bounded exposure window and route privacy/legal decisions to accountable owners.
7. Recheck the original locator and every known deployment/alias with a fresh anonymous context. Check permitted caches and archives separately.

Do not assume repository privatization removes prior deployments, forks, package releases, build artifacts, or copied files. Do not delete logs needed for response. If containment would cause material outage, escalate the explicit tradeoff; active harm may still justify immediate isolation.

## Closure

`closed` requires fresh observation evidence showing the expected access/content state for every known live locator plus completion of the declared residue scope. Target and policy bindings must match the registered original and aliases. If live access is contained but archive/cache/deployment coverage is incomplete, use `partially_closed`. After closure, a current `BODY_SERVED`, unknown/incomplete observation, or equal-time conflict returns the finding to review; a digest change alone does not.

Set owner, action due date, recheck due date, backoff/retry policy, and escalation route. Unchanged observations can remain quiet, but overdue, failed, reopened, and user-action-required events must be visible.
