# Delegation freeze and overlay dispatch revalidation

## Dispatch overlays

Containment and capability-set suspension are consulted immediately before dispatch, including immediately ready admissions. Revalidation is read-only, preserves the configured missing-context policy, and denies unavailable or malformed authority evidence. Only an Allow verdict permits dispatch. These reads consume no admission quota or approval.

The check is best-effort: an independent authority can change after revalidation and before invocation. Atomic closure requires a fence shared with the dispatch writer. Subtree closure, ProcessTree closure and closure draining remain separate contracts.

## Delegation admission

The common delegation-admission path checks issuer-signed delegated capabilities after signature, ancestry and scope validation. A configured freeze authority requires signed tenant and lineage fields on every delegated token and authorizes the Delegate operation against the final link's parent capability id.

- A child preserves the tenant and lineage of its nearest bound ancestor. An unbound child of a bound ancestor is refused.
- Missing signed ancestor evidence before the nearest bound ancestor is refused when the child is bound or a freeze authority is configured.
- Bound delegation requires a freeze authority. Standalone unbound delegation requires none.
- Issued roots are not delegation operations. Tool invocation independently refuses security-bound delegation.
- Freeze intervals are not retained. Presentation after a freeze is lifted does not establish when an offline signature was created.
- Resource subscription admission and queued MCP resource-update delivery check the freeze. Immediate nested-flow resource-update notifications do not recheck it.

## Verification

Public delegation tests cover subscription and parent-registration refusal, required authority and binding, nearest-bound-ancestor identity, missing ancestor evidence, standalone delegation, root admission and the independent tool-invocation ban. Every refusal asserts its exact error.

Dispatch tests cover active overlays, authority outages and malformed authority responses across ordinary and nested evaluation, direct and compound guard composition, and immediate and delayed readiness. Unchanged authority permits one invocation with a one-use quota.
