# Inbound authority design

User authorization: continue the proposed AP4-AP6 batch and two API-protect JSON
boundaries, implement and publish with local evidence. Base: `e84e53ae436ed8d8e2e5b85e62dea185cf7c33d6`.

## Behavior

Unmatched API-protect routes deny for every HTTP method, including when a valid
capability is presented. Matched routes require capabilities by default. Anonymous
reads need an explicit local operator opt-in. Spec claims may tighten policy at
any source; a claim that removes side effects is honored only after the exact
bytes from an operator-specified local path match its configured SHA-256. A pin
never authorizes an unmatched route or overrides approval requirements.

JWT and introspection confirmation claims must not disappear during decoding.
Unknown, empty, null-valued and unsupported jkt confirmations reject. Existing
Chio sender proofs remain bound to signed token identity, target and method with
nonce replay custody. Client certificate and attestation claims require trusted
transport evidence. The chosen deployment path is an explicitly configured
proxy, authenticated by both actual socket peer IP and a dedicated credential;
forwarded peer headers do not establish trust. The proxy must strip client
identity headers and inject values obtained from its own verified transport.
Unconfigured listeners reject bound tokens despite self-asserted headers. TLS
termination itself remains the separate AP7 owner.

Invocation proofs travel through the core normalized session operation and MCP
`tools/call` `_meta.chioDpopProof`. Proofs are parsed at bounded original-byte
boundaries, not invented from bearer capability data. Shared production kernel
composition installs replay custody using the same owned clock; HushSpec's
`tool_access.dpop_required` survives compilation and inheritance. Production
principals come from authenticated context; explicit claimed identities are not
proof. Existing unbound bearer policy is preserved where the operator did not
require proof. Missing, malformed, mismatched and replayed required proofs deny
without invoking the tool. Volatile replay custody must not be described as
restart-safe, and no proof-required projection may silently drop the requirement.

Threshold proposal and token submissions use the existing strict bounded reader
before typed decoding, preserving signed numeric and duplicate-key rejection and
redacted local causes. Authentication remains ahead of authority mutations.

## Verification and limits

Use behavioral RED/GREEN tests at the changed production boundaries, honest
success controls, exact denial/status and no-invocation assertions, then owner
suites, strict Clippy, formatting and affected source gates. Keep failed attempts
and incomplete campaigns distinct. No new dependency, allowance, debt increase,
ignore or timeout relaxation is planned. One independent integrated review.
Source publication does not establish hosted, full-workspace, release or deployed
acceptance. Preserve preexisting output and unrelated worktrees.
