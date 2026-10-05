# Inbound authority execution, October 2, 2026

Published source `aaa413406d63cc109f6aeda14de4e517a6d574a6` on
`packet/3-retention-accounting`, based on
`e84e53ae436ed8d8e2e5b85e62dea185cf7c33d6`. The implementation and local qualification below are complete; publication is recorded in Git.
This record does not establish hosted qualification, deployment, release or
activation of a durable replay authority.

## Scope

AP4 denies unknown routes for every method and makes anonymous access explicit
local policy. Only a local spec whose exact loaded bytes match its configured
SHA-256 may relax side-effect classification. Specific paths take precedence;
equally specific overlaps choose denial. Client route hints do not choose policy.

AP5 carries invocation proofs through native messages, ordinary/nested sessions
and MCP metadata. Production kernels install bounded replay custody with the
same clock. HushSpec preserves the requirement through wildcard compilation and
inheritance. An operator-required proof also rejects external bearer grants.
HTTP authority projection refuses required proofs it cannot preserve.

AP6 rejects unknown, empty and null confirmation profiles, including unverified
RFC 9449 `jkt`. Trusted proxy identity requires both a configured socket peer IP
and a dedicated credential loaded from a private bounded file. Caller headers
are removed before authentication; JWT, introspection and local OAuth receive
only typed transport provenance. Resume identity binds the proxy configuration.

Both API-protect threshold handlers decode the original bounded body before
projection, preserve typed local causes, and redact rejected payload text.

## Evidence and review

Archive: `/home/connor/chio-security-evidence/2026-10-02-inbound-authority`.
Initial RED controls reproduced five proof-consumer gaps, five invalid cnf
acceptances, spoofed transport identity and threshold-reader provenance loss.
Successful local owner checks:

| Boundary | Passing tests |
|---|---:|
| API-protect | 243 |
| Core types | 432 |
| HTTP core | 102 |
| Kernel | 1,506 |
| MCP edge | 133 |
| Remote MCP | 125 |
| HushSpec policy | 197 |
| Native CLI sessions | 43 |
| CLI integration | 11 |
| Wire protocol schemas | 11 |
| Generated primitives / security vectors | 1 / 5 |
| SSRF external guard / API dispatch | 6 |
| A2A / ACP-Client / MCP examples | 6 / 6 / 7 |

The control-plane campaign was interrupted after four nested proof failures; it
is not a full-suite pass. All five affected nested controls subsequently passed,
as did the production proof-preview control. CLI parsing and 22 focused review
controls passed. Counts above describe individual owner runs, not one full
workspace runtime campaign. Failed compiler/fixture runs and the CLI test abort
remain retained. Final commands, logs and source/binary identities are in the
[artifact directory](artifacts/2026-10-02-inbound-authority/README.md).

Workspace qualification also repaired stale A2A/ACP-Client example callers, all three
examples' unbounded line allocation, and MCP's duplicate-collapsing example reader.
Four new controls went RED to GREEN. Existing UUID is now a dev dependency for
generated-type tests. SSRF fixtures explicitly authorize their known read route
while retaining redirect, size and zero-forbidden-target assertions. ACP-Client test
imports/layout were repaired without allowances.

One fresh independent review returned **changes requested**, with two Important
findings and no Critical or Minor finding. Both were reproduced and repaired:
native/stdio issuance now uses an operator-bound caller key, remote issuance and
resume retain the verified sender key, and URL normalization changes deny before
route authorization. The 22 focused controls subsequently passed. The
[original verdict and dispositions](artifacts/2026-10-02-inbound-authority/independent-review.md)
remain retained; there was no second independent review and no Minor deferral.
The integrated run additionally found that existing nested clients send the same
proof both explicitly and in their operation. Equal typed proofs now coalesce;
conflicting proofs reject. The original MCP reader also overvalidated malformed
notifications; original proof bytes remain strict while notification validity
stays with the protocol layer. Full-width signed integers are intentionally
supported; the regression test rejects duplicate original proof fields instead
of incorrectly rejecting the valid native integer domain.

Strict `cargo clippy --workspace --all-targets --locked --keep-going -- -D warnings`
and formatting pass. Rust code generation is in sync. Trust-boundary, security
clock, wire identifier/vector, schema registry and file-hygiene gates pass without
debt additions or lint allowances. Gate-negative suites passed 35 trust-boundary
and 23 ingress controls. The final source inventory retains 476 constructors,
85 tenant tables, 170 SQL principal contracts and 38 pinned clock compositions.

## Decisions and remaining boundaries

Existing worktree and publication authorization apply; preexisting `output/` and
unrelated worktrees are preserved. Unbound grants retain explicit bearer
semantics. Mandatory durable proof custody remains a separate activation boundary.
Origin-specific proof requirements are rejected at compile time until a suitable
origin-aware guard exists; use the root tool-access policy. The reference policy
evaluator cannot verify sender proofs and denies such requests. The trusted proxy
must sanitize caller headers and protect its link to Chio. TLS listeners remain
AP7 work. No new runtime crate was added; raw JSON support and the test router
harness use existing workspace dependencies.

## Subsequent execution

AP7/AP8 are implemented and qualified separately in the
[October 3 transport and revocation record](2026-10-03-transport-revocation-execution.md).
The proposal below retains this batch's original continuation scope.

## Next substantial batch at publication

AP7 and AP8 remain live in the current source. Add a shared TLS listener profile
for trust-control, MCP serve-http and API-protect, with explicit certificate/key
custody, plaintext non-loopback startup rejection and a deliberate operator
compatibility opt-in. Refuse non-loopback HTTP control endpoints and downgrade
redirects. Exercise actual connections, certificate failures, direct/proxy sender
identity and secret-safe error paths across all three production compositions.

Repair session-wide revocation to report non-2xx unless every capability is
confirmed revoked. Preserve per-capability failures and partial progress; test
remote 500 responses, local store write failure, readback failure, already-revoked
capabilities and idempotent retry after partial success. Follow this with AP9 and
the receipt/export/retention findings, plus remaining key/guard and release gates.
