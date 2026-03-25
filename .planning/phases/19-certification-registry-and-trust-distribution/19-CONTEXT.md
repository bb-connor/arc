# Phase 19: Certification Registry and Trust Distribution - Context

**Gathered:** 2026-03-25
**Status:** Completed

<domain>
## Phase Boundary

Phase 19 turns signed certification checks into durable trust objects rather
than local artifacts only. Operators can now publish, retrieve, resolve, and
revoke certification artifacts locally or over trust-control with stable
artifact IDs and immutable verification.

</domain>

<decisions>
## Implementation Decisions

### Stable Artifact Identity
- Registry entries are keyed by a SHA-256 digest of the canonical signed
  artifact JSON.
- The signed artifact itself remains the source of truth; registry metadata
  layers status and lookup semantics on top.

### Local and Remote Parity
- Local CLI and remote trust-control use the same registry model.
- The trust-control admin surface loads and saves the configured registry file
  on demand instead of inventing a second storage backend.

### Status Resolution
- Publish is idempotent for the same artifact.
- Publishing a newer artifact for the same tool server supersedes the current
  active entry.
- Resolution prefers `active`, then `revoked`, then the latest remaining entry.

</decisions>

<canonical_refs>
## Canonical References

- `.planning/ROADMAP.md` -- Phase 19 goal and success criteria
- `.planning/REQUIREMENTS.md` -- `CERT-01`, `CERT-02`
- `crates/pact-cli/src/certify.rs` -- registry model and local CLI flows
- `crates/pact-cli/src/main.rs` -- CLI command wiring
- `crates/pact-cli/src/trust_control.rs` -- remote registry endpoints and
  client calls
- `crates/pact-cli/tests/certify.rs` -- local and remote registry integration
  tests
- `docs/PACT_CERTIFY_GUIDE.md` -- operator-facing registry docs

</canonical_refs>

<code_context>
## Existing Code Insights

- The project already shipped signed certification artifacts and local verify
  semantics.
- The missing work was storage and distribution: artifact IDs, registry state,
  lookup semantics, and remote admin exposure.
- The existing trust-control admin model made a file-backed registry the
  shortest truthful path to operator usability.

</code_context>

<deferred>
## Deferred Ideas

- public certification discovery network
- multi-writer registry replication
- certification search by richer metadata beyond tool-server identity

</deferred>

---

*Phase: 19-certification-registry-and-trust-distribution*
*Context gathered: 2026-03-25*
