# Phase 53: OID4VCI-Compatible Issuance and Delivery - Context

**Gathered:** 2026-03-27
**Status:** Ready for planning

<domain>
## Phase Boundary

Add at least one interoperable credential issuance and delivery path for ARC
passports or equivalent portable credentials beyond ARC-native file exchange.
This phase is about issuance and delivery only. Portable lifecycle state,
holder presentation transport, and external verifier qualification remain in
phases 54 through 56.

</domain>

<decisions>
## Implementation Decisions

### Issuance scope
- Ship one conservative OID4VCI-style issuance lane rather than a broad wallet
  ecosystem abstraction.
- Treat interoperability as an external delivery and issuance contract layered
  over existing ARC passport artifacts, not as a rewrite of ARC's credential
  cryptography or identity model.
- Keep the scope operator-bounded and explicitly non-public; no global issuer
  discovery or wallet marketplace semantics are introduced in this phase.

### Credential model and trust boundaries
- Preserve the current ARC-native credential and passport substrate:
  `did:arc` issuer and subject identifiers, Ed25519-signed credentials, and
  ARC passport bundle semantics remain the source of truth.
- Expose interoperable issuance as a profile mapping from ARC passport
  artifacts into an OID4VCI-compatible offer and retrieval flow.
- Fail closed when requested formats, profile identifiers, issuance metadata,
  audience, or subject binding do not match the configured issuer contract.

### Delivery surfaces
- Support both local CLI and trust-control delivery surfaces so operators can
  test flows locally and expose them remotely through the existing admin plane.
- Use replay-safe issuance grants or offer codes instead of anonymous raw file
  download links.
- Keep issuance state explicit and inspectable rather than hiding it inside
  transient process memory.

### Claude's Discretion
- Exact naming of the interoperable offer and metadata document types.
- Whether the first delivery artifact wraps full passports, individual
  credentials, or both, as long as the scope stays within the phase boundary.
- Whether one-time offer state lives in SQLite or a file-backed registry, as
  long as it is durable enough for operator and test flows.

</decisions>

<specifics>
## Specific Ideas

- Prefer a pre-authorized issuance flow first, because it is the smallest
  credible interoperability slice and fits ARC's operator-mediated model.
- Reuse the existing passport issuance inputs from local reputation and receipt
  evidence rather than inventing a second issuance corpus.
- Make docs explicit about what is compatible with OID4VCI-style expectations
  and what remains intentionally ARC-specific.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Portable credential boundaries
- `crates/arc-credentials/src/lib.rs` — current ARC-native credential,
  passport, policy, and presentation schemas
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md` — conservative portability
  boundaries; explicitly excludes public wallet distribution today
- `spec/PROTOCOL.md` — current portable trust and passport protocol surface,
  including the statement that full wallet/distribution semantics are not yet
  shipped

### Existing passport surfaces
- `docs/AGENT_PASSPORT_GUIDE.md` — current operator and verifier-facing
  passport lifecycle, evaluation, and presentation behavior
- `crates/arc-cli/src/passport.rs` — local CLI issuance, verifier-policy,
  challenge, and lifecycle operations
- `crates/arc-cli/src/trust_control.rs` — remote trust-control passport admin
  and verifier endpoints
- `crates/arc-cli/tests/passport.rs` — existing end-to-end CLI and remote
  regression coverage for passport behavior

### Research rationale
- `docs/research/DEEP_RESEARCH_1.md` — rationale for VC portability,
  OID4VCI-aligned issuance, and wallet-mediated passport distribution as the
  next post-underwriting milestone
- `.planning/PROJECT.md` — active milestone framing and the promise not to
  widen trust boundaries while adding interop
- `.planning/REQUIREMENTS.md` — `VC-01` and `VC-05` requirements for this
  phase

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `arc_credentials::issue_reputation_credential*` and
  `arc_credentials::build_agent_passport` already produce the portable
  credential material that an interoperable issuance flow can deliver.
- `crates/arc-cli/src/passport.rs` already has the local operator issuance
  commands and status publication logic needed to derive offer inputs.
- `crates/arc-cli/src/trust_control.rs` already exposes remote passport
  challenge, verifier-policy, and lifecycle endpoints, giving phase 53 a
  natural place to add issuance endpoints.
- `crates/arc-cli/tests/passport.rs` already provides a strong test harness for
  CLI and trust-control credential workflows.

### Established Patterns
- ARC generally keeps signed artifact truth in `arc-core` or
  `arc-credentials`, then layers CLI and trust-control transport around it.
- New protocol slices typically land as typed contracts first, then local and
  remote operator surfaces, then docs and regression coverage.
- Fail-closed validation is a release boundary, not an optional hardening pass.

### Integration Points
- Passport issuance and verification in `crates/arc-cli/src/passport.rs`
- Remote control plane endpoints in `crates/arc-cli/src/trust_control.rs`
- Portable credential and presentation types in `crates/arc-credentials/src`
- Protocol and operator docs in `spec/PROTOCOL.md`,
  `docs/AGENT_PASSPORT_GUIDE.md`, and
  `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`

</code_context>

<deferred>
## Deferred Ideas

- Portable status, revocation, and supersession distribution contracts —
  phase 54
- Holder-facing wallet transport and presentation semantics — phase 55
- External verifier or wallet compatibility proof and qualification — phase 56
- Any public marketplace, global issuer registry, or automatic authority
  widening semantics

</deferred>

---

*Phase: 53-oid4vci-compatible-issuance-and-delivery*
*Context gathered: 2026-03-27*
