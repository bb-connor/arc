# Phase 15: Multi-Issuer Passport Composition - Research

**Researched:** 2026-03-24
**Domain:** Rust credential-bundle verification, issuer-aware policy reporting,
truthful multi-issuer composition semantics
**Confidence:** HIGH

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| PASS-01 | Multi-issuer passport composition semantics are explicitly defined and enforced without weakening current single-credential verification guarantees | Composition contract is concentrated in `build_agent_passport` and `verify_agent_passport`; the single-issuer rejection was an explicit alpha guard rather than a deeper architectural dependency |
| PASS-02 | Verifier evaluation reports acceptance and rejection at the issuer and credential level for composed portable-trust bundles | `evaluate_agent_passport` already evaluates per credential; adding issuer-aware result fields and top-level matched issuers is sufficient and truthful |

## Summary

Phase 15 is narrower than it first appears. The codebase did not fundamentally
assume one issuer everywhere; it explicitly rejected multi-issuer bundles in
`build_agent_passport` and `verify_agent_passport`, while verifier evaluation
already walked every credential independently. That means the safest
implementation is to remove the single-issuer alpha guard, keep the same-subject
and independent-signature guarantees, and make issuer identity explicit in the
verification and evaluation outputs.

The most important non-goal is aggregate truth synthesis. ARC still should not
invent a cross-issuer composite score, averaged reputation, or bundle-level
issuer claim. Acceptance remains "at least one credential matched the verifier
policy" and rejection remains "no credential matched," with issuer identity
reported per credential.

## Recommended Implementation

- Allow `build_agent_passport` and `verify_agent_passport` to accept bundles
  with multiple issuers as long as subject consistency and per-credential
  validity hold
- Extend `PassportVerification` with:
  - optional single `issuer`
  - full `issuers` list
  - `issuer_count`
- Extend `CredentialPolicyEvaluation` with `issuer`
- Extend `PassportPolicyEvaluation` with `matched_issuers`
- Update CLI and reputation comparison output to report issuer lists truthfully
- Add accepted, rejected, and mixed multi-issuer regression coverage

## Risks

### Risk 1: Backward-compat reporting drift
Existing single-issuer consumers may expect one `issuer` field. Mitigation:
keep `issuer` for the single-issuer case and add explicit multi-issuer fields
instead of overloading one string.

### Risk 2: Implicit aggregation by presentation or evaluation
If new code starts summarizing scores across issuers, Phase 15 would violate its
own truthful-boundary requirement. Mitigation: preserve the existing per-
credential evaluation contract and only improve reporting.

### Risk 3: Overpromising authoring support
`passport create` still reflects one local signing authority. Mitigation: keep
creation semantics unchanged and document that composed bundles are a bundle
verification/evaluation feature, not a new local authoring pipeline.

## Validation

- `cargo test -p arc-credentials -- --nocapture`
- `cargo test -p arc-cli --test passport -- --nocapture`
- `cargo test -p arc-cli --test local_reputation -- --nocapture`
