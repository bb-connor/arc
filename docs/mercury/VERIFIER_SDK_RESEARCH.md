# MERCURY Verifier Research

**Date:** 2026-04-02  
**Audience:** Engineering, security, and partner integration teams

---

## 1. Objective

MERCURY needs a verifier that can be trusted independently of the runtime that
produced the evidence. The verifier must confirm:

- receipt integrity
- checkpoint inclusion
- publication-chain integrity
- evidence-bundle integrity
- normative publication and continuity semantics where policy requires them

The initial product should ship one strong verifier surface before expanding to
multiple SDKs or browser packages.

The stable commercial object should be the proof package, not the transport
used to deliver it. Reviewed inquiry exports should be a derived layer on top
of that proof package, not a separate unverifiable artifact family.

---

## 2. Recommended Initial Surface

### Rust library

Why first:

- closest to ARC primitives
- easiest to keep deterministic and auditable
- straightforward to package into a CLI and future FFI or WASM surfaces

### CLI

Why first:

- easiest evaluator experience
- supports offline use
- forces the verification contract to be explicit before UI packaging begins

Recommended initial output modes:

- pass / fail summary
- structured JSON report
- explain mode listing each verification step

The CLI should accept `Proof Package v1` as its primary input contract.

---

## 3. Verification Contract

Inputs:

- `Proof Package v1`
- local trust policy
- optional audience-specific disclosure policy when validating a redacted
  export

### Proof Package v1

`Proof Package v1` should include:

- receipt
- evidence bundle manifest
- checkpoint
- inclusion proof
- publication metadata
- witness or immutable anchor record
- trusted-key material
- rotation or revocation material
- schema and profile versions

Core verification steps:

1. verify trusted key or key chain
2. verify receipt signature
3. verify checkpoint signature
4. verify inclusion proof
5. verify evidence-bundle references and integrity
6. verify publication profile and witness semantics
7. verify continuity, consistency, completeness, and freshness rules required
   by local policy
8. report any missing material or trust assumptions clearly

---

## 4. Trust Distribution

The verifier is only as useful as its trust-anchor story.

Recommended trust inputs:

- published signing-key fingerprint
- rotation certificates or equivalent chain
- publication witness or immutable anchor
- environment-specific trust policy for accepted keys
- bootstrap rules for first trust establishment
- archive-renewal policy for long-lived evidence stores

The verifier should never silently trust a key only because the key appears in
the receipt.

---

## 5. Packaging Roadmap

### Current program

- Rust crate
- CLI
- `Proof Package v1`
- `Publication Profile v1`

### Phase 4 candidates

- WASM package
- browser verification widget
- lightweight partner-facing package or SDK bindings
- archive, review-system, or OEM verifier packaging

### When to add them

Only after:

- the CLI contract is stable
- the proof package contract is stable
- trust distribution is understood
- buyers or partners clearly need those surfaces

### Redacted and audience-specific packages

The verifier should support multiple package views:

- internal full package
- redacted reviewer package
- client or auditor package

For each, the verifier must report whether the package remains
verifier-equivalent or whether it is a disclosure-oriented subset only.

### Inquiry Package v1

`Inquiry Package v1` should be defined as a reviewed export layered on top of a
specific proof package. It should carry:

- reference to the underlying `Proof Package v1`
- audience scope
- redaction profile
- rendered export digest
- approval and disclosure metadata

The verifier should check that the inquiry package corresponds to a specific
proof package and report whether it remains verifier-equivalent or disclosure
only.

---

## 6. Open Design Questions

- how much publication metadata should the verifier require by default
- how trust policies are configured for multi-tenant or partner distribution
- whether browser verification should operate on full bundles or export
  packages only
- whether partner APIs should call the verifier library directly or shell out
  to the CLI contract
- how redaction and disclosure policy are represented in package metadata
- what continuity or outage semantics a verifier should require from the
  publication profile
- how provider and dependency provenance should appear in verification reports
- how long-term archive renewal is proven without mutating original truth

---

## 7. Recommendation

Ship the Rust verifier and CLI first, freeze `Proof Package v1`,
`Publication Profile v1`, and `Inquiry Package v1`, then expand verifier
surfaces only where distribution demand is clear. This keeps the proof story
stronger than a broad but immature SDK program.
