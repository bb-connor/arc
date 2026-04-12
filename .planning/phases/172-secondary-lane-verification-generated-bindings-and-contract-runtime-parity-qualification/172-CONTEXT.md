# Phase 172: Secondary-Lane Verification, Generated Bindings, and Contract/Runtime Parity Qualification - Context

**Gathered:** 2026-04-02
**Status:** Complete locally

<domain>
## Phase Boundary

Harden ARC's bounded web3 runtime so proof bundles validate declared
secondary lanes cryptographically and the official contract, binding, runtime,
and standards surfaces all derive from the same artifact truth.

</domain>

<decisions>
## Implementation Decisions

### Secondary-Lane Verification
- reject undeclared secondary-lane evidence instead of treating extra bundle
  material as informational
- require Bitcoin/OpenTimestamps evidence to commit to the SHA-256 digest of
  the ARC super-root string and to attest the declared Bitcoin block height
- keep Solana secondary-lane verification bounded to normalized memo-root
  equality rather than inventing a wider trust model

### Artifact-Derived Bindings
- make compiled Solidity interface artifacts the canonical source for
  `arc-web3-bindings`
- fix interface drift in the Solidity interface layer first, then derive Rust
  bindings from those artifacts
- keep one shared Rust `ArcMerkleProof` adapter so detailed Merkle-proof calls
  remain type-safe without per-contract manual drift

### Parity Qualification
- add dedicated parity tests that compare interface artifacts,
  implementation artifacts, generated bindings, runtime constants, and
  standards examples
- run the parity lane inside the existing web3 qualification script so the
  official release surface cannot skip it
- update public docs to claim cryptographic verification and artifact-derived
  parity only where the code now proves them

</decisions>

<code_context>
## Existing Code Insights

- proof-bundle verification already enforced primary-lane and Solana-root
  consistency, but Bitcoin secondary-lane validation previously accepted
  metadata presence without proving the imported OTS proof committed to the
  ARC super-root digest
- the checked-in Solidity interface files had drifted from the implementation
  surface around detailed Merkle-proof calls and price-resolver events
- ARC already shipped the contract package, chain configuration, and runtime
  constants needed for parity checks; the missing piece was a single executed
  qualification lane tying them together

</code_context>

<deferred>
## Deferred Ideas

- hosted execution and publication of the web3 qualification lane in phase
  `173`
- live deployment promotion and rollback workflow in phase `174`
- generated monitoring artifacts, operator drills, and integrated hosted
  recovery qualification in phases `175` and `176`

</deferred>
