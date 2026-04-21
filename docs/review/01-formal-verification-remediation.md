# Formal Verification Remediation Memo

Date: 2026-04-13
Owner: Formal-verification gap

## Problem

ARC currently makes public formal-proof claims that are stronger than the proof artifacts and release gates actually shipped in the repo.

The core mismatch has five parts:

1. The Lean model is materially narrower than the Rust runtime surface.
2. There is no mechanized refinement story from Lean semantics to the Rust implementation.
3. The current proof gate checks compilation and `sorry` hygiene, not end-to-end proof coverage of the claimed properties.
4. The cryptographic layer is modeled symbolically or axiomatically, but the public claims often read as if the real crypto and full runtime are formally verified.
5. Different repo documents describe different evidence boundaries, so the strongest marketing language outruns the strongest honest claim.

If left unresolved, this gap weakens three things at once: scientific credibility, security-review credibility, and the value of the proof work already completed.

## Current Evidence

The current repo does contain meaningful formal and proof-adjacent evidence, but it is narrower than the top-line narrative.

- The Lean root is small. `formal/lean4/Chio/Chio.lean` imports `Chio.Core.Capability`, `Chio.Core.Receipt`, `Chio.Core.Scope`, `Chio.Core.Revocation`, `Chio.Spec.Properties`, `Chio.Proofs.Monotonicity`, and `Chio.Proofs.Receipt`.
- The current bounded capability model in `formal/lean4/Chio/Chio/Core/Capability.lean` includes only tool grants, list-valued constraints, a single `maxInvocations` budget, and a simplified delegation chain. It does not model resource grants, prompt grants, monetary caps, DPoP flags, governed-approval tokens, runtime-assurance constraints, metered billing, or the richer attenuation surface present in `crates/arc-core-types/src/capability.rs`.
- The current receipt model in `formal/lean4/Chio/Chio/Core/Receipt.lean` is symbolic. `ReceiptSignature` is the body itself, `signReceipt` copies the body into the signature field, and `MerkleHash` is an inductive tree constructor rather than a real hash function.
- The current revocation/evaluation model in `formal/lean4/Chio/Chio/Core/Revocation.lean` uses an axiom `verifyCapabilitySignature` and models a simplified evaluation path over a reduced request and store surface.
- The theorem inventory in the shipped Lean tree is real but limited. The root-imported theorem families cover scope monotonicity, structural subset lemmas, delegation-chain integrity in the bounded scope model, receipt inclusion soundness, checkpoint consistency, and symbolic receipt immutability.
- The current protocol spec already distinguishes evidence classes. `spec/PROTOCOL.md` says executable differential tests in `formal/diff-tests` are the release gate for scope attenuation semantics, while Lean artifacts are informative unless root-imported and `sorry`-free.
- The current release audit says full theorem-prover coverage is consciously deferred and not part of the launch claim boundary in `docs/release/RELEASE_AUDIT.md`.
- The current CI lane does run `./scripts/check-formal-proofs.sh`, which performs `lake build` plus a `sorry` scan over the shipped Lean modules, and `formal/diff-tests` is included as the `arc-formal-diff-tests` workspace member.

Current command status on this checkout:

- `./scripts/check-formal-proofs.sh`: passed
- `cargo test -p arc-formal-diff-tests`: passed

That is useful evidence. It is not yet evidence for the broader claim that the ARC protocol, as implemented in Rust, is formally verified across recursive delegation chains, execution environments, and trust boundaries.

## Why Claims Overreach

### 1. Model-scope mismatch

The Lean model proves properties about a bounded abstract language, not the full production surface.

- Lean `ArcScope` currently models only `grants`.
- Rust `ArcScope` includes `grants`, `resource_grants`, and `prompt_grants`.
- Rust `ToolGrant` includes monetary caps and `dpop_required`.
- Rust constraints include governed-intent, approval-threshold, seller binding, runtime assurance, and autonomy-tier constraints.
- Rust also includes governed request objects, approval tokens, runtime attestation evidence, and richer delegation metadata.

A theorem over the smaller model does not automatically transfer to the larger one.

### 2. Missing refinement to Rust

There is no proof that the Rust code refines the Lean semantics.

- No theorem states that `ToolGrant::is_subset_of`, `ArcScope::is_subset_of`, `validate_delegation_chain`, or the kernel decision path are extensionally equivalent to the Lean model.
- No proof connects Rust canonicalization, serialization, or signature verification behavior to the Lean objects.
- No release artifact states which Rust commit the Lean theorems are supposed to justify, beyond loose repo co-location.

Without refinement, the current Lean lane is a specification proof, not an implementation proof.

### 3. Symbolic crypto shortcuts are under-disclosed

The receipt model currently proves statements in a symbolic world where signatures are structural equality and Merkle hashes are constructors.

That can still be valuable, but only if the public claim is framed correctly:

- acceptable: "theorems are proven under an abstract signature/hash interface or symbolic cryptographic model"
- not acceptable: "Ed25519 receipt integrity and Merkle log semantics are formally verified end to end" unless those assumptions are explicitly stated and audited

### 4. Proof-gate mismatch

The repo’s honest technical docs already say Lean is not the shipped release gate for the full protocol surface, but README, `docs/VISION.md`, and `docs/COMPETITIVE_LANDSCAPE.md` still present stronger language such as:

- "formally verified specification protocol"
- "Lean 4 verified"
- "P1-P5 are proven in Lean 4"
- "ARC's core safety properties (P1-P5) are proven in Lean 4"

That is a claim-discipline failure, not just a proof-completion failure.

### 5. Property inventory mismatch

The public P1-P5 story suggests a closed set of protocol theorems. The actual root-imported theorem surface is narrower and differently shaped.

- There is strong partial evidence for P1-style attenuation properties.
- There is strong partial evidence for symbolic receipt and checkpoint properties.
- There is some structural delegation-chain evidence.
- There is not yet a full root-imported theorem package matching the README/VISION wording for P2, P3, P4, and P5 as system-level properties over the production runtime surface.

## Target End-State

The target end-state should be:

1. ARC defines a precise `Verified Core` boundary.
2. Every public formal claim is mapped to a named theorem over that boundary.
3. The production runtime routes its security-critical pure decision logic through code that is refinement-checked against the Lean model.
4. Every proof dependency on symbolic or computational assumptions is explicit, machine-audited, and documented.
5. CI and release qualification fail if the proof boundary, theorem inventory, or claim registry drift.
6. Public docs use only claim language approved by that evidence boundary.

The right ambition is not "prove the whole company in Lean." The right ambition is "prove the security-critical pure semantics that justify the strongest protocol claims, and aggressively mark everything else as empirical or operational evidence."

## Required Architecture/Spec Changes

### 1. Define a Verified Core boundary in the spec

Add a new spec section and one machine-readable manifest that declare the exact verified boundary:

- capability syntax relevant to authorization
- delegation-chain syntax and lineage rules
- attenuation semantics
- revocation semantics
- pure request-evaluation semantics
- receipt body and checkpoint semantics
- allowed cryptographic assumptions
- excluded surfaces

This boundary should explicitly exclude distributed control plane behavior, payment settlement rails, external attestation services, and tool-side real-world effects unless and until they have their own formal lane.

### 2. Split the Rust implementation into a proof-facing pure core and an operational shell

Create a new crate or module boundary, for example `crates/arc-verified-core`, that contains:

- proof-facing data types
- normalization from full runtime objects into the verified subset
- a pure evaluator for authorization and receipt construction
- no network, clock, database, subprocess, or transport concerns

The kernel should call this pure layer for the decision procedure rather than open-coding portions of the logic in the operational path.

This is the architectural precondition for a real refinement proof.

### 3. Introduce normalized proof-facing types

Do not attempt to prove directly over every production struct. Define a smaller normalized AST for the verified core.

Examples:

- `VerifiedCapabilityToken`
- `VerifiedScope`
- `VerifiedDelegationChain`
- `VerifiedRequest`
- `VerifiedDecision`
- `VerifiedReceiptBody`

Then:

- prove semantics over the normalized AST in Lean
- prove or verify the Rust normalizer from production structs into that AST
- state all public claims over the normalized semantics

### 4. Make assumptions explicit and centralized

Replace hidden or ad hoc symbolic shortcuts with one audited assumptions layer.

Recommended structure:

- `Arc.Assumptions.Crypto`: signature unforgeability, canonicalization stability, hash collision resistance
- `Arc.Assumptions.Time`: trusted monotone clock assumptions
- `Arc.Assumptions.Store`: revocation-store query semantics if used in the verified core

All theorem statements should either:

- quantify over these assumptions, or
- be clearly labeled symbolic-model theorems

No untracked `axiom` should appear in the proof surface outside approved assumption modules.

### 5. Add a machine-readable proof manifest

Add a file such as `formal/proof-manifest.toml` that records:

- root modules
- named public theorems
- allowed axioms
- covered Rust modules/functions
- excluded Rust modules/functions
- commands that must pass in CI
- approved public claim text

This becomes the single source of truth for proof scope and documentation wording.

### 6. Add claim-discipline infrastructure

Add `docs/PROOF_CLAIMS.md` or equivalent with three evidence classes:

- formally proved
- executable specification or differential test
- runtime or qualification verified

Then add a lint script that rejects unapproved phrases in README, `docs/VISION.md`, `docs/COMPETITIVE_LANDSCAPE.md`, and release docs unless they match the proof manifest.

## Proof Plan

### Phase 0: Immediate claim containment

Before expanding any proof, stop the repository from overclaiming.

- Replace "formally verified protocol" with language tied to the current verified boundary.
- Remove or qualify "Lean 4 verified" unless it points to a bounded proof lane.
- Rewrite P1-P5 statements to reference the evidence class for each property.
- Make the protocol spec, README, vision doc, and competitive landscape agree.

This step is mandatory even if the team wants the stronger end-state later.

### Phase 1: Model the real verified-core syntax in Lean

Expand the Lean core so it matches the chosen Rust verified-core boundary.

Minimum expected parity:

- tool, resource, and prompt grants
- operations parity with Rust
- full constraint surface inside the verified core
- monetary caps
- DPoP requirement bits if the claim includes subject-bound delegation
- delegation-link signatures and capability IDs
- normalized request and decision types
- normalized receipt body and checkpoint body

This phase should also remove obsolete comments claiming a direct mirror to old Rust paths if the mirror is incomplete.

### Phase 2: Re-prove P1-P5 over the real verified core

Once the syntax matches, re-prove the named properties over the actual verified-core semantics.

Recommended property restatement:

- `P1` Attenuation monotonicity over the full verified scope lattice
- `P2` Revocation completeness over the verified delegation-chain semantics
- `P3` Fail-closed totality for the pure evaluator
- `P4` Receipt integrity and checkpoint consistency under explicit crypto assumptions
- `P5` Delegation-chain structural validity, including connectivity, depth, timestamp monotonicity, and any acyclicity invariant actually enforced

Do not preserve the old wording if the real property is different. Rename the property before shipping a misleading theorem name.

### Phase 3: Build a refinement story from Lean to Rust

This is the critical missing piece.

Recommended approach:

1. Implement the verified-core evaluator in a dedicated pure Rust crate.
2. Define a normalized AST shared conceptually by Lean and Rust.
3. Prove the Lean semantics over that AST.
4. Verify the Rust evaluator against contracts derived from the Lean semantics.
5. Treat normalization from production structs into the AST as a separate verified obligation.

Practical implementation options:

- Preferred: use Lean for spec proofs plus Rust contract verification on the pure crate via Creusot or an equivalent Rust verification tool.
- Acceptable interim step: use exhaustive bounded model checking on the pure Rust core for finite domains plus property-based equivalence against a Lean-derived oracle, but do not call this full refinement.
- Long-term strongest option: generate the pure evaluator from the verified source or prove a one-way refinement theorem from Rust evaluator outputs to Lean semantics for all normalized inputs.

The team should not attempt to refine the entire kernel at once. Refine the pure authorization core first.

### Phase 4: Add theorem-dependency auditing

CI should not only check that Lean builds. It should check what assumptions the theorems depend on.

Add a script that:

- runs `lake build`
- rejects all `sorry`
- prints theorem axioms for every public theorem
- rejects any axiom outside the approved assumptions modules
- emits a proof report artifact for CI and release qualification

This closes the current gap where "no `sorry`" can still hide an unreviewed assumption boundary.

### Phase 5: Bind release claims to proof artifacts

Add a release artifact, for example `target/proof-report/proof-summary.json`, that records:

- Git commit
- theorem inventory
- allowed axioms
- proved property set
- covered Rust modules/functions
- formal commands executed

Release notes and partner-facing proof docs should quote that artifact, not hand-maintained prose.

## Validation Plan

Validation must test four different failure modes: proof drift, implementation drift, assumption drift, and documentation drift.

### 1. Proof-surface validation

- `lake build` on the proof root
- zero `sorry`
- theorem inventory matches the manifest
- `#print axioms` output matches the approved assumption set

### 2. Syntax and model-parity validation

- round-trip tests for normalized proof-facing Rust AST
- translation tests from production structs to verified-core AST
- schema diff checks when Rust types evolve

### 3. Refinement validation

- contract proofs or model-checking proofs on the Rust pure core
- equivalence tests between Rust evaluator outputs and Lean-derived reference outputs
- mutation tests to ensure proof gates fail when evaluator logic drifts

### 4. Claim-discipline validation

- doc lint that checks approved formal-claim wording
- release qualification artifact that includes proof status
- CI failure if README or vision docs overstate the verified boundary

## Milestones

### Milestone 1: Claim containment and boundary declaration

Scope:

- define `Verified Core`
- add proof manifest
- align README, protocol spec, vision doc, competitive doc, and release docs

Exit:

- every public formal claim is either downgraded or tied to a named theorem/evidence class

### Milestone 2: Lean parity for the verified core

Scope:

- expand Lean syntax to match the chosen verified-core Rust AST
- delete obsolete or partial "mirror" language

Exit:

- no material syntax element inside the verified core exists only in Rust

### Milestone 3: P1-P5 proof closure on the real model

Scope:

- prove the revised P1-P5 set over the updated Lean semantics
- isolate crypto/time/store assumptions

Exit:

- all public theorem claims exist as root-imported theorems with audited assumptions

### Milestone 4: Rust refinement of the pure core

Scope:

- create the Rust pure evaluator
- verify contracts or refinement obligations
- connect kernel decision path to the verified core

Exit:

- the production kernel uses the verified core for the covered decision path

### Milestone 5: Proof-gated release process

Scope:

- CI proof report
- release artifact
- doc-claim lint

Exit:

- no release can ship with a stronger claim than the current proof artifact justifies

## Acceptance Criteria

The formal-proof claims are only allowed to become strong again when all of the following are true:

1. A written `Verified Core` boundary exists in the spec and proof manifest.
2. The public theorem inventory is root-imported, `sorry`-free, and assumption-audited.
3. Theorems are stated over a Lean model that matches the Rust verified-core AST for all covered fields.
4. The Rust verified-core evaluator is refinement-checked or contract-verified against the Lean semantics.
5. The production kernel actually uses that verified-core evaluator on the claimed authorization path.
6. Public docs only claim formal verification for the covered boundary and named properties.
7. CI emits a machine-readable proof report and fails on theorem drift, assumption drift, or claim drift.

Anything short of this is still useful, but it is not enough to justify the current strongest wording.

## Risks/Non-Goals

### Risks

- Proof-scope explosion if the team tries to verify all of ARC instead of a pure core.
- Architecture churn while carving out the verified-core evaluator from existing kernel logic.
- Proof brittleness if public theorem names are tied too directly to unstable implementation details.
- Tooling risk if the Rust verification toolchain chosen for refinement is immature for the required subset.

### Non-Goals

- Proving distributed HA correctness, leader election, or budget consistency in this memo's scope
- Proving payment-rail settlement correctness or legal/compliance semantics
- Proving real-world tool side effects
- Proving Ed25519, SHA-256, or Merkle trees from first principles inside Lean
- Claiming more than "properties hold under explicit assumptions" for the cryptographic layer

The disciplined end-state is not "everything is formally verified." It is "the security-critical pure semantics that justify ARC's core authorization claims are formally verified, implementation-linked, assumption-audited, and release-gated."
