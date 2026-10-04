# Bounded independent security review

Reviewed 2026-10-02 in `/tmp/arc-security-launch`, comparing base `6cf283c4b9e36485a98275ba6798052b01a5a9d0` with the working tree, including new untracked replication/CLI/tests/verifier files and the ignored release-identity workflow. Read-only on the repository. No Cargo, mutation of git state, or subagents. Findings below describe the inspected state before executor follow-up fixes. Source reasoning is explicitly distinguished from an executed regression.

## Strengths

- Replication roots trust in an explicitly provisioned immutable checkpoint. Each transition is verified under its predecessor head and commits to exact stream, anchor, previous commitment, generation, new key, rotation time and complete issuer history. A signer supplied only by the proposed snapshot cannot bootstrap trust.
- Import verifies the full chain and its exact current prefix while holding an immediate SQLite transaction, then atomically publishes public state and durable replay/clock state. Signed conflicting successors cannot both become durable. Prior generations cannot append history. Private seeds are retained locally and follower rotation/issuance is refused on custody mismatch.
- Both incremental and full cluster paths reach authenticated import. Cluster clients require literal-loopback plaintext or normal HTTPS and disable redirects. The regressions exercise actual HTTP pulls and actual kernel denial for refused issuers.
- AP1 removes public-label seed derivation at both mint entrypoints and tests real DPoP behavior. Python confines the operator bearer to mint requests; Kubernetes takes the separately provisioned workload public key.
- RL1 uses a hard-coded canonical repository, literal workflow/tag certificate identity and exact OIDC issuer. Production cosign defaults retain public trust/log checks. Local fixture evidence is explicitly scoped and does not claim hosted keyless acceptance.

## Critical findings

None found in this bounded review.

## Important findings

### I1. The sidecar parser accepts syntactically encoded invalid public keys

Location: `crates/products/chio-api-protect/src/proxy/sidecar.rs:1205-1210`; supporting implementation `crates/core/chio-core-types/src/crypto.rs:342-366` and `:428-432`.

`PublicKey::from_hex` is an encoding parser, not full validation for all of the algorithms it accepts. Its P-256/P-384 constructors check length and the uncompressed-point prefix only. The new parser then calls `is_weak_ed25519`, which returns false for every non-Ed25519 variant. Consequently `"p256:04" + "00" * 64` reaches capability issuance despite representing the off-curve point (0,0). The P-384 equivalent behaves likewise. Hybrid wrappers also bypass the direct weak-Ed25519 predicate.

Reproduction by source reasoning: authenticated POST to either mint path using that subject and an otherwise valid request. `ClassicalWire::public_key` routes it to `from_p256_sec1`, both length/prefix checks pass, `is_weak_ed25519` returns false, and the handlers proceed to sign and mutate the receipt state. The existing invalid-subject router matrix covers Ed25519 inputs only. No Rust regression was run by this reviewer.

Impact: violates AP1's requirement to reject malformed/non-key subjects before issuance or mutation and can issue tokens for which no caller signer exists. This is not a demonstrated DPoP forgery or issuer-trust bypass. Restrict the mint subject contract to strong Ed25519 or perform actual key validation for every permitted algorithm, including hybrid classical components. Add invalid-curve-point controls through both production routes.

### I2. Incomplete legacy authority initialization is accepted as a successful empty-trust migration

Location: `crates/platform/chio-store-sqlite/src/authority.rs:110-129`; migration/schema setup in the same file at `:445-572`; `crates/platform/chio-store-sqlite/src/authority/replication.rs:33-43`.

The revised opener seeds `authority_trusted_keys` only if it inserted a new `authority_state` row. An existing legacy authority state with an absent or empty trust-history table therefore gets the table created and its schema stamped as revision 2, but returns success with an empty trusted issuer list. Replication initialization subsequently fails `AuthorityReplicationAnchor::new` because empty history is invalid. Capability validation relying on this CA list also loses its authority key. Normal complete revision-1 databases are unaffected.

Concrete supported input to reproduce: a pre-stamping database with only `authority_state(singleton_id, seed_hex, generation, rotated_at)` and one valid local seed row, then `SqliteCapabilityAuthority::open` followed by `trusted_public_keys` and `initialize_replication`. Source reasoning predicts successful open, empty keys, and failed initialization. The same state can follow an interrupted old initializer: historical commit `1d2b229521` inserted the authority state and initial history in separate autocommit operations. No Rust reproduction was run by this reviewer.

The follower-reopen protection is necessary and must remain. Either reject inconsistent legacy local state explicitly with a documented operator recovery path, or implement narrowly scoped legacy-only recovery that cannot add a follower's private-key identity to an authenticated replication set. Add a legacy incomplete-state fixture alongside the existing signed-follower reopen control.

## Minor findings

None requiring a separate source change. Ensure `.github/workflows/release-identity-check.yml` is explicitly included at commit time: the existing git info/exclude `workflows/` rule hides it. The executor already identified this packaging condition; its existence was verified in the working tree.

## Validation scope

This review inspected source, tests, workflow producers and operator docs. It did not run Cargo to avoid competing with the executor's serial builds. At review time the executor reported AP1 Rust/Python/Go checks and RL1 local cosign fixture/workflow checks passing; KG1 integration was still being corrected and rerun. Those reports are not independent terminal verification by this reviewer. No hosted/publication acceptance is asserted.

## Declined to judge

- Actual GitHub OIDC/Fulcio/Rekor hosted acceptance: requires an actual exact-tag hosted signing result; local CA fixtures deliberately cannot establish it.
- Account ownership, registry trust registration, protected environments, deployment and publication: operator actions/evidence outside this source review.
- KG2 issuer retirement/revocation/recovery, bounded-chain recheckpointing, custody handover and the kernel's separate always-trusted local receipt key: explicitly outside this batch and retained as open limitations.
- KG3 cleartext SQLite private-seed storage/default permissions: pre-existing custody finding outside AP1/KG1/RL1; replication does not copy those seeds.
- Full cluster snapshot atomicity across receipt, budget, revocation and authority databases, plus election-fence authentication: broader existing cluster protocol; this review judged authority import atomicity and issuer installation only. Omitted optional authority does not install issuers, but does not qualify the other snapshot fields.
- Concurrent stale fallback caches after explicit local pinning: docs require offline provisioning before service; this review does not qualify online checkpoint replacement or whole-process cache invalidation.
- Canonical shorthand mint grants remain bearer grants without required DPoP: explicitly documented compatibility behavior; AP1 proves caller possession only for grants requiring DPoP.
- Python SDK operator methods other than minting: bearer attachment intentionally scoped to the newly documented minting contract; other control clients were not repaired or qualified here.
- Whole-workspace qualification, all deployment topologies, non-Ed25519 crypto implementation audits, performance benchmarking at maximum chain size, and unrelated roadmap closure: outside this bounded review.

## Assessment

Ready to call the entire AP1/KG1/RL1 batch closed: **No, with fixes required**. The main issuer-injection repair and exact release identity policy are sound on this read-through, but I1 and I2 should be resolved and the executor must retain terminal focused integration/lint results. Re-review of these fixes can be bounded to their changed validation/migration paths; this report does not authorize merge, release or activation.


## Limited follow-up: I1 and I2 source repairs

Reviewed the executor's follow-up working tree on 2026-10-02, limited to the two findings, their focused regression fixtures and migration/subject-contract documentation. No Cargo or repository writes. The original findings and original assessment above remain as historical review evidence; this section supersedes their outstanding-source-fix status.

The retained `review-fixes-red.log` independently confirms both original reports: the P-256 off-curve subject returned HTTP 200 with an issued token in the production mint route, and the incomplete legacy opener did not return the required schema error. Thus both findings now have executed pre-repair reproductions, not just the original source reasoning.

### I1 resolution: resolved in source

`parse_sidecar_subject_key` now requires `SigningAlgorithm::Ed25519` and rejects weak Ed25519 keys. P-256, P-384 and hybrid encodings cannot pass this boundary regardless of whether their outer encoding is syntactically valid. Existing Ed25519 decoding validates the compressed point; the weak-key check supplies the remaining explicit mint restriction. Both handlers continue to call this parser before issuance/state mutation. The production-router invalid-subject matrix adds both off-curve examples across all three request shapes and retains assertions that receipt/revocation stores are unchanged. Documentation explicitly narrows the mint contract to strong Ed25519.

### I2 resolution: resolved in source

After reading durable public status, `open_with_clock` now refuses a head absent from persisted issuer history with an explicit schema error. It does not add the local seed's key as a repair. That rule rejects the missing/empty-history legacy states while allowing a signed follower whose public head is present in authenticated history and differs from its preserved local seed. Tests add both incomplete-history cases, verify unchanged seed/no invented issuer rows, and include successful complete legacy checkpoint migration. Existing authenticated follower restart and custody checks are retained. Recovery documentation requires an authenticated backup or explicit new authority provisioning and forbids treating the old seed as missing-history evidence.

Schema setup may still add schema objects/stamp revision before this error. This follow-up accepts that bounded migration behavior: the error no longer presents an unusable empty-trust authority as successfully opened, and no issuer trust or private seed is manufactured or replaced.

### Follow-up assessment

No remaining source objection from I1/I2. The repairs address the causes and preserve the relevant security boundaries. **The two review findings are resolved in source; terminal post-repair test/lint acceptance remains the executor's responsibility.** The combined focused suite was still running when this follow-up was requested, so this review does not label it passed. The original Declined to judge list, hosted/publication limitations and bounded scope remain in force. No broader re-audit was performed.
