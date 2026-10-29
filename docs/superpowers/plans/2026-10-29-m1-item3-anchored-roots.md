# Relying-Party Wedge M1 Item 3 Implementation Plan: Anchored Roots

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish M1 item 3 of the relying-party wedge on top of part 1 (#1706, merged as `c87bf753f1`). After this plan:
- `root_anchor` is a signed member of the `chio.capability.v1` body. A delegated token copies it byte for byte from its root.
- `AnchoredTrustRoot` admits a depth-0 anchored root against the loaded root policy, its delegation context and the exchange key set, and enforces every section 7.1 binding.
- `CapabilityPresentation`, the chain digest and the strict-decoding gate exist for items 4 and 6 to consume.
- Every receipt for an anchored capability carries the section 7.6 `authority` block.

**Architecture:**
- **Types (`chio-core-types`):**
  - `capability::anchor::RootAnchor` becomes an `Option` member of `CapabilityTokenBody`, serialized only when present.
  - `root_authority::CapabilityPresentation` and `root_authority::chain_digest` are added beside the part 1 types, `no_std + alloc` compatible.
- **Consistency:** `check_root_consistency` reads the anchor from the root's own body. The separate `anchor` input is deleted together with every caller.
- **Resolver (`chio-kernel-core`):** `AnchoredTrustRoot` implements `TrustRootResolver` and adds `admit_anchored_root`. It is pure: the policy, the delegation context, the exchange key set, the provider identity digest and the time are parameters. It reads no store, registry or clock.
- **Receipts (`chio-kernel`):** the receipt signer fills `authority` from the verified capability state (anchor, chain digest, depth 0, holder) when the exercised capability is anchored.

**Spec:** `docs/superpowers/specs/2026-10-17-relying-party-wedge-design.md`:
- 2.2 (D16, D17), 2.5 (G18, G19);
- 6.4 (depth 0 in M1), 6.5;
- 7.1, 7.2, 7.3, 7.5, 7.6 (`authority`);
- 8.2;
- 9.9 (padding);
- 10.1, 10.2;
- 11.1, 11.2;
- 13.2 item 3 (M, 7-9), 13.3 step 3.

**Plans this one depends on or feeds:**
- Item 1, the signing wrapper (`2026-10-20-m1-item1-signing-wrapper.md` l.559): "The `root_anchor` member in the capability signing body merges after this PR. It rebases on this PR and regenerates capability fixtures."
- Item 2, committed receipts (`2026-10-20-m1-item2-committed-receipts.md` l.1451 and Open Question 3, l.1871): F adds `ReceiptAuthority` with every producer setting `authority: None`; item 3 fills it.
- Item 4, exchange (`2026-10-20-relying-party-wedge-m1-item4.md` l.247, l.669, l.714): PR E needs part 2; `RootExchange::issue` signs the body with `root_anchor`; admission verifies with this plan's resolver.
- Item 6, verifier and export (`2026-10-20-m1-item6-verifier-export.md` l.135): 6b verifies `root_anchor` inside the signed capability body and waits for part 2.

**Census base:** `origin/main` `92fd8f147f`; #1837 (item 1) `87546a1bba` and #1875 (item 4 PR A) `ed24c8056e`, both open. Task 0 re-reads every cited site at each PR's base.

## Facts this plan builds on

| # | Fact | Source |
|---|---|---|
| F1 | #1706 landed the part 1 types: `RootAnchor` and the closed `AnchorKind` (8 kinds, plain string enum); `root_authority::{DelegationContext, RootPolicy, LoadedRootPolicy, EnterpriseProviderIdentity, IdpKeySnapshot, VerifierTrust, RevocationEntry}`; `RootPolicy::load`; `IdpKeySnapshot::verify_signature`; `check_root_consistency`. | `chio-core-types/src/capability/anchor.rs`, `src/root_authority/` (10 files, 3142 lines) |
| F2 | Every deserializable root-authority struct carries `deny_unknown_fields`. The structs without it are serialize-only signing bodies (`RootPolicySigningBody`, `IdpKeySnapshotSigningBody`), `RevocationEntry` (serialize-only) or non-serde (`LoadedRootPolicy`, `RevocationTarget`). No root-authority type uses `#[serde(flatten)]` or `#[serde(tag)]`. | `src/root_authority/*.rs` |
| F3 | Padding negatives exist as schema examples for every nested object of the delegation context, root policy, provider identity, IdP key snapshot, root anchor and presentation, and decode through `tests/root_authority_examples.rs` with the pinned reason. They are unsigned decoding cases; no padding negative carries a valid signature over the padded body. | `tests/root_authority_examples.rs`, `spec/schemas/chio-wire/v1/root_authority/examples/invalid/*padding*.json` |
| F4 | `CapabilityTokenBody` (`deny_unknown_fields`) has no `root_anchor`. `CapabilityTokenSigningBody` and `CapabilityTokenAttenuationBody` are serialize-only and use `#[serde(flatten)]` over the body. | `src/capability/token.rs:166-200` |
| F5 | `check_root_consistency(RootConsistencyInput { root, anchor, context, policy, sender_key })` takes the anchor beside the root because the body cannot carry it. It already covers every section 7.1 binding and the root policy rule checks (28 `RootConsistencyError` variants). | `src/root_authority/consistency.rs:20-260` |
| F6 | Item 4 part 1 prepares anchored roots it cannot sign: `PreparedAnchoredRoot { body: CapabilityTokenBody, anchor: RootAnchor, .. }`, documented "Issuing it needs `root_anchor` as a signed member of the capability body". | `chio-mcp-remote/src/remote_mcp/root_exchange/exchange.rs:101-150` |
| F7 | `TrustRootResolver` is `fn trust_root_scope_hash(&self, issuer: &PublicKey) -> Option<ScopeHash>`, consumed by `verify_capability_full_with_evidence(token, trusted_issuers, clock, crypto_floor, evidence, trust_root, budgets)`. No `AnchoredTrustRoot` exists. | `chio-kernel-core/src/capability_verify.rs:367-520` |
| F8 | `chio.capability-presentation.v1` has a schema (`capability/presentation.schema.json`: required `schema`, `leaf`, `ancestors`; optional `delegation_context`), examples and a generated type, but no hand-written Rust type. Items 4 (`presentation()` store read) and 6 (`EvidenceBundle.presentations`) consume `root_authority::CapabilityPresentation`. | `spec/schemas/chio-wire/v1/capability/`, item 4 l.416, item 6 l.363 and l.516 |
| F9 | No chain-digest helper exists for capabilities (`chain_digest` names on `main` are store and memory-provenance hashes). The spec domain is `chio.receipt.chain-digest.v1\0` over `canonical_json([root, ..., parent, leaf])`. | spec 7.6 |
| F10 | No repository check rejects `#[serde(flatten)]` on strict types; spec 11.1 requires one. | `scripts/`, `xtask/` |
| F11 | `capability/token.schema.json` has no `root_anchor` member; `root_authority/root-anchor.schema.json` exists. | `spec/schemas/chio-wire/v1/` |
| F12 | `CapabilityTokenBody { .. }` struct literals: 87 outside tests, 357 in all. `delegate` builds child tokens at `capability/attenuation.rs:1017`. | `git grep` at `92fd8f147f` |
| F13 | SDK capability decoders that must learn `root_anchor`: `sdks/go/chio-go/invariants/capability.go`, `sdks/python/chio-py/src/chio/invariants/capability.py`, `sdks/typescript/chio-ts/src/invariants/capability.ts`, the Python SDK generated `capability/token_schema.py`, `sdks/k8s/webhooks/capability.go`, `sdks/go/chio-go-http/types.go`. | `git grep delegation_chain -- sdks` |
| F14 | `tests/bindings/vectors/capability/` holds `v1.json` and `security-binding-v1.json`; no anchored-root vectors. | |

## Decisions

1. **`root_anchor` is optional in the body, required at admission.** `CapabilityTokenBody.root_anchor: Option<RootAnchor>` with `skip_serializing_if = "Option::is_none"`. An unanchored token's bytes are unchanged, so tokens outside `serve-http` (kernel-local issuance, conformance) keep verifying. `serve-http` (item 4 PR E) and `api protect` (M3) admit only through `AnchoredTrustRoot`, which refuses `None` (8.2). This is not a dual path: there is one body type and one admission rule per surface.
2. **One anchor source.** After part 2 the anchor lives only in the signed body. `RootConsistencyInput.anchor` (5 construction sites, all in tests or `consistency.rs`) and `PreparedAnchoredRoot.anchor` are deleted with every caller in the same PR.
3. **Resolver purity.** `AnchoredTrustRoot` takes `&LoadedRootPolicy`, the exchange key set, `&DelegationContext`, the provider identity digest the caller read for this request (`None` for kinds that are not provider-backed) and `now: u64`. Store reads (item 4 `presentation()`), registry reads (G17) and the clock stay with the caller.
4. **Depth 0.** `admit_anchored_root` refuses any non-empty `ancestors` with a typed error (8.2 "Any non-empty `ancestors` before M2"). Depth one and deeper arrive with the M2 portable chain work.
5. **Strict-decoding gate is a Rust test.** `chio-core-types` gains a test that scans `src/capability`, `src/root_authority` and `src/receipt` and fails on `#[serde(flatten)]` on any type deriving `Deserialize`. Serialize-only signing bodies (F4) are allowed. No new script.

## Global constraints

- House rules: no em dashes; fail-closed; no legacy or compat paths; `unwrap` and `expect` denied; conventional commits.
- RED first in every task: the failing test commit precedes the implementation commit.
- Every function in `root_authority` and the resolver takes time as a parameter (spec 10.1); `scripts/check-security-clocks.py` passes.
- Every new decoder gets a trust-boundary inventory entry with its contract and reader evidence; `scripts/check-trust-boundaries.py` returns 0 at each PR head.
- `docs/formal/COVERAGE.md` is regenerated as the last commit of each PR.
- Signed fixtures regenerate only through `cargo xtask gen signed-fixtures`, at the integrated base.

## PR slicing and order

| PR | Title | Signs | Depends on | Size |
|---|---|---|---|---|
| Part 1 | #1706 `feat(core-types): root-authority wire types, root policy load rules and root consistency checks` | no | merged `c87bf753f1` | done |
| 3a | `feat(core-types): capability presentation, chain digest and the strict-decoding gate` | no | `main` (may land before item 1) | S, 1-2 |
| 3b | `feat(core-types): root_anchor in the signed capability body and the depth-0 AnchoredTrustRoot` | adds a signed member; unanchored bytes unchanged | item 1 #1837 merged; 3a | M, 4-5 |
| 3c | `feat(kernel): fill the receipt authority block from the verified anchored capability` | changes anchored receipts only | 3b; item 2 F merged | S, 2 |

Downstream: item 4 PR E and `RootExchange::issue` need 3b; item 6 6b needs 3b (and 3c for receipt `authority`); item 5 PR 3 follows item 4's store, which follows 3b.

## Tasks

### Task 0: Census and preconditions (every PR)

- [ ] Re-read F1 to F14 at the PR base; record changed sites in the PR body.
- [ ] 3b only: confirm #1837 is on `main`; recount `CapabilityTokenBody {` literals and SDK decoders.
- [ ] 3c only: confirm item 2 F is on `main` and read `ReceiptAuthority`'s final shape.

### Task 1: Capability presentation, chain digest, strict-decoding gate (PR 3a)

**Files:** `crates/core/chio-core-types/src/root_authority/presentation.rs` (new), `root_authority/chain.rs` (new), `root_authority/mod.rs`, `tests/root_authority_presentation.rs` (new), `tests/strict_serde_gate.rs` (new), `docs/security/trust-boundary-inventory.json`.

- [ ] **RED:**
  - `presentation_decodes_the_schema_examples` (valid example round-trips; every `invalid/presentation.*` example refuses with its pinned reason);
  - `presentation_refuses_padding_in_the_envelope_and_the_context`;
  - `presentation_ancestors_bound_matches_the_schema`;
  - `chain_digest_uses_the_spec_domain_and_root_to_leaf_order`;
  - `chain_digest_of_a_single_root_is_pinned` (literal expected hex);
  - `strict_types_never_flatten_on_deserialize` (passes on `main`, fails on a planted fixture in the test's own input set).
- [ ] **Implement:** `CapabilityPresentation { schema, leaf: CapabilityToken, ancestors: Vec<CapabilityToken>, delegation_context: Option<DelegationContext> }` with `deny_unknown_fields` and the exact-string schema guard; `chain_digest(&[CapabilityToken]) -> Result<Sha256Digest, Error>`; the gate test.
- [ ] Inventory entry for the presentation decoder; trust-boundaries rc 0.

### Task 2: `root_anchor` in the signed body (PR 3b, commit group 1)

**Files:** `capability/token.rs`, `capability/attenuation.rs` (`delegate`), every `CapabilityTokenBody { .. }` literal (F12), `root_authority/consistency.rs`, `chio-mcp-remote/src/remote_mcp/root_exchange/exchange.rs`, `spec/schemas/chio-wire/v1/capability/token.schema.json`, `_generated/chio_wire_v1.rs`, `spec/schemas/MANIFEST.sha256`, `wire-schemas.lock`.

- [ ] **RED:**
  - `root_anchor_round_trips_in_the_signed_body`;
  - `unanchored_token_bytes_are_unchanged` (the canonical signing bytes of a pre-change token fixture are byte-identical);
  - `root_anchor_padding_refuses_even_with_a_valid_signature` (pad inside `root_anchor`, re-sign the padded body, decode refuses);
  - `root_anchor_unknown_kind_refuses_at_decode`;
  - `delegate_copies_root_anchor_byte_for_byte`;
  - `consistency_reads_the_anchor_from_the_root_body` and `consistency_refuses_an_unanchored_root` (new `RootConsistencyError::NotAnchored`);
  - `prepared_anchored_root_body_carries_its_anchor` (item 4 part 1 caller).
- [ ] **Implement:** the `Option<RootAnchor>` member; `delegate` copies the parent's anchor; delete `RootConsistencyInput.anchor` and `PreparedAnchoredRoot.anchor` with every caller; set `root_anchor: None` at every unanchored literal in one mechanical commit; schema member referencing `root_authority/root-anchor.schema.json`; regenerate the generated types, the registry digests and the lock.

### Task 3: `AnchoredTrustRoot`, depth 0 (PR 3b, commit group 2)

**Files:** `crates/kernel/chio-kernel-core/src/capability_verify.rs`, `capability_verify/anchored.rs` (new), `capability_verify_tests/anchored.rs` (new).

- [ ] **RED (one test per 8.2 rule that applies at depth 0):**
  - `anchored_root_admits_at_depth_0` for each M1 kind (`oauth_id_jag`, `entra_jwt`, `oidc_jwt`, `oauth_introspection`, `chio_local_as`, `chio_operator_key`, `operator_static_bearer`);
  - `root_without_root_anchor_denies`;
  - `root_signed_outside_exchange_keys_denies`;
  - `root_policy_digest_other_than_loaded_denies`;
  - `loaded_policy_outside_validity_window_denies`;
  - `expires_after_assertion_exp_denies`;
  - `context_digest_mismatch_denies`;
  - `assertion_exp_not_token_exp_denies`, `anchored_at_not_exchanged_at_denies`, `issuer_not_exchange_key_denies`, `scope_hash_not_effective_root_scope_hash_denies`;
  - `caller_root_subject_not_sender_key_denies`, `edge_session_root_with_sender_key_denies`;
  - `provider_identity_digest_mismatch_denies` and `provider_backed_kind_without_identity_digest_denies`;
  - `non_empty_ancestors_deny_before_m2`;
  - `delegated_token_with_a_different_anchor_denies`;
  - `resolver_scope_hash_derives_from_policy_and_context`;
  - `admission_is_a_pure_function_of_its_time_parameter` (same inputs at `now` and `now + 1` across `assertion_exp`).
- [ ] **Implement:** `AnchoredTrustRoot<'a> { policy, exchange_keys, context, provider_identity_digest }` implementing `TrustRootResolver`, and `admit_anchored_root(token, ancestors, sender_key, now) -> Result<AdmittedRoot, AnchoredRootError>` over `check_root_consistency` plus the policy window, ancestor and chain-equality checks. `AnchoredRootError` maps each 8.2 rule to one variant.

### Task 4: Vectors and SDK verifiers (PR 3b, commit group 3)

**Files:** `tests/bindings/vectors/capability/anchored-root/v1.json` (new), `tests/bindings/vectors/MANIFEST.sha256`, the generator under `scripts/` that emits signed vectors, the F13 SDK decoders and their tests.

- [ ] **RED:** SDK tests in TypeScript, Python and Go that load the new vector file and fail on the missing member.
- [ ] **Vectors:**
  - one valid anchored root per M1 kind;
  - one negative per Task 3 rule, with the expected error class;
  - padding negatives with a valid signature over the padded body: `root_anchor`, the delegation context (`anchor`, `exchange`, a commitment, `claims`) and the presentation envelope (spec 11.2 l.1157).
- [ ] **Implement:** each SDK decodes `root_anchor` strictly (unknown member and unknown kind refuse) and copies it unchanged on re-encode; each runs the vector file.

### Task 5: Receipt `authority` (PR 3c)

**Files:** `crates/kernel/chio-kernel-core/src/receipts.rs`, the hosted kernel's receipt assembly, `tests/bindings/vectors/receipt/` (added cases only).

- [ ] **RED:**
  - `receipt_authority_present_iff_capability_anchored`;
  - `authority_root_anchor_equals_the_capability_anchor_bytes`;
  - `authority_chain_digest_and_depth_0`;
  - `authority_holder_matches_the_delegation_context`;
  - `anchored_receipt_with_tenant_id_refuses_signing` (item 2 F's T27 refusal reached from a real anchored capability);
  - `unanchored_capability_receipt_has_no_authority`.
- [ ] **Implement:** fill `ReceiptAuthority` from `AdmittedRoot`; add receipt vectors with an `authority` block and its `authority.root_anchor` padding negative, unless F's vectors already carry them.

## Vectors and schemas touched

| Artifact | PR | Change |
|---|---|---|
| `spec/schemas/chio-wire/v1/capability/token.schema.json` | 3b | `root_anchor` member referencing `root_authority/root-anchor.schema.json` |
| `crates/core/chio-core-types/src/_generated/chio_wire_v1.rs`, `spec/schemas/MANIFEST.sha256`, `wire-schemas.lock` | 3b | regenerated |
| `tests/bindings/vectors/capability/anchored-root/v1.json` | 3b | new: allow per M1 kind, 8.2 negatives, signed padding negatives |
| `tests/bindings/vectors/MANIFEST.sha256` | 3b, 3c | new and changed lines |
| Capability signed fixtures | 3b | none for unanchored tokens (Decision 1); anchored roots are new files |
| `tests/bindings/vectors/receipt/` | 3c | added `authority` cases if F does not carry them |
| `docs/security/trust-boundary-inventory.json` | 3a, 3b | presentation decoder; capability body decoder contract gains `root_anchor` |

## Open decisions (OWNER)

| # | Question | Default |
|---|---|---|
| O1 | Does 3b need a D17 byte-change window? It adds a signed member but leaves every unanchored token's bytes unchanged. | No D17 window; the PR body pins `unanchored_token_bytes_are_unchanged`. |
| O2 | The 357 `CapabilityTokenBody { .. }` literals (87 outside tests) gain `root_anchor: None`. | Edit every literal in one mechanical commit. No `Default` derive or builder that hides the member. |
| O3 | Where does `chain_digest` live? Spec 10.2 names kernel-core; `chio-bundle-verify` and the wasm verifier need it without kernel-core. | `chio-core-types::root_authority::chain`; amend spec 10.2 in 3a. |
| O4 | Where does `CapabilityPresentation` live, and who owns it? No plan owns the Rust type; items 4 and 6 consume it. | Item 3 PR 3a, under `root_authority` (spec 10.1). |
| O5 | Who fills the receipt `authority` block? Item 2's Open Question 3 default says item 3. | Item 3 PR 3c, after F. |
| O6 | Is the provider identity check (G17) inside the resolver? | The resolver compares the digest its caller read for this request; item 4 owns the per-request registry read. |

## Cross-plan amendments

- Item 2 Open Question 3: names PR 3c as the PR that fills `authority`.
- Item 4: `RootExchange::issue` and PR E cite PR 3b; `PreparedAnchoredRoot.anchor` is deleted in 3b, which item 4's PR A to C rebase onto.
- Item 6 6b: depends on 3b, and on 3c for receipt `authority` checks.
- Spec 10.2: `chain_digest` moves to `chio-core-types` if O3 keeps its default.

## Spec traceability

| Spec | Task |
|---|---|
| 7.1 member, kinds, byte-for-byte copy, `expires_at <= assertion_exp`, digests, bindings | 2, 3 |
| 7.2 closed kinds | part 1; 2 (unknown kind at decode) |
| 7.5 presentation | 1 |
| 7.6 `authority`, `chain_digest`, T27 | 1, 5 |
| 8.2 edge admission at depth 0 | 3 |
| 9.9 padding, G18 | 1 (gate), 2, 4 |
| 10.1 `root_authority` additions | 1 |
| 10.2 `AnchoredTrustRoot`, `chain_digest` | 1, 3 |
| 11.1 strict decoding tests, flatten repository check | 1, 2 |
| 11.2 capability vectors | 4 |
| 13.2 item 3 size M 7-9 | 3a 1-2, 3b 4-5, 3c 2 |
