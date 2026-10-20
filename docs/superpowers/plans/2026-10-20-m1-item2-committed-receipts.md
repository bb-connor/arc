# Relying-Party Wedge M1 Item 2 Implementation Plan: Committed Receipts

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land M1 item 2 of the relying-party wedge. `chio.receipt.v1` has one format, committed. Every producer computes salted commitments to arguments and results inside its own signing boundary, with salts drawn from the `Rng` seam of the process that signs. Every consumer that today binds to the unsalted `action.parameter_hash` or `content_hash` gets a planned binding to the committed value. `RedactionMode`, `parameter_hash`, `content_hash`, `sign_receipt_relaying_trusted_body` and `HttpReceipt` are deleted with every caller. Every verifier opens commitments, and every signed fixture is regenerated once.

**Shape:** four byte-neutral precursor PRs, then one atomic format PR (G1). The precursors add code that the format PR switches on. No precursor changes a signed byte, a fixture or a wire shape. Signed bytes change exactly once, in the format PR, which is squash-merged; its intermediate commits need not build, and its tip is the verified unit.

| PR | Title | Bytes | Contents |
|---|---|---|---|
| P-a | `refactor(core-types): move the Rng seam into core types and make it fallible` | none | Task 2 |
| P-b | `feat(core-types): receipt commitment and disclosure types with openers` | none (additive) | Task 3 |
| P-c | `feat(store): receipt openings table, reads and erasure` | none (additive table, reads and erase routes; the append writes openings only in F) | Task 4 |
| P-d | `feat(kernel): guard evidence declarations and the receipt metadata key registry` | none (declarations and registry; dropping and refusal off) | Task 5 |
| P-e | `fix(core-types): route every committed-receipt raw decode through UntrustedJsonText::decode_signed` (shared fix, lead-owned in the fwdcompat lane) | none | Task 5b |
| P-f | `feat(trust-control): caller credentials with scopes and tenant authority, and an internal listener` | none | Task 5c |
| P-g | `feat(identity): keyed enterprise subject identifiers` | every derived enterprise subject key (A1 identity closure) | A1, P-g |
| F | `feat(core-types): committed receipts for every producer` | every receipt | Tasks 6 to 19 |

**Architecture:** `chio-core-types` holds the moved `Rng` seam and `receipt/disclosure.rs` (commitments, salts, content preimages, the `chio.receipt-disclosure.v1` document and its opener). Producers stop building a signed body. They build a `ReceiptDraft` (the body without commitments) and pass `ReceiptPreimages` and an `Rng` to the one receipt signer. The signer draws salts, computes both commitments, signs through the item 1 wrapper and returns the receipt with its `ReceiptOpenings`. A hosted kernel persists the openings in the same transaction as the receipt append (SQLite, or trust-control through the same remote append request), so an opening is never written separately from its receipt. Relay adapters (FFI, WASM, mobile, ACP, HTTP) pass preimages, never hashes. Consumers bind to commitment values, to store-internal digests, or open with a persisted opening, per the consumer table in Task 1.

**Tech Stack:** Rust workspace (every cargo command through `cs`, defined under Global Constraints), JSON Schema draft 2020-12, `cargo xtask codegen` (Rust, TS, Go, Python), `cargo xtask gen signed-fixtures` (from item 1), `cargo xtask freeze-vectors`, Python reference generator `scripts/gen-signing-wrapper-vectors.py`, Go, TypeScript (npm), Python (uv), Kotlin (Gradle), .NET (dotnet), C++ (CMake through `scripts/check-chio-cpp.sh`), Miniflare for the Workers test.

**Spec:** `docs/superpowers/specs/2026-10-17-relying-party-wedge-design.md`, sections 2.2 (D2, D17), 2.5 (G1, G3, G4, G13, G14, G15, G18), 7.4 (producers without a root policy), 7.6, 7.7, 7.8, 8.4, 9.4, 10.1 to 10.3, 10.7, 10.10, 11, 13.2, 13.3. Inputs: `docs/superpowers/specs/relying-party-wedge/receipt-producer-inventory.md`, `docs/superpowers/specs/relying-party-wedge/protocol/protocol-6-committed-receipts.md`, `docs/superpowers/specs/relying-party-wedge/in-place-schemas/receipt/record.schema.json` and its README, `docs/superpowers/specs/relying-party-wedge/verdict-matrix/` (`receipt_disclosure`), `tests/bindings/vectors/receipt/committed/v1.json`, `scripts/gen-signing-wrapper-vectors.py`, the item 1 plan `docs/superpowers/plans/2026-10-20-m1-item1-signing-wrapper.md`, the item 6 plan (part 6a moves `chio-control-plane/src/evidence_export/verification.rs` into `chio-bundle-verify`), and `docs/adr/ADR-0019-kernel-delivery-contract.md` item 7 (the receipt-metadata key registry).

**Builds on:** #1715 (fwdcompat receipts, option 2: `deny_unknown_fields` across the receipt trees, `Decision` and `OperationTerminalState` through `chio_security_types::lossless_serde!`, commerce routing off the receipt bytes) and #1716 (closed receipt decode in the Go, Python and TypeScript verifiers). Item 2 keeps both contracts and extends them to the new members: every new receipt block is `deny_unknown_fields`; every new tagged enum and closed union decodes through `chio_security_types::lossless_serde!`, the path #1706 already uses inside `chio-core-types` (no local helper, G18); the commerce authority receipt route stays outside the signed bytes; and each SDK verifier's closed layer list gains the new blocks. #1723 (the shared `lossless_serde!` fix, at `852c60127f`) is the predecessor of the strictness gate: its macro takes the enum definition, and a private remote mirror leaves the trait impl as the only reachable decoder, so `Type::deserialize` is the concrete decode path; its 11 census types carry exact concrete-path refusal tests. #1715 and #1706's `ClaimValue` rebase onto it. Every committed-receipt type in this plan decodes through the #1723 macro (or `deny_unknown_fields` for plain structs) and gets a concrete-path refusal test of the same shape (Task 6). Item 2 also reuses #1706's `root_authority::wire::SaltRef` (an open dotted string of at most 64 characters), `Sha256Digest`, `RootAnchor` and `HolderClass`.

**Census base:** facts below were measured at `origin/main` `fcc31d25fb` (consumers) and `a93a2f69a3` (producers and fixtures), where neither item 1 nor #1715 is merged. Task 1 re-runs every census at each PR's integrated base and updates the counts in that PR's body. Counts from any earlier base are planning figures only.

## Global Constraints

Quoted verbatim from the spec.

D2 (spec 2.2):

> Committed receipts are protocol-wide: one receipt format. Every producer gets a salt source from the host RNG through the existing `Rng` seam, including the FFI and WASM signers. Inline-versus-committed disclosure per tool and per field lives in the signed root policy, so a verifier can see that plaintext was authorized. Default is committed.

G1 (spec 2.5):

> Committed receipts land in one squash-merged PR (M1 item 2). `ChioReceiptBody` and `ToolCallAction` are single structs, so the format change and every producer change together. Inside the PR, commits follow the inventory's commit groups (1 core types and the portable signer, 2 hosted kernel, 3 FFI, WASM and mobile, 4 security, control-plane, HTTP and proxy producers, 5 observability, products, harnesses and fixtures), and each producer's salt-source wiring is its own commit. Intermediate commits need not build; the PR tip is the verified unit, as for the M0 trait collapse. No producer-by-producer PRs follow it.

The body changes (spec 7.6):

> 1. `action.parameters` and `action.parameter_hash` are replaced by `action.parameter_commitment` and optional `action.parameters_inline`.
> 2. `content_hash` is replaced by `content_commitment` and optional `result_inline`. The signer recomputes the commitment from the content preimage and the salt inside its own trust boundary. WYSIWYS is kept. No signing path accepts a caller-supplied hash or commitment; a producer that holds only a hash today receives the preimage (G3).
> 3. `redaction_mode` is replaced by a `disclosure` block. `RedactionMode` is deleted. Builder task in M0: inventory every producer of `summary` and `redacted` and record how each maps to committed-with-inline-fields or fully committed.
> 4. New top-level `authority` block, present whenever the exercised capability carries `root_anchor`.
> 5. A receipt with an `authority` block must omit `tenant_id` (T27); signing fails otherwise. The tenant is carried only as the delegation context commitment and the unsigned tenant tag.

Commitment rules (spec 7.6):

> - `value = SHA-256(domain || salt || preimage)` where the domain is `chio.receipt.parameters.v1\0` or `chio.receipt.content.v1\0`, the salt is 32 bytes drawn per receipt per field from the producer's host `Rng`, and the preimage is the existing canonical preimage (RFC 8785 canonical arguments; the WYSIWYS content preimage for outputs). The salt is fixed-length, so the concatenation is unambiguous.
> - A verifier selects the domain from the commitment's position in the receipt, never from the opening.
> - The content preimage has three forms. A value output uses the canonical JSON of the result. An empty output (no result) uses the zero-length byte string, so its commitment is `SHA-256(domain || salt)`. A stream output uses the concatenation of the lowercase hex SHA-256 of each canonical chunk; a stream with no chunks is an empty output. A verifier derives the preimage from its own copy of the output (or from the absence of one) and never from an opening's `payload`: a `payload: null` opening is salt only and supplies no preimage, so the literal `null` is never an output preimage. Per-chunk digests are not written to any signed field, metadata or evidence, because they are unsalted.
> - Salts are never in the signed body. They are returned to the producer's host with the signed receipt and written to the disclosure store keyed by `(receipt_id, salt_ref)` where a store exists.
> - `disclosure.policy_digest` is required when either inline list is non-empty and must name the loaded root policy. The inline lists must equal the policy's lists for that tool. A verifier with the policy checks that every inline field was authorized (A5) and that each inline value matches the opened commitment when openings are available.
> - A receipt with no inline fields omits `policy_digest` and both lists are empty.
> - `chain_digest = SHA-256("chio.receipt.chain-digest.v1\0" || canonical_json([root, ..., parent, leaf]))` over the full signed tokens.
> - Guard `evidence` entries and `metadata` must not contain argument or result values outside the inline fields. Enforcement is in section 8.4.
> - Decoding is strict (G18): an unknown member in a commitment, `disclosure`, `authority` or its `root_anchor`, or in any later block (`enforcement`, `settlement`), rejects the receipt at decode.

The opening document (spec 7.7):

> - An opening with a `salt` and `payload: null` is valid only in the caller copy, in `caller` bundles (section 7.12) and in the AuthZEN response to the PEP that sent the arguments (section 7.9). Export refuses to write salt-only openings in auditor profiles.
> - A verifier opens a commitment by recomputing it. A mismatch marks that field `rejected` and the receipt as tampered disclosure.
> - A verifier rejects an opening document in which the same `salt` value appears for more than one `salt_ref`, and marks the receipt as tampered disclosure. A producer draws a fresh salt for every field.
> - Decoding is strict (G18): an unknown member in the document or in any opening rejects it.
> - Deleting a receipt's openings from the disclosure store makes its commitments permanently hiding and leaves the signed receipt valid (erasure path).

Producer salt sources (spec 7.8):

> Rule (G3): a producer draws salts from the `Rng` seam of the process that signs. The inventory assigns every producer to one row. A producer that holds only a hash today (ACP relays, verified-fix evidence, fixture re-signers) receives the preimage over its existing channel, and a fixture that re-signs a recorded hash is regenerated from its recorded preimage.
>
> The FFI and WASM relay seam (T14) is replaced: those adapters pass the unsigned body plus the parameter and content preimages, and the core computes commitments and salts. `sign_receipt_relaying_trusted_body` is deleted, which also removes the one place where a caller-asserted content hash was trusted. Out-of-workspace emitters (the Lambda extension under `sdks/lambda/`) adopt the format in the same PR or are deleted.

G4 (spec 2.5):

> `HttpReceipt` is a receipt: it carries `receipt_kind`, `boundary_class`, `verdict`, `trust_level`, `redaction_mode` and `content_hash`, and chio-http-core already projects it into a `ChioReceipt` that embeds the whole `HttpReceipt` in `metadata` (`receipt.rs:350`), so one record has two signed forms today. It is deleted. chio-http-core signs `chio.receipt.v1` directly through the shared kernel signer: `tool_server = "http"`, `tool_name = "<METHOD> <route_pattern>"`, the canonical HTTP request (method, route, request id and the request body preimage) is the parameter preimage, and the response status with the response body preimage is the content preimage. `caller_identity_hash` is dropped; the caller is covered by the committed parameters and, from M3, by `authority`. The SDK middleware types (Python, JVM, .NET, `chio-tower`, `api protect`) change in the same PR. No `chio.http-receipt.v1` id exists. The ACP proxy, SCIM deprovision and verified-fix paths follow the G3 preimage rule.

G13 and G15 (spec 2.5):

> The content preimage of an output has three forms: canonical JSON for a value, the zero-length byte string for an empty output, and the concatenated lowercase hex SHA-256 of each canonical chunk for a stream (no chunks is empty). The verifier derives the preimage from its own copy of the output, never from an opening's `payload`, so the literal `null` is never a preimage and cannot collide with a salt-only `payload: null` opening.

> A verifier rejects an opening document in which the same salt appears for more than one `salt_ref`. The receipt is marked as tampered disclosure.

Privacy (spec 8.4):

> - Receipt assembly fails signing (the call denies) if `parameters_inline` or `result_inline` contains a pointer not authorized by the root policy for that tool, if any inline list is non-empty without a root policy, or if a receipt with `authority` carries `tenant_id`.
> - Guard evidence and metadata: guards declare which evidence fields are safe under committed disclosure. Undeclared fields are dropped before signing. A guard that marks a field required and unsafe fails at load.
> - Salt generation failure fails signing.
> - Disclosure-store write failure after signing: the receipt is still appended (receipts are authority), the opening is marked lost, and an operator alert fires. The commitment then stays permanently hiding (Q-B5).

Producers without a root policy (spec 7.4):

> Producers without a root policy (`chio mcp serve`, `chio run`, the local kernel, `api protect` before M3, cage and broker receipts) emit fully committed receipts. Plaintext in a receipt always requires a signed root policy referenced by digest.

Further constraints:

- M1 scope (spec 13.1 cut 1): every receipt is fully committed. `parameters_inline` and `result_inline` exist in the types, the schema and the verifiers, and the signer refuses to set them. Inline disclosure lands in M2.
- Merge order (precondition): #1674, #1601 (merged), #1607, #1723 (`852c60127f`), #1715 and #1706 (both rebased onto #1723), #1716, #1705, #1710, #1708, the Root-2 K-stack in Root-2's order (T7 #1675, C6 #1682, native-ledger #1678, stop-error #1701, D5 #1269, KERN-TRACE-LOCK-FSYNC), #1722 (subtree cancellation, draft at `188a6af6ff`), item 6 part 6a, item 1, and the store schema-adoption cleanup (no PR or implementation yet; it is the last serial store item and an explicit unresolved predecessor, never a guessed PR number); then P-a to P-d in that order (P-d as part 1, #1727, and part 2, the stacked projections PR after P-a, P-b and #1706), P-e (any time before F) and P-f (before P-c, which uses its credentials and listener); then P-g (enterprise subject identity closure, A1), then F. F stays stopped until Amendment A1 (value-carrying metadata blocks) merges, and F depends on P-g. P-c also waits for #1722 and the schema-adoption cleanup, because it adds a store table. #1710 is an explicit predecessor of F (Root-2 condition 7), not "whichever lands second". Item 3's capability change (`root_anchor` in the capability body) follows F. Root-2's order is not an approval of any candidate head.
- Preconditions (D17): the "D17 Coordination" list is acknowledged by the lead and Root-2 on `ws2:~/lanes/claude-pr1160-evidence/lead2/sync.md` before F opens. Each Root-held file in that list has Root-2's ACK before the lane edits it.
- Precursors are byte-neutral: each one's tip passes the full changed-crate suites and `cs cargo xtask gen signed-fixtures --check` with no fixture change.
- F is one PR, squash-merged. Commits follow "Commit Grouping" for F: the inventory's five groups in order, and inside them each producer's salt-source wiring in its own commit. Intermediate commits need not build. Each group's last commit passes `cs cargo check -p <crate>` for the crates that group finishes.
- Fixtures: every signed fixture is regenerated once, in F, at the integrated base, by `cs cargo xtask gen signed-fixtures`. No signed fixture is edited by hand, patched by a script or rewritten by any tool other than its owning generator.
- A signed or durably admitted receipt keeps its exact receipt id and its exact salts across every retry and recovery. Nothing re-signs with new entropy to recover an ambiguous append (Root-2 condition 3).
- No legacy, compat or dual paths; everything is v1. No `parameter_hash` or `content_hash` alias, no `redaction_mode` reader, no relay signer that accepts a hash, no second HTTP receipt, no default trait method standing in for a declaration, no store migration or adoption fallback (the DDL changes in place, and v1 catalog validation refuses any other layout).
- Fail-closed: salt generation failure, a malformed `salt_ref`, a commitment that does not recompute, `tenant_id` beside `authority`, an inline field without a root policy, an unregistered Chio-internal metadata key, an unavailable opening where a consumer needs one, and a decode error each refuse with an explicit error.
- Strict decoding (G18) for every type added or changed: `deny_unknown_fields` at every level, closed string enums for `alg` and `holder`, `lossless_serde!` for tagged enums, no `#[serde(flatten)]`. Opaque caller data (`parameters_inline`, `result_inline`, an opening's `payload`, caller `metadata` values) stays opaque.
- Strictness gate (mandatory, Root-2 r2 request 3): every committed-receipt type, existing and new, goes through the #1723 macro (or `deny_unknown_fields` for a plain struct) and passes `committed_receipt_types_refuse_padding_and_lossy_decode` (Task 6) through each of its decode paths: the trait path `T::deserialize`, `serde_json::from_str`, `serde_json::from_value` and every public concrete decoder. A type absent from that test's list cannot merge. Neither a variant shape elsewhere (#1706's `ClaimValue`) nor the derive attributes count as evidence.
- Clock reads only through the approved seams; fixtures use fixed timestamps (`issued_at = 1792234800`). Run `python3 scripts/check-security-clocks.py`.
- Clippy denies `unwrap_used` and `expect_used` outside tests. Format with `cs cargo fmt --all`.
- No em dashes (U+2014) in any file. No narrative or meta comments; comments state invariants and contracts.
- Public-path rule: files under `spec/`, `docs/adr/`, `tests/`, `scripts/`, `crates/`, `sdks/`, `examples/` never mention milestones, the wedge, pilots or `docs/superpowers`.
- Build slots: on ws2, `cs` means `CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/var/tmp/claude-targets/m1i2 ~/lanes/cslot.sh`; on the x86 runner and host 3 it means `CARGO_INCREMENTAL=0 ~/cslot.sh` with that host's lane target dir. Every cargo command runs under `cs`: `cargo build`, `test`, `check`, `clippy`, `fmt`, `run`, `tree` and `xtask`, and every script, Makefile target, generator, freeze or fixture command and SDK manifest build that reaches cargo directly or nested (`make codegen-check`, `scripts/check-bindings-parity.sh`, `scripts/check-chio-cpp.sh`, `scripts/check-sdk-parity.sh`, `scripts/check-adapter-no-bypass.sh`, `scripts/check-fixture-rng.py`, `scripts/check-security-ci-contract.py`, `scripts/check-aws-lc-fork.py`, `wasm-pack`, every `--manifest-path` build). No command in this plan invokes cargo outside `cs`.
- Formal tools: no Lean, lake, Aeneas or Kani runs on ws2, including single harnesses. Kani and any Lean gate run only on the approved x86 runner under `cs`.
- Work happens on ws2 in worktrees `~/lanes/m1i2-<pr>` off fresh `origin/main` (fetched over https). Coder checks run under `cs`; heavy suites run on the integrators (`integ-x86`, `integ-h3`). Never `git stash`. Inspect `git diff --cached --stat -M` before every commit. Push explicit SHAs over https.
- Shared surfaces: before requesting merge of each PR, post `<UTC> <lane>: REVIEW? #<N> M1 item 2 <part> (<surfaces>)` to `sync.md`, then `MERGING #<N>` with the 10-minute window and the OBJECT check.

## Review Focus

1. **A consumer or parameter reader without a planned binding.** Expected: the census script (`docs/superpowers/plans/m1-item2-census/census.py`) classifies every production line its six patterns find (three line patterns for the receipt hashes, hash member names and `action.parameters`; three whole-file patterns for receipt `tenant_id` readers, rustfmt-split `action` chains and JSON indexing of `action` parameters) with no `UNCLASSIFIED` row at each PR's base; at the F tip only kind D, GEN and DOC lines remain; every consumer that needs an opening fails with `OpeningUnavailable` when it is erased, unknown or the read is refused. A reader outside these patterns is not covered, so a reviewer who finds one adds a pattern. Pinned by the committed census TSV, the per-consumer tests in Tasks 7 and 16, and `compacted_replay_survives_erased_openings` (Task 7).
2. **An opening written apart from its receipt.** Expected: on every hosted path (SQLite and trust-control), openings are written in the receipt's append transaction, and every replicated import (receipt delta or snapshot) writes the receipt, its opening state and the cursor advance in one transaction; no `put_openings` call exists outside it; a crash, a lost ACK or a retry leaves the receipt and its salts identical. Pinned by the Task 4 crash and ACK tests and the Task 7 recovery tests.
3. **A signing path that still accepts a hash or a commitment.** Expected: the only receipt signers take `ReceiptDraft`, `ReceiptPreimages` and `&dyn Rng`, including `chio-selective-disclosure` `sign_chio_receipt_with_bbs`. Pinned by `receipt_signers_take_preimages` (Task 6) and the Task 1 grep re-run at the F tip.
4. **A salt that is not fresh, not 32 bytes, or seeded in a release build.** Expected: two salts per receipt from the producer's own `Rng`, refused when equal; fallible `Rng::fill_bytes`; no zero-fill fallback; `chio-fixture-rng` absent from the release dependency graph. Pinned by Task 2's tests and `scripts/check-fixture-rng.py` (Task 14).
5. **Plaintext surviving in a signed field, or a required metadata block disappearing.** Expected: the marker property test passes across every guard evidence producer, the metadata merge and OCSF; an unregistered Chio-internal metadata key refuses signing; only caller and hook keys are dropped. Pinned by Task 5 and Task 8.
6. **A regenerated fixture that changed more than the committed fields.** Expected: the changed values are the committed members, signatures, receipt ids and digests traced to them, and the consumer artifacts whose member changes the consumer table names. Pinned by the extended fixture diff aid (Task 18).
7. **A committed-receipt type that decodes padding, duplicates or a lossy shape on a production path.** Expected: every type in `COMMITTED_RECEIPT_STRICT_TYPES` refuses padding at every level and padded tagged variants through `T::deserialize`, `from_str`, `from_value` and its public decoders, and re-encodes losslessly; every production raw decode of those types goes through `UntrustedJsonText::decode_signed` (opening documents through `decode_document`), which refuses duplicate keys at every depth and keeps full-width integers. Direct `T::deserialize` over raw bytes is not claimed to refuse nested duplicates; the gate keeps it off production paths. Pinned by `committed_receipt_types_refuse_padding_and_lossy_decode` (Task 6), P-e's `raw_duplicate_keys_refused_by_decode_signed` and `scripts/check-committed-receipt-raw-decode.py` (Task 5b).
8. **A raw tenant or plan identifier in a signed metadata projection.** Expected: the `active_defense` and `response_simulation` projections carry digests, enums, timestamps, counters and salted commitments, and no raw `TenantId`, `ActionId`, finding id, submitter or affected id. Pinned by `security_projections_carry_no_raw_identifiers` and the marker property test over those producers (Tasks 5 and 8).

---

## File Structure

| Path | PR | Task | Responsibility |
|---|---|---|---|
| `crates/core/chio-core-types/src/rng.rs` (new; moved from `chio-kernel-core/src/rng.rs`) | P-a | 2 | `Rng` with fallible `fill_bytes`, `RngError` |
| `crates/kernel/chio-kernel/src/rng.rs` (new) | P-a | 2 | `OsEntropyRng` |
| `crates/tooling/chio-fixture-rng/` (new crate, `publish = false`) | P-a | 2 | `FixtureRng` (ChaCha20, `rand_chacha`) |
| `crates/core/chio-core-types/src/receipt/disclosure.rs` (new) | P-b | 3 | `Salt`, `CommitmentAlg`, `ReceiptCommitment`, `CommitmentDomain`, `ContentPreimage`, `commit`, `ReceiptDisclosure`, `Opening`, `open_receipt`, `OpeningReport`, `OpeningState` |
| `sdks/typescript/chio-ts`, `sdks/python/chio-py`, `sdks/go/chio-go` `invariants/disclosure.*` (new) | P-b | 3 | SDK openers |
| `spec/schemas/chio-wire/v1/receipt/receipt-disclosure.schema.json` (new) | P-b | 3 | unsigned opening document |
| `crates/kernel/chio-kernel/src/receipt_store.rs`, `crates/platform/chio-store-sqlite/src/receipt_store/**` (new `receipt_openings` table), `crates/platform/chio-control-plane/src/trust_control/service_runtime/remote_stores.rs` and the trust-control append route | P-c | 4 | openings in the append transaction, local and remote; `OpeningState` reads; erase tombstones |
| `crates/kernel/chio-kernel-core/src/guard.rs`, `crates/kernel/chio-kernel/src/kernel/mod.rs`, every `Guard` impl (111, 65 non-test at `fcc31d25fb`), `chio-wasm-guards` `WasmGuard`, `chio-external-guards` `ExternalGuard` and `ScopedAsyncGuard` | P-d | 5 | `evidence_declaration` |
| `crates/core/chio-core-types/src/receipt/metadata.rs` (key registry), `crates/kernel/chio-kernel/src/receipt_support/receipt_metadata.rs`, `spec/PROTOCOL.md` 6.4 key table | P-d | 5 | ADR-0019 item 7 registry with committed-disclosure declarations |
| `crates/core/chio-core-types/src/receipt/{body,decision,kinds,metadata,signing}.rs`, `spec/schemas/chio-wire/v1/receipt/record.schema.json` (moved in), registry, manifest, generated code, `spec/errors/registry.yaml` | F | 6 | committed body; `RedactionMode` deleted |
| `crates/kernel/chio-kernel-core/src/receipts.rs`, `kani_public_harnesses.rs` | F | 6 | committed portable signer |
| `crates/kernel/chio-kernel/src/**` (producers and the internal consumers in the Task 1 table), `crates/platform/chio-store-sqlite/src/**` (receipt and admission rows) | F | 7 | kernel salt wiring; store-internal bindings |
| `crates/kernel/chio-kernel-browser`, `chio-kernel-mobile`, `crates/sdk/chio-cpp-kernel-ffi`, `sdks/typescript/packages/{workers,edge,deno}`, `sdks/swift` | F | 9 | preimage-taking relays |
| `crates/security/chio-cage`, `crates/platform/chio-control-plane/src/{keyring_runtime.rs,security/**,trust_control/{config_and_public,finding_verified_fix}.rs}`, `crates/kernel/chio-kernel/src/response_simulation_report.rs`, `crates/observability/chio-lineage` | F | 10 | security and control-plane producers and their readers |
| `crates/trust/chio-selective-disclosure/src/lib.rs` | F | 10 | BBS signer and projection |
| `crates/protocol/chio-acp-proxy` | F | 11 | ACP preimages |
| `crates/platform/chio-http-core`, `crates/products/chio-api-protect`, `crates/protocol/chio-tower`, `crates/tooling/chio-bundle-verify` (after 6a), store retained-read and export metadata, `spec/schemas/chio-http/v1/evaluate-response.schema.json`, HTTP middleware SDKs, `examples/hello-*/smoke.sh` | F | 12 | `HttpReceipt` deleted |
| group 5 producers and harnesses | F | 13, 14 | std and fixture producers |
| cross-artifact consumers (federation, attest, credit, settle, web3, open-market, enterprise-export, agent-web, commerce-order, finding market, mcp-remote, runtime-harness) | F | 16 | consumer bindings |
| `crates/observability/chio-siem`, verdict-matrix driver, store query readers | F | 15 | readers |
| SDK receipt verifiers | F | 17 | commitments, openings, closed decode |
| `tests/bindings/vectors/receipt/committed/v1.json`, `scripts/gen-signing-wrapper-vectors.py` | F | 17 | cross-check, padding and HTTP preimage vectors |
| `xtask/src/signed_fixtures.rs`, `scripts/check-fixture-rng.py` (new) | F | 14, 18 | regeneration, release-graph gate |
| `spec/PROTOCOL.md` 6, `spec/HTTP-SUBSTRATE.md`, `spec/OPENAPI-INTEGRATION.md`, `spec/WIRE_PROTOCOL.md`, docs | F | 19 | contract text |
| `docs/formal/COVERAGE.md`, Kani manifest and harnesses | each PR | 20 | formal touchpoints |

## Commit Grouping

Precursors are ordinary PRs with conventional commits. F is one branch `feat/m1-committed-receipts`, one PR, squash-merged, commits in this order (trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`). A "producer" is one signing entry point that owns a salt source: one row of the producer table in Task 1.

| # | Group | Commit | Task |
|---|---|---|---|
| 1 | 1 | `feat(core-types): committed receipt body and the record schema move-in` | 6 |
| 2 | 1 | `feat(kernel-core): sign committed receipts from preimages and delete the trusted-body relay` | 6 |
| 3 | 2 | `feat(kernel): draw receipt salts from the OS RNG in the hosted kernel and persist openings with the append` | 7 |
| 4 | 2 | `refactor(kernel): bind admission, recovery and delivery to commitment values and store-internal digests` | 7 |
| 5 | 2 | `feat(kernel): drop undeclared guard evidence and caller metadata; refuse unregistered internal keys` | 8 |
| 6 | 2 | `feat(secret-broker): sign broker-hosted kernel receipts with OS RNG salts` | 7 |
| 7 | 3 | `feat(kernel-browser): sign committed receipts from preimages with Web Crypto salts` | 9 |
| 8 | 3 | `feat(kernel-mobile): sign committed receipts from preimages with OS RNG salts` | 9 |
| 9 | 3 | `feat(cpp-kernel-ffi): sign committed receipts from preimages with OS RNG salts` | 9 |
| 10 | 4 | `feat(cage): draw cage receipt salts from the host RNG and persist openings with cage evidence` | 10 |
| 11 | 4 | `feat(control-plane): commit keyring enterprise receipt projections` | 10 |
| 12 | 4 | `feat(control-plane): commit native active-defense evidence receipts; readers bind to the signed body` | 10 |
| 13 | 4 | `feat(control-plane): commit response simulation receipts; readers bind to the signed report` | 10 |
| 14 | 4 | `feat(control-plane): commit SCIM deprovision receipts` | 10 |
| 15 | 4 | `feat(control-plane): pass verified-fix evidence preimages to the receipt signer` | 10 |
| 16 | 4 | `feat(selective-disclosure): sign committed receipts with BBS over the committed projection` | 10 |
| 17 | 4 | `feat(acp-proxy): pass ACP session update preimages to the receipt signer` | 11 |
| 18 | 4 | `feat(http-core): sign chio.receipt.v1 for HTTP calls and delete HttpReceipt` | 12 |
| 19 | 4 | `feat(api-protect): sign committed sidecar receipts with OS RNG salts` | 12 |
| 20 | 4 | `refactor(tower): read chio.receipt.v1 from the HTTP authority` | 12 |
| 21 | 4 | `feat(sdks): HTTP middleware carries chio.receipt.v1` (Python, JVM, .NET, TS, Go, examples) | 12 |
| 22 | 5 | `feat(otel-exporter): commit span receipts with OS RNG salts` | 13 |
| 23 | 5 | `feat(cli): commit chio run evidence and swarm bootstrap receipts and persist their openings` | 13 |
| 24 | 5 | `feat(mercury): commit step receipts with OS RNG salts` | 13 |
| 25 | 5 | `feat(wall): commit wall receipts with OS RNG salts` | 13 |
| 26 | 5 | `test(runtime-harness): take the caller's Rng for treaty proof receipts` | 14 |
| 27 | 5 | `test(cli): seed proof fixture receipt salts and re-sign from recorded preimages` | 14 |
| 28 | 5 | `test(conformance): take the caller's Rng for native suite receipts` | 14 |
| 29 | 5 | `test(attest-loopback): take the caller's Rng for loopback receipts` | 14 |
| 30 | 5 | `refactor: read commitments in SIEM, lineage, store queries and the verdict-matrix driver` | 15 |
| 31 | 5 | `refactor: bind cross-artifact receipt consumers to commitment values or persisted openings` | 16 |
| 32 | 5 | `test(vectors): cross-check committed receipt vectors and add padding and HTTP preimage negatives` | 17 |
| 33 | 5 | `feat(sdk): verify committed receipts and openings in every SDK` | 17 |
| 34 | 5 | `test: regenerate signed fixtures for committed receipts` | 18 |
| 35 | 5 | `docs(spec): specify committed receipts in PROTOCOL 6` | 19 |
| 36 | 5 | `chore(formal): refresh proof coverage` | 20 (last, after the final rebase) |

A diff touching `.github/workflows/` is handed to the lead to push from the Mac (ws2 has no workflow scope).

---

### Task 1: Base, census and coordination (before each PR)

**Files:** none changed. Output goes to `ws2:~/lanes/claude-pr1160-evidence/m1i2/census-<pr>-<base>.md`.

- [ ] **Step 1: Preconditions.** `gh pr view <N> --repo bb-connor/arc --json state` reports `MERGED` for every predecessor in the merge order. If any is open, the lane waits; it does not reorder. Create the worktree at that base: `git -C /home/connor/backbay/arc fetch -q https://github.com/bb-connor/arc.git main:refs/remotes/origin/main && git -C /home/connor/backbay/arc worktree add -b <branch> ~/lanes/m1i2-<pr> origin/main`.
- [ ] **Step 2: Producer census.** The inventory's Method greps with the corrected signer regex, which matches every receipt signer spelling including handle and BBS variants and aliases:
```bash
git grep -n -E "sign_receipt(_with_handle|_relaying_trusted_body)?\(|ChioReceipt::sign[A-Za-z_]*\(|\.sign_prepared_with_bbs[A-Za-z_]*\(|sign_chio_receipt_with_bbs\(|build_and_sign_receipt\(|core_sign_receipt|core_relay_trusted_body|HttpReceipt::sign" -- crates sdks ':!**/tests/**' ':!*_tests.rs'
git grep -n -E "use [a-z_:]*(sign_receipt|ChioReceipt)[a-z_]* as " -- crates sdks
git grep -n -E "pub fn [a-z_]*sign[a-z_]*\(" -- crates | grep -i receipt
```
  The last grep lists every public function with `sign` and `receipt` in its name; each hit is either a producer row or recorded as not a `chio.receipt.v1` signer. Expected at `a93a2f69a3`: the inventory's 54 call sites plus `chio-selective-disclosure` `sign_chio_receipt_with_bbs` (through `ChioReceipt::sign_prepared_with_bbs_using_handle`), which the inventory regex missed.
- [ ] **Step 3: Consumer census (script and committed output).** `docs/superpowers/plans/m1-item2-census/census.py` lists every line under `crates`, `sdks` and `xtask` that matches one of three line patterns: the receipt hashes and their helpers (`action\.parameter_hash|\.content_hash\b|ToolCallAction::from_parameters|verify_hash\(`), the hash member names (`"content_hash"|"parameter_hash"`), and the plaintext parameter readers (`action\.parameters\b`); plus three whole-file patterns: receipt tenant readers (`\b\w*(receipt|body|signed|launch|terminal)\s*(\(\))?\s*\.\s*tenant_id\b` over Rust and `.inc` files, so rustfmt-split chains are caught), rustfmt-split chains (`\baction\s*\n\s*\.(parameters|parameter_hash)\b` over Rust files, recorded at the `.parameters` line) and JSON indexing (`["action"]` or `action` followed by `["parameters"]`, `["parameter_hash"]` or `.get("parameters")`, over `sdks` and `crates`). It marks each line test or production (test paths and `#[cfg(test)]` modules), applies the first matching rule of `rules.tsv` (path regex, line regex, kind, replacement source), writes `census-<rev>.tsv`, and fails closed (Root-2 r6): it verifies `<rev>` is a commit, treats any git failure other than an empty grep as exit 2, and exits 1 when any production line has no rule or when the census finds no lines. `census.py --self-check <repo> <rev> <workdir>` runs it on a nonexistent revision and with an empty rule set and requires both to exit nonzero. Run: `python3 -I docs/superpowers/plans/m1-item2-census/census.py <repo> <rev> docs/superpowers/plans/m1-item2-census/rules.tsv docs/superpowers/plans/m1-item2-census/census-<rev>.tsv`.
  Committed output at `fcc31d25fb`: `census-fcc31d25fb.tsv`, 1289 lines in 491 files (tests included), of which 551 production lines in 210 files, 0 unclassified. Production lines by kind: R 63, S 50, V 45, X 44, A 42, P-ii 36, TN-D 32, GEN 30, F 29, C 27, D 17, A0 17, TN-U 15, T 15, TN-B 14, H 14, E/P-ii 10, DOC 10, TN-C 9, B 8, TN-X 6, P-i 5, E 5, P-iii 2, E-k 2, A/E 2, TN-H 1, MOVED 1. The multi-line and JSON patterns (lead r3 P1-1) added the six split-chain readers the earlier census missed (`chio-mcp-edge/src/runtime/requests.rs:490`, `chio-commerce-order/src/settlement.rs:244`, `chio-open-market/src/recovery.rs:311`, `chio-enterprise-export/src/artifacts.rs:476`, `chio-agent-web-interop/src/interop.rs:1077`, `proof/fixture_agent_web.rs:62`) and the SDK JSON readers. The tenant pattern (lead r4-delta e2 (b)) adds every reader of a receipt's `tenant_id`, including `execution_validation.inc:502,683`, `support/security_evidence.rs:60`, `cage_policy/evidence.rs:179,239`, `retained_read.rs:207,331`, `receipt_query/read.rs:225`, `session_certificate_read.rs:305,347` and `append.rs:62`. The census is complete only for these patterns; Review Focus 1 names them. Task 1 re-runs the script at each PR's base and commits the new TSV; a new unclassified production line stops the lane for a plan update.
- [ ] **Step 4: Other censuses.**
```bash
git grep -n -E "content_hash|parameter_hash|RedactionMode|redaction_mode" -- crates sdks xtask ':!**/_generated/**'
git grep -n -E "HttpReceipt|http_receipt|httpReceipt|http-receipt|caller_identity_hash" -- . ':!docs/superpowers'
git grep -n -E "impl[^{]*Guard for" -- crates sdks
git grep -n -E "NullRng|fill_bytes|impl [A-Za-z_:<>]*Rng for" -- crates sdks
git grep -n -E "ChioKernel::new|build_kernel|set_receipt_store" -- crates
git grep -n -E "\"[a-z_]+\"" -- crates/kernel/chio-kernel/src/receipt_support/receipt_metadata.rs crates/core/chio-core-types/src/receipt/metadata.rs
git grep -l -E '"content_hash"|"parameter_hash"|"redaction_mode"' -- '*.json' '*.ndjson' '*.jsonl'
```
  Expected: `HttpReceipt` and its spellings in 103 files (417 lines); 111 `Guard` impls (65 non-test); 421 kernel construction sites; 893 JSON fixtures with `content_hash` (861 under `fixtures/proof-room/`); 189 Rust test files naming `content_hash`. The metadata census lists every key read by non-test code (at least 25 at `fcc31d25fb`, including `receipt_context`, `financial`, `chio_runtime`, `admission_operation`, `caller_delivery`, `budget_authority`, `post_invocation`, `lineage`, `parent_receipt_ids`, `route_selection`, `security_event_projection`, `mercury`, `active_defense_body`, `delivery_contract`, `execution_nonce_id`) with its writer and its readers, including the admission, active-response and settlement paths (Root-2 condition 5).

**Producer table** (Step 2 output; starting rows from the inventory):

| Producer | Call sites | Salt source | Openings | Preimages |
|---|---|---|---|---|
| Portable signer (`chio-kernel-core`) | `sign_receipt`, `sign_receipt_with_handle` | host-supplied `Rng` | returned in `SignedReceipt` | passed in |
| Hosted kernel (`chio-kernel`; also `serve-http`, `chio mcp serve`, `api protect` mediated kernel, the secret broker's hosted kernel) | the 20 kernel rows of the inventory | `OsEntropyRng` injected at construction | persisted with the append (SQLite or trust-control) | request arguments; `ReceiptSigningHandle` content |
| Browser WASM | `pure.rs`, `wasm.rs`, TS workers, edge, deno | `WebCryptoRng` | returned to JS | passed in |
| Mobile | `lib.rs`, UDL, Swift | `MobileRng` | returned to the host | passed in |
| C ABI | `chio-cpp-kernel-ffi` | `OsEntropyRng` inside the library | returned to the caller | passed in |
| Cage | `prepare_cage_receipt` | host `Rng` | written beside the cage evidence (consumer kind E) | in scope |
| Keyring projection | `keyring_runtime.rs` | `OsEntropyRng` | dropped (no downstream content check) | the signed key enterprise receipt |
| Native evidence | `native_evidence.rs` | `OsEntropyRng` | dropped; readers bind to the signed body (kind F) | the active-defense body |
| Response simulation | `response_simulation.rs` | `OsEntropyRng` | dropped; readers bind to the signed report (kind F) | the simulation report |
| SCIM deprovision | `config_and_public.rs` | `OsEntropyRng` | dropped (no downstream content check) | request and result |
| Verified-fix evidence | `finding_verified_fix.rs` | `OsEntropyRng` | persisted in the trust-control store (kind E) | the evidence body |
| BBS selective disclosure | `chio-selective-disclosure` `sign_chio_receipt_with_bbs` | caller `Rng` | returned to the caller | passed in |
| ACP proxy | `interceptor.rs` (two), `kernel_signer.rs` | `OsEntropyRng` | dropped (telemetry and compliance read commitment values only) | session update and audit entry body |
| HTTP authority (`chio-http-core`) | `authority.rs` (four construction sites) | `OsEntropyRng` | persisted by `api protect` mediated mode with its receipt store; otherwise dropped | canonical HTTP request and response |
| `api protect` sidecar | `sidecar.rs` | `OsEntropyRng` | as the HTTP authority row | in scope |
| OTel exporter | `sink.rs` | `OsEntropyRng` | dropped | sanitized span attributes |
| `chio run` | four sites, one producer | `OsEntropyRng` | written with the evidence export (kind E) | in scope |
| Mercury, Wall | `builders.rs`, `commands.rs` | `OsEntropyRng` | dropped | in scope |
| Runtime harness, conformance native suite, attest loopback | `treaty.rs`, `native_suite.rs`, `lib.rs`, `package.rs` | the caller's `Rng` (`OsEntropyRng` in release commands; `FixtureRng` in tests and generators) | returned | in scope |
| Proof fixtures | `fixture.rs` (two), `fixture_agent_web.rs` | `FixtureRng` (generator only) | fixture material | recorded preimages |

The Lambda extension emits an unsigned detect-only `EvaluateResponse` with no receipt body, hash or arguments, so it is not a producer; Task 13 pins that.

**Consumer kinds** (each production line of the census carries exactly one; `rules.tsv` names the replacement source per site):

| Kind | Rule | Production sites (census) |
|---|---|---|
| R. Producer site | Builds a receipt. Becomes a `ReceiptDraft` plus `ReceiptPreimages`, signed with its producer's `Rng` (producer table). | 62 lines: kernel responses, terminal receipts, session ops, drop guard, reconciliation, receipt persistence; control-plane, cage, ACP, HTTP authority, OTel, Mercury, Wall, `chio run`, fixtures, harness, conformance, attest loopback |
| X. Signer internals | Core and kernel signing internals, relay doc comments. Replaced by the committed signer. | 44 lines in `chio-core-types` receipt modules, `chio-kernel-core`, kernel signing, browser, mobile and C ABI docs, `chio-http-core/src/receipt.rs` (deleted) |
| A. Store-internal binding | The kernel or store row keeps its own digest of material it already retains (the operation binding's request digest, the retained output blob digest) and records the receipt's `parameter_commitment.value` and `content_commitment.value` in the same transaction that durably admits or terminates the operation. Replay and recovery compare receipt to row by commitment equality and blob to row by the row's digest; when `opening_status` is `Present` they also recompute the content commitment over the blob, so the signed receipt still covers the blob link (P2-C). They never require an opening, so erasure cannot wedge them. Row digests stay inside the store, which already retains the request and output. | 41 lines: admission projection, authorization consumer check (Root-held), refusal, remote projection, terminal, compacted replay, admission terminal receipt, effect obligation, coupling, store columns (`chio_tool_receipts`, query snapshot, read boundary, evidence retention) |
| A0. Request digest helper | `ToolCallAction::from_parameters` used only to hash request arguments for a non-receipt binding. Replaced by `canonical_parameter_digest(&Value)`. The digest leaves the store in three signed artifacts (execution nonce `NonceBinding.parameter_hash`, treaty `request_sha256`, caller delivery `parameters_digest`); every holder of each already holds the arguments (the tool server, the treaty peer, the caller), so it adds no oracle (P2-D). | 17 lines |
| B. At-signing check | Runs in the signing process with the preimage in hand and the salts from `SignedReceipt.openings`. | 8 lines: nonce admission and reconciliation, treaty request binding, `authoritative_spend` (offline parameter check deleted, OQ8), `chio-tee` runner |
| C. Copy the commitment value | A later artifact copies the commitment value in a renamed member and compares by equality (D17 item 2). | 27 lines: treaty outcome, federation DSSE and cosign, attest loopback and buyer report, IOU receivable, settlement observation (#1705), lineage column, runtime-harness buyer closure and proof parity, verified-fix nonce, `chio run` nonce evidence, BBS projection slot, `DeliveryAcknowledgement.result_hash` (becomes `result_commitment`) |
| D. Unrelated | Merkle `verify_hash`, HTTP request body digest, ACP audit entry digest, approval parameter hashes. Unchanged. | 17 lines |
| E. Open with a carried opening | The carrier holds the commitment's complete preimage in plaintext and carries a salt-only opening for that one `salt_ref` (OQ9). The verifier rebuilds the preimage from the carrier and opens; an absent opening fails with `OpeningUnavailable`. In each of these flows the carrier already holds an unsalted digest of the same content, so the content commitment hides nothing new there. | 5 lines: commerce replay and settlement (event bytes in the bundle), settle and web3 anchor proofs (preimage rebuilt from public parts by `settlement_anchor_receipt_content_hash_parts`; the anchor proof gains `content_opening`), session response |
| E-k. Kernel opens with its store's opening | The kernel opens a receipt's commitment with the opening from its local store or, when its receipt store is remote (`--control-url`), through the internal `POST /v1/internal/receipts/openings/read` route with the `receipt-openings:read` scope (Task 4). An `Erased` or `Unknown` state, or a refused read, fails with `ReceiptOpeningUnavailable`. | 2 lines: `allow_responses.rs:547,879` (finding memory write: the parent's content commitment opens over the written content; `contract.expected_digest` stays an unsalted internal digest compared with `written_content_digest`); tests `finding_memory_write_refuses_erased_parent_opening`, `remote_store_finding_memory_write_opens_via_internal_read`, `remote_store_finding_memory_write_refuses_without_scope` |
| A/E. Credential row arguments plus the store's opening | `chio-mcp-remote` completed result. Parameters: the session credential call row holds the call's own arguments from call creation, before any receipt exists (an independent source; today it holds only their digest, so F stores the arguments in the row, which already lives beside the session's retained request), and the check opens the receipt's `params` commitment over them. Output: the delivered output opens the content commitment. Both openings come from the in-process kernel's `SignedReceipt` when it is still held, else from the local store or the internal read route (`/v1/internal/receipts/openings/read`) under `--control-url`. A refused read, `Erased` or `Unknown` fails with `OpeningUnavailable`. | 2 lines: `completed_result.rs:133,154`; tests `completed_result_binds_params_to_call_arguments`, `completed_result_refuses_receipt_for_other_arguments`, `completed_result_refuses_erased_opening`, `completed_result_opens_via_internal_read_under_control_url`, `completed_result_refuses_internal_read_without_scope` |
| E/P-ii. Carrier with parameter rebuild | As E for content; for parameters the verifier rebuilds the exact canonical parameter object from carrier fields and opens with a carried `params` opening. Preimage forms per site: enterprise export content is the artifact bytes as `{"kind":"bytes","b64u":..}` (a JSON value the producer wraps), parameters `{artifact_ref, artifact_sha256, event_id}`; agent-web content is the subject bytes in the same wrapped form, parameters rebuilt from the envelope; finding pool ledger rebuilds both from ledger data and reads the opening from the same store; `process_response_verify` holds request and output and opens with the `chio run` export's openings; commerce settlement (`settlement.rs:244`) reads the dispatch fields from the replayed dispatch event in the bundle and opens with the artifact's `params_opening`. | 10 lines |
| F. Bind to a signed Chio-internal projection or contract | The reader binds to a signed metadata block that carries no argument or result value: the `active_defense`, `response_simulation` and `security_event` projections (Task 5), the finding-delivery `delivery_contract` digests (finding verifier, challenge standing and replay contradiction, open-market recovery, purchase routes), or the audited `cage_receipt`. The retraction resolver binds to the PARENT delivery receipt's `delivery_contract.observed_digest`, reached through the child's signed parent link; the child's own contract, when present, describes the memory-write tool's result, not the written content (test `retraction_lineage_uses_parent_delivery_digest`). | 29 lines |
| P-i. Parameter value from kernel or registered state | The reader extracts a value from `action.parameters`. It reads the value instead from the kernel's own row or a signed Chio-internal metadata field that carries no argument value. | 5 lines: `authorization.rs:64` (Root-held; every value read through that binding comes from the authorization operation's admission row and is compared with `consumption`: `operation_payload` digest from the row binding, `session_id` and `tool_call_id` from the row's session and tool-call columns, `authorization_parameter_hash` from the row's request digest; tests `authorization_projection_reads_{payload_digest,session_id,tool_call_id,parameter_digest}_from_row`), `delivery_preparation.rs:37` (Root-held; launch state from the signed `cage_receipt.enforcement_record.state`, which the launch receipt already carries, so no new key), `finding_purchase_routes.rs:295` (`finding_id` from the existing `finding_delivery` metadata key), `proof/fixture_agent_web.rs:62` (`agent_web_receipt_ref` from the fixture index or metadata; the parameter fallback is deleted), ACP `kernel_signer.rs:240` (authorization parameters from the proxy's own authorization request record) |
| P-ii. Parameter value from a rebuilt object | The verifier holds or rebuilds the exact canonical parameter object, opens the `params` commitment with a persisted or carried opening, then reads values from the object it holds. | 36 lines: `chio run` process-host evidence (the export holds the evidence object and writes its openings), Mercury proof package, attest loopback runtime validation, settle finding enforcement, finding challenge replay contradiction, `chio-mini-swe` repository proof |
| P-iii. Deleted as redundant | The read duplicates a value already in scope. | 2 lines: `chio-mcp-edge/src/runtime/requests.rs:490` (the deny log line reads the request's own `uri`, which is in scope), `chio-open-market/src/recovery.rs:311` (redundant with `delivery.finding_id`, checked at line 321) |
| V. `verify_hash()` caller | Deleted: the parameter commitment is signed and has no unsalted hash to recheck. The caller keeps its signature check; report fields named `parameter_hash_valid` are deleted. | 45 lines |
| H. Format or projection reader | Reads the commitment value instead. | 14 lines: SIEM, sidecar, http-core evaluation, ACP telemetry and bounds, tower, verdict-matrix driver, dashboard |
| S. SDK | SDK verifier, middleware or adapter reads commitments and openings (Tasks 12, 17). | 50 lines |
| TN-C. Tenant from the verified store column | A generic tenant-scoped store read. It reads the store's tenant column, which append wrote from `SignedReceipt.tenant` and verified against whichever signed tenant form the receipt carries. | 9 lines: `append.rs:62`, `retained_read.rs:207,331`, `receipt_query/read.rs:225`, `receipt_query_snapshot/{fetch.rs:90,project.rs:101}`, `session_certificate_read.rs:305,347`, `read_boundary/projection.rs:76` |
| TN-B. Verify the signed binding | A reader of a moved producer's receipt (native evidence, response simulation, security event, cage). It verifies the signed `tenant_binding` against its expected plaintext tenant with `TenantIndexKeySet::verify`; an absent binding or unknown `key_id` refuses. `cage_policy/evidence.rs:179,239` (lead r5 N1): the policy side is `CageReceiptRuntimePolicy`, whose `tenant_id` stays plaintext, so the check is `verify(policy.tenant_id, receipt.tenant_binding)`; a policy with no tenant requires a launch or terminal receipt with neither tenant form, and a binding or `tenant_id` present there refuses (tests `cage_policy_tenant_binding_matches`, `..._mismatch_refuses`, `..._no_tenant_neither_form_accepts`, `..._no_tenant_binding_present_refuses`). It never compares `Option` to `Option`, so `None == None` cannot pass. | 14 lines: `execution_validation.inc:502,683`, `ingest_active_defense.rs:189`, `native_evidence.rs:605`, `event_consumer/verification.rs:161,324`, `support/security_evidence.rs:60`, `declassification_codec.rs:115,144,175`, `active_defense_migration.rs:1084`, `cage_policy/evidence.rs:179,239`, `chio-cage/src/receipt.rs:378` |
| TN-U. Ordinary producer tenant | The receipt's producer keeps the signed `tenant_id`; unchanged. | 15 lines |
| TN-X, TN-H, TN-D | Body plumbing and projections that carry whichever tenant form is signed; tenant of non-receipt bodies (unchanged). | 6, 1, 32 lines |
| GEN, DOC, T | Regenerated code, docs, and test modules the path heuristic misses. `evidence_export/verification.rs` lines are kind V and are applied in `chio-bundle-verify`, where 6a moved the file. | 30, 10, 14 lines |

Test-only sites (`from_parameters` in tests, fixtures inside test modules) move to a test helper `chio_core_types::receipt::testing::draft_for(params)` behind `#[cfg(any(test, feature = "test-support"))]`.

- [ ] **Step 5: D17 check (before F).** Post the "D17 Coordination" list to `sync.md` as `<UTC> <lane>: D17 m1i2 byte changes: <list>; holding PR open until lead and Root-2 ACK`. Record the merge SHA of every predecessor.

---

### Task 2: P-a, the `Rng` seam (byte-neutral)

**Files:** create `crates/core/chio-core-types/src/rng.rs`, `crates/kernel/chio-kernel/src/rng.rs`, `crates/tooling/chio-fixture-rng/{Cargo.toml,src/lib.rs}`; delete `crates/kernel/chio-kernel-core/src/rng.rs`; modify every `Rng` impl and import (`chio-kernel-browser`, `chio-kernel-mobile`, `chio-kernel-core`, `chio-kernel` `session_ops.rs`), workspace `Cargo.toml` members.

**Interfaces:**

```rust
// chio-core-types/src/rng.rs
pub trait Rng {
    /// Fills `dest` with cryptographically secure random bytes or fails. No implementation
    /// zero-fills on failure.
    fn fill_bytes(&self, dest: &mut [u8]) -> core::result::Result<(), RngError>;
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RngError(pub &'static str);
impl<T: Rng + ?Sized> Rng for &T { /* forwards */ }

// chio-kernel/src/rng.rs
/// OS CSPRNG through `getrandom`. The `Rng` every std producer injects in release code.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropyRng;

// chio-fixture-rng (publish = false; a dev-dependency or an optional dependency only)
/// Deterministic ChaCha20 stream from a 32-byte seed. Output is fixture material only.
pub struct FixtureRng { /* interior-mutable ChaCha20Rng */ }
impl FixtureRng {
    /// `seed = SHA-256("chio.fixture-rng.v1\0" || label || 0x00 || fixture_id)`.
    pub fn for_fixture(label: &str, fixture_id: &str) -> Self;
}
```

`NullRng` is deleted (no non-test user). The browser and mobile zero-fill fallbacks and the browser's all-zero seed probe are deleted; both adapters return `RngError`. Existing callers (receipt ids, DPoP nonces, the browser seed) propagate the error as a refusal. `chio-kernel-core` does not re-export the trait.

- [ ] **Step 1: Failing tests:** `os_entropy_rng_fills`; browser and mobile `fill_failure_returns_error` (test builds with an injected failing source); `fixture_rng_is_deterministic_per_fixture`.
- [ ] **Step 2: Implement, run** `cs cargo test -p chio-core-types -p chio-kernel-core -p chio-kernel -p chio-kernel-browser -p chio-kernel-mobile -p chio-fixture-rng --no-fail-fast`, `cs wasm-pack test --node crates/kernel/chio-kernel-browser`, clippy for each, and `cs cargo xtask gen signed-fixtures --check` (expected: no change). Expected: PASS.

---

### Task 3: P-b, commitment and disclosure types with openers (additive)

**Files:** create `crates/core/chio-core-types/src/receipt/disclosure.rs`, `tests/receipt_disclosure.rs`, `spec/schemas/chio-wire/v1/receipt/receipt-disclosure.schema.json`, SDK `invariants/disclosure.*` in TS, Python and Go with tests; modify `src/receipt/mod.rs`, `spec/schemas/registry.json`, `MANIFEST.sha256`, generated code.

**Interfaces:**

```rust
use crate::root_authority::wire::SaltRef; // #1706: open dotted string, at most 64 chars

pub const SALT_LEN: usize = 32;
pub const PARAMETERS_COMMITMENT_DOMAIN: &[u8] = b"chio.receipt.parameters.v1\0";
pub const CONTENT_COMMITMENT_DOMAIN: &[u8] = b"chio.receipt.content.v1\0";
pub const CHAIN_DIGEST_DOMAIN: &[u8] = b"chio.receipt.chain-digest.v1\0";
pub const CHIO_RECEIPT_DISCLOSURE_SCHEMA: &str = "chio.receipt-disclosure.v1";
pub const PARAMS_SALT_REF: &str = "params";
pub const CONTENT_SALT_REF: &str = "content";

/// 32 secret bytes, zeroized on drop. Debug prints `Salt(..)`. Wire form `b64u:` plus
/// unpadded base64url; a padded form or a length other than 32 rejects at decode.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Salt([u8; SALT_LEN]);
impl Salt { pub fn draw(rng: &dyn Rng) -> Result<Self>; pub fn as_bytes(&self) -> &[u8; SALT_LEN]; }

/// Closed. Serializes as `sha256-salted`.
pub enum CommitmentAlg { Sha256Salted }

/// The receipt's commitment. Its wire shape (`alg`, `value`, `salt_ref`) is fixed by spec 7.6
/// and differs from the delegation context's `SaltedCommitment` (`commit`, `salt_ref`), which
/// spec 7.3 fixes; both reuse `SaltRef` and `Sha256Digest`. Decoding checks `salt_ref` by
/// position: `params` under `action.parameter_commitment`, `content` under `content_commitment`.
#[serde(deny_unknown_fields)]
pub struct ReceiptCommitment { pub alg: CommitmentAlg, pub value: Sha256Digest, pub salt_ref: SaltRef }

pub enum CommitmentDomain { Parameters, Content, DelegationSubject, DelegationTenant, DelegationClaim }
pub fn commit(domain: CommitmentDomain, salt: &Salt, preimage: &[u8]) -> Sha256Digest;

/// G13. `Stream` holds each canonical chunk's SHA-256; an empty `Stream` encodes as `Empty`.
pub enum ContentPreimage<'a> { Value(&'a serde_json::Value), Empty, Stream(&'a [[u8; 32]]) }
impl ContentPreimage<'_> { pub fn to_bytes(&self) -> Result<Vec<u8>>; }

/// `chio.receipt-disclosure.v1`, unsigned. `receipt_id` is bare lowercase hex (G14).
#[serde(deny_unknown_fields)]
pub struct ReceiptDisclosure { pub schema: DisclosureSchema, pub receipt_id: String, pub openings: Vec<Opening> }
/// `payload` is opaque. `None` serializes as `null` (a salt-only opening).
#[serde(deny_unknown_fields)]
pub struct Opening { pub salt_ref: SaltRef, pub salt: Salt, pub payload: Option<serde_json::Value> }

pub enum FieldVerdict { Verified, Rejected, Unverifiable }
pub struct OpeningReport { pub parameters: FieldVerdict, pub content: FieldVerdict, pub disclosure_valid: bool }

/// The persisted state of one receipt's openings (Task 4).
pub enum OpeningState { Present(ReceiptOpenings), Erased { erased_at: u64 }, Unknown }
/// Salt-free status, the only form the public status route and logs carry.
pub enum OpeningStatus { Present, Erased { erased_at: u64 }, Unknown }
/// What a reader may see: the `salt_ref`s it needs and the tenant binding it is scoped to.
pub struct OpeningReadScope { pub salt_refs: Vec<SaltRef>, pub tenant_binding: Option<TenantBinding> }
pub struct OpeningUnavailable { pub receipt_id: String, pub state: OpeningStateKind }

/// The caller supplies its own arguments and output; `payload` never supplies a content
/// preimage. A salt shared by two `salt_ref`s, a malformed salt, a duplicate `salt_ref` or a
/// `receipt_id` that is not the receipt's id marks `disclosure_valid = false` and every field
/// `Rejected` (G15). Generic over the receipt's two commitment values so it lands before the
/// receipt body changes.
pub fn open_commitments(receipt_id: &str, parameter_commitment: &ReceiptCommitment,
    content_commitment: &ReceiptCommitment, disclosure: &ReceiptDisclosure,
    own_parameters: Option<&serde_json::Value>, own_output: Option<ContentPreimage<'_>>) -> OpeningReport;
```

Payload forms (P2-4): a parameters opening's `payload` is the arguments value. A content opening's `payload` exists only for a value output and is the canonical result (spec 7.7). Empty and stream outputs have salt-only content openings; a holder of such an opening derives the preimage from its own copy of the output, as for every opening. The auditor payload form for empty and stream outputs is left to `auditor_full` in M2.

Register `chio.receipt-disclosure.v1` as an unsigned artifact; the schema is `additionalProperties: false` on the document and each opening, `salt` pattern `^b64u:[A-Za-z0-9_-]{43}$`, `salt_ref` as #1706's `SaltRef` grammar, `payload` unconstrained.

- [ ] **Step 1: Failing tests** in `receipt_disclosure.rs`: `commitment_matches_layout` (domain, then salt, then preimage); `empty_output_preimage_is_zero_length`; `salt_wire_form_is_strict` (padded, 31 and 33 bytes fail); `duplicate_salt_marks_disclosure_invalid`; `padded_document_and_opening_fail_decoding`; `delegation_claim_salt_refs_are_accepted` (`anchor.claims.client_id` decodes as an opening `salt_ref`); `opener_reproduces_committed_vectors` (reads `tests/bindings/vectors/receipt/committed/v1.json` and calls `open_commitments` on each case's commitments and preimages; every `parameters`, `content` and `disclosure_valid` matches). SDK openers run the same vector file.
- [ ] **Step 2: Implement, run** `cs cargo test -p chio-core-types --no-fail-fast`, `--no-default-features --lib`, the SDK tests, `bash scripts/check-chio-schema-registry.sh`, `cs make -C ~/lanes/m1i2-pb codegen-check`, and `cs cargo xtask gen signed-fixtures --check` (no change). Expected: PASS.

---

### Task 4: P-c, the openings table, reads and erasure (additive); the atomic append in F

**Files:** `crates/kernel/chio-kernel/src/receipt_store.rs` (trait), every `ReceiptStore` impl (58 at `fcc31d25fb`, 16 non-test: `SqliteReceiptStore`, `SqliteAdmissionOperationStore`, `RemoteReceiptStore`, `RemoteAdmissionAuthority`, `chio-federation` `InMemoryReceiptStore` and the kernel, tower and broker test doubles), `crates/platform/chio-store-sqlite/src/receipt_store/{bootstrap/open.rs,append.rs,openings.rs (new)}`, `crates/platform/chio-control-plane/src/trust_control/service_runtime/remote_stores.rs`, the trust-control receipt routes, `crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs` (`sync_peer_tool_receipts`), the store's v1 catalog validation.

**Split between P-c and F (P3-2).** P-c adds the table, the read and erase methods on every impl, the trust-control read and erase routes, tombstone replication and catalog validation. It adds no append argument and no transitional path. F changes `append_chio_receipt` to take `&SignedReceipt` and writes the openings, in one change, so no dual append exists on `main` at any point.

**Design (Root-2 conditions 1 to 3 and 6; lead r2 P1-B, P1-C, P2-B, c2):**
- Openings are written inside the store-owned `ReceiptStore::append_chio_receipt` transaction, under #1708's existing fence (rank 1) and receipts (rank 2) guards. No lock, rank or callback is added, and the projection guard (rank 3) is unchanged. A successful append acknowledges the commit of the receipt and its openings together; an error does not prove non-commit, so the idempotent retry below covers the unknown-ACK case. The replay path (`receipts(true)`) reads `opening_status` and `read_openings` only outside the publication guards. There is no separate opening write, so spec 8.4's "opening marked lost" state cannot arise on a hosted path (OQ2).
- Crash before commit: neither row exists and today's append-failure path applies. Crash after commit: both rows exist. A non-admission publication path that loses its in-memory `SignedReceipt` before the ACK either committed both rows or loses the receipt exactly as today; nothing re-signs.
- Remote trust-control (`--control-url`, used by `chio mcp serve`, `chio run` and `serve-http`): F's remote append request carries the openings and trust-control writes the receipt and openings in one transaction on its own SQLite store. The client never stores openings locally. P-c adds two routes: the public `GET /v1/receipts/{id}/openings/status`, which returns only `{"state": "present" | "erased" | "unknown"}` and never a salt, and `POST /v1/receipts/{id}/openings/erase`; plus the internal opening read below.
- Cluster replication (lead r2 P1-B option (a); transport per lead r3 P1-6):
  - **Receipt deltas carry their openings (Root-2 r5, option (a)).** Each record of the receipt `seq` delta (`/v1/internal/receipts/tools/delta`, `list_tool_receipts_after_seq_with_context`) carries the receipt, its unsigned `tenant` and its complete current opening state as the source holds it when it serves the page: present salts, or tombstones if the source already erased them. The receiver imports each record through the same merge as a snapshot, writing the receipt row, its opening rows and the `peer_tool_seq` advance in one transaction, so no receipt becomes visible without its opening state, and a crash leaves either the whole record or nothing. A separate openings stream carries only later state changes: an erase allocates a monotonic `openings_seq` in the erasing transaction, each peer keeps `peer_openings_seq` beside `peer_tool_seq` in `partition.rs`, and `sync_peer_receipt_openings` pulls tombstone pages from `/v1/internal/receipts/openings/delta` and advances that cursor per page in the same transaction as the tombstones. The hosted append and every replicated import are therefore atomic per receipt; erasure reaches peers within one openings-sync interval (PROTOCOL 6 states this, lead r5 P3-3).
  - **Merge.** A tombstone always wins. A replicated tombstone for an unknown receipt id is stored (the table has no foreign key, and the replication path does not apply the client path's `ReceiptNotPublished` refusal); a later receipt or present-salt row for that id from any stream finds the tombstone and writes no salt. A present row for an id already present with identical salts is a no-op; with different salts it is recorded in a per-row `replication_quarantine` table (receipt id, salt_ref, origin node, reason) and skipped, and the page still advances, so a conflict never wedges the loop. The client retry path keeps its `ConflictingOpenings` refusal; the replication path never returns it.
  - **Snapshots.** `cluster/snapshots.rs` exports `receipt_openings` rows (present and tombstone) beside the tool receipts (`snapshots.rs:166-171`) and imports them at `snapshots.rs:365-368` through the same merge as ordinary deltas, in the same transaction as the receipt rows, so a node rebuilt from a stale snapshot applies every tombstone it carries and the next openings-stream sync delivers the rest. No receipt-only import exists.
  - **Retention (lead r5 P3-4; Root-2 r6).** Tombstones are not pruned with receipts, and no node ever compares bare local sequence numbers, because a replicated receipt gets a new local `seq` on each node (`receipt_store/append.rs:45-49`) and the same receipt can be `seq` 5 on one node and 100 on another. Every tombstone instead carries its origin: `(origin_node_id, origin_openings_seq)`, assigned once by the node that performed the erase and replicated unchanged. Each node keeps, per origin, a contiguous applied watermark `openings_applied_through[origin]`: the highest origin sequence below which it has applied every tombstone of that origin, advanced only over a gap-free prefix (tombstones that arrive out of order through a snapshot or a third node are held in a per-origin pending set until the prefix closes). Nodes report these per-origin watermarks in their signed cluster status. A node's GC horizon for an origin is the minimum of the watermarks every configured cluster member reports for that origin; configured members include offline ones, so an unreachable member counts with its last reported watermark or, if it has never reported, holds the horizon at zero. A tombstone row is deleted only when its `origin_openings_seq` is at or below that horizon and its receipt has been pruned locally; a peer that does not report keeps the horizon from advancing, which is safe and bounded only by that peer's return. Anti-resurrection evidence survives GC: each node stores its per-origin GC horizon durably, every replication source states its per-origin watermarks with each delta page and snapshot, and an import from a source whose watermark for any origin is below the importer's horizon is refused with `StaleReplicationSource`. Each stated watermark is bound to the exact payload it accompanies: it is covered by the same signature as that snapshot or delta page, and an import that applies a payload records the stated watermarks in the same transaction. The GC horizon is preserved durably across restarts and is carried in snapshots, so a node built from a snapshot imports the horizon with it and starts no lower than its source. A peer rejoining after pruning therefore cannot replay pre-erase state and must rebuild from a snapshot whose watermarks are at or above the horizon.
  - **Credential.** Peers authenticate with P-f peer credentials (one Ed25519 key per node, pinned in the cluster configuration beside `peer_urls`, scope `cluster-openings:replicate`) on the internal listener; `validate_cluster_peer_auth` checks the signature against the pinned key of the claimed `node_id`. The signed payload (`chio.cluster.peer-signature.v1`, #1729) binds the scheme, the node id, the method, the path, the raw query (which carries the cursor), `issued_at` within the freshness window, the cluster term, the SHA-256 of the request body and a single-use nonce. The receiver records each nonce for the freshness window and refuses a replayed nonce, so a captured request cannot be replayed even inside the window. The shared `service_token` HMAC no longer authenticates any cluster route.
  - **Tests:** `receipt_delta_imports_receipt_and_openings_atomically`, `receipt_delta_first_then_openings_tombstone`, `openings_tombstone_first_then_receipt_delta`, `tombstone_first_for_unknown_receipt_then_delta_writes_no_salt`, `crash_between_receipt_delta_and_openings_stream_leaves_receipt_with_full_opening_state`, `crash_inside_receipt_delta_import_leaves_nothing`, `no_receipt_visible_without_opening_state`, `erase_emits_new_openings_seq`, `erase_replicates_tombstone_to_peers`, `peer_delta_with_salts_does_not_resurrect_tombstone`, `snapshot_import_applies_tombstones`, `stale_snapshot_rebuild_does_not_resurrect_salts`, `conflicting_replicated_salts_quarantined_and_sync_advances`, `tombstone_retained_until_every_peer_acks_and_prunes`, `two_origins_with_overlapping_sequence_numbers_prune_independently`, `same_receipt_with_different_local_seq_on_two_nodes_prunes_by_origin`, `out_of_order_tombstones_hold_watermark_until_prefix_closes`, `rejoining_peer_after_gc_refused_until_fresh_snapshot`, `stale_snapshot_replay_after_gc_refused`, `client_credential_cannot_read_replicated_salts`, `peer_signature_covers_cursor_and_term`, `peer_offline_during_erase_erases_on_next_sync`.
- Durable admission: when a terminal receipt is durably admitted before publication, the admission row holds the signed receipt and its openings, so recovery republishes the exact receipt and salts (Root-2 condition 3). The admission row's salts are cleared in the transaction that records the publication acknowledgement, because recovery needs them only before it; an `erase_openings` call before that point refuses with `ReceiptStoreError::ReceiptNotPublished`.
- Idempotency: an append of a receipt id that exists with byte-identical receipt and salts is a no-op success; with different bytes or salts it refuses with `ReceiptStoreError::ConflictingOpenings`. A retry resends the same request, held in memory until ACK or recovered from the admission row. Nothing re-signs.
- Erasure: `erase_openings(receipt_id, erased_at)` replaces the salt rows with tombstones in one transaction. A missing row reads as `OpeningState::Unknown`, never as erased or lost.
- Internal opening read (Root-2 r3 and r4; lead r4-delta e2 (a) and e3): `POST /v1/internal/receipts/openings/read` on trust-control's internal listener (P-f), with body `{"receipt_id", "salt_refs": [..]}` and nothing else. Authorization comes only from the authenticated P-f caller credential, never from the request:
  - **Scope.** The credential must carry `receipt-openings:read`. The P-f registry grants it only to the kernel-hosting processes of one deployment (`serve-http`, `chio mcp serve` and `chio run` with `--control-url`) and to the control plane's security and settlement services. Evaluate, caller, admin-UI and tenant-read credentials do not carry it.
  - **Deployment.** The credential names one deployment; the receipt's `kernel_key` must be one of that deployment's kernel keys, or the read is refused.
  - **Tenant.** The credential's tenant authority is `Deployment` or `Tenant(t)`. For `Tenant(t)`, trust-control derives the tenant from the credential and checks the receipt's signed form itself: a signed `tenant_id` must equal `t`; a signed `tenant_binding` must equal `TenantIndexKeySet::bind(t)` computed server-side under the receipt's `key_id`. A binding copied from the receipt into the request is never an input, so it proves nothing (test `internal_read_refuses_binding_copied_from_receipt`). A `Deployment` credential is entitled to either form for receipts its deployment signed. A receipt carrying both forms is malformed and refused. A receipt carrying neither is untenanted and is returned only to a `Deployment` credential.
  - **Response.** `{"state":"present","openings":[..]}` (only the requested `salt_ref`s), `{"state":"erased","erased_at":..}` or `{"state":"unknown"}`, with `Cache-Control: no-store`. Every read is written to the trust-control audit log with the credential id, receipt id and `salt_ref`s, never the salts.
  - **Callers.** `RemoteReceiptStore::read_openings`; the mcp-remote output path, E-k and A/E under `--control-url`, and the settle and web3 anchor-proof producer.
- Stores without openings: every one of the 58 impls implements `opening_status`, `read_openings` and `erase_openings` explicitly (no default method). A store that keeps no openings (test doubles, `InMemoryReceiptStore`) returns `Unknown` from `opening_status` and `read_openings` and `Ok(())` from `erase_openings`, because no salt exists to erase.

**Salt copies and erasure (P1-C).** Every place a salt is stored, and whether `erase_openings` reaches it:

| Copy | Erasure |
|---|---|
| `receipt_openings` rows (local SQLite, trust-control) | tombstoned |
| cluster peers' `receipt_openings` | the erase emits a new `openings_seq`; peers pull the tombstone on the openings stream or through snapshot import; tombstones outlive receipt retention; a peer offline during the erase erases on its next sync |
| admission row (pre-publication only) | cleared at the publication acknowledgement; test `admission_row_salts_cleared_at_publication`; erase before publication refuses |
| in-memory `SignedReceipt`, retry buffers | zeroized on drop (`Salt: ZeroizeOnDrop`) |
| `chio run` disclosure documents written beside the evidence export | not reached: the export is the operator's own file once written |
| kind E carriers (commerce authority receipt artifacts, enterprise export events, agent-web envelopes, settle and web3 anchor proofs, Mercury and attest-loopback packages, finding challenge evidence) | not reached: each carrier already holds the committed preimage in plaintext, so its salt reveals nothing the carrier does not hold |
| SDK and caller copies (none in M1; `/v1/evaluate` returns no openings) | n/a |

PROTOCOL 6 (F) states that erasure makes the stored openings permanently unavailable and does not reach openings already delivered in exports or carriers. Test `erase_clears_store_and_admission_copies`.

**Interfaces:**

```rust
pub trait ReceiptStore {
    /// F: appends the receipt and its openings in one store transaction. Replaces the current
    /// receipt argument of `append_chio_receipt` and every `append_chio_receipt_*` variant.
    fn append_chio_receipt(&self, signed: &SignedReceipt) -> Result<(), ReceiptStoreError>;
    /// P-c. Required on every impl. Never returns salts.
    fn opening_status(&self, receipt_id: &str) -> Result<OpeningStatus, ReceiptStoreError>;
    /// P-c. Required on every impl. Returns salts only for the requested refs and only within
    /// `scope`; a remote store calls the internal opening read.
    fn read_openings(&self, receipt_id: &str, scope: &OpeningReadScope) -> Result<OpeningState, ReceiptStoreError>;
    /// P-c. Required on every impl.
    fn erase_openings(&self, receipt_id: &str, erased_at: u64) -> Result<(), ReceiptStoreError>;
}
```

DDL (fresh-only v1; catalog validation refuses any other layout with an exact error and mutates nothing, Root-2 condition 6):

```sql
CREATE TABLE receipt_openings (
  receipt_id TEXT NOT NULL CHECK (typeof(receipt_id) = 'text' AND instr(receipt_id, char(0)) = 0 AND length(CAST(receipt_id AS BLOB)) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
  salt_ref TEXT NOT NULL CHECK (typeof(salt_ref) = 'text' AND instr(salt_ref, char(0)) = 0 AND length(CAST(salt_ref AS BLOB)) BETWEEN 1 AND 64 AND salt_ref GLOB '[a-z]*' AND salt_ref NOT GLOB '*[^a-z0-9_.]*' AND salt_ref NOT GLOB '*..*' AND salt_ref NOT GLOB '*.'),
  state TEXT NOT NULL CHECK (typeof(state) = 'text' AND instr(state, char(0)) = 0 AND state IN ('present', 'erased')),
  salt BLOB,
  state_at INTEGER NOT NULL CHECK (typeof(state_at) = 'integer' AND state_at >= 0),
  CHECK ((state = 'present' AND typeof(salt) = 'blob' AND length(salt) = 32) OR (state = 'erased' AND salt IS NULL)),
  PRIMARY KEY (receipt_id, salt_ref)
) WITHOUT ROWID;
```

Every text key column also carries `instr(col, char(0)) = 0`, and the length checks measure bytes (`length(CAST(col AS BLOB))`), because SQLite's `length()` and `GLOB` stop at an embedded NUL, so `'params' || char(0) || 'BAD'` would otherwise pass the grammar (Root-2 r3). The state check has two explicit branches (Root-2 r2 request 1): present means `typeof(salt) = 'blob'` and `length(salt) = 32`; erased means `salt IS NULL`. The `salt` column has BLOB affinity, so SQLite performs no type conversion and a TEXT or INTEGER value reaches the check as itself. The `salt_ref` check is #1706's grammar `^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$` with at most 64 characters, written as GLOB clauses: the first character is a lowercase letter, every character is in `[a-z0-9_.]`, no empty segment (`..`) and no trailing `.`. Delegation-context claim salts (`anchor.claims.*`) fit without a later table change. The same grammar is enforced at the Rust boundary: every write takes a `SaltRef` (decoded through #1706's checked constructor) and every read decodes the column through that constructor, refusing a row that fails it with `ReceiptStoreError::CorruptOpeningRow`. Writer custody and fencing follow the existing serving writer.

The DDL was checked with `/usr/bin/sqlite3` 3.51.0 (the Mac CLI; ws2 has no sqlite3 binary), not with cargo. The probe (`docs/superpowers/plans/m1-item2-census/ddl-probe/{ddl.sql,probe.py,probe-result.json}`, run as `python3 -I probe.py /usr/bin/sqlite3 ddl.sql`; `probe-result.json` sha256 `52f9984fe5099750692ab4bf109d645418cb7ae3a8eaf023909d36b503a0a7be`) runs 28 INSERT cases and 6 UPDATE cases against a seeded present row. All 34 behaved as expected:

| Case | Expected | Observed |
|---|---|---|
| INSERT present 32-byte BLOB; erased NULL; present `anchor.claims.client_id` (controls) | accept | accept |
| INSERT erased with a 1-byte BLOB, a 32-byte BLOB or TEXT | refuse | refuse |
| INSERT present with 32-character TEXT, NULL, a 31- or 33-byte BLOB, or INTEGER | refuse | refuse |
| INSERT state `lost`; state `'erased' || char(0) || 'x'` | refuse | refuse |
| INSERT salt_ref uppercase, `..`, trailing `.`, leading digit, `-`, empty, 65 characters | refuse | refuse |
| INSERT salt_ref `'params' || char(0) || 'BAD'` and `'params' || char(0)` (Root-2 r3) | refuse | refuse |
| INSERT receipt_id uppercase hex; 63 characters | refuse | refuse |
| INSERT receipt_id 64 hex then `char(0) || 'BAD'` (Root-2 r3); 64 bytes with a NUL inside | refuse | refuse |
| INSERT state_at TEXT; negative | refuse | refuse |
| UPDATE to erased clearing the salt (control) | accept | accept |
| UPDATE to erased leaving the salt | refuse | refuse |
| UPDATE salt_ref, receipt_id or state to a value with an embedded NUL | refuse | refuse |
| UPDATE salt to 32-character TEXT | refuse | refuse |

P-c turns each row into a named Rust test in `chio-store-sqlite` that executes the same INSERT against the crate's DDL and asserts the exact `CHECK constraint failed` refusal or the stored `(state, typeof(salt), length(salt))` for the controls: `opening_row_accepts_present_blob32`, `opening_row_accepts_erased_null`, `opening_row_accepts_claim_salt_ref`, `opening_row_refuses_erased_with_blob1`, `opening_row_refuses_erased_with_blob32`, `opening_row_refuses_erased_with_text`, `opening_row_refuses_present_with_text32`, `opening_row_refuses_present_with_null`, `opening_row_refuses_present_with_blob31`, `opening_row_refuses_present_with_blob33`, `opening_row_refuses_present_with_integer`, `opening_row_refuses_lost_state`, `opening_row_refuses_state_with_nul`, one `opening_row_refuses_salt_ref_<case>` per grammar case (including `opening_row_refuses_salt_ref_with_embedded_nul` and `opening_row_refuses_salt_ref_with_trailing_nul`), `opening_row_refuses_receipt_id_<case>` (including `opening_row_refuses_receipt_id_with_trailing_nul` and `opening_row_refuses_receipt_id_with_inner_nul`), `opening_row_refuses_state_at_<case>`, and the UPDATE cases `opening_update_accepts_erase_clearing_salt`, `opening_update_refuses_erase_leaving_salt`, `opening_update_refuses_salt_ref_nul`, `opening_update_refuses_receipt_id_nul`, `opening_update_refuses_state_nul` and `opening_update_refuses_text_salt`. Erasure is an `UPDATE ... SET state = 'erased', salt = NULL`; `erase_leaving_salt_refuses` pins that an UPDATE changing only `state` fails the check.

- [ ] **Step 1: Failing tests in P-c** (SQLite, trust-control client and server, cluster): the DDL tests above; `missing_row_reads_unknown`; `erase_writes_tombstones`; `erase_route_refuses_without_token`; `status_route_never_returns_salts`; internal read: `internal_read_returns_requested_present_openings`, `internal_read_returns_erased_and_unknown_states`, `internal_read_refuses_token_without_scope`, `internal_read_refuses_evaluate_and_caller_tokens`, `internal_read_ordinary_tenant_id_succeeds`, `internal_read_tenant_binding_succeeds`, `internal_read_cross_tenant_tenant_id_refused`, `internal_read_cross_tenant_binding_refused`, `internal_read_both_tenant_forms_refused`, `internal_read_untenanted_receipt_deployment_token_succeeds`, `internal_read_untenanted_receipt_tenant_token_refused`, `internal_read_foreign_deployment_kernel_key_refused`, `internal_read_request_supplied_tenant_refused_at_decode`, `internal_read_refuses_credential_without_scope`, `internal_read_refuses_service_token`, `internal_read_matching_binding_from_other_tenant_token_refused`, `internal_read_refuses_binding_copied_from_receipt`, `internal_read_not_on_public_listener`, `internal_read_audit_log_has_no_salts`, `remote_store_read_openings_round_trip`; the cluster replication tests (lead r3 P1-6 list); `every_store_impl_answers_opening_status_and_read` (one case per non-test impl); `old_layout_refuses_without_mutation` (catalog validation of `receipt_openings`).
- [ ] **Failing tests in F** (Task 7 runs them): `append_writes_receipt_and_openings_atomically` (fault injected after the receipt row: neither row exists); `crash_after_commit_before_ack_retains_salts` (commit, drop the ACK, restart, retry: same receipt id and salts, no duplicate); `retry_with_conflicting_salts_refuses`; `erase_then_retry_keeps_tombstone`; `unknown_ack_remote_append_is_idempotent` (trust-control); `admission_row_salts_cleared_at_publication`; `erase_clears_store_and_admission_copies`; and extensions of #1708's ordering tests in `crates/kernel/chio-kernel/src/kernel/tests/receipt_publication/{concurrency,ordering,durable}.rs` that append with openings concurrently with replay and an injected append failure, asserting #1708's rank order and that replay reads openings outside the guards.
- [ ] **Step 2: Implement, run** `cs cargo test -p chio-store-sqlite -p chio-kernel -p chio-control-plane --no-fail-fast`, clippy, `cs cargo xtask gen signed-fixtures --check` (no change). Expected: PASS.

---

### Task 5: P-d, guard evidence declarations and the metadata key registry (declarations only)

**Files:** both `Guard` traits, every impl including test impls (111 at `fcc31d25fb`), `chio-wasm-guards/src/runtime/guard.rs`, `chio-external-guards/src/lib.rs` (`ExternalGuard`, `ScopedAsyncGuard`), `crates/core/chio-core-types/src/receipt/metadata.rs`, `crates/kernel/chio-kernel/src/receipt_support/receipt_metadata.rs`, `spec/PROTOCOL.md` 6.4.

**Interfaces:**

```rust
pub enum EvidenceDisclosure { /// `details` never carries argument or result values.
    Safe, Unsafe }
pub struct GuardEvidenceDeclaration { pub details: EvidenceDisclosure, pub details_required: bool }
// Required on both Guard traits and on ExternalGuard; no default method.
fn evidence_declaration(&self) -> GuardEvidenceDeclaration;
```

- `WasmGuard` declares `{ details: Unsafe, details_required: false }` for every module, because one impl covers modules whose output Chio cannot inspect. `ScopedAsyncGuard<E>` returns `E::evidence_declaration()`.
- Registration refuses `{ details: Unsafe, details_required: true }` (spec 8.4 "fails at load"). This refusal is live in P-d; no current guard declares it, which P-d's test pins.
- Operator impact (P3): a guard declared `Unsafe` loses its `details` text in receipts from F onward, for example the forbidden-path guard's matched path. The text still reaches the kernel's structured deny log and the caller's error response, which the PR body states.

Metadata key registry (ADR-0019 item 7, built here as that ADR schedules): a named-const registry in `receipt/metadata.rs`:

```rust
pub enum MetadataKeyOrigin { ChioInternal, CallerOrHook }
pub enum MetadataDisclosure {
    /// Carries no argument or result value. `reason` records the field audit.
    CommittedSafe,
    /// Carries an argument or result value; refused in signed metadata.
    Unsafe }
pub struct MetadataKeySpec { pub key: &'static str, pub origin: MetadataKeyOrigin, pub disclosure: MetadataDisclosure,
    pub schema: Option<&'static str>, pub reason: &'static str }
pub const RECEIPT_METADATA_KEYS: &[MetadataKeySpec];
pub fn metadata_key_spec(key: &str) -> Option<&'static MetadataKeySpec>;
```

Every Chio-internal key the Task 1 metadata census found is registered with its declaration, including the operational blocks admission, active response and settlement need (`admission_operation`, `budget_authority`, `financial`, `execution_nonce_id`, `delivery_contract`, `caller_delivery`, `lineage`, `parent_receipt_ids`, `route_selection`, `security_event_projection`, `receipt_context`, `chio_runtime`, `post_invocation`, `mercury`), each with a `reason` naming its field audit. No key is added for the parameter readers: `delivery_preparation.rs` reads the signed `cage_receipt.enforcement_record.state`, and `finding_purchase_routes.rs` reads the existing `finding_delivery` key (`FINDING_DELIVERY_METADATA_KEY`, `finding_id`, a public listing id). `delivery_contract` is written for every grant with `Constraint::OutputDigestSha256`, and its `observed_digest` is the unsalted digest of the actual output; F splits it: (i) for a finding-delivery grant the digests equal the finding's `payload_sha256`, which the listing already publishes, so they stay plaintext and are registered `CommittedSafe` with that reason (the finding verifier, challenge and recovery readers bind to them, kind F; open question 12); (ii) for every other grant `expected_digest` stays (the grant holder set it) and `observed_digest` becomes a salted commitment under `salt_ref` `delivery_contract.observed`, opened by the kernel's own checks with the persisted opening. `security_event_projection` carries `SecurityEventBody` (`tenant_id`, `subject`, `source_receipt_id`, `producer_id`), which is also the receipt's content preimage; it gets the same treatment as the two blocks below: a `security_event` projection with `tenant_binding` (keyed, Task 5 tenant binding) in place of `tenant_id`, `subject` as a salted commitment (`security_event.subject`), and the Chio receipt and producer ids kept; `event_consumer/verification.rs` moves from `projection.body == *body` to `matches_projection` with the persisted openings plus the content opening. A key that carries an argument or result value has no committed-safe declaration; the lead's proposed third class for Chio-internal plaintext is not needed because no registered key carries a result after the projections below. Being generated by the kernel does not make a block committed-safe (Root-2 r2 request 2). `active_defense_body` and `response_simulation_report` are each the content preimage of their receipt and carry raw tenant and plan identifiers, so neither is registered. Each is replaced by a safe projection that P-d builds and tests and F switches on (option (a) of the request).

Field audit of `active_defense_body` (`ActiveDefenseReceiptBody`, 12 variants, at `fcc31d25fb`):

| Field | Variants | Class | Projection |
|---|---|---|---|
| `header.tenant_id: TenantId` | all 12 | raw tenant id | dropped from the projection; the receipt's signed `tenant_binding` is the one tenant representation (lead r4-delta e2 (g)) |
| `header.transition_id` | all 12 | domain hash over `{kind, tenant_id, action_id, plan_hash, expected_generation, mutation}`, no secret | keyed: `HMAC-SHA256(tenant_index_key, "chio.active-defense.keyed-digest.v1\0" || transition_id)` |
| `header.prior_receipt_ids` | all 12 | receipt ids | kept (receipt ids are public by spec) |
| `header.schema_version`, `occurred_at_unix_ms` | all 12 | metadata | kept |
| `policy.policy_version`, `policy.policy_hash` | policy-bound variants and `response.policy` | policy identity | kept |
| `response.action_id: ActionId` | ResponsePlan, ResponseStateTransition, EffectTransition, ResponseCompletion, LiftRollbackCompletion, SchedulerHealth | raw plan identifier | salted commitment, `salt_ref` `active_defense.action` |
| `response.trigger_finding_id`, `response.trigger_finding_receipt_id` | same six | raw finding identifiers | salted commitments, `active_defense.finding` and `active_defense.finding_receipt` |
| `response.plan_hash`, `trigger_finding_hash`, `plan_expires_at_unix_ms` | same six | digests over kernel bodies that include high-entropy material, and time | kept; `plan_hash` and `trigger_finding_hash` are keyed as below if the P-d entropy test cannot show a random or signature-derived input |
| `response.affected_set_hash` | same six | `SHA-256(domain || canonical({tenant_id, affected_ids}))` with no secret: a dictionary oracle on tenant and subject ids | keyed as `transition_id` |
| `grant_id: GrantId` | DeclassificationConsumption, DeclassificationOutcome | raw grant identifier | salted commitment, `active_defense.grant` |
| `request_id: RequestId` | TripwireObservation | raw request identifier | salted commitment, `active_defense.request` |
| `finding_id: RecordId`, `ordered_source_receipt_ids` | CorrelatedFinding | finding id; receipt ids | finding id committed (`active_defense.finding`); receipt ids kept |
| `event_id`, `ordered_event_ids`, `lineage_seed` | most variants | Chio event and lineage ids | kept (kernel-minted, opaque) |
| `scheduler_lease_owner_id` | ResponseStateTransition, EffectTransition | internal lease owner | kept |
| every `*_hash`, `*_digests`, enum, counter, `error_code`, fencing token | all | digests, enums, counters | kept |

Field audit of `response_simulation_report` (`ResponseSimulationReport`):

| Field | Class | Projection |
|---|---|---|
| `plan` (`ResponsePlan`: `tenant_id`, `action_id`, `trigger_finding_id`, `trigger_finding_receipt_id`, `affected_ids`, `submitter`, `effects`, `operator_capability`, ...) | raw tenant, plan, subject and affected identifiers | dropped; the projection keeps `plan_hash`, `policy_hash`, `affected_set_hash`, `created_at_unix_ms`, `expires_at_unix_ms` (the tenant is carried only by the receipt's signed `tenant_binding`) |
| `snapshot` (`tenant_id`, `plan_hash`, `states`, `scopes`) | raw tenant and per-subject state | dropped; the projection keeps a keyed `snapshot_digest` and `captured_at_unix_ms` |
| `evaluation` (steps and states per phase) | per-subject outcomes | dropped; the projection keeps a keyed `evaluation_digest` |
| `schema`, `configuration_digest`, `authorization_capability_hash`, `governed_intent_hash`, `policy_decision_hash`, `approval_set_hash`, `authorized_at_unix_ms` | schema, digests, time | kept |
| `response_simulation_evidence_id` | domain hash over tenant, caller-supplied action id, `plan_hash` and configuration digest; `plan_hash` and the configuration digest are in the clear, so the only unknowns are low-entropy ids | keyed as `transition_id` |

Field audit of `cage_receipt` (`CageReceiptBody`): `schema`, `attempt_id` (cage-minted), `stage` (enum), `bindings` (digests), `admitted_policy_digest`, `enforcement_record`, `started_at_unix_ms`, `recorded_at_unix_ms`. P-d audits `CageEnforcementRecord` member by member. If it carries no process argument, path, environment value or tenant identifier, `cage_receipt` is registered `CommittedSafe` and the cage reader binds to it (kind F, no disclosure file). If it does, the cage gets a projection like `active_defense`, with the same tests. The receipt's top-level `tenant_id` from the cage signing context is dropped as for the two producers below.

Projection types, in `chio-core-types` beside `ActiveDefenseReceiptBody` and in `chio-kernel` beside `ResponseSimulationReport`:

```rust
/// Signed metadata block `active_defense`. Same variant set as `ActiveDefenseReceiptBody`,
/// each identifier the audit marks raw replaced by a `SaltedCommitment` (#1706 shape).
pub enum ActiveDefenseReceiptProjection { /* 12 variants, closed structs, lossless_serde! */ }
impl ActiveDefenseReceiptBody {
    /// Draws one salt per committed identifier from `rng`; returns the projection and its openings.
    pub fn project(&self, rng: &dyn Rng) -> Result<(ActiveDefenseReceiptProjection, ProjectionOpenings)>;
    /// True when `projection` opens to this body with `openings`.
    pub fn matches_projection(&self, projection: &ActiveDefenseReceiptProjection, openings: &ProjectionOpenings) -> bool;
}
/// Signed metadata block `response_simulation`.
#[serde(deny_unknown_fields)]
pub struct ResponseSimulationProjection { /* kept fields above, tenant commitment, three digests */ }
impl ResponseSimulationReport {
    pub fn project(&self, rng: &dyn Rng) -> Result<(ResponseSimulationProjection, ProjectionOpenings)>;
}
```

The projection openings are stored with the receipt's own openings in `receipt_openings` (the producers run where a receipt store exists: the kernel's active-response coordinator and the control plane's security store), under the `salt_ref`s named above. Both projections are registered `ChioInternal`, `CommittedSafe`. The full body and the full report stay the content preimages, so the content commitment hides them. Readers change in F (consumer kind F, Task 10): a reader that holds the full body or report (the coordinator, the control-plane security store) checks `matches_projection` with the persisted openings and opens the content commitment; a reader that holds only the receipt (lineage ingest, the security event consumer) uses the projection's digests and commitments and never sees a raw identifier. An erased or unknown projection opening fails closed with `OpeningUnavailable`.

Tenant binding (Root-2 r3). The top-level `tenant_id` that these producers set today is the signed tenant binding the store's authorization reads use: `receipt_query_snapshot/project.rs:101` derives the snapshot tenant from it, `receipt_query_snapshot/fetch.rs:87-94` refuses a snapshot tenant unlike it, and `receipt_store/reports/read_boundary/projection.rs:76` authenticates the stored tenant against it. F replaces the raw member for the native evidence, response simulation and cage producers with a signed opaque binding inside the signed body, so the store still authenticates tenant from the signature and no raw tenant id is published:

```rust
/// Signed body member. `value = HMAC-SHA256(tenant_index_key, "chio.receipt.tenant-binding.v1\0" || tenant_id)`.
#[serde(deny_unknown_fields)]
pub struct TenantBinding {
    pub alg: TenantBindingAlg,          // closed: "hmac-sha256"
    pub key_id: Sha256Digest,           // SHA-256("chio.tenant-index-key-id.v1\0" || key)
    pub value: Sha256Digest,
}
/// Loaded from a 32-byte file at startup by every process that signs or reads tenant-scoped
/// receipts (the spec 7.12 tenant index key; item 4 reuses it for serve-http).
pub struct TenantIndexKey { /* zeroized on drop */ }
impl TenantIndexKey {
    pub fn bind(&self, tenant_id: &str) -> TenantBinding;
    /// Constant-time comparison; refuses an unknown `key_id`.
    pub fn verify(&self, tenant_id: &str, binding: &TenantBinding) -> Result<(), TenantBindingError>;
}
```

The binding is keyed, so a holder of the receipt without the key cannot test a tenant guess, and it is deterministic, so the store verifies it without any opening; erasure of openings never affects it, and nothing falls back to trusting the column. `ChioReceiptBody` gains `tenant_binding: Option<TenantBinding>`; a body that carries both `tenant_id` and `tenant_binding`, or `authority` with either, fails signing. Other producers keep `tenant_id` as spec 7.6 allows; moving them to the binding is open question 11. Checks:

| Reader | Check after F |
|---|---|
| append (`SqliteReceiptStore`, trust-control, replication import) | the tenant column is written from `SignedReceipt.tenant` and checked by the tenant rule below (`TenantIndexKeySet::verify` for a binding, equality for a signed `tenant_id`) before the row commits; any mismatch refuses |
| snapshot project (`project.rs:101`) | the snapshot tenant comes from the stored column and is verified against the signed binding; a mismatch refuses the projection |
| snapshot fetch (`fetch.rs:87-94`) | a snapshot tenant is accepted only when `verify` succeeds against the receipt's signed binding |
| read boundary (`read_boundary/projection.rs:76`) | the stored tenant projection is authenticated with `verify` |
| evidence export and the internal opening read | tenant-scoped selection uses the verified column; the internal read derives the tenant from the caller credential and computes the binding server-side |
| every other receipt tenant reader | per the census TN kinds: TN-C reads the verified column, TN-B verifies the binding, TN-U is unchanged |

Tenant source (lead r4-delta e2 (c), (d)). The receipt no longer carries the tenant in plaintext, so the tenant travels beside it as unsigned context that never enters the signed body: `SignedReceipt` gains `tenant: Option<TenantId>`, set by the producer from its own context. It travels on the remote append request, in cluster openings and receipt deltas and in snapshots (every node verifies, so every node holds the key set), and in the admission row before publication. Append and every replication import enforce one rule before the row commits: a signed `tenant_binding` requires a present `tenant` that verifies; a signed `tenant_id` requires `tenant` equal to it; neither signed form requires `tenant` absent and the column NULL; anything else refuses. No receipt query treats a NULL tenant as visible to a tenant-scoped reader (test `null_tenant_not_visible_to_tenant_scoped_reads`).

Key set and provisioning (lead r4-delta e2 (e)). `TenantIndexKeySet { active: TenantIndexKey, retired: Vec<TenantIndexKey> }`: `bind` uses the active key; `verify` selects the key by the binding's `key_id` across the active and retired generations and refuses an unknown `key_id`. One key set per deployment, generated by the new `chio keys tenant-index generate --out <dir>` (F), provisioned by the operator as a directory (`active`, `retired/<key_id>`) to every process of the deployment that signs or reads tenant-scoped receipts: trust-control, the kernel-hosting processes (`--tenant-index-keys <dir>`), the control plane's security services and every cluster node (operators provision each node; the cluster does not replicate keys). Startup refuses a missing active key, a key length other than 32 bytes, a duplicate `key_id`, or a file readable by group or other or not owned by the process user (spec 8.3). Rotation generates a new active key and moves the old one to `retired`; retired keys only verify. Removing a retired key makes its bindings unverifiable, so tenant-scoped reads of those receipts refuse; the operations guide says to retain retired keys for the receipt retention period. Keys never leave a process and are never signing keys. Tests: `tenant_index_keys_refuse_wrong_length`, `..._refuse_loose_permissions`, `..._refuse_duplicate_key_id`, `tenant_binding_verifies_after_rotation`, `tenant_binding_unknown_key_id_refuses`.

Linkability (lead r4-delta e2 (f)). The binding is deterministic per tenant and key, so any holder of several receipts can group them by tenant without learning the tenant. This is accepted and stated in PROTOCOL 6 next to the "not a dictionary oracle" property.

`TenantBinding` and `TenantIndexKeySet` are additive types and land in P-b; F adds the body member, `SignedReceipt.tenant` and the checks.

A required block that would carry argument or result values is redesigned in F to a committed-safe typed form or the producer fails closed (Root-2 condition 5); Task 1 lists any such block, and an unexpected one stops the lane. The scattered key literals move to the registry constants; PROTOCOL 6.4 gains the normative key table; the kernel's reserved-key collision assertion and metadata-is-object assertion run before body construction. Dropping and refusal stay off in P-d and are switched on in F (Task 8).

- [ ] **Step 1: Failing tests:** `unsafe_required_guard_refuses_registration`; `security_projections_carry_no_raw_identifiers` (random marker tenant, action, finding, grant, request, submitter, subject and affected ids through every `ActiveDefenseReceiptBody` variant, a `ResponseSimulationReport` and a `SecurityEventBody`; no marker raw, hex or base64 in any projection); `kept_digests_are_keyed_or_entropy_backed` (for each kept digest, derive the unkeyed digest from the marker inputs and assert it does not appear in the projection; a digest kept unkeyed must have a named high-entropy input that the test randomizes); `projection_opens_to_its_body`; `every_guard_declares` (compiles only when every impl declares); `wasm_guard_declares_unsafe`; `registry_covers_census_keys` (every key the census found is registered); `reserved_key_from_caller_refuses`.
- [ ] **Step 2: Implement, run** `cs cargo test -p chio-kernel-core -p chio-kernel -p chio-guards -p chio-external-guards -p chio-wasm-guards -p chio-security-kernel -p chio-core-types --no-fail-fast`, clippy, `cs cargo xtask gen signed-fixtures --check` (no change). Expected: PASS.

---

### Task 5b: P-e, every committed-receipt raw decode through `UntrustedJsonText::decode_signed` (shared fix, lead-owned in the fwdcompat lane)

`serde_json::Value` keeps the last of two duplicate keys, so a duplicate key inside a `Value`-typed member (`metadata`, `parameters_inline`, `result_inline`, an opening's `payload`) collapses when a committed-receipt type is decoded straight from raw bytes with `serde_json::from_str`, `from_slice` or a raw `T::deserialize`. Main already has the strict entry: `chio-core-types/src/canonical/untrusted.rs` `UntrustedJsonText::decode_signed` parses through `signed_json::StoredValue`, which refuses duplicate keys at every depth before they reach a map, keeps full-width integers and integer-valued floats (the native signed numeric domain), and has 327 production call sites. `decode_document` is the duplicate-refusing entry for unsigned documents. P-e adds no decoder.

**Contract (one strict entry plus a gate).**
- Every production raw decode of a committed-receipt type (receipts, receipt bodies, disclosure blocks, projections, the relay inputs, trust-control route bodies, receipt-store row decodes, SDK verifier entry points that sit in Rust) goes through `UntrustedJsonText::decode_signed`. Opening documents (`chio.receipt-disclosure.v1`) go through `decode_document`.
- The public `Deserialize` impls stay, and the plan does not claim that a direct `T::deserialize` over raw bytes refuses a duplicate nested inside a `Value` member. The gate keeps such calls off production paths.
- Strict types are transitive (lead r5 N2): a type is strict when it is in `COMMITTED_RECEIPT_STRICT_TYPES` or contains one at any depth (`Vec<ChioReceipt>`, `Option<..>`, maps, tuples, `SignedExportEnvelope<..>`, request and response structs with a receipt member). The list is generated by a module walk in `chio-core-types` tests and exported for the gate.
- Gate: `scripts/check-committed-receipt-raw-decode.py` finds every non-test decode whose target is a strict type outside `UntrustedJsonText::decode_signed` and `decode_document`: `serde_json::from_str`, `from_slice`, `from_reader`, `serde_json::Deserializer::from_*` feeding a `Deserialize` call, a decode to `serde_json::Value` followed by `from_value`, and serde-driven extractors (`axum::Json<T>`, `axum::extract::Query<T>`, `axum::Form<T>`, and any other extractor implemented with serde). Such routes use a new `SignedJson<T>` extractor whose body decode calls `decode_signed` (the remote append route `receipt_handlers.rs:121` first among them). The allowlist is the two entry points and `SignedJson`.

**Tests.**
- `raw_duplicate_keys_refused_by_decode_signed`: for every type in `COMMITTED_RECEIPT_STRICT_TYPES`, bytes with a duplicate key at the top level, in each nested Chio object and inside each `Value`-typed member refuse through `decode_signed` (and each public concrete decoder that wraps it) with the exact duplicate-key error.
- `decode_signed_keeps_native_numeric_domain`: a receipt whose arguments carry a u64 above 2^53 and a `100.0` float decodes through `decode_signed` and re-encodes byte-identically, so P-e refuses nothing the native signed domain accepts.
- `opening_document_duplicates_refused_by_decode_document`.
- `http_append_route_refuses_duplicate_keys`: a `POST /v1/receipts/tools` body with a duplicate key inside a receipt's `metadata` is refused by `SignedJson` before the handler runs.
- `strict_type_list_is_transitive`: a container of a strict type appears in the exported list.
- `direct_raw_decode_of_receipt_types_is_gated`: the gate's behavior on a fixture tree with a raw `serde_json::from_str::<ChioReceipt>` outside the entry points (fails) and inside them (passes), run as part of the gate script's own invocation, not a separate test file.
- The SDK verifiers (Task 17) run the same raw duplicate cases.

- [ ] **Run** `cs cargo test -p chio-core-types --test receipt_strict_decode`, the changed decoders' crates, `python3 scripts/check-committed-receipt-raw-decode.py`, and `cs cargo xtask gen signed-fixtures --check` (no change).

---

### Task 5c: P-f, trust-control caller credentials and an internal listener (precursor)

Trust-control today has one bearer secret, `config.service_token`, checked by `validate_service_auth` (`report_validation.rs:263-281`) on every client route and keying the cluster peer HMAC, plus per-tenant `tenant_read_tokens` (`service_types/config.rs:73`), and serves one router on one listener (`service_runtime/init.rs:325`), including the existing `/v1/internal/*` routes (`router.rs:373,389`). The internal opening read and salt-bearing replication need scoped, attributable credentials and a listener the public cannot reach (lead r4-delta e3). P-f builds them before P-c.

**Interfaces.**
- Config: `[[credentials]]` entries `{ id, kind: "caller" | "deployment", secret_sha256, scopes: [..], deployment, tenant_authority: "deployment" | { tenant = ".." } }`, where `kind` is required (no default; a missing or unknown kind refuses at load), and `[cluster.peers]` entries `{ node_id, internal_url, public_key, scopes: [..] }`, where `scopes` is required, non-empty and drawn only from `cluster:replicate` and `cluster-openings:replicate` (any other scope refuses at load). A peer reaches a `cluster-openings:replicate` route only when its entry lists that scope. `service_token` and `tenant_read_tokens` are removed. The operator rewrites the configuration: the release notes and `chio trust config check` show the credential entries that reproduce today's access (the old service token's routes as one credential per caller role, each tenant read token as a `Tenant(t)` credential with `receipts:read`, `reports:read` and `evidence:read`, so a migrated tenant keeps evidence export). Nothing is migrated automatically, and a configuration that still names `service_token` or `tenant_read_tokens` refuses at startup.
- Route authorization table (Root-2 r5). Today's `json_ingress::authenticate` middleware (`json_ingress.rs:276-312`) maps JSON ingress paths to an authentication class, and handlers recheck. P-f turns that map into one table covering every route on both listeners, enforced in the middleware for every request (not only JSON ingress) and rechecked by `validate_caller(required_scope)` in each handler. A request for a route absent from the table, or a credential naming a scope absent from the closed scope set, refuses. The table below is generated from the router at `origin/main` `2bfbbfff2b` by `docs/superpowers/plans/m1-item2-routes/trust_control_routes.py` (committed with its rules `scope_rules.tsv` and output `routes-2bfbbfff2b.tsv`; 217 routes: 210 mounted, all in the table, 0 unruled, and 7 unmounted listed apart in `routes-2bfbbfff2b-unmounted.tsv`). It fails closed (Root-2 r6): it verifies the revision is a commit, exits 2 on any git failure other than an empty grep, and exits 1 when it finds no routes, when a route has no rule, when a matched rule yields `UNMAPPED`, or when a path constant or handler does not resolve. Path constants resolve by crate: a name qualified or imported from a crate resolves in that crate, an unqualified name resolves to the trust-control crate's own definition first, and a name defined only in several other crates is unresolved (exit 1). `trust_control_routes.py --self-check <repo> <rev> <workdir>` requires a nonexistent revision, a rule set whose only rule is the `UNMAPPED` fallback, and an empty rule set each to exit nonzero, and checks the resolver on a same-named constant from another crate (`chio-http-core`'s `/emergency-stop` against trust-control's `/v1/admin/emergency-stop`), a qualified name, a name defined in two other crates and an unknown name. It parses every `.route(` call in the trust-control router sources, resolves path constants and aliases, finds the router function that contains each call and treats a route as mounted only when non-test code outside that function's definition names it, and records the authentication helper each handler (or a function it calls, two levels deep) uses today, so each row's credential kind follows today's check. Rows marked "unchanged" keep their existing non-credential authentication (anonymous public metadata, finding seller signatures, OID4VCI wallet tokens). `frost_coordinator_router` (`frost/coordinator.rs:565`) has no caller, so its seven `/v1/frost/coordinator/sessions/*` routes are unmounted: they are not in the table, and since the middleware refuses any route absent from the table, mounting that router later fails closed until its rows are added with their scopes. The four rows marked "new in this plan" are the routes Task 4 adds.

| Method | Route | Listener | Credential | Scope | Tenant authority |
|---|---|---|---|---|---|
| GET | `/.well-known/chio-oid4vp-verifier` | public | anonymous | `none` | n/a (public issuer and verifier metadata; unchanged) |
| GET | `/.well-known/chio-passport-jwt-vc-json` | public | anonymous | `none` | n/a (public issuer and verifier metadata; unchanged) |
| GET | `/.well-known/chio-passport-sd-jwt-vc` | public | anonymous | `none` | n/a (public issuer and verifier metadata; unchanged) |
| GET | `/.well-known/jwks.json` | public | anonymous | `none` | n/a (public issuer and verifier metadata; unchanged) |
| GET | `/.well-known/openid-credential-issuer` | public | anonymous | `none` | n/a (public issuer and verifier metadata; unchanged) |
| GET | `/health` | public | anonymous | `none` | n/a (liveness only; unchanged) |
| GET | `/metrics` | public | caller | `metrics:read` | Deployment only |
| POST | `/scim/v2/Users` | public | caller | `scim:write` | Deployment only |
| DELETE | `/scim/v2/Users/{user_id}` | public | caller | `scim:write` | Deployment only |
| POST | `/v1/admin/emergency-resume` | public | caller | `admin:emergency` | Deployment only |
| GET | `/v1/admin/emergency-status` | public | caller | `admin:emergency` | Deployment only |
| POST | `/v1/admin/emergency-stop` | public | caller | `admin:emergency` | Deployment only |
| GET | `/v1/agents/{subject_key}/receipts` | public | caller | `receipts:read` | Tenant(t) sees only tenant t; Deployment sees its deployment |
| GET | `/v1/authority` | public | deployment | `authority:read` | Deployment only |
| POST | `/v1/authority` | public | caller | `authority:admin` | Deployment only |
| POST | `/v1/authority/key-log/sync` | public | caller | `authority:admin` | Deployment only |
| POST | `/v1/bond-losses/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/bonds/issue` | public | caller | `credit:write` | Deployment only |
| GET | `/v1/budgets` | public | deployment | `budgets:read` | Deployment only |
| POST | `/v1/budgets/authorize-exposure` | public | deployment | `budgets:write` | Deployment only |
| POST | `/v1/budgets/capture-invocation` | public | deployment | `budgets:write` | Deployment only |
| POST | `/v1/budgets/cumulative-approval/lookup` | public | deployment | `budgets:write` | Deployment only |
| POST | `/v1/budgets/holds/authorize` | public | deployment | `budgets:write` | Deployment only |
| POST | `/v1/budgets/holds/authorize-cumulative` | public | deployment | `budgets:write` | Deployment only |
| POST | `/v1/budgets/holds/cancel-captured` | public | deployment | `budgets:write` | Deployment only |
| POST | `/v1/budgets/holds/capture-invocation` | public | deployment | `budgets:write` | Deployment only |
| POST | `/v1/budgets/holds/capture-spend` | public | deployment | `budgets:write` | Deployment only |
| POST | `/v1/budgets/holds/reconcile` | public | deployment | `budgets:write` | Deployment only |
| POST | `/v1/budgets/holds/release` | public | deployment | `budgets:write` | Deployment only |
| POST | `/v1/budgets/holds/reverse` | public | deployment | `budgets:write` | Deployment only |
| POST | `/v1/budgets/increment` | public | deployment | `budgets:write` | Deployment only |
| POST | `/v1/budgets/reconcile-spend` | public | deployment | `budgets:write` | Deployment only |
| POST | `/v1/budgets/release-exposure` | public | deployment | `budgets:write` | Deployment only |
| POST | `/v1/capabilities/issue` | public | deployment | `capabilities:issue` | Deployment only |
| POST | `/v1/capital/allocations/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/capital/instructions/issue` | public | caller | `credit:write` | Deployment only |
| GET | `/v1/certifications` | public | caller | `certifications:read` | Deployment only |
| POST | `/v1/certifications` | public | caller | `certifications:write` | Deployment only |
| POST | `/v1/certifications/discovery/consume` | public | caller | `certifications:write` | Deployment only |
| POST | `/v1/certifications/discovery/publish` | public | caller | `certifications:write` | Deployment only |
| GET | `/v1/certifications/discovery/resolve/{tool_server_id}` | public | caller | `certifications:read` | Deployment only |
| GET | `/v1/certifications/discovery/search` | public | caller | `certifications:read` | Deployment only |
| GET | `/v1/certifications/discovery/transparency` | public | caller | `certifications:read` | Deployment only |
| GET | `/v1/certifications/resolve/{tool_server_id}` | public | caller | `certifications:read` | Deployment only |
| GET | `/v1/certifications/{artifact_id}` | public | caller | `certifications:read` | Deployment only |
| POST | `/v1/certifications/{artifact_id}/dispute` | public | caller | `certifications:write` | Deployment only |
| POST | `/v1/certifications/{artifact_id}/revoke` | public | caller | `certifications:write` | Deployment only |
| POST | `/v1/evidence/export` | public | caller | `evidence:read` | Tenant(t) exports only tenant t; Deployment its deployment |
| POST | `/v1/evidence/import` | public | caller | `evidence:write` | Deployment only |
| POST | `/v1/facilities/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/federation/capabilities/issue` | public | caller | `federation:write` | Deployment only |
| GET | `/v1/federation/evidence-shares` | public | caller | `federation:read` | Deployment only |
| GET | `/v1/federation/open-admission-policies` | public | caller | `federation:read` | Deployment only |
| POST | `/v1/federation/open-admission-policies/evaluate` | public | caller | `federation:write` | Deployment only |
| DELETE | `/v1/federation/open-admission-policies/{policy_id}` | public | caller | `federation:write` | Deployment only |
| GET | `/v1/federation/open-admission-policies/{policy_id}` | public | caller | `federation:read` | Deployment only |
| PUT | `/v1/federation/open-admission-policies/{policy_id}` | public | caller | `federation:write` | Deployment only |
| GET | `/v1/federation/providers` | public | caller | `federation:read` | Deployment only |
| DELETE | `/v1/federation/providers/{provider_id}` | public | caller | `federation:write` | Deployment only |
| GET | `/v1/federation/providers/{provider_id}` | public | caller | `federation:read` | Deployment only |
| PUT | `/v1/federation/providers/{provider_id}` | public | caller | `federation:write` | Deployment only |
| POST | `/v1/findings/collateral` | public | caller | `findings:write` | Deployment only |
| POST | `/v1/findings/operator/retractions` | public | finding seller (seller signature) | `none` | n/a (seller authentication; unchanged) |
| POST | `/v1/findings/operator/verified-fixes` | public | finding seller (seller signature) | `none` | n/a (seller authentication; unchanged) |
| POST | `/v1/findings/profiles` | public | caller | `findings:write` | Deployment only |
| POST | `/v1/findings/publish` | public | caller | `findings:write` | Deployment only |
| POST | `/v1/findings/recipes` | public | caller | `findings:write` | Deployment only |
| GET | `/v1/findings/search` | public | anonymous | `none` | n/a (public listing reads; unchanged) |
| POST | `/v1/findings/search` | public | anonymous | `none` | n/a (public listing search; unchanged) |
| POST | `/v1/findings/status/{feed}/intents` | public | caller | `findings:write` | Deployment only |
| GET | `/v1/findings/status/{feed}/proof/{finding_id}` | public | anonymous | `none` | n/a (public listing reads; unchanged) |
| GET | `/v1/findings/status/{feed}/root` | public | anonymous | `none` | n/a (public listing reads; unchanged) |
| GET | `/v1/findings/{finding_id}` | public | anonymous | `none` | n/a (public listing reads; unchanged) |
| POST | `/v1/findings/{finding_id}/activate` | public | caller | `findings:write` | Deployment only |
| GET | `/v1/findings/{finding_id}/admission` | public | anonymous | `none` | n/a (public listing reads; unchanged) |
| POST | `/v1/findings/{finding_id}/challenges` | public | caller | `findings:write` | Deployment only |
| GET | `/v1/findings/{finding_id}/challenges/{challenge_id}` | public | caller | `findings:read` | Deployment only |
| POST | `/v1/findings/{finding_id}/operator/live-status` | public | caller | `findings:write` | Deployment only |
| POST | `/v1/findings/{finding_id}/participation` | public | caller | `findings:write` | Deployment only |
| GET | `/v1/findings/{finding_id}/proof` | public | anonymous | `none` | n/a (public listing reads; unchanged) |
| POST | `/v1/findings/{finding_id}/purchase` | public | caller | `findings:write` | Deployment only |
| POST | `/v1/fiscal/activations` | public | caller | `fiscal:write` | Deployment only |
| POST | `/v1/fiscal/approvals` | public | caller | `fiscal:write` | Deployment only |
| POST | `/v1/fiscal/marketplace/credit-limit` | public | caller | `reports:read` | Tenant(t) sees only tenant t; Deployment sees its deployment |
| POST | `/v1/fiscal/marketplace/price` | public | caller | `fiscal:write` | Deployment only |
| POST | `/v1/fiscal/proposals` | public | caller | `fiscal:write` | Deployment only |
| POST | `/v1/fiscal/proposals/admit` | public | caller | `fiscal:write` | Deployment only |
| POST | `/v1/fiscal/proposals/preview` | public | caller | `fiscal:write` | Deployment only |
| POST | `/v1/fiscal/resolve` | public | caller | `fiscal:write` | Deployment only |
| GET | `/v1/fiscal/runtime` | public | caller | `fiscal:read` | Deployment only |
| POST | `/v1/internal/admission-authority` | internal | deployment | `admission-authority:write` | Deployment only |
| GET | `/v1/internal/authority/snapshot` | internal | peer | `cluster:replicate` | n/a (peer of the same cluster; pinned node key) |
| GET | `/v1/internal/budgets/delta` | internal | peer | `cluster:replicate` | n/a (peer of the same cluster; pinned node key) |
| POST | `/v1/internal/cluster/partition` | internal | peer | `cluster:replicate` | n/a (peer of the same cluster; pinned node key) |
| GET | `/v1/internal/cluster/snapshot` | internal | peer | `cluster-openings:replicate` | n/a (peer of the same cluster; pinned node key; the response carries openings) |
| GET | `/v1/internal/cluster/status` | internal | peer | `cluster:replicate` | n/a (peer of the same cluster; pinned node key) |
| GET | `/v1/internal/lineage/delta` | internal | peer | `cluster:replicate` | n/a (peer of the same cluster; pinned node key) |
| GET | `/v1/internal/receipts/children/delta` | internal | peer | `cluster:replicate` | n/a (peer of the same cluster; pinned node key) |
| GET | `/v1/internal/receipts/tools/delta` | internal | peer | `cluster-openings:replicate` | n/a (peer of the same cluster; pinned node key; the response carries openings) |
| GET | `/v1/internal/revocations/delta` | internal | peer | `cluster:replicate` | n/a (peer of the same cluster; pinned node key) |
| POST | `/v1/liability/adjudications/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/liability/auto-bind/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/liability/bound-coverages/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/liability/claim-payouts/instructions/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/liability/claim-payouts/receipts/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/liability/claim-responses/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/liability/claim-settlements/instructions/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/liability/claim-settlements/receipts/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/liability/claims/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/liability/disputes/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/liability/placements/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/liability/pricing-authorities/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/liability/providers/issue` | public | caller | `credit:write` | Deployment only |
| GET | `/v1/liability/providers/resolve` | public | caller | `credit:read` | Deployment only |
| POST | `/v1/liability/quote-requests/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/liability/quote-responses/issue` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/lineage` | public | caller | `lineage:write` | Deployment only |
| GET | `/v1/lineage/{capability_id}` | public | caller | `lineage:read` | Deployment only |
| GET | `/v1/lineage/{capability_id}/chain` | public | caller | `lineage:read` | Deployment only |
| POST | `/v1/metered-billing/reconcile` | public | deployment | `settlement:write` | Deployment only |
| POST | `/v1/passport/challenges` | public | caller | `passport:write` | Deployment only |
| POST | `/v1/passport/challenges/verify` | public | caller | `passport:write` | Deployment only |
| POST | `/v1/passport/issuance/credential` | public | holder (OID4VCI pre-authorized code or access token) | `none` | n/a (wallet protocol credential; unchanged) |
| POST | `/v1/passport/issuance/offers` | public | caller | `passport:write` | Deployment only |
| POST | `/v1/passport/issuance/token` | public | holder (OID4VCI pre-authorized code or access token) | `none` | n/a (wallet protocol credential; unchanged) |
| POST | `/v1/passport/oid4vp/requests` | public | caller | `passport:write` | Deployment only |
| GET | `/v1/passport/statuses` | public | caller | `passport:read` | Deployment only |
| POST | `/v1/passport/statuses` | public | caller | `passport:write` | Deployment only |
| GET | `/v1/passport/statuses/resolve/{passport_id}` | public | caller | `passport:read` | Deployment only |
| GET | `/v1/passport/statuses/{passport_id}` | public | caller | `passport:read` | Deployment only |
| POST | `/v1/passport/statuses/{passport_id}/revoke` | public | caller | `passport:write` | Deployment only |
| GET | `/v1/passport/verifier-policies` | public | caller | `passport:read` | Deployment only |
| DELETE | `/v1/passport/verifier-policies/{policy_id}` | public | caller | `passport:write` | Deployment only |
| GET | `/v1/passport/verifier-policies/{policy_id}` | public | caller | `passport:read` | Deployment only |
| PUT | `/v1/passport/verifier-policies/{policy_id}` | public | caller | `passport:write` | Deployment only |
| GET | `/v1/public/certifications/metadata` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| GET | `/v1/public/certifications/resolve/{tool_server_id}` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| GET | `/v1/public/certifications/search` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| GET | `/v1/public/certifications/transparency` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| POST | `/v1/public/passport/challenges/verify` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| GET | `/v1/public/passport/challenges/{challenge_id}` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| GET | `/v1/public/passport/discovery/issuer` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| GET | `/v1/public/passport/discovery/transparency` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| GET | `/v1/public/passport/discovery/verifier` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| POST | `/v1/public/passport/oid4vp/direct-post` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| GET | `/v1/public/passport/oid4vp/launch/{request_id}` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| GET | `/v1/public/passport/oid4vp/requests/{request_id}` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| GET | `/v1/public/passport/statuses/resolve/{passport_id}` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| GET | `/v1/public/passport/wallet-exchanges/{request_id}` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| GET | `/v1/public/registry/listings/search` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| GET | `/v1/public/registry/namespace` | public | anonymous | `none` | n/a (public registry, certification and passport surfaces; unchanged) |
| GET | `/v1/receipts/analytics` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/receipts/children` | public | caller | `receipts:read` | Tenant(t) sees only tenant t; Deployment sees its deployment |
| POST | `/v1/receipts/children` | public | deployment | `receipts:append` | Deployment only |
| GET | `/v1/receipts/query` | public | caller | `receipts:read` | Tenant(t) sees only tenant t; Deployment sees its deployment |
| POST | `/v1/receipts/query/snapshot/recovery` | public | caller | `receipts:admin` | Deployment only |
| GET | `/v1/receipts/tools` | public | caller | `receipts:read` | Tenant(t) sees only tenant t; Deployment sees its deployment |
| POST | `/v1/receipts/tools` | public | deployment | `receipts:append` | Deployment only |
| POST | `/v1/registry/governance/cases/evaluate` | public | caller | `registry:write` | Deployment only |
| POST | `/v1/registry/governance/cases/issue` | public | caller | `registry:write` | Deployment only |
| POST | `/v1/registry/governance/charters/issue` | public | caller | `registry:write` | Deployment only |
| POST | `/v1/registry/market/fees/issue` | public | caller | `registry:write` | Deployment only |
| POST | `/v1/registry/market/penalties/evaluate` | public | caller | `registry:write` | Deployment only |
| POST | `/v1/registry/market/penalties/issue` | public | caller | `registry:write` | Deployment only |
| POST | `/v1/registry/trust-activations/evaluate` | public | caller | `registry:write` | Deployment only |
| POST | `/v1/registry/trust-activations/issue` | public | caller | `registry:write` | Deployment only |
| GET | `/v1/reports/authorization-context` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/authorization-profile-metadata` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/authorization-review-pack` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/behavioral-feed` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/bond-loss-policy` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/bond-losses` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/bond-policy` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| POST | `/v1/reports/bonded-execution-simulation` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/bonds` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/capital-book` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/comptroller-surface` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/cost-attribution` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/credit-backtest` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/credit-scorecard` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/economic-completion-flow` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/economic-receipts` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/exposure-ledger` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/facilities` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/facility-policy` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/liability-claims` | public | caller | `reports:read` | Deployment only |
| GET | `/v1/reports/liability-market` | public | caller | `reports:read` | Deployment only |
| GET | `/v1/reports/liability-providers` | public | caller | `reports:read` | Deployment only |
| GET | `/v1/reports/metered-billing` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/operator` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/provider-risk-package` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| POST | `/v1/reports/runtime-attestation-appraisal` | public | caller | `reports:read` | Deployment only |
| POST | `/v1/reports/runtime-attestation-appraisal-result` | public | caller | `reports:read` | Deployment only |
| POST | `/v1/reports/runtime-attestation-appraisal/import` | public | caller | `reports:read` | Deployment only |
| GET | `/v1/reports/settlements` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/underwriting-decision` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| GET | `/v1/reports/underwriting-decisions` | public | caller | `reports:read` | Deployment only |
| GET | `/v1/reports/underwriting-input` | public | caller | `reports:read` | Deployment only |
| POST | `/v1/reports/underwriting-simulation` | public | caller | `reports:read` | Deployment only (today's admin report read context) |
| POST | `/v1/reputation/compare/{subject_key}` | public | caller | `reputation:write` | Deployment only |
| GET | `/v1/reputation/local/{subject_key}` | public | caller | `reputation:read` | Deployment only |
| POST | `/v1/reputation/portable/evaluate` | public | caller | `reputation:write` | Deployment only |
| POST | `/v1/reputation/portable/events/issue` | public | caller | `reputation:write` | Deployment only |
| POST | `/v1/reputation/portable/summaries/issue` | public | caller | `reputation:write` | Deployment only |
| GET | `/v1/revocations` | public | caller | `revocations:read` | Deployment only |
| POST | `/v1/revocations` | public | caller | `revocations:write` | Deployment only |
| POST | `/v1/settlements/reconcile` | public | deployment | `settlement:write` | Deployment only |
| POST | `/v1/underwriting/appeals` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/underwriting/appeals/resolve` | public | caller | `credit:write` | Deployment only |
| POST | `/v1/underwriting/decisions/issue` | public | caller | `credit:write` | Deployment only |
| GET | `/v1/receipts/{id}/openings/status` (new in this plan) | public | caller | `receipts:read` | Tenant(t) only for receipts of tenant t (either signed form, checked server-side); Deployment for its deployment |
| POST | `/v1/receipts/{id}/openings/erase` (new in this plan) | public | caller | `receipt-openings:erase` | Deployment only |
| POST | `/v1/internal/receipts/openings/read` (new in this plan) | internal | deployment | `receipt-openings:read` | Deployment, or Tenant(t) checked against the receipt's signed tenant_id or a server-computed binding (Task 4) |
| GET | `/v1/internal/receipts/openings/delta` (new in this plan; later state changes only) | internal | peer | `cluster-openings:replicate` | n/a (peer of the same cluster; pinned node key) |

Closed scope set: `admin:emergency`, `admission-authority:write`, `attestation:write`, `authority:admin`, `authority:read`, `budgets:read`, `budgets:write`, `capabilities:issue`, `certifications:read`, `certifications:write`, `cluster:replicate`, `cluster-openings:replicate`, `credit:read`, `credit:write`, `evidence:read`, `evidence:write`, `federation:read`, `federation:write`, `findings:read`, `findings:write`, `fiscal:read`, `fiscal:write`, `lineage:read`, `lineage:write`, `metrics:read`, `passport:read`, `passport:write`, `receipt-openings:erase`, `receipt-openings:read`, `receipts:admin`, `receipts:append`, `receipts:read`, `registry:write`, `reports:read`, `reputation:read`, `reputation:write`, `revocations:read`, `revocations:write`, `scim:write`, `settlement:write`. Credential kinds: `caller` (an operator or service client), `deployment` (a kernel-hosting process or control-plane service of one deployment), `peer` (a cluster node, pinned Ed25519 key, internal listener only); a `peer` credential is refused on every public route and a `caller` or `deployment` credential on every peer route.
- `validate_caller(&headers, required_scope) -> Result<AuthenticatedCaller>` with `AuthenticatedCaller { credential_id, deployment, tenant_authority, scopes }`, constant-time secret comparison, used by every route.
- Internal listener: a second bind address `internal_listen`. Every `/v1/internal/*` route (the existing receipt delta and cluster snapshot routes, the new openings stream and openings read) is mounted only on the internal router; the public router has none of them. Peers use `internal_url`.
- Peer auth: `validate_cluster_peer_auth` verifies an Ed25519 signature by the claimed node's pinned key over the payload above (method, path, raw query, issue time, term, body digest and a single-use nonce).

**Tests:** `route_table_covers_every_router_route` (the router's route list equals the table's), `unknown_route_refuses`, `credential_with_unknown_scope_refuses_at_startup`, `read_scope_cannot_write` (for each family, a `:read` credential on its write routes refuses), `write_scope_cannot_read_other_family`, `tenant_credential_cross_tenant_read_refused` (a `Tenant(a)` credential on `/v1/receipts/query`, `/v1/receipts/tools` and the reports for tenant b), `tenant_credential_refused_on_deployment_only_routes`, `peer_credential_refused_on_public_routes`, `caller_credential_refused_on_peer_routes`, `deployment_credential_of_other_deployment_refused`, `public_router_has_no_internal_paths`, `internal_listener_refuses_without_credential`, `scope_required_per_route`, `existing_client_routes_keep_access_under_mapped_scopes`, `tenant_credential_limited_to_its_tenant`, `service_token_secret_no_longer_authenticates_cluster_routes`, `peer_signature_from_unpinned_key_refused`, `old_config_keys_refuse_at_startup`.

**Size:** 3-5 days, counted in the Size table. It changes trust-control configuration for every deployment (D17 item 8).

---

### Task 6:### Task 6: F commits 1 and 2, committed body and the portable signer

**Files:** `crates/core/chio-core-types/src/receipt/{body,decision,kinds,metadata,signing}.rs`, `tests/committed_receipt_negatives.rs` (new); `crates/kernel/chio-kernel-core/src/{receipts,lib,kani_public_harnesses}.rs`; contract move-in files.

**Interfaces:**

```rust
#[serde(deny_unknown_fields)]
pub struct ToolCallAction {
    pub parameter_commitment: ReceiptCommitment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters_inline: Option<serde_json::Map<String, serde_json::Value>>,
}
// ToolCallAction::from_parameters and verify_hash are deleted; canonical_parameter_digest
// (consumer kind A0) is the request digest helper.
pub fn canonical_parameter_digest(arguments: &serde_json::Value) -> Result<Sha256Hex>;

// ChioReceiptBody: removed redaction_mode, content_hash; added
//   content_commitment: ReceiptCommitment, result_inline: Option<Map>,
//   disclosure: DisclosureBlock, authority: Option<ReceiptAuthority>
#[serde(deny_unknown_fields)]
pub struct DisclosureBlock { pub policy_digest: Option<Sha256Digest>,
    pub parameter_inline_fields: Vec<JsonPointer>, pub result_inline_fields: Vec<JsonPointer> }
#[serde(deny_unknown_fields)]
pub struct ReceiptAuthority { pub root_anchor: RootAnchor, pub chain_digest: Sha256Digest,
    pub chain_depth: u32, pub holder: HolderClass }

pub struct ReceiptDraft { /* id, timestamp, capability_id, tool_server, tool_name, decision,
    receipt_kind, boundary_class, observation_outcome, tool_origin, actor_chain, policy_hash,
    evidence, metadata, trust_level, tenant_id, authority, kernel_key, bbs_projection_version */ }
pub struct ReceiptPreimages<'a> { pub parameters: &'a serde_json::Value, pub content: ContentPreimage<'a> }
/// Salts of one receipt; zeroized on drop; Debug prints the receipt id only.
pub struct ReceiptOpenings { pub receipt_id: String, pub parameters: Salt, pub content: Salt }
impl ReceiptOpenings {
    pub fn salt_only(&self) -> ReceiptDisclosure;
    /// Value outputs only (Task 3 payload forms).
    pub fn with_value_payloads(&self, parameters: &serde_json::Value, content: &serde_json::Value) -> ReceiptDisclosure;
}
#[must_use]
pub struct SignedReceipt { pub receipt: ChioReceipt, pub openings: ReceiptOpenings }

impl ChioReceipt {
    pub fn sign(draft: ReceiptDraft, preimages: ReceiptPreimages<'_>, rng: &dyn Rng, keypair: &Keypair) -> Result<SignedReceipt>;
    pub fn sign_with_backend(draft: ReceiptDraft, preimages: ReceiptPreimages<'_>, rng: &dyn Rng, backend: &dyn SigningBackend) -> Result<SignedReceipt>;
    pub fn sign_with_backend_using_handle(draft: ReceiptDraft, parameters: &serde_json::Value, rng: &dyn Rng, backend: &dyn SigningBackend, handle: ReceiptSigningHandle) -> Result<SignedReceipt>;
    pub fn sign_prepared_with_bbs_using_handle(draft: ReceiptDraft, parameters: &serde_json::Value, rng: &dyn Rng, backend: &dyn SigningBackend, handle: ReceiptSigningHandle, bbs: &BbsSigner) -> Result<SignedReceipt>;
    pub fn open(&self, disclosure: &ReceiptDisclosure, own_parameters: Option<&serde_json::Value>, own_output: Option<ContentPreimage<'_>>) -> OpeningReport;
}

// chio-kernel-core
pub enum ReceiptSigningError { ContentCommitmentMismatch { salt_ref: SaltRef }, KernelKeyMismatch,
    SaltGeneration(RngError), DuplicateSalt, TenantIdWithAuthority, InlineFieldsWithoutPolicy, SigningFailed(String) }
pub fn sign_receipt(draft: ReceiptDraft, preimages: ReceiptPreimages<'_>, rng: &dyn Rng, backend: &dyn SigningBackend) -> Result<SignedReceipt, ReceiptSigningError>;
pub fn sign_receipt_with_handle(draft: ReceiptDraft, parameters: &serde_json::Value, rng: &dyn Rng, backend: &dyn SigningBackend, handle: ReceiptSigningHandle) -> Result<SignedReceipt, ReceiptSigningError>;
```

Signer order: kernel key check against `backend.public_key()?`, two salt draws (equal salts refuse), commitment computation, recompute check (`ContentCommitmentMismatch`), body validation (`validate_signable_semantics`, `tenant_id` rule, inline-field rule), wrapped signing. Deleted: `sign_receipt_relaying_trusted_body`, `ContentHashMismatch`, every signer that takes a `ChioReceiptBody`, `RedactionMode`, `ReceiptSemanticFields.redaction_mode`. `ReceiptSigningHandle` owns a `ContentPreimage`. Every producer sets `authority: None` (open question 3).

Contract move-in (in-place schemas README): `git mv` the staged `record.schema.json` over the live file after removing `enforcement`, the `pdp_decision`, `prevent_external` and `delegated` values and rule, and `settlement`; re-diff against live and carry in #1715's closed layers and item 1's `algorithm` removal first. `content_commitment` is required. Register `urn:chio:error:attest:receipt-tenant-id-with-authority`. Regenerate code in four languages.

- [ ] **Step 1: Failing tests** in `committed_receipt_negatives.rs` and `receipts.rs`: `equal_salts_refuse`, `rng_failure_refuses_signing` (no backend call), `tenant_id_with_authority_refuses_signing`, `padded_blocks_fail_decoding` (each new block and `authority.root_anchor`), `removed_members_fail_decoding` (`content_hash`, `redaction_mode`, `action.parameters`, `action.parameter_hash`), `commitment_salt_ref_checked_by_position`, `kernel_key_mismatch_refuses_before_salts`, `receipt_signers_take_preimages` (calls every public receipt signer in core-types, kernel-core and selective-disclosure with the new signatures).
- [ ] **Strictness gate (mandatory).** `crates/core/chio-core-types/tests/receipt_strict_decode.rs` (from #1715) gains `committed_receipt_types_refuse_padding_and_lossy_decode`, driven by `COMMITTED_RECEIPT_STRICT_TYPES`, which lists every committed-receipt type: `ChioReceipt`, `ChioReceiptBody`, `ChioReceiptIdInput`, `ChioReceiptSigningBody`, `ToolCallAction`, `ReceiptCommitment`, `CommitmentAlg`, `DisclosureBlock`, `ReceiptAuthority` (with `RootAnchor` and `HolderClass`), `Decision`, `OperationTerminalState`, `GuardEvidence`, `ActorRef`, `ReceiptDisclosure`, `Opening`, `TenantBinding`, `ActiveDefenseReceiptProjection` (each variant), `ResponseSimulationProjection`, the relay `content` input union and the HTTP `HttpBody` tag. For each type, in the shape of #1723's concrete-path tests: a padded member at every nesting level, a duplicate member at a Chio-object level (refused by the derived impls on raw paths; duplicates nested inside `Value`-typed members are refused by `decode_signed` and covered by P-e's tests, not by direct `T::deserialize`; `from_value` cannot express a duplicate key), and for each tagged variant (unit variants included) a padded variant such as `{"verdict":"allow","pad":0}`, each refused with the exact error, through `T::deserialize(&mut serde_json::Deserializer::from_str(..))`, `serde_json::from_str::<T>`, `serde_json::from_value::<T>` and every public concrete decoder of the type; and a lossless round trip (the decoded value re-encodes to exactly the input). A type missing from the list fails `committed_receipt_strict_types_cover_the_module` (a module walk over the public receipt and disclosure types). The same cases run against #1716's SDK decoders in Task 17.
- [ ] **Step 2: Run** `cs cargo test -p chio-core-types -p chio-kernel-core --no-fail-fast` (expected: PASS except golden signatures, listed for Task 18).

---

### Task 7: F commits 3, 4 and 6, hosted kernel salts and internal consumers

**Files:** `crates/kernel/chio-kernel/src/{kernel/construction.rs,kernel_struct.rs,receipt_support/**,kernel/responses/**,kernel/signing_task.rs,kernel/admission_terminal_receipt.rs,kernel/effect_obligation/**,kernel/kernel_drop_guard.rs,kernel/reconciliation.rs,kernel/session_ops/**,kernel/admission_coordinator/**,admission_operation/**,tool_outcome/caller_delivery.rs,kernel/verified_treaty.rs,kernel/nonce_admission.rs,kernel/validation/tool_output.rs,kernel/settlement_observer.rs}`, `chio-store-sqlite` admission operation rows, `chio-secret-broker` kernel host, `chio-control-plane/src/lib.rs` (`build_kernel_with_clock`, `configure_receipt_store`), `chio-api-protect/src/proxy/mediated.rs`.

- Kernel construction carries `rng: Arc<dyn Rng + Send + Sync>` in `KernelConfig` (one constructor input, no setter), defaulting nowhere: every one of the 421 construction sites passes it (release code `OsEntropyRng`, tests `OsEntropyRng` or `FixtureRng`). A durable receipt store, local or remote, always stores openings (Task 4), so no "store without disclosure store" state exists (P1-1).
- Commit 3 wires the kernel `Rng` into all 20 kernel producer rows (one producer). `api protect`'s mediated kernel and the secret broker's hosted kernel are this producer; commit 6 wires the broker host's `Rng` and store.
- Commit 4 applies consumer kinds A, A0 and B to every kernel and store row in the Task 1 table. The admission operation row gains `receipt_parameter_commitment` and `receipt_content_commitment`, written in the same transaction that records the terminal receipt; the row's existing `action_parameter_hash` becomes the `canonical_parameter_digest` value; the retained output blob keeps its own digest. Compacted replay compares `sha256(blob)` with the row's output digest and the receipt's commitment values with the row's commitment values; it never requires an opening, and when `opening_status` is `Present` it also reads the opening and recomputes the content commitment over the blob (kind A).
- Kernel paths that need an opening are kind E-k (`allow_responses.rs`) and the optional compacted-replay recompute. E-k fails with `KernelError::ReceiptOpeningUnavailable(OpeningUnavailable)` when the opening is erased, unknown or the remote read is refused; compacted replay skips the recompute in those states and never fails on them.

- [ ] **Step 1: Failing tests:**
  - `kernel_receipt_openings_persist_with_append`; `deny_receipt_commits_empty_output`;
  - `compacted_replay_survives_erased_openings` (erase the openings of a compacted admission, replay: completes with the same receipt; no wedge);
  - `compacted_replay_blob_mismatch_refuses` (the existing refusal, now against the row digest);
  - `compacted_replay_detects_blob_rewrite_when_opening_present` (a store that rewrites the blob and the row digest is refused when the opening is present, because the content commitment is recomputed over the blob; P2-C);
  - `delivery_preparation_reads_launch_state_from_signed_cage_receipt`, `authorization_projection_reads_payload_digest_from_row` (Root-held P-i sites);
  - `finding_memory_write_refuses_erased_parent_opening` (E-k);
  - `fresh_only_catalog_refuses_old_receipt_column_without_mutation` and `fresh_only_catalog_refuses_old_admission_row_without_mutation`: F's in-place `chio_tool_receipts.content_commitment` column and the two admission-row commitment columns are validated by the fresh-only v1 catalog for `SqliteReceiptStore` and `SqliteAdmissionOperationStore`, each refusing an old, unstamped or malformed layout with the exact error and no mutation (Root-2 condition 6);
  - `recovery_republishes_exact_receipt_and_salts` (crash after durable admission before publication);
  - `post_effect_stop_races_receipt_append` (C6: a durable stop racing the append still withholds post-effect output, Root-2 condition 4);
  - the existing T7, native-ledger and D5 admission and security dispatch identity and refusal tests keep their assertions; where a signature or API changes they are rewritten to assert the same refusal, not only regenerated (Root-2 condition 4);
  - `settlement_seed_and_drain_keep_receipt_references` (#1710 seeding, durable append and drain reconciliation after ids change, Root-2 condition 5);
  - `treaty_request_binding_checked_at_signing`, `nonce_parameter_binding_checked_at_signing`, `caller_delivery_uses_request_digest`;
  - `remote_receipt_store_kernel_starts` (`chio mcp serve --control-url` against a trust-control stub: starts, appends with openings).
- [ ] **Step 2: Run** `cs cargo test -p chio-kernel --no-fail-fast`, `cs cargo test -p chio-kernel --test durable_admission_sqlite`, `cs cargo test -p chio-store-sqlite -p chio-control-plane -p chio-api-protect -p chio-secret-broker --no-fail-fast`, clippy. Expected: PASS except golden signatures.

---

### Task 8: F commit 5, evidence and metadata enforcement

- Receipt assembly drops `GuardEvidence.details` of guards declared `Unsafe`, drops every caller or hook metadata key (origin `CallerOrHook`, untrusted input, spec 8.4), and refuses signing with `Error::UnregisteredMetadataKey(key)` for a Chio-internal key absent from the registry or declared `Unsafe`. A revocation entry id in deny evidence (spec 7.11) is `Safe`.
- [ ] **Step 1: Failing tests:** `undeclared_guard_evidence_field_dropped` (backing staged `receipt-disclosure-003`); `unregistered_internal_metadata_key_refuses`; `caller_metadata_dropped`; `required_operational_blocks_survive` (admission, budget authority, settlement and active-response blocks present after assembly); `receipt_marker_property` (proptest with `PROPTEST_CASES=512`: random 16-byte markers through every guard evidence producer, the metadata merge, the native evidence, response simulation and cage producers (markers placed in nested tenant, plan, finding and subject identifiers) and the `chio-siem` OCSF projection; no marker raw, hex or base64 in the signed body, evidence, metadata or OCSF; backing staged `receipt-disclosure-004`); `stream_chunk_digests_absent` (backing `receipt-disclosure-006`).
- [ ] **Step 2: Run** `cs cargo test -p chio-kernel -p chio-guards -p chio-external-guards -p chio-security-kernel -p chio-siem --no-fail-fast`, clippy. Expected: PASS.

---

### Task 9: F commits 7 to 9, FFI, WASM and mobile relays

**Interfaces:**
- Browser: `#[wasm_bindgen] pub fn sign_receipt(draft_json: &str, parameters_json: &str, content: JsValue, signing_seed_hex: &str) -> Result<JsValue, JsError>`; `content` is `{"kind":"value","value":..}`, `{"kind":"empty"}` or `{"kind":"stream","chunk_sha256":[..]}`, decoded through `lossless_serde!`; returns `{"receipt":..,"openings":<salt-only chio.receipt-disclosure.v1>}`; salts from `WebCryptoRng`. Relay exports deleted.
- Mobile: `sign_receipt(draft_json, parameters_json, content: ContentInput, signing_seed_hex) -> Result<SignedReceiptOutput, MobileError>`; UDL and Swift regenerated; relay deleted.
- C ABI: `ChioFfiResult chio_kernel_sign_receipt(const char *draft_json, const char *parameters_json, const char *content_json, const char *signing_seed_hex);` with `OsEntropyRng`; relay symbol deleted from header and `tests/abi/*.symbols`.
- TS `workers`, `edge`, `deno`: `signReceipt(draft, parameters, content, signingSeedHex): { receipt, openings }`.
- [ ] **Step 1: Failing tests:** per adapter `relay_api_has_no_hash_parameter`, `signed_receipt_opens`, `rng_failure_refuses`; Miniflare test in `sdks/typescript/packages/workers` signing with salts from `globalThis.crypto` (`WebCryptoRng::try_new` already probes `globalThis.crypto`).
- [ ] **Step 2: Run** `cs cargo test -p chio-kernel-browser -p chio-kernel-mobile -p chio-cpp-kernel-ffi --no-fail-fast`, `cs wasm-pack test --node crates/kernel/chio-kernel-browser`, the three TS packages and Miniflare, `cs bash scripts/check-chio-cpp.sh`, the Swift regeneration check. Expected: PASS.

---

### Task 10: F commits 10 to 16, cage, control-plane and BBS producers

Per-producer opening decisions for receipts that are content-checked downstream (P1-6):

| Producer | Downstream content checks | Decision | Reader after F | Fail-closed test |
|---|---|---|---|---|
| Cage | `chio-cage` receipt verification (`receipt.rs:395,410`) | (b) rebind to the audited signed `cage_receipt` (or its projection, per the P-d audit); no disclosure file and no salt copy | `cage_receipt` from signed metadata | `cage_reader_refuses_missing_metadata`, `cage_reader_refuses_tampered_metadata` |
| Native evidence | `execution_validation.inc` (two), `verify_native_security_receipt`, lineage active-defense ingest, store `security_evidence.rs`, security event consumer | (b) rebind: the producer writes the `active_defense` projection (Task 5); a reader holding the body checks `matches_projection` with the persisted projection openings and opens the content commitment; a receipt-only reader uses the projection's digests and commitments | projection from signed metadata | `native_evidence_reader_refuses_missing_projection`, `..._refuses_tampered_projection`, `..._refuses_erased_projection_opening` |
| Response simulation | `verify_response_simulation_receipt`, `verify_active_response_simulation` | (b) rebind: `verify_response_simulation_receipt` takes the report from the caller's security store, checks `report.validate()`, `matches_projection` against the signed `response_simulation` projection with the persisted openings, and opens the content commitment over the report | projection plus the held report | `simulation_reader_refuses_missing_projection`, `..._refuses_erased_opening`, `..._refuses_report_projection_mismatch` |
| Verified-fix evidence | finding verified-fix verifier, finding market (kind E) | (a) persist in the trust-control receipt store (append with openings) | opens from the store | `verified_fix_reader_refuses_erased_opening` (`Erased`) |
| Security event producer | `event_consumer/verification.rs` | (b) rebind: the producer writes the `security_event` projection (Task 5); the consumer checks `matches_projection` with the persisted openings and opens the content commitment over the body it holds | projection plus the held body | `security_event_reader_refuses_tampered_projection`, `..._refuses_erased_opening`, `security_event_projection_has_no_raw_tenant` |
| Keyring projection, SCIM deprovision | none | openings dropped; commitments permanently hiding | n/a | n/a |
| BBS selective disclosure | BBS projection verifiers | the projection's content slot carries `content_commitment.value` and its action slot the canonical `action` (commitment only) | BBS verify over the committed projection | `bbs_projection_has_no_unsalted_digest` |

Each commit converts one producer to `ChioReceipt::sign*` with a draft, preimages and its salt source, and changes its readers in the same commit. The cage takes `&dyn Rng` from its host (no `chio-kernel` dependency). Verified-fix passes the evidence body, not its hash (G3).

- [ ] **Step 1:** Per commit: convert; `<producer>_receipt_opens_with_its_preimages`; the fail-closed test in the table; `cs cargo test -p <crate> --no-fail-fast` and clippy.
- [ ] **Step 2:** `cs cargo test -p chio-control-plane -p chio-lineage -p chio-cage -p chio-selective-disclosure -p chio-store-sqlite --no-fail-fast`. Expected: PASS except golden signatures.

---

### Task 11: F commit 17, ACP proxy preimages

`sign_acp_receipt(&self, update: &AcpSessionUpdate, entry: &AuditEntry, rng: &dyn Rng) -> Result<SignedReceipt>`. Parameters: the update's canonical tool-call arguments; content: the canonical audit entry body. `entry.content_hash` stays the audit log's own field (kind D) and never reaches the signer. Telemetry and compliance bundle bounds read commitment values (kind C).

- [ ] `acp_receipt_commits_session_update_preimages` (both interceptor paths), `acp_signer_has_no_hash_input`; `cs cargo test -p chio-acp-proxy --no-fail-fast`, clippy.

---

### Task 12: F commits 18 to 21, `HttpReceipt` deletion and the HTTP middleware SDKs

**Interfaces:**
- `chio-http-core` (Root-held `receipt.rs`, D17 ACK): `HttpReceipt`, `HttpReceiptBody`, `HttpReceipt::sign`, the `ChioReceipt` projection and `caller_identity_hash` are deleted.
  ```rust
  pub struct HttpCallPreimages {
      /// `{"body": <HttpBody>, "method": .., "request_id": .., "route": <route pattern>}`
      pub request: serde_json::Value,
      /// `{"body": <HttpBody>, "status": <u16>}`; `None` before the upstream answers.
      pub response: Option<serde_json::Value>,
  }
  /// The body is always committed as the raw bytes the upstream received or returned, tagged
  /// (unambiguous by tag): `{"kind":"bytes","content_type":<string or null>,"b64u":<unpadded base64url>}`
  /// or `{"kind":"absent"}`. No JSON parsing, so the preimage is unambiguous and WYSIWYS holds.
  impl HttpAuthority {
      pub fn sign_decision_receipt(&self, draft: ReceiptDraft, preimages: &HttpCallPreimages, rng: &dyn Rng) -> Result<SignedReceipt>;
      pub fn sign_final_receipt(&self, draft: ReceiptDraft, preimages: &HttpCallPreimages, rng: &dyn Rng) -> Result<SignedReceipt>;
  }
  ```
  `tool_server = "http"`, `tool_name = "<METHOD> <route_pattern>"`. The decision receipt commits the empty output; the final receipt commits the response object.
- `chio-api-protect`: `/v1/evaluate` returns `{"receipt": <chio.receipt.v1>}` and no openings in M1 (P2-3: spec 7.7 lists no such surface, and the caller copy is an M2 cut). In mediated mode the openings persist with the append (Task 4); in sidecar mode without a store they are dropped. `spec/schemas/chio-http/v1/evaluate-response.schema.json` changes with it.
- `chio-tower` reads `SignedReceipt` and attaches the receipt only.
- Readers: `chio-bundle-verify` loses `verify_http_receipt_evidence` (item 6 part 6a moved `evidence_export/verification.rs` there and deleted the control-plane file; this PR edits the extracted verifier only); `chio-store-sqlite` `retained_read.rs` and `receipt_query_snapshot/export/metadata.rs` drop the HTTP branch.
- SDK middleware verifies the receipt with its language's shared verifier (Task 17): Python (`chio_sdk`, `chio-asgi`, `chio-django`, `chio-fastapi`, `chio-streaming`, `chio-langchain` tests), JVM (`chio-sdk-jvm`, `chio-spring-boot`), .NET (`ChioMiddleware`), TypeScript (`node-http`, `express`, `fastify`, `elysia`, `ai-sdk`, `chio-ai-sdk-middleware`, `conformance`), Go (`chio-go-http`), the ten `examples/hello-*/smoke.sh` and `scripts/tests/check-receipt-query-http.test.py`.
- [ ] **Step 1: Failing tests:** `http_final_receipt_commits_raw_bodies`; `json_body_and_raw_bytes_never_share_a_preimage` (a JSON body `{"b64u":"AA"}` and a raw `0x00` body yield different preimages; also a committed vector, Task 17); `http_decision_receipt_commits_empty_output`; `evaluate_response_carries_receipt_without_openings`; `tower_attaches_receipt`; per SDK `evaluate_response_receipt_verifies` against a recorded sidecar response.
- [ ] **Step 2: Run** `cs cargo test -p chio-http-core -p chio-api-protect -p chio-tower -p chio-bundle-verify -p chio-store-sqlite --no-fail-fast`, clippy; each Python package's `uv run pytest`; `./gradlew test` in `sdks/jvm`; `dotnet test sdks/dotnet/ChioMiddleware`; the TS packages; `(cd sdks/go/chio-go-http && go test ./...)`; the example smokes CI runs; `python3 scripts/check-trust-boundaries.py`.
- [ ] **Step 3:** `git grep -n -E "HttpReceipt|http_receipt|httpReceipt|http-receipt|caller_identity_hash" -- . ':!docs/superpowers'; test $? -eq 1`.

---

### Task 13: F commits 22 to 25, group 5 std producers

| Commit | Producer | Preimages | Openings |
|---|---|---|---|
| 22 | OTel exporter | span arguments; sanitized span attributes | dropped |
| 23 | `chio run` (four sites) | call arguments; call outcome | written beside the evidence export as `chio.receipt-disclosure.v1` (value payloads for value outputs, salt-only otherwise); the run's verifiers (kind E) open them |
| 24 | Mercury | step input; step output | dropped |
| 25 | Wall | command input; command output | dropped |

- [ ] Per commit: convert with `OsEntropyRng`; `<producer>_receipt_opens`; for `chio run`, `run_verify_refuses_missing_opening`. Add `lambda_evaluate_response_carries_no_arguments` (not a producer). Run the touched crates' tests, `cs cargo test --locked --manifest-path sdks/lambda/chio-lambda-extension/Cargo.toml`, clippy.

---

### Task 14: F commits 26 to 29, harness, conformance and fixture producers

- `chio-runtime-harness`, `chio-conformance` (native suite) and `chio-attest-loopback` producers take `&dyn Rng` from their caller. Release commands (`chio runtime loopback` and every CLI and control-plane path) pass `OsEntropyRng`. Their tests and fixture generators pass `FixtureRng` through dev-dependencies on `chio-fixture-rng`.
- Proof fixtures: `chio proof fixture regenerate` moves behind a `chio-cli` feature `proof-fixture-regenerate` that alone depends on `chio-fixture-rng` and that no release build enables. Item 1's `gen signed-fixtures` row becomes `cs cargo run -p chio-cli --features proof-fixture-regenerate --bin chio -- proof fixture regenerate`. The commerce event receipt and the agent-web re-sign take the recorded event and output bodies as content preimages (G3).
- `scripts/check-fixture-rng.py`: runs `cs cargo tree -e normal,features --target all -p chio-cli --no-default-features --features <release feature set>` and the same for every release binary and `chio-control-plane`, and fails if `chio-fixture-rng` appears; and fails if any crate depends on `chio-fixture-rng` outside `[dev-dependencies]`, xtask, or `chio-cli`'s `proof-fixture-regenerate` feature.
- [ ] `fixture_receipts_are_reproducible`; `release_loopback_uses_os_entropy` (two runs differ in salts); `cs python3 scripts/check-fixture-rng.py`; the touched crates' tests.

---

### Task 15: F commit 30, readers

OCSF 1.3.0 reads commitment values only (spec 7.13); `parameter_hash_valid`, the `parameter_hash` projection member and `source_redaction_mode` are deleted. The verdict-matrix driver asserts commitments. Store query projections and read-boundary checks use `content_commitment` (kind A/H). `chio-cli` receipt `health` and `explain` read commitments.

- [ ] `ocsf_projection_carries_commitments_only`; `cs cargo test -p chio-siem -p chio-conformance -p chio-proof-room -p chio-commerce-order -p chio-store-sqlite --no-fail-fast`, clippy.

---

### Task 16: F commit 31, cross-artifact consumers

Applies kinds C, E, E/P-ii, F, P-ii and V of the census outside the kernel; each site's replacement source is its `rules.tsv` row. Carrier members (D17 item 3), each holding a salt-only opening for exactly the named `salt_ref` and only where the carrier holds that commitment's complete preimage:

| Carrier | Member | `salt_ref` | Preimage the verifier rebuilds |
|---|---|---|---|
| commerce authority receipt artifact | `content_opening` | `content` | the event bytes in the bundle |
| settle and web3 anchor proof | `content_opening` | `content` | `settlement_anchor_receipt_content_hash_parts(...)` from public fields |
| enterprise export event | `content_opening`, `params_opening` | `content`, `params` | artifact bytes wrapped `{"kind":"bytes","b64u":..}`; `{artifact_ref, artifact_sha256, event_id}` |
| agent-web envelope | `content_opening`, `params_opening` | `content`, `params` | subject bytes wrapped as above; the envelope's parameter object |
| Mercury proof package step | `params_opening` | `params` | the step's canonical parameter object |
| attest-loopback package step | `params_opening` | `params` | `{workflowId, caseRef, tool}` from the step |
| settle finding-enforcement proof | `params_opening` | `params` | `finding_enforcement_anchor_parameters(verified)` |
| finding challenge replay evidence | `params_opening` | `params` | the expected action object the challenger rebuilds |

The finding verifier, challenge standing, open-market recovery and purchase routes hold only `payload_sha256`; they bind to the signed `delivery_contract` (kind F), never to an opening. Each carrier keeps G15's same-salt rejection per document. Tests: each E and P-ii consumer gets `<consumer>_refuses_unavailable_opening` with the explicit `OpeningUnavailable` state and `<consumer>_opens_rebuilt_preimage`; each C consumer `<consumer>_binds_commitment_value`; each F consumer `<consumer>_refuses_tampered_contract`.

- [ ] Run the touched crates' tests (`chio-federation`, `chio-attest-loopback`, `chio-attest-buyer-core`, `chio-credit`, `chio-settle`, `chio-web3`, `chio-open-market`, `chio-mercury-core`, `chio-trace-validate`, `chio-reputation`, `chio-enterprise-export`, `chio-agent-web-interop`, `chio-commerce-order`, `chio-finding-verifier`, `chio-finding-challenge`, `chio-mcp-remote`, `chio-runtime-harness`, `chio-tee`), clippy. Then the census script at the F tip finds no production line of kinds A, A0, B, C, E, E-k, A/E, E/P-ii, F, H, P-i, P-ii, R, S, V or X (each site was changed) and only kind D, GEN regenerated and DOC rewritten lines remain.

---

### Task 17: F commits 32 and 33, vectors and SDK verifiers

- `crates/core/chio-core-types/tests/committed_receipt_vectors.rs`: every `commitment_domains` entry equals the Rust constant; every case decodes or refuses as `receipt_valid` says, verifies as `signature_valid` says and opens as its `expected` says (including the delegation-context cases); Rust signing with a scripted test `Rng` yielding `fixture_salts` reproduces each positive receipt byte for byte; `empty_output` uses the zero-length preimage (regenerate through the script if #1537's `null` form remains).
- Generator additions (single-sourced): padding negatives for `parameter_commitment`, `content_commitment`, `disclosure`, `authority`, `authority.root_anchor`, the document and one opening; an HTTP case pair (`http_json_body_lookalike` and `http_raw_zero_byte`) with distinct preimages and commitments. Regeneration only adds cases.
- SDK verifiers (TS, Python, Go, C++ through the FFI, `chio-bedrock` and every SDK receipt reader in the census): `openReceipt`/`open_receipt`/`OpenReceipt`; #1716's closed layers gain the new blocks and lose the removed members, with its message form `unknown receipt member: <path>`; salts decode strictly.
- [ ] Run `cs cargo test -p chio-core-types --test committed_receipt_vectors`; `uv run --with-requirements scripts/gen-signing-wrapper-vectors.requirements.txt python3 -I scripts/gen-signing-wrapper-vectors.py write` then `check`; `cs cargo xtask freeze-vectors` then `--check`; `cs bash scripts/check-bindings-parity.sh`, `bash scripts/check-chio-py.sh`, `cs bash scripts/check-chio-cpp.sh`, `(cd sdks/go/chio-go && CGO_ENABLED=0 go test ./...)`, `(cd sdks/python/packages/chio-bedrock && uv run pytest)`, `chio-ts` typecheck and tests, `cs bash scripts/check-sdk-parity.sh`, `bash scripts/check-consumer-sdk-parity.sh`.

---

### Task 18: F commit 34, fixture regeneration

Every receipt fixture changes bytes and receipt id; every kind C artifact fixture changes its renamed member. One command, `cs cargo xtask gen signed-fixtures`, runs each owning generator until a pass changes nothing; `--check` fails without writing. Added generator rows: `committed/v1.json` (the Python script), recorded sidecar evaluate responses (`#[ignore]` regenerator in `crates/products/chio-api-protect/tests/evaluate_response_fixtures.rs`, new), and the proof-room row with `--features proof-fixture-regenerate`. The PR body lists every changed fixture and its generator.

- [ ] **Step 1:** Collect every golden failure after Tasks 6 to 17; map each to a generator.
- [ ] **Step 2:** Regenerate; run the item 1 fixture diff aid extended in `ws2:~/lanes/claude-pr1160-evidence/m1i2/diff-signed-fixtures.py`: allowed changes are the committed receipt members, signatures, ids and digests traced to a changed body, and the kind C renamed members whose new value equals the referenced receipt's commitment; a receipt whose `action` does not recompute from its recorded fixture preimage and fixture salt fails; an untraced change fails. Output in the PR body.
- [ ] **Step 3:** `cs cargo xtask gen signed-fixtures --check`, `cs cargo xtask freeze-vectors --check`, `cs cargo run -p chio-cli --features proof-fixture-regenerate --bin chio -- proof fixture regenerate --check`.

---

### Task 19: F commit 35, PROTOCOL and docs

- [ ] Move `protocol-6-committed-receipts.md` into `spec/PROTOCOL.md` after "Receipt Identity And DAG"; delete the staged file, its comment, status and "Sections in force" lines; keep only the export-profile text this PR implements; apply the spec amendments the owner approves (open questions 2 and 9); rewrite the section 6 field table and "WYSIWYS Signing Invariant"; delete HTTP receipt text in `spec/HTTP-SUBSTRATE.md`, `spec/OPENAPI-INTEGRATION.md`, `spec/WIRE_PROTOCOL.md`.
- [ ] `git grep -n -E "HttpReceipt|content_hash|parameter_hash|redaction_mode|RedactionMode|sign_receipt_relaying_trusted_body|caller_identity_hash" -- docs spec sdks/*/README.md crates/*/*/README.md ':!docs/superpowers'`, then the em-dash, public-path, `check-chio-owned-v1-only.sh`, `check-native-host-docs.py` and `cs cargo test -p chio-spec-validate` checks.

---

### Task 20: Formal touchpoints and coverage (each PR; last commit of F)

- [ ] Kani: update `kani_public_harnesses.rs` and the `#[cfg(kani)]` blocks for the fallible `Rng` (P-a) and the committed signer (F); remove `sign_receipt_relaying_trusted_body` entries from `kani-public-harnesses.toml`; add `receipt_commitment_layout` over a pure `assemble_commitment_input(domain: &'static [u8], salt: [u8; 32], preimage: [u8; 8])` on fixed buffers (F).
- [ ] `cs cargo xtask check formal-mirrors`. If `Receipt.lean` names `content_hash` or `parameter_hash`, F edits it and the Lean gates run on the x86 runner only.
- [ ] After each PR's final rebase: `cs cargo xtask gen proof-coverage` then `--check`; commit `docs/formal/COVERAGE.md` last.

---

## D17 Coordination

F changes the signed bytes of every `chio.receipt.v1` receipt and deletes the only other receipt artifact. The precursors change no signed byte. Root-2 and the lead check this list before F opens.

Signed artifacts whose bytes change in F:
1. Every `chio.receipt.v1` receipt and every receipt id (`ChioReceiptIdInput` contains the body), and transitively every artifact embedding a receipt id, digest or whole receipt: child receipts, lineage statements, checkpoints and inclusion proofs, evidence export manifests and their commitments, commerce authority receipt artifacts, session compliance certificates, proof-room graph nodes, passports and bundle manifests.
2. Kind C consumer artifacts, whose renamed member now carries a commitment value: verified treaties (`outcome_commitment`), federation bilateral DSSE envelopes and cosign bindings, attest loopback issuance requests and packages, attest buyer reports, IOU receivables, settlement observations (#1705), child contracts, runtime-harness buyer closures and proof parity records, verified-fix nonce bindings, ACP telemetry and compliance bundles, BBS selective-disclosure projections, TEE tap and runner records, `chio run` nonce evidence.
3. Carriers gain salt-only opening members (Task 16 table): commerce authority receipt artifacts, settle and web3 anchor proofs, enterprise export events, agent-web envelopes, Mercury and attest-loopback package steps, settle finding-enforcement proofs, finding challenge replay evidence. Signed metadata changes: `active_defense_body` is replaced by the `active_defense` projection, `response_simulation_report` by the `response_simulation` projection, `security_event_projection` by the `security_event` projection, `cage_receipt` per its audit, kept low-entropy digests become keyed digests, and a non-finding `delivery_contract.observed_digest` becomes a salted commitment. `DeliveryAcknowledgement.result_hash` becomes `result_commitment`.
4. `HttpReceipt` is deleted; `/v1/evaluate` carries `chio.receipt.v1` without openings; every HTTP middleware SDK and example changes.
5. Relay APIs (browser, mobile, C ABI, TS workers, edge and deno, Swift) change.
6. The receipt body gains `tenant_binding` for the native evidence, response simulation and cage producers, which stop setting `tenant_id`; their signing and reading processes load the tenant index key.
7. Trust-control (P-f, before P-c): caller credentials with scopes and tenant authority replace `service_token` and `tenant_read_tokens`; `/v1/internal/*` routes move to an internal listener; cluster peers use pinned Ed25519 keys. Every deployment's trust-control configuration changes once.
8. `SignedReceipt.tenant` travels unsigned beside the receipt on the remote append, cluster deltas and snapshots, and in the admission row; every node holds the deployment's tenant index key set.
9. Store: `chio_tool_receipts.content_hash` becomes `content_commitment` in place, the admission operation row gains the two commitment columns, `receipt_openings` is used; the trust-control append request carries openings.

Changes before F (no signed bytes): P-a moves `Rng` and makes it fallible; P-b adds types; P-c adds `receipt_openings`, `opening_status`, `read_openings` and `erase_openings` on all 58 `ReceiptStore` impls, the public status route, the internal opening read, the erase route and cluster tombstone replication (no append change); P-b adds the `TenantBinding` and `TenantIndexKey` types; P-e refuses duplicate JSON keys before `Value`; P-d adds `evidence_declaration` to every guard and the metadata registry. In-flight branches that implement `Rng`, a guard, a receipt store or a metadata key rebase on these.

Root-held files (Root-2 ACK before the lane edits them):
- `crates/platform/chio-http-core/src/receipt.rs` (deleted in F).
- `crates/kernel/chio-kernel/src/tool_outcome/caller_delivery.rs` and `tool_outcome/security_release/context.rs` (kind A0).
- `crates/kernel/chio-kernel/src/admission_operation/projection/authorization.rs` (kind P-i: `operation_payload`, `session_id`, `tool_call_id` and `authorization_parameter_hash` from the authorization operation's admission row) and `crates/kernel/chio-kernel/src/kernel/evaluation/delivery_preparation.rs` (kind P-i, launch state).
- `crates/kernel/chio-kernel/src/kernel/admission_coordinator.rs` and `admission_coordinator/**`, `admission_operation/**`, the `admission_operation_store` and `dispatch_ledger/policy.rs` that consume the admission binding (kind A).
- `crates/platform/chio-store-sqlite/src/serving_owner*` and the receipt store publication path (Task 4).
- `crates/kernel/chio-kernel/src/kernel/construction.rs` and `kernel_struct.rs` (also edited by #1708).
- `crates/tooling/chio-bundle-verify` verification module (moved there by 6a; item 2 edits only the extracted verifier).
- `crates/platform/chio-control-plane/src/trust_control/cluster/{deltas.rs,snapshots.rs,partition.rs}` (openings stream, cursor, snapshot import), `report_validation.rs` (`validate_cluster_peer_auth`, the per-peer credential) and the trust-control receipt routes.

Shared files with in-flight work:
- #1723 (`852c60127f`): the shared decoder; lands first, and #1715 and #1706 rebase onto it.
- #1715 and #1716: receipt structs, `receipt_strict_decode.rs`, the commerce authority decoder, SDK `invariants/receipt.*`. Both land first.
- Item 1: lands first; F signs through `sign_wrapped` and regenerates through its command, with the proof-room row's feature change.
- Item 6 part 6a: lands first; F edits `chio-bundle-verify`, never `evidence_export/verification.rs`.
- #1706: lands first; F and P-b reuse `SaltRef`, `Sha256Digest`, `RootAnchor`, `HolderClass`; `receipt_openings` accepts `anchor.claims.*`.
- #1674: lands first; receipt signing files shared.
- #1705 (settlement observations): `observation_for` and `tests/settlement_observer_byte_identity.rs`; lands before F; F renames `SettlementObservation.content_hash` to `content_commitment` and rewrites the byte-identity test's expected bytes through its generator.
- #1710 (settlement ledger hook): lands before F (explicit). F keeps its seeding, durable append and drain reconciliation tests with exact receipt references after id changes.
- #1708 (concurrent publication): lands before P-c; openings are written inside the store-owned append under its fence and receipts guards, with no new lock, rank or callback; the projection guard and visibility boundary are unchanged.
- #1682 (C6) and #1717: store receipt and query snapshot files, including the adjacent `receipt_query_snapshot/project.rs` and `receipt_store/evidence_retention.rs` that F changes.
- K-stack (#1675, #1678, #1701, #1269, KERN-TRACE-LOCK-FSYNC): merged before item 1; F keeps every K-stack invariant test's assertions.
- #1722 (subtree cancellation, draft at `188a6af6ff`) and the store schema-adoption cleanup (no PR yet; the last serial store item): predecessors of P-c and F (Root-2 condition 7).
- #1607: shares the registry, `MANIFEST.sha256` and `wire-schemas.lock`; lands first.
- Item 3: follows F and fills `ReceiptAuthority` from verified capability state.

Fixtures whose bytes change in F: every receipt-bearing set in item 1's Task 11 table (893 JSON files carry `content_hash` at the census base, 861 under `fixtures/proof-room/`), the Rust golden receipts in about 189 test files, `tests/bindings/vectors/receipt/v1.json` and `MANIFEST.sha256`, the kind C and kind E artifact fixtures, the new evaluate-response fixtures, and `committed/v1.json` (added cases only).

Merge order: as under Global Constraints. The census and every signed fixture are refreshed at F's integrated base.

## Verification

Run at each PR's head after its final rebase. Every cargo command, direct or nested, runs under `cs`. Coder checks on ws2; heavy suites on `integ-x86` and `integ-h3`. Logs under `ws2:~/lanes/claude-pr1160-evidence/m1i2/<pr>/` with sha256 in the PR body.

**Every PR (P-a to P-d and F).** For every crate in `git diff --name-only origin/main...HEAD -- crates`: `cs cargo test -p <crate> --no-fail-fast` and `cs cargo clippy -p <crate> --all-targets -- -D warnings`. Plus `cs cargo check --locked --workspace --all-targets`, `--all-features`, `cs cargo fmt --all --check`, and `cs cargo xtask gen signed-fixtures --check` (precursors: no change; F: after regeneration).

**F additionally.** `cs cargo test -p chio-core-types --features fips,pq --no-fail-fast`, `cs cargo test -p chio-core-types --no-default-features --lib`, `cs cargo test -p chio-kernel --test durable_admission_sqlite`, and the CLAUDE.md one-liner once at the final tip with each step under `cs`: `cs cargo build --workspace && cs cargo test --workspace && cs cargo clippy --workspace -- -D warnings && cs cargo fmt --all -- --check`.

**Native-cage chio-cli and chio-conformance (required for P-a, P-c, P-d and F; lane-common "CLI/conformance full runs need the native cage").** Full suites on host 3 (or x86) with the setup copied from `ws2:~/lanes/claude-pr1160-evidence/root2/k6/verify-native-final-fa34a7dc65.sh`: self-contained node 24 and npm 9.2.0 first on `PATH`; `cs cargo build --locked --target x86_64-unknown-linux-musl -p chio-cage-init --bin chio-cage-init --features real-linux-enforcement` and `CHIO_CAGE_INIT` exported to it; the privileged `enforced_discovery` test; `scripts/prepare-native-python-runtime.py` and `scripts/prepare-enforced-native-fixture.py` with the fixture env exported; `CHIO_CAGE_SYSCALL_PROFILE=native-standard-v1`; `CHIO_CHECKOUT_ROOT` set; then `cs cargo test --locked --no-fail-fast -p chio-conformance` and `cs cargo test --locked --no-fail-fast -p chio-cli`. Required: rc=0 for both. Environment-only failures are not accepted.

**Final qualification at the new main (F).** At the `origin/main` commit F merges onto, recorded by SHA: the suites above, the stop-error MCP routes (#1701), the CLI transport paths, `chio mcp serve-http` with `--auth-token` against the conformance peers, `chio mcp serve --control-url` against a live trust-control, and `chio api protect` in sidecar and mediated modes.

**Gates.**
```bash
python3 scripts/check-security-clocks.py && python3 scripts/check-escape-hatches.py && python3 scripts/check-negative-assertions.py \
 && python3 scripts/check-trust-boundaries.py && python3 scripts/check-rust-file-hygiene.py && bash scripts/check-http-egress-contract.sh \
 && python3 scripts/check-error-urn-registry.py && cs bash scripts/check-adapter-no-bypass.sh \
 && python3 scripts/check-domain-separation.py && python3 scripts/check-signing-exemptions.py \
 && cs python3 scripts/check-fixture-rng.py && python3 scripts/check-receipt-trace-negative-registry.py \
 && python3 scripts/check-kani-crypto-scope.py && python3 scripts/check-kani-public-harnesses.py
```

**Wire-schemas, schema-registry and freeze gates.**
```bash
python3 scripts/check-wire-schemas.py && bash scripts/tests/check-wire-schemas.test.sh
bash scripts/check-chio-schema-registry.sh && bash scripts/tests/check-chio-schema-registry.test.sh && bash scripts/check-chio-owned-v1-only.sh
uv run --with jsonschema==4.26.0 --with referencing==0.37.0 python3 -I scripts/check-root-authority-schema-examples.py
python3 scripts/check-security-wire-vectors.py
cs make -C ~/lanes/m1i2-<pr> codegen-check && cs cargo xtask snippets regen --check
cs cargo xtask freeze-vectors --check
uv run --with-requirements scripts/gen-signing-wrapper-vectors.requirements.txt python3 -I scripts/gen-signing-wrapper-vectors.py check
cs cargo xtask gen signed-fixtures --check
cs cargo run -p chio-cli --features proof-fixture-regenerate --bin chio -- proof fixture regenerate --check
cs cargo xtask eval-receipt-regen --check
cs cargo test -p chio-conformance --test vectors_schema_pair --no-fail-fast
cs cargo test -p chio-binding-helpers --test vector_fixtures --no-fail-fast
```
If `Cargo.lock` changes (P-a adds `chio-fixture-rng`; `rand_chacha` is already in the lock): the Cargo.lock digest pin in `scripts/check-security-ci-contract.py` and `deploy/docker/Dockerfile.security-evidence-runner`, `git lfs pull` per lane-common, `cs python3 scripts/check-security-ci-contract.py`, `cs python3 scripts/check-aws-lc-fork.py`, and the cargo-deny and cargo-vet checks with the duplicate baseline.

**Formal-mirrors and Kani.** `cs cargo xtask check formal-mirrors`. Kani 0.68 runs only on the approved x86 runner under `cs`, detached with `setsid -f` and a pid file through `~/lanes/claude-pr1160-evidence/q.sh ... < /dev/null`: every harness in the manifest plus `receipt_commitment_layout` (F). No Kani, Lean, lake or Aeneas on ws2. `cs cargo xtask gen proof-coverage --check` last.

**SDK builds (P-b and F).** `cs bash scripts/check-bindings-parity.sh`, `bash scripts/check-chio-py.sh`, `cs bash scripts/check-chio-cpp.sh`, `(cd sdks/go/chio-go && CGO_ENABLED=0 go test ./...)`, `(cd sdks/go/chio-go-http && go test ./...)`, `(cd sdks/k8s/webhooks && go test ./...)`, `uv run pytest` in every touched Python package, `./gradlew test` in `sdks/jvm`, `dotnet test sdks/dotnet/ChioMiddleware`, the TS packages' tests, typecheck and lint (with `workers`, `edge`, `deno` and Miniflare under `cs` when they reach cargo or wasm-pack), `cs wasm-pack test --node crates/kernel/chio-kernel-browser`, the Swift regeneration check, `cs bash scripts/check-sdk-parity.sh`, `bash scripts/check-consumer-sdk-parity.sh`, `python3 scripts/tests/check-consumer-sdk-inventory.test.py`, `cs cargo test --locked --manifest-path sdks/lambda/chio-lambda-extension/Cargo.toml`, and every `examples/hello-*/smoke.sh` CI runs.

Pre-existing reds on `main` are reported with `main`'s result at the same base.

## Verdict-matrix scope

The staged `receipt_disclosure` category stays staged. Every scenario in it starts `serve_http_edge` with a `root_policy`, a `tenant_index_key` and the `rust-mcp-serve-http` driver, none of which exist before items 4 and 7, and 007 to 010 are export scenarios that item 6 implements. F lands the kernel-level behavior and tests behind 001 to 006 and registers `urn:chio:error:attest:receipt-tenant-id-with-authority`. The category moves with the driver (open question 4).

## Amendment A1: value-carrying metadata fields, guard error text and the cage projection

Status: proposed amendment to the merged plan, written against Root-2's decisions for #1727 (`root2/decision-1727-metadata-split-and-projections.md`) and the lead's #1727 review. **F stays stopped until this amendment merges.** No F commit that switches on metadata refusal (Task 8) or signs a block below in a new form lands before it.

### Rules (Root-2 decision 2)

- **Salted commitment is the default** for every field that carries a caller or tool value, or an unsalted digest whose preimage is low-entropy or contains such a value.
- A field stays **plaintext only in a minimal typed projection**, only when a **named downstream reader** needs it in plaintext, and only when the value is a closed code, or is entropy-backed (drawn from the `Rng` seam) or keyed (an operator key). The registry records it `CommittedSafe` with that reader and a Safe reason. A deterministic id or digest whose preimage holds a caller, provider or low-entropy value is committed even when Chio computes it. No blanket block-level Safe classification.
- **Derived digests and copies follow their inputs.** A retained plaintext digest whose preimage includes a committed field is itself committed or keyed, and a committed value is never copied into another plaintext key. `digest_aliases.py` (below) censuses every digest-named receipt metadata field, every carrier of the governed intent hash and every read of a committed source value in the receipt producers; each line has a rule stating its preimage and decision.
- **Fields with no reader are committed** (OQ-A1-1, Root-2), including closed codes and Chio ids.
- **No silent drop and no fallback.** A removed field is either committed or replaced by a named projection field; a reader that needs a value it can no longer read refuses with a named error. A present block that does not decode refuses (for `financial`, `MalformedFinancialMetadata`) and is never read as absent. Unregistered keys stay refused (P-d); that holds for hook metadata only once the reserved-key PR adds the check to the hook merge at `runtime_admission.rs:48`.
- **Entropy failure denies:** a salt draw failure refuses signing (Task 2 `RngError`), for metadata salts as for parameter and content salts.
- **Raw evidence and openings stay private under disclosure authority.** Salts live in `receipt_openings`; operator-readable plaintext lives in `receipt_metadata_values`; both are read only by the operator's own store and by callers with the `receipt-openings:read` credential scope (Task 4). Neither is published beside a public commitment, except a salt-only opening in a carrier that already holds the complete preimage (OQ9 wording).

### Mechanism

- **No whole-block commitments.** Every block is split by field; each committed field has its own salt and `salt_ref`. The rows below follow the lead's #1727 review addendum (b) and were checked against the census.
- `MetadataCommitment { alg: CommitmentAlg, value: Sha256Digest, salt_ref: SaltRef }` (the receipt commitment shape), `salt_ref` `metadata.<block>.<field>` (#1706 grammar; a camelCase key uses its snake_case form, e.g. `metadata.wall_guard_outcome.reason`; every `salt_ref` below is at most 64 bytes), domain `chio.receipt.metadata.v1\0 || utf8(salt_ref) || 0x00`, so a metadata opening cannot stand in for a parameter, content or other metadata opening. Preimage: the canonical JSON of the field value. The salt is drawn with the receipt's other salts and refused when equal to any of them.
- The salt goes to `receipt_openings` and the plaintext value to the new erasable `receipt_metadata_values` table, both in the receipt's append transaction (Task 4), replicated with the receipt and erased together (one transaction, tombstones on the openings stream).
- Openings: an operator store reader opens with its own rows; a remote reader uses `POST /v1/internal/receipts/openings/read` with `receipt-openings:read`; an in-process reader uses `SignedReceipt.openings` at signing; an external verifier opens only with a carried opening under OQ9.
- Refusal vocabulary: `OpeningUnavailable { Erased | Unknown }`, `MetadataCommitmentMismatch { salt_ref }`, `ReceiptMetadataUnavailable { block, field, state: Erased | Missing }`. **Every erased or missing value refuses.** A reader that needs a committed value whose values row or opening is erased or missing returns `ReceiptMetadataUnavailable` for that receipt; it never substitutes a default, an empty value or a signed field. A report over many receipts returns that refusal as the row for the affected receipt and does not render the field.
- **Derived copies are ephemeral.** No store persists a plaintext copy derived from a values row. The claim log's authorization details (`claim_log/metadata.rs:186-225`, `claim_log/authorization.rs:223,307,410`) stop persisting `purpose`, the payment token and the asserted call chain: the persisted claim-log row keeps the `salt_ref`s, and the plaintext details are materialized on read from the values rows, under the same access as the values table (the operator's own store, or the internal read with `receipt-openings:read`). Erasure of the values row therefore leaves nothing to read, and the next read refuses. Replication carries values rows and their tombstones, never a materialized copy. Test `derived_details_follow_values_erasure`: append, read (details present), erase, read (refuses), replica import of the erased state (refuses), replica import before erasure followed by the tombstone (refuses).

`receipt_metadata_values` DDL, probed with `/usr/bin/sqlite3` 3.51.0 (13 of 13 cases as expected; `docs/superpowers/plans/m1-item2-census/metadata-blocks/values-ddl.sql`, `values_probe.py`, `values-probe-result.json`, sha256 `c4a6295c49fdb9401b833bd7c2347a8add05f15e64993d16d6c7bef98428785f`):

```sql
CREATE TABLE receipt_metadata_values (
  receipt_id TEXT NOT NULL CHECK (typeof(receipt_id) = 'text' AND instr(receipt_id, char(0)) = 0 AND length(CAST(receipt_id AS BLOB)) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
  salt_ref TEXT NOT NULL CHECK (typeof(salt_ref) = 'text' AND instr(salt_ref, char(0)) = 0 AND length(CAST(salt_ref AS BLOB)) BETWEEN 10 AND 64 AND salt_ref GLOB 'metadata.[a-z]*' AND salt_ref NOT GLOB '*[^a-z0-9_.]*' AND salt_ref NOT GLOB '*..*' AND salt_ref NOT GLOB '*.'),
  state TEXT NOT NULL CHECK (typeof(state) = 'text' AND instr(state, char(0)) = 0 AND state IN ('present', 'erased')),
  value TEXT,
  state_at INTEGER NOT NULL CHECK (typeof(state_at) = 'integer' AND state_at >= 0),
  CHECK ((state = 'present' AND typeof(value) = 'text' AND json_valid(value)) OR (state = 'erased' AND value IS NULL)),
  PRIMARY KEY (receipt_id, salt_ref)
) WITHOUT ROWID;
```

### Census

`docs/superpowers/plans/m1-item2-census/metadata-blocks/metadata_blocks.py` lists, at `bc5579aaf4`, every non-test line under `crates` and `sdks` naming one of 26 blocks by literal, by a constant whose value is the key, or by a typed accessor (`financial_metadata()`, `governed_transaction_metadata()`, `delivery_contract()`), with its role (writer, reader, constant, other). Every reader and writer line matches a rule in `rules.tsv`. It fails closed: exit 2 on a git failure, exit 1 on a non-commit revision, an empty block or an unclassified reader or writer; `--self-check` requires a nonexistent revision and an empty rule set to exit nonzero (both do). Output `blocks-bc5579aaf4.tsv`: 314 lines, 26 blocks, 0 unclassified. Lines whose literal is unrelated (a provider `stream` flag, the `otel` cargo feature, the `acp` payment adapter) are classified `unrelated` by rule. Field-level readers reached after a typed decode are named in the table from a direct grep of the field. The settlement readers of #1705 (head `afe49dcd0e`) and #1710 (head `cbd953833f`) are listed at those heads. The `rules.tsv` notes state the decided per-field form of each row.

`docs/superpowers/plans/m1-item2-census/metadata-blocks/digest_aliases.py` censuses derived digests and copies at `bc5579aaf4`. It lists every non-test line of three kinds:

- `field`: a digest-named field of a signed receipt metadata type under `chio-core-types/src/receipt/`.
- `intent`: a struct field or JSON key carrying the governed intent binding hash.
- `copy`: a read of a committed source value in the receipt producer files.

Each line must match a rule in `digest-rules.tsv` stating its preimage, whether the preimage holds a committed field, and the decision. The script fails closed the same way: exit 2 on a git failure, exit 1 on a non-commit revision, a kind with no lines, or an unclassified line. Its `--self-check` refuses a nonexistent revision and an empty rule set. Output `digests-bc5579aaf4.tsv`: 177 lines (61 field, 85 intent, 31 copy), 0 unclassified.

### Per-field table

Columns: the field; its producer; every reader and whether it needs plaintext; the retained projection (plaintext, with the named reader and Safe reason) or the commitment; the opening path; the refusal when the value or opening is missing or wrong. "Store" means the operator's own `receipt_openings` and `receipt_metadata_values` rows.

**`financial`** (writers: kernel responses, validation and evaluation, 31 census lines incl. `terminal.rs:1422`, `reconciliation.rs:398-403`, `tool_output.rs:521,577`, `finding_verified_fix.rs:1342`, `iou_store.rs:397`)

| Field | Readers (plaintext need) | Projection or commitment | Opening | Refusal |
|---|---|---|---|---|
| `cost_charged`, `currency` | settlement: `settlement_observer.rs:113,258-300` (#1705, #1710), `settlement_ledger.rs:46-100` (#1710), `reconciliation.rs:352-370` (#1710); credit `local_account.rs:165`, `receivable_iou.rs:775`; `channel/state.rs:359`, `channel_terminal.rs:579`, `participant_evidence.rs:577`, `remote_projection.rs:896`; claim log `claim_log/metadata.rs:156,175`, `schema.rs:74`; SIEM `event.rs:96`, `sink_projection.rs:127`; finding `standing.rs:191`, `cost.rs:87,132`; `authoritative_spend.rs:39` (all need plaintext) | **Settlement projection**, `CommittedSafe`: the kernel-computed charge settlement must reconcile against the payment rail; not a tool value | none | unchanged reader errors (`settlement_observer.rs:267-300`) |
| `settlement_status`, `payment_reference` | `settlement_observer.rs:305-337,820-848` (#1705, #1710), `settlement_ledger.rs:46-100,98` (#1710) | **Settlement projection**, `CommittedSafe`: kernel settlement state and the rail transaction id (`hold.reserved_payment_reference`), read by settlement and the ledger transcript | none | unchanged |
| Retained-payment shape on a denied receipt: `payment_authorization_ambiguous`, `payment_authorization_error_code`, `payment_attempt_reference` (writers `async_evaluation_core.rs:1550-1560`, `nested_flow_evaluation.rs:1225-1227`) | `retained_payment_settlement`, `settlement_observer.rs:113-145` (#1705, #1710), which requires the attempt reference | **Settlement projection**, `CommittedSafe`, as the `RetainedAmbiguous` variant below. The error code is a closed code (`unavailable`, `rail_error`, `declined`, `insufficient_funds`, from `async_evaluation_core.rs:1477-1482`). The attempt reference is `payment_operation_reference` (`dispatch.rs:1043-1052`): the durable operation id for an operation with a payment requirement, else the request id. F requires the durable operation id on this path (a payment authorization only runs for an operation with a payment requirement) and refuses signing otherwise; the id-entropy test covers it | none | missing attempt reference refuses as today (`"retained payment requires a payment attempt reference"`); an undecodable block refuses `MalformedFinancialMetadata` |
| `grant_index`, `budget_remaining`, `budget_total`, `delegation_depth`, `root_budget_holder`, `attempted_cost`, `oracle_evidence` | credit, channel, projection, claim log and finding readers above (budget and grant accounting) | **Accounting projection**, `CommittedSafe` per field with its readers: kernel-computed budget, grant and conversion state | none | unchanged |
| `cost_breakdown`, split at both tool-value writers. `tool_output.rs:521-527` merges the tool-reported `cost.breakdown` with the kernel `payment_breakdown` and the cross-currency note; `reconciliation.rs:398` writes the tool-reported `realized_cost.breakdown` (`reconciliation.rs:152`) alone | kernel recovery check `terminal/financial_receipt.rs:18,118` compares it with `payment_cost_breakdown(..)`; `terminal.rs:521-527` copies the persisted block for byte-exact replay; `effect_obligation/preparation.rs:307-320` copies kept fields | `cost_breakdown` keeps only kernel content (the payment breakdown and the cross-currency note): **Projection**, `CommittedSafe` with those readers. The tool-reported breakdown from either writer moves to `reported_cost_breakdown`, a **commitment** `metadata.financial.reported_cost_breakdown`; a reconciled receipt has no kernel breakdown, so its `cost_breakdown` is absent | the recovery check compares kernel-derived values only and needs no opening. The journal path that recovery checks never carries the cross-currency note (the note arises only on a metered or oracle conversion); F pins that with a test, so a recovered receipt with a note mismatches and refuses as today. The operator opens the reported part from its values row | recovery mismatch refuses as today; an erased reported part refuses its reader with `ReceiptMetadataUnavailable` |

The settlement readers move from `metadata.get("financial")` field picks to a typed enum read by a new decoder, `financial_settlement_projection()`, not by `financial_metadata()` (which decodes `FinancialReceiptMetadata` and cannot decode the partial denied block):

```rust
pub enum FinancialSettlementProjection {
    Charged { cost_charged: u64, currency: String, settlement_status: SettlementStatus, payment_reference: Option<String> },
    RetainedAmbiguous { payment_authorization_error_code: PaymentAuthorizationErrorCode, payment_attempt_reference: String },
}
```

The decoder returns `Ok(None)` only when the receipt has no `financial` key, and `Err(MalformedFinancialMetadata)` for a present block that matches neither variant exactly (`deny_unknown_fields`). Readers never read `cost_breakdown` or `reported_cost_breakdown`. Test `ambiguous_denied_receipt_yields_retained_payment`: a denied receipt from the ambiguous authorization path, through #1705's `retained_payment_settlement`, produces a `RetainedPayment` observation after F; a malformed block refuses. `budget_authority` (`hold_id`, `authorize.exposure_units`, read at `settlement_observer.rs:98,138,869-870`) is already `CommittedSafe`; its kept fields are named in the registry reason. #1705 rebases onto the projection type in F (D17); #1710's readers follow the atomic rule below.

**`governed_transaction`** (writers: `receipt_metadata.rs:473,534,586,600`, `validation.rs:1726,1785`; conformance `native_suite.rs:465`)

| Field | Readers | Projection or commitment | Opening | Refusal |
|---|---|---|---|---|
| `purpose` | store claim log `claim_log/metadata.rs:186-225`, `claim_log/authorization.rs:307` (authorization details) | **Commitment** `metadata.governed_transaction.purpose` (caller text) | details are materialized on read from the values row (derived copies are ephemeral, above) | missing or erased refuses the authorization-details read with `ReceiptMetadataUnavailable { purpose }` |
| `commerce.shared_payment_token_id` | `claim_log/metadata.rs:220`, `claim_log/authorization.rs:307` (copies it and requires it non-empty) | **Commitment** `metadata.governed_transaction.payment_token` | as above; the non-empty check runs on the values row | missing or erased refuses with `ReceiptMetadataUnavailable { payment_token }`, as an empty token refuses today |
| `economic_authorization.payer.funding_source_ref` (set from the token at `receipt_metadata.rs:402`) | `chio-credit/receivable_iou.rs:916-918` (`funding_source_ref != facility_id` on a `credit_facility` rail) | **Commitment** `metadata.governed_transaction.funding_source_ref` | none needed: no production producer writes `rail.kind == "credit_facility"` today, so the only path to this reader is a token-funded receipt, and after F it refuses with `BindingMismatch` (fail-closed). A future credit-facility producer writes the operator-assigned facility id to a `CommittedSafe` projection field with this reader | `BindingMismatch` |
| `economic_authorization.rail.contract_or_account_ref` | `receivable_iou.rs:918` | **Projection**, `CommittedSafe`: the rail transaction id `payment_reference` only. The token fallback at `receipt_metadata.rs:420-423` (`.or_else(|| Some(shared_payment_token_id))`) is deleted: with no payment reference the field is `None` | none | test `payment_token_never_copied_to_plaintext_key`: a token-funded receipt with no payment reference carries the token in no plaintext field |
| `intent_hash`, and its alias `economic_authorization.economic_intent_digest` (`receipt_metadata.rs:393`, equal to the intent hash via `governed_validation.rs:1571-1575`) | `participant_evidence.rs:591,600,612` (compares with the operation row and the credit atom), `receivable_iou.rs:882` (IOU binding), `call_evidence/export.rs:117`, `claim_log/authorization.rs`, `claim_log/metadata.rs`, `native_suite.rs:1157` | **Commitment** `metadata.governed_transaction.intent_hash`, see "Governed intent hash" below; both locations carry the one commitment value | see below | see below |
| `call_chain`, every member except `evidence_class` (`session_anchor_id`, `receipt_lineage_statement_id`, asserted parent request and receipt ids, actor and hop data) | `claim_log/metadata.rs:281`, `claim_log/authorization.rs:223,410`, `receipt_store/reports.rs:81-203`, `support/lineage.rs:951` (lineage statements), underwriting `policy_support.rs:641` | **Commitment** per member `metadata.governed_transaction.call_chain_<member>`. `GovernedCallChainProvenance` has a `session_anchor_id` and no anchor hash, and it carries caller-asserted ids, so nothing in it passes the entropy test. `evidence_class` is a closed code read by the reports and stays in the projection | store values rows | missing or erased refuses the reader with `ReceiptMetadataUnavailable` |
| `intent_id`, `server_id`, `tool_name`, `max_amount`, `approval` (incl. `approval_artifact_digest`, a digest over the approver-signed token, keyed by the approver's signature), `runtime_assurance`, `autonomy`, `metered_billing` (`quote_hash`, `meter_profile_hash` over the provider quote), `commerce.seller`, `commerce.settlement_destination_ref`, `economic_authorization.payee_binding_digest` (over seller and destination, both kept) and `pre_action_authority_digest` (equal to `approval_artifact_digest`) | core `body.rs:603` (typed accessor), `receivable_iou.rs:868-877`, `participant_evidence.rs:520,569-600`, `finding-verifier/verify.rs:1657` | **Projection**, `CommittedSafe` per field with these readers. `intent_id` is kept only if the id-entropy test shows the kernel mints it from the `Rng` seam; otherwise it is committed. P-d part 2 records each preimage in `digest_aliases.py`'s rules | none | unchanged |

**Session anchor lineage (Root-2 #1728 item 2).** No producer writes a session anchor hash: `GovernedCallChainProvenance` carries only `session_anchor_id`, and the parent-anchor lookup (`kernel/mod.rs:849-880`) needs both an id and a hash. Today only the caller-supplied `lineageReferences` fallback can satisfy it. The reserved-key PR deletes that fallback. After that, the persisted-parent branch of `governed_validation.rs:966-990` (`LocalReceiptArtifact::session_anchor_reference`) has no authoritative source and refuses with the existing "could not be verified against authoritative parent lineage" denial. The live-parent branch, which reads the anchor from the in-memory parent session (`session.session_anchor().reference()`), stays the positive control, with a test. A1 claims no persisted-parent producer. Supporting persisted parents needs a typed, kernel-written anchor reference specified and tested on its own; the existing manually signed fallback fixture is deleted, not repaired.

**`governed_transaction_diagnostics`** (writer `receipt_metadata.rs:68-85,609`; readers `receipt_store/reports.rs:65`, `operator_report/authorization_context.rs:322,407`, `behavioral_analysis.rs:102`): `asserted_call_chain` and both `lineage_references` members (`session_anchor_id`, `receipt_lineage_statement_id`, copies of `call_chain` members) become **commitments** `metadata.governed_transaction_diagnostics.<member>`, read by the operator reports from the values rows; missing or erased refuses the report row. The top-level `lineageReferences` fallback in `kernel/mod.rs:869-877` is deleted in the reserved-key PR, so no reader takes lineage from caller metadata.

**`receipt_context`** (kernel writers `return_context.rs:78`, `post_effect.rs:228`, `preparation.rs:149`, `receipt_persistence.rs:177`, `receipt_identity.rs:80`; ACP writers `kernel_signer.rs:532`, `kernel_checker.rs:264`)

| Field | Readers | Projection or commitment | Opening | Refusal |
|---|---|---|---|---|
| `request_id`, `request_namespace_digest`, `evaluation_id`, `session_id` | 13 readers: `projection/authorization.rs:62`, `receipt_identity.rs:70`, `allow_responses.rs:890`, `call_evidence.rs:301,389`, `run_evidence/custody.rs:93`, `process_response_verify.rs:212`, `chio-cross-protocol/execution.rs:242`, `completed_result.rs:140`, `chio-trace-validate` `capture.rs:602`, `observation.rs:269`, `acp-proxy/kernel_signer.rs:282` | **Projection**, `CommittedSafe`, with these readers, only for values the id-entropy test shows are entropy-backed or keyed (the request namespace digest and kernel-issued ids); a request id the caller chooses is committed and its readers open it from the store | none for kept fields | a committed request id with a missing or erased opening refuses its reader |
| ACP `authorization_resource` | `acp-proxy/kernel_signer.rs:342` compares it | **Commitment** `metadata.receipt_context.authorization_resource` (from the tool call) | proxy opens over the resource in its own authorization request record | `MetadataCommitmentMismatch` refuses the session update |

**`stream`** (writers `finalization.rs:272-282`, `receipt_content.rs:53`)

| Field | Readers | Projection or commitment | Opening | Refusal |
|---|---|---|---|---|
| `chunks_received`, `total_bytes` | `compacted_replay.rs:220`, `tool_outcome/receipt_signing.rs:107` (presence), CLI `process_response_verify.rs:353-360`, conformance `driver.rs:1094-1111` | **Projection**, `CommittedSafe`: kernel-counted stream size, compared by the CLI with its own chunks | none | unchanged |
| `chunk_hashes` | CLI `process_response_verify.rs:310,331,353-360` | **Dropped from signed metadata** (spec 7.6: per-chunk digests are not written to any signed field). The content commitment already commits the stream preimage | the CLI recomputes the content commitment from its own chunks and opens it with the caller-copy opening (Task 7) | `OpeningUnavailable` or `ContentCommitmentMismatch` fails verification |

**`memory_provenance`** (writers `allow_responses.rs:352,1016`; no receipt reader: the store's `memory_provenance` constant is a schema key). Decision under no-silent-drop and OQ-A1-1: the producer stays and every member is committed, each with its own `salt_ref` `metadata.memory_provenance.<member>`, opened by the operator from its values rows when auditing a memory read.

| Field | Reader | Form | Why |
|---|---|---|---|
| `store`, `key` | none | **Commitment** | argument-derived |
| `hash`, `prev_hash`, `chain_digest` | none | **Commitment** | unsalted digests over memory content |
| `status`, `reason` | none | **Commitment** | closed codes with no reader (OQ-A1-1) |
| `entry_id`, `capability_id`, `receipt_id`, `written_at` | none | **Commitment** | Chio ids with no reader of this block (OQ-A1-1); the receipt's own `id` and `capability_id` body fields are not metadata and stay as they are |

**`post_invocation`** (writer `finalization.rs:351`): `sanitized` stays in the **projection** (readers `chio-arena/runtime.rs:285` and conformance `verdict_matrix/driver.rs:941` read only it); `escalations` (hook text) becomes the **commitment** `metadata.post_invocation.escalations`, opened by the operator from its values row. No reader needs it, so no reader changes.

**`session_report`** (writer `session_ops/reports.rs:105-140`; no receipt reader). Decision under no-silent-drop and OQ-A1-1: the producer stays and every event member is committed (`metadata.session_report.<member>`). The receipt `content_hash` over the event is replaced by the content commitment like every other receipt.

| Field | Reader | Form | Why |
|---|---|---|---|
| `operation_sha256`, `context_sha256` | none | **Commitment** | unsalted digests over the operation and the caller context |
| `agent_id`, `session_anchor_id`, `auth_epoch`, `request_id`, `capability_sha256`, `execution_outcome` | none | **Commitment** | Chio session state and a closed outcome code with no reader of this block (OQ-A1-1). Session lineage reads the anchor from the session store and `governed_transaction.call_chain`, never from this block |

**Governed intent hash (Root-2 #1728 item 1).** `GovernedTransactionIntent::binding_hash` (`governance.rs:1221-1227`) is an unsalted SHA-256 over the whole canonical intent, including `purpose` and the context. A plaintext copy confirms a guessed purpose when the rest of the intent is known. `digest_aliases.py` lists every carrier of it (kind `intent`), and each falls in one class:

| Class | Carriers | Decision |
|---|---|---|
| Signed receipt metadata | `GovernedTransactionReceiptMetadata.intent_hash` (`receipt/governance.rs:110`), `EconomicAuthorizationReceiptMetadata.economic_intent_digest` (`receipt/economics.rs:317`) | One **commitment** `metadata.governed_transaction.intent_hash` over the raw binding hash, referenced from both fields. The salt is drawn at admission and persisted on the admission operation row, so retries and recovery keep it, and so artifacts minted before signing can carry the commitment value |
| Outbound economic artifacts (leave the deployment to creditors, factors or a rail) | `chio-credit` `ObligationAtomInputV1` (`obligation.rs:103`), `CreditExposureReservationRequest` (`credit_admission.rs:833`), `CreditFacilityBindInputV1` (`credit_facility_bind.rs:42`); kernel `GovernedPaymentContext.intent_hash` (`payment/types.rs:135`) passed to payment adapters; `VerifiedGovernedPayeeBinding.economic_intent_digest` (`kernel/mod.rs:675`) | Carry the **commitment value**, never the raw hash. Equality readers (`participant_evidence.rs:591,600,612`, `receivable_iou.rs:882`) compare commitment values, which are equal by construction |
| Lineage and reports | `RequestLineageRecord.intent_hash` (`session/lineage.rs:41`), `GovernedAuthorizationTransactionContext.intent_hash` (`operator_report/authorization_context.rs:46`) | Carry the **commitment value** |
| Authorization protocol artifacts exchanged only among the caller, its approvers and Chio kernels, all of which hold the intent | `GovernedApprovalTokenBody` and `GovernedApprovalToken.governed_intent_hash` (`governance.rs:1306,1321`), `ThresholdApprovalProposalBody` (`:1469`), `ApprovalSetBody` (`:1727`), `CallChainContinuationTokenBody` and token (`:374,407`), `GovernedApprovalRequest` (`ports/approval.rs:53`) | **Raw hash kept**: approvers sign over the intent they see. These artifacts are never embedded in a receipt, an evidence export or an outbound artifact; the receipt keeps only `approval_artifact_digest` (keyed by the approver signature). Test `no_approval_artifact_in_receipt_or_export` |
| Signed security response receipt bodies | `ResponseExecutionDispatchBinding.governed_intent_hash` (`chio-security-types/src/response.rs:537`), carried in the security response state-transition receipt body | The Task 5 security projection carries the **commitment value**; executors (`chio-quarantine/approval.rs:281`, `executor_proof.rs:111`, `chio-secret-broker/provision.rs:1081`) compare the raw hash only in private dispatch state |
| Deployment-internal rows and active-response dispatch (kernel, store and executors of one deployment, private under disclosure authority) | admission operation rows and approval stores (`governed_approval_claim.rs:63`, `governed_approval_replay.rs:43`, `chio-store-sqlite` approval and replay stores), active-response submission, artifact, dispatch and executor bindings (`active_response_*.rs`, `chio-security-types` `ports/dispatch.rs:64`, `ports/outbox.rs:30`, `response.rs:537`), `request_binding.rs:22`, `response_simulation_report.rs:19` | **Raw hash kept** in private state. Any of these that a receipt or export carries goes through its projection (Task 5), whose kept digests the entropy test covers |

Test `intent_hash_has_no_public_alias`: two intents equal except `purpose` (and, separately, except the context) produce receipts, exports and outbound credit and payment artifacts in which no field equals either raw binding hash, and whose commitment values differ.

**`chio_receipt_signing_nonce`** (writers `signing.rs:106,137`; ACP producer): readers `terminal.rs:747,764`, `compacted_replay.rs:241`, `chio-settle/evm/prepare.rs:504`, `chio-web3/settlement.rs:19,685` require `nonce == governed_receipt_id`, so committing it would break them. **Projection**, `CommittedSafe` with those readers. **Producer fix:** the ACP proxy (`acp-proxy/kernel_signer.rs`) today embeds an unsalted content hash in `body.id`; it mints the id from the `Rng` seam like the kernel, with no content hash. A nonce that fails the kernel-form shape check refuses signing.

**`protocol_admission`** (writer `admission_terminal_receipt.rs:833`; no reader): free-text `last_error` and the closed `last_error_code` both become **commitments** (OQ-A1-1, no reader).

**`protocol_refusal`** (writer `session_ops/protocol_refusal.rs:266`; readers `session_certificate_read.rs:410-411`, `acp-proxy/compliance.rs:352,358` read `session_id`): `request_digest.sha256` (over the original wire bytes), `method_sha256` and `target_sha256` become **commitments**; `session_id` and the refusal code stay in the projection. Registered `Unsafe` by P-d until F.

**`admission_operation`** (writers `refusal.rs:245`, `admission_terminal_receipt.rs:834`, `terminal.rs:760,1450`): `request_binding_hash` (over the immutable request hash and the unsalted parameter hash) becomes the **commitment** `metadata.admission_operation.request_binding`. Kernel and store readers (`projection.rs:1266`, `remote_projection.rs:1083`, `refusal.rs:454`, `terminal.rs:732`, `compacted_replay.rs:170`, `payload_compaction/eligibility.rs:155`, `finding_purchase_coordinator.rs:1251`) compare with the operation row and open with the store or `SignedReceipt.openings` over the row's binding hash; `MetadataCommitmentMismatch` refuses. `operation_id`, `projected_state` and the other Chio state stay in the projection for the external readers (`chio-process/lib.rs:636`, `call_evidence.rs:284`, `nonce_evidence.rs:25,53,120`, `completed_result.rs:77,139`, `chio-mini-swe` `model.py:117`, `repository_proof.py:98,154`). Registered `Unsafe` by P-d until F.

**`finding_pool_mutation`** (writer `receipt_persistence.rs:61,68`; reader `finding_pool_ledger.rs:1570,1577`): the block duplicates the action parameters. It is replaced by the parameter commitment (no new metadata field): the ledger rebuilds the expected mutation and opens the parameter commitment with the store opening (census kind E/P-ii); `OpeningUnavailable` refuses the ledger mutation.

**`otel`** (writer `chio-otel-receipt-exporter/sink.rs:368,373`; no receipt reader). Every member is committed: each span attribute value as `metadata.otel.attr_<n>` (n is its position in the sorted attribute names), and the trace id and span id as `metadata.otel.trace_id` and `metadata.otel.span_id` (Chio-minted ids with no receipt reader, OQ-A1-1). The operator's trace backend joins on the exported span, which carries the ids itself; it never reads them from the receipt.

**`scimLifecycle`** and the SCIM deprovisioning receipt (writer `config_and_public.rs:1510-1580`; no receipt reader). Every block member is committed as `metadata.scim_lifecycle.<field>`: `providerId`, `providerRecordId`, `principal`, `subjectKey`, `userId`, `userName`, `revokedCapabilityIds`, `entitlements` and `receiptKind` (OQ-A1-1). The same receipt carries aliases of those values outside the block, each of which would confirm a guessed user:

| Field | Today | Decision |
|---|---|---|
| receipt `id` | `"scim-deprovision-" + sha256(provider_id:user_id:now)` (`:1536-1539`) | drawn from the `Rng` seam like every kernel receipt id; any index keyed by the old derived id moves to the stored id (P-g) |
| `capability_id` | `"scim-user:" + user_id` (`:1541`), where `user_id` is the provider's id or `derive_scim_user_id` (`scim_lifecycle.rs:300-304`) | `"scim-user:"` followed by keyed output under the P-g enterprise subject key over the provider and user id; no reader parses it (P-g) |
| `policy_hash` | `sha256("chio.scim-lifecycle-delete.v1:" + provider_id + ":" + subject_key)` (`:1527-1533`) | keyed under the P-g key over the same preimage (P-g) |
| action parameters and `content_hash` | `providerId`, `userId`, `userName`, `subjectKey`, `revokedCapabilityIds` (`:1514-1526`) | the parameter and content commitments of the main plan |
| `attribution.subject_key` | `derive_enterprise_subject_key`, an unsalted SHA-256 over the provider scope and the canonical principal (`scim_lifecycle.rs:452-461`) | keyed in P-g (the blocking identity-closure precursor below), together with the remote MCP producer and every consumer |

**`mercury`** (writers `chio-mercury-core/receipt_metadata.rs:283,294`; readers `receipt_metadata.rs:311` and the proof package `proof_package.rs:205-256,376-407,547-548,1020-1032`):

| Fields | Readers | Projection or commitment | Opening | Refusal |
|---|---|---|---|---|
| `schema`, `decision_context.decision_type`, `chronology.stage`, `chronology.ingested_at`, `chronology.source_timestamp`, `sensitivity.classification`, `sensitivity.contains_customer_data`, `sensitivity.contains_market_data`, `disclosure.policy`, `disclosure.verifier_equivalent`, `disclosure.reviewed_export_approved`, `approval_state.state` | proof package `:547-548,1020-1032` | **Projection**, `CommittedSafe`: closed codes, flags and times the package checks | none | unchanged |
| `business_ids.workflow_id`, `.account_id`, `.desk_id`, `.strategy_id` | proof package `:205-256,376-407` (equality across records) | **Commitment** per field `metadata.mercury.<field>` | the proof package carries each value with a salt-only opening (OQ9 carrier: the package holds the preimage); the verifier opens before comparing | `OpeningUnavailable` or `MetadataCommitmentMismatch` refuses the package |
| every other member: remaining `business_ids`, `chronology.event_id`, `.idempotency_key`, `.causal_parent_event_ids`, `decision_context.workflow_version`, `.policy_reference`, `.model_id`, all `provenance` members, `sensitivity.retention_class`, `disclosure.redaction_profile`, `.audience`, `approval_state.approver_subjects`, `.approval_ticket_id`, `bundle_refs` | proof package `:1020-1032` (event id) and the package display | **Commitment** per field | as above | as above |

**`authorizationContext`, `guardOutcome`, `deniedAccessRecord`** (writer `chio-wall/commands.rs:401-408`, structs in `chio-wall-core/control_path.rs`; no receipt reader). Every member of the three blocks is committed with `salt_ref` `metadata.wall_<block>.<field>`; the wall's `content_hash` over the metadata is replaced by the content commitment.

| Field | Reader | Form | Why |
|---|---|---|---|
| `request_id`, `workflow_id`, `actor_label`, `tool_name`, `policy_reference`, `guard_name`, `pipeline_name`, `matched_policy`, `evaluated_tool`, `allowed_tools`, `reason`, `escalation_owner`, `support_owner`, `note` | none | **Commitment** | operator or caller values |
| `schema`, `buyer_motion`, `control_surface`, `source_domain`, `requested_domain`, `decision`, `fail_closed` | none | **Commitment** | closed codes with no reader (OQ-A1-1) |

**`acp`** (writer `acp-proxy/kernel_signer.rs:511`): `sessionId`, `toolCallId` and `status` stay in the projection (readers `session_certificate_read.rs:408`, `acp-proxy/compliance.rs:350`; kept only as entropy-backed ids under the id-entropy test, else committed; `status` is a closed code); `authorizationResource` and any content-bearing member become **commitments**.

**`active_defense_backfill_v1`** (reader `active_defense_migration.rs:22,1068`): carries the `active_defense` projection (Task 5), never the body; the reader verifies the projection.

**`batch_witness`** (reader `explain.rs:66,776`, a display): **committed** until P-d part 2's audit shows the witness reference is an entropy-backed or keyed Chio checkpoint reference; the audit may then flip it to a projection with `explain.rs` as its named reader.

**Child request receipts.** `ChildRequestReceiptBody.outcome_hash` (`receipt/lineage.rs:35`) is an unsalted SHA-256 over the nested request's outcome payload (`receipt_building.rs:13`), so it confirms a guessed child result. F replaces it with a salted outcome commitment (`salt_ref` `outcome`, the content commitment shape) drawn from the signing process's `Rng`. Its readers are store-only: `receipt_query_snapshot/project.rs:173`, `store_impl.rs:465` and the dedupe comparison at `evidence_retention.rs:1127`. They compare commitment values, which are equal for byte-identical receipts. The digest census found this row; the main plan's producer inventory gains it.

**`chio_http_receipt_v1`, `delivery_contract`, `active_defense_evidence_id`**: already planned (deleted with `HttpReceipt`, Task 12; split, OQ12; keyed, r5).

### Cage projection (Root-2 decision 3)

Every alias of an argument-derived digest is committed, in every location, and the receipt's top-level `policy_hash` follows the projection, so no raw digest survives under another key. The projection binds to the raw cage evidence through one commitment over the whole raw body.

| Field (all locations) | Producer | Readers | Projection or commitment | Opening | Refusal |
|---|---|---|---|---|---|
| `plan_digest` in `bindings` and `enforcement_record.fully_enforced.prepared` | `chio-cage/src/launch/linux.rs:216,258-260,1035`, `receipt.rs` (`prepare_cage_receipt`) | cage verifier (`verify_signed_cage_receipt`), launch checks `linux.rs:364-366,676-677,1093-1095` (in-process, raw plan) | **Commitment** `metadata.cage_receipt.plan_digest` (preimage covers `target_argv`, environment, descriptor paths); one commitment, referenced from both locations | in-process launch checks use the raw plan; an authorized verifier opens with the cage host's evidence store | `MetadataCommitmentMismatch` |
| `fd_table_digest` in `bindings` and `fully_enforced.prepared` | as above | as above | **Commitment** `metadata.cage_receipt.fd_table_digest` | as above | as above |
| `profile_digest` in `bindings` and `fully_enforced.prepared`, and the receipt's top-level `policy_hash` | as above | cage verifier (`profile_digest == policy_hash`), `cage_policy/evidence.rs` | **Commitment** `metadata.cage_receipt.profile_digest` over the raw profile digest; `policy_hash` is set to that commitment's value, so the verifier's equality still holds and neither confirms a guess | authorized verifier opens with the evidence store | mismatch between `policy_hash` and the commitment refuses |
| `admitted_policy_digest` | `prepare_cage_receipt` | cage verifier | **Commitment** when equal to the profile digest (the same commitment value is referenced); otherwise its own commitment | as above | as above |
| `raw_evidence` | cage host | authorized verifier | **Commitment** `metadata.cage_receipt.raw` over the canonical raw `CageReceiptBody`: the verifiable binding to the authoritative raw evidence | an authorized verifier with disclosure authority opens it, then recomputes every field commitment above from the opened raw body | any mismatch refuses |
| `manifest_digest`, `helper_binding_digest`, `target_binding_digest`, `target_identity` | as above | cage verifier and `cage_policy/evidence.rs` (tool and binary identity) | **Projection**, `CommittedSafe`: digests and file identity of operator-installed binaries and the signed manifest, not caller values | none | unchanged |
| `seccomp_filter_digest`, `trace_session_digest`, `applied_execution_identity` | as above | cage verifier (enforcement checks) | **Commitment** per field until the cage producer audit (before F) shows the preimage holds no caller value; the audit may then flip a field to a projection with the verifier as its named reader | authorized verifier opens with the evidence store | `MetadataCommitmentMismatch` |
| landlock and seccomp status and versions | as above | cage verifier | **Projection**, `CommittedSafe`: closed codes and version numbers | none | unchanged |
| `exit.exit_code`, `exit.signal` | cage executor | `generic_semantics` in the cage verifier and `cage_policy/evidence.rs` derive the decision and terminal state from them | **Projection**, `CommittedSafe` with that reader: the wrapped process status decides the signed decision | none | unchanged |
| `exit.process_id`, `fully_enforced.prepared.process_id`, `exec_transition.process_id` | as above | none | **Commitment** (no reader; no silent drop) | authorized verifier | none |
| `attempt_id`, `stage`, `state`, timestamps | as above | cage verifier, `cage_policy/evidence.rs` (TN-B rule), `delivery_preparation.rs:37` (state) | **Projection**, `CommittedSafe`: closed stage and state codes, timestamps, and an `attempt_id` kept only as an entropy-backed id under the id-entropy test (else committed) | none | unchanged |

### Guard error text and deny reasons (lead #1727 review P1-2)

A guard `Err(e)` becomes `GuardDenied("guard \"{name}\" error (fail-closed): {e}")` (`kernel/dispatch.rs:416-455`, also `dispatch/runtime_admission.rs:156`), which is the signed `Decision::Deny.reason`. The portable kernel builds the same text in `chio-kernel-core/src/evaluate.rs:199-205` (`KernelCoreError::GuardError { guard, reason }`) and appends `reason` for `ConstraintEvaluation`. Example: `HttpProjectionGuard`, declared SAFE, returns `projected.capability.invalid_reason` and serde errors over `ctx.request.arguments` (`chio-http-core/src/authority.rs:249-274`). `evidence_declaration` covers only `GuardEvidence.details`.

- **Signed reason.** `Decision::Deny.reason` and `Decision::Cancelled.reason` become a closed template: `guard "<guard name>" <GuardFailureCode>` for guard errors and `<RefusalCode>` for kernel refusals; the guard name is Chio-defined. No `e` text enters a signed field.
- **Detail.** The error text is a **commitment** `metadata.guard_error.detail` with the plaintext in `receipt_metadata_values` for the operator; an operator reader that needs it reads the values table.
- **SAFE classification rule.** `EvidenceDisclosure::Safe` now requires that the guard's `details`, its deny reason and its `Err` text are all free of argument- or result-derived text. P-d part 2 reclassifies `HttpProjectionGuard` and any other guard whose `Err` interpolates request data to `UNSAFE` and changes guard deny reasons to `&'static str` or a closed enum where they are SAFE (lead #1727 review P3-4).
- **Tests.** `deny_reason_carries_no_argument_text` (marker property: markers in arguments through every guard `Err` path, including `HttpProjectionGuard`, runtime admission hooks and the portable kernel's `GuardError` and `ConstraintEvaluation`, never appear in `Decision::Deny.reason` or `Cancelled.reason`); `guard_error_detail_committed`; `safe_guard_err_text_is_static`.

### Registry follow-ups (lead #1727 review P1-1)

- `protocol_refusal` and `admission_operation` are registered `Unsafe` in P-d until F applies the rows above.
- `lineageReferences`: the top-level fallback (`kernel/mod.rs:869-877`) is deleted in the reserved-key PR; F adds no reader of it.
- The store claim log builds authorization details on read from values rows (derived copies are ephemeral, above); `derived_details_follow_values_erasure` pins that an erased `purpose` or `payment_token` refuses and never yields an empty token.
- `kept_digests_are_keyed_or_entropy_backed` extends to every `CommittedSafe` registry entry and to kept ids (the id-entropy test), not only the security projections, and to every row `digest_aliases.py` marks kept. P-d part 2 audits the next candidates member by member: `caller_delivery`, `chio_runtime`, `finding_purchase_replay_snapshot`, `finding_recovery_replay_snapshot`, `threshold_approval`.

### Split of P-d

- **Reserved-key fix** (Root-2 decision 1): a separate small PR on current main that only expands the caller-metadata reserved list (12 to 29 names) with exact-refusal tests; it lands independently and does not wait for this amendment.
- **P-d part 1** (#1727): guard declarations and the registry, with the classifications above registered `Unsafe` until F.
- **P-d part 2** (stacked, after P-a, P-b and #1706): `MetadataCommitment`; the `active_defense`, `response_simulation`, `security_event`, `stream`, `acp`, `financial` and `cage_receipt` projections; registry rows flipped to their decided forms with named readers; the guard SAFE rule change; the census script and output; the tests that need no F wiring. The plan's merge order and size table now name P-d part 2 explicitly.

### OQ-A1-1 (resolved by Root-2)

- **Decision (Root-2):** fields with no named plaintext reader are committed, including closed codes and Chio ids: `memory_provenance`, `session_report`, the wall blocks, `otel`, `scimLifecycle` and `protocol_admission.last_error_code`. Root-2's decision covers only no-reader fields. It approves no retained field as such. A field this plan keeps plaintext stays so only on this plan's own justification, which Root-2 reviews row by row: a named reader, a provenance that is a closed code or entropy-backed or keyed, and a binding to the value it stands for. The per-field tables give that justification for each kept field (`receipt_context` ids and namespace digest, `chio_receipt_signing_nonce`, `admission_operation.operation_id` and state, `acp` ids, the financial projections, the cage identity projection), and the id-entropy test commits any kept id that fails it. The governed intent hash is not a kept field: it is committed (above), and it stays an open finding until F lands that change.

### OQ-A1-2 (resolved: P-g)

- **Global `attribution.subject_key`.** Resolved by Root-2's identity decision: derived enterprise subject keys are keyed in P-g (below), real public keys keep their form. The text below records the original finding. Every receipt with enterprise attribution carries `attribution.subject_key`, an unsalted SHA-256 over the provider scope and the canonical principal (`scim_lifecycle.rs:452-461`), so it confirms a guessed principal wherever the principal is committed. It is a cross-block identity key used for attribution joins, outside A1's metadata blocks. **Default:** key it with the `TenantIndexKey` construction (HMAC-SHA256 under the active key, retired keys accepted on verify), so joins inside a deployment still work and a guessed principal confirms nothing. The SCIM receipt follows whatever Root-2 decides here.

### #1710 settlement readers (atomic with F)

A reader may stay untouched by F only if a test on F's final source proves it already consumes the new shape with unchanged behavior. Every reader that needs adaptation, including the denied retained-payment path, changes in F's own commits. There is no intermediate commit with a broken caller and no compatibility decoder. The list, at #1710 head `cbd953833f`, is the input to the lead's settle-hook lane:

| Reader (file:line at `cbd953833f`) | What it reads | Disposition |
|---|---|---|
| `chio-kernel/src/kernel/settlement_observer.rs:113-145` (`retained_payment_settlement`) | `metadata.get("financial")` object picks: `payment_authorization_ambiguous`, `payment_attempt_reference` | **moves with F**: reads `FinancialSettlementProjection::RetainedAmbiguous`. Its fixture at `:778-781` uses error code `"timeout"`, outside the closed set, and is regenerated with a closed code |
| `settlement_observer.rs:228` | `receipt.financial_metadata().is_none()` for channel receipts | **moves with F**: uses `financial_settlement_projection()`, so a retained or malformed block refuses instead of reading as absent |
| `settlement_observer.rs:258-337` | object picks `cost_charged`, `currency`, `settlement_status`, `payment_reference` | **moves with F**: reads `FinancialSettlementProjection::Charged` |
| `chio-store-sqlite/src/receipt_store/reports/reconciliation.rs:334-369` | `extract_financial_metadata(&receipt)` then `.cost_charged`, `.currency` | **moves with F**: uses the enum decoder; a retained receipt reports as retained, a malformed block refuses the row |
| `chio-kernel/src/settlement_ledger.rs:46-100` (incl. `transcript_id` `:98`) | `ObservedSettlement` (no receipt metadata read) | **proven unchanged**: `settled_charge_records_one_reconciled_row_and_replays_idempotently`, `retained_payment_waits_for_rail_resolution`, `non_final_charge_is_a_permanent_unsupported_economic_form`, `missing_receipt_is_an_invalid_observation`, `mismatched_idempotency_key_is_rejected`, and the integration test `settlement_ledger_records_one_reconciliation_for_a_settled_durable_receipt` (`tests/settlement_routing_sqlite.rs:583`), rerun on F's final source with producer-regenerated receipts |
| `chio-settle/src/hook.rs:84-98,255,287` (`ObservedSettlement`, `MalformedFinancialMetadata` code) | type definitions | **proven unchanged**: `observed_settlement_round_trips_with_a_closed_shape`, `ledger_failure_codes_round_trip_with_their_retry_class`, `observation_schema_is_stable` |
| `chio-kernel/src/kernel/settlement_drain.rs:40-56` | the settlement claim row, not receipt metadata | **proven unchanged**: `settlement_drain_reruns_a_retryable_attempt_once_it_is_due`, `settlement_drain_fails_on_a_completion_write_and_keeps_the_row_for_reclaim` (`tests/settlement_routing_sqlite.rs:646,673`) |

If #1710 merges before F, F carries these changes; if F merges first, #1710 rebases onto the enum before it merges. Either way no merged state has a reader of the old shape.

### Identity closure: P-g, a blocking F predecessor (Root-2 identity decision)

The SCIM rows above leave outside-block aliases that A1's metadata scope cannot close alone: `derive_enterprise_subject_key` is an unsalted SHA-256 over the provider scope and the canonical principal, and it has two implementations (`chio-control-plane/src/scim_lifecycle.rs:452`, `chio-mcp-remote/src/remote_mcp/session_identity.rs:467`) whose output feeds capability and identity records, `attribution.subject_key`, SCIM `subjectKey`, the SCIM receipt id, `capability_id` and `policy_hash`. Closing it is **P-g, a named precursor that blocks F**, not a Safe exception.

- **Scope.** Derived enterprise subject identifiers only. Real public keys (an agent's Ed25519 `subject_key`, read by signature and authorization readers such as `reputation.rs`, `passport_handlers.rs:1480,1647`, `capital_and_liability.rs:602,845-873`) are entropy-backed and keep their form. P-g's census script classifies every `subject_key` reader and writer as real-key or derived-enterprise, failing closed on an unclassified line.
- **Derivation.** `esk_v1 = "esk1:" || kid || ":" || hex(HMAC-SHA256(K[kid], "chio.enterprise-subject.v1\0" || len32(provider_scope) || provider_scope || len32(canonical_principal) || canonical_principal))`, with a length-prefixed preimage so no two (scope, principal) pairs share an input. One function in `chio-core-types` replaces both implementations; the control plane and the remote MCP edge change in the same PR, with no unsalted fallback and no dual decoder.
- **Key.** `EnterpriseSubjectKeySet { active, retired }`, a dedicated 32-byte key per deployment (or per provider scope when the operator configures one), loaded from its own file by every process that derives or matches enterprise subjects, never derived from a signing or index key. `kid` is the first 8 bytes of SHA-256 over the key. Rotation adds a new active key; matching recomputes under the `kid` a stored value names, so retired keys verify old records. Every node of a deployment loads the same set; a value whose `kid` is not loaded refuses (`EnterpriseSubjectKeyUnavailable`), and startup refuses a missing key file when enterprise federation or SCIM is configured.
- **SCIM aliases.** The receipt id is drawn from the `Rng` seam. Any index that looked a SCIM receipt up by its derived id is updated to the stored id, never dropped. `capability_id` becomes `"scim-user:"` followed by output of the same keyed construction (its own domain, `chio.scim-capability.v1`) over the provider and user id. `policy_hash` is keyed with the same construction. The block members stay committed per the SCIM table.
- **Evidence (tests).** A dictionary of controlled principals cannot reconstruct a retained identifier without the key. Distinct provider or deployment scopes do not alias. Every control-plane, remote and SCIM equality reader stays correct. A missing or wrong key refuses. The old 64-hex unkeyed shape refuses structurally. No raw principal or unkeyed digest appears in signed artifacts or log exports. Key rotation and retired-key verification follow the contract above.
- **Size.** 4-6 engineer-days (census and classification, the shared derivation, key set and provisioning, both producers and every consumer, SCIM aliases, tests).

### Tasks

- **P-c:** `receipt_metadata_values` with the 13 probe cases as named Rust tests; included in erasure, replication and snapshot import.
- **P-d part 2:** as above.
- **P-g:** enterprise subject identity closure (above); F depends on it.
- **F:** writers emit commitments and values rows in the append transaction; readers move to projections, values rows or openings as the tables say; the #1705 and #1710 settlement readers listed above move to `FinancialSettlementProjection` in F's own commits; the claim log stops persisting derived plaintext; the intent-hash commitment and its carriers; the token fallback deletion; the SCIM keyed ids; the deny reason template in both kernels; Task 8's refusal switches on only after every row here has its decided form.
- **F acceptance** (Root-2): exact refusals for `Unsafe`, unknown and caller-origin keys; unchanged behavior of every valid reader in the tables; `ambiguous_denied_receipt_yields_retained_payment`, `payment_token_never_copied_to_plaintext_key`, `intent_hash_has_no_public_alias`, `derived_details_follow_values_erasure`, the live-parent anchor positive control and the persisted-parent refusal; wrong and missing opening failures for every committed field with a reader; field-level disclosure tests (marker values in every committed field and in deny reasons never appear in signed fields, OCSF or logs); producer-regenerated signed fixtures on the integrated base. All shapes stay v1; no legacy decoder or compatibility path.

### Size

+8 to +11 engineer-days: P-d part 2 +3-4 (commitment type, projections, registry flips, SAFE rule, digest census rules), P-c +1 (values table, ephemeral claim-log details), F +4-6 (writers, readers, settlement enum and retained path, intent-hash commitment and its carriers, token fallback, SCIM keyed ids, deny template in both kernels, tests). P-g adds 4-6 engineer-days as its own precursor. Item 2 becomes **L, 66-93 engineer-days, planning figure 78**; the M1 total becomes 152-218.

## Size

Spec 13.2 sizes item 2 at L, 26-37 engineer-days. Estimate from the census:

| Part | Days |
|---|---|
| P-a `Rng` move, fallible fill, `OsEntropyRng`, `chio-fixture-rng` | 1-2 |
| P-b types, opener, document schema, SDK openers, vector cross-check of the opener | 2-3 |
| P-c openings table with the exact DDL tests, status, scoped reads and erasure on 58 store impls, public status and internal read routes with scope and tenant checks, the openings stream with its cursor, snapshot import, quarantine, tombstone retention and per-peer credential | 6-8 |
| P-e routing every committed-receipt raw decode through `decode_signed`, the raw-decode gate and its tests | 1-2 |
| P-f trust-control caller credentials with scopes and tenant authority, internal listener, peer keys, config migration of every route | 3-5 |
| P-d `evidence_declaration` on 111 impls, metadata key registry with field audits, `active_defense` (12 variants) and `response_simulation` projections, cage audit | 4-6 |
| F core body, schema move-in, portable signer, strictness gate over every committed-receipt type, signed tenant binding and tenant index key (Task 6) | 4-5 |
| F hosted kernel salt wiring across 421 construction sites; atomic append with openings under #1708's guards; kernel and store consumer bindings (A, A0, B, E-k, P-i), tenant binding verification at append, snapshot, fetch, read boundary and export, and their recovery, C6, compacted-replay, cross-tenant and catalog tests (Task 7) | 7-9 |
| F evidence and metadata enforcement, marker property over the projections (Task 8) | 1-2 |
| F relays (Task 9) | 2-3 |
| F cage, control-plane, BBS producers and projection readers (Task 10), ACP (Task 11) | 3-4 |
| F `HttpReceipt` deletion across 103 files and the middleware SDKs (Task 12) | 5-6 |
| F group 5 producers, fixture RNG release gate (Tasks 13, 14) | 2-3 |
| F readers and cross-artifact consumers: 551 census lines, P-ii rebuilds, carriers, the `security_event` projection, keyed digests and the split `delivery_contract` (Tasks 15, 16) | 6-9 |
| F vectors and SDK verifiers (Task 17) | 2-3 |
| F fixture regeneration (Task 18) | 2-3 |
| PROTOCOL, docs, formal (Tasks 19, 20) | 1-2 |
| Integration, native-cage runs on five PRs, review rounds | 3-4 |
| Amendment A1: metadata commitments, projections, values table, settlement enum and retained path, intent-hash commitment and carriers, ephemeral claim-log details, SCIM keyed ids, deny template in both kernels, digest census, writers and readers | 8-11 |
| P-g enterprise subject identity closure (blocking F predecessor) | 4-6 |
| Total | 69-99 |

The parts sum to 69-99, including Amendment A1 and P-g. With them the plan is **L, 66-93 engineer-days, planning figure 78** (54-76 before A1). The M1 total is 152-218 engineer-days: 13.2's 104-148, plus 3-8 for item 1, 5-6 for item 6, and 40-56 for item 2.

## Open Questions

Each needs an owner decision. The plan is written against the recommended default.

1. **`Rng` home and fallibility.** **Default:** move to `chio_core_types::rng` with `fill_bytes -> Result<(), RngError>`; delete `NullRng` and the browser and mobile zero-fill fallbacks; P-a.
2. **Opening persistence versus spec 8.4.** Spec 8.4 says a disclosure-store write failure after signing appends the receipt and marks the opening lost. **Default:** openings are written in the receipt's append transaction (SQLite and trust-control), so an opening is never lost apart from its receipt and a failure is a receipt append failure handled as today. Amend spec 8.4 and Q-B5 to say so in F's PROTOCOL commit.
3. **When the kernel fills `authority`.** **Default:** F adds the type, the `tenant_id` refusal, the schema and the vectors; every producer sets `authority: None`; item 3 fills it.
4. **`receipt_disclosure` verdict-matrix category.** **Default:** stays staged; F lands the kernel tests behind 001 to 006 and the error code.
5. **Metadata policy.** **Default:** drop guard evidence declared `Unsafe` and every caller or hook metadata key; refuse signing on an unregistered or `Unsafe` Chio-internal key; register every internal key in the ADR-0019 item 7 registry in P-d.
6. **Security bodies in signed metadata.** **Default:** option (a) of Root-2's r2 request 2: `active_defense_body` and `response_simulation_report` leave signed metadata; each is replaced by an audited projection that commits the raw tenant and plan identifiers (Task 5), and `cage_receipt` follows its audit. No privacy-contract change is needed. The alternative, option (b), keeps the full bodies as public Chio-internal metadata, which requires amending spec 7.6 and the fully-committed claim; this plan does not take it.
7. **HTTP body preimage.** **Default:** always the raw bytes, tagged: `{"kind":"bytes","content_type":..,"b64u":..}` or `{"kind":"absent"}`, never parsed; vectors pin the lookalike pair.
8. **Offline nonce parameter binding in `authoritative_spend`.** The offline check compares the nonce's bound parameter digest with the receipt's `parameter_hash`, which F removes; the spend receipt differs from the allow receipt the nonce was minted from, so no commitment equality can replace it. **Default:** the parameter binding is checked at signing time by the kernel (`reconciliation.rs`), and the offline check reduces to the signed `budget_authority.execution_nonce_id` equal to the nonce id. This default holds only if PROTOCOL drops the offline parameter-binding claim for authoritative spend; F's PROTOCOL commit drops it.
9. **Salt-only openings in carriers.** Spec 7.7 lists only the caller copy, `caller` bundles and the PEP response. **Default:** amend spec 7.7 with: "A salt-only opening for the `<salt_ref>` commitment may accompany an artifact that carries that commitment's complete preimage. It is never written for a field whose preimage the artifact does not carry, and erasure does not reach openings already delivered in such artifacts." It applies only to the Task 16 carriers, each for its named `salt_ref`. It does not apply to the finding verifier, which holds only `payload_sha256` and binds to `delivery_contract` (kind F). The alternative, rebinding each carrier consumer to a receipt id recorded by a signed Chio artifact at signing time, adds about 3 days.
10. **`/v1/evaluate` openings.** **Default:** none in M1 (spec 7.7 and the 13.1 caller-copy cut); mediated mode persists them, sidecar mode without a store drops them.
11. **Signed tenant binding beyond the security producers.** The keyed `tenant_binding` member is an addition to spec 7.6, which today allows only a plaintext `tenant_id` or, with `authority`, no signed tenant at all. **Default:** add it to spec 7.6 in F's PROTOCOL commit for the native evidence, response simulation and cage producers only; every other producer keeps `tenant_id` until a later item decides whether all tenant-scoped receipts move to the binding.
12. **Plaintext `delivery_contract` digests for finding-delivery grants.** The kernel decides that a grant is a finding-delivery grant from the grant's signed constraint set (a `FindingDelivery` constraint on the capability), never from an argument or caller-supplied marker, so a caller cannot select the plaintext form. **Default:** keep them plaintext, because they equal the finding's `payload_sha256`, which the listing publishes, and the finding verifier holds only that digest; every other `OutputDigestSha256` grant's `observed_digest` becomes a salted commitment. The entropy argument is the listing's: no new value is disclosed. The alternative commits the finding-delivery digests too and moves the finding verifier to an opening the listing would have to carry.

## Unresolved in this revision

- The store schema-adoption cleanup has no PR or implementation yet. It is the last serial store item and an explicit unresolved predecessor of P-c and F; this plan names no PR number for it.
- #1722 is a draft at `188a6af6ff`; it is not compiled or runtime-green yet, and its native stage 1 and 2 follow C6.
- Open questions 2 (openings in the append transaction versus spec 8.4), 8 and 9 need owner decisions and PROTOCOL amendments. If 9 is rejected, Task 16 switches the carrier consumers to the rebind alternative and the size rises by about 3 days.
- P-e's owner is open: it may land from the fwdcompat lane or from this lane; it precedes F either way.
- Open question 11 (the signed tenant binding as a spec 7.6 addition) needs an owner decision.
- Open question 12 (plaintext finding-delivery `delivery_contract` digests) needs an owner decision.
- P-f changes every deployment's trust-control configuration (caller credentials replace `service_token` and `tenant_read_tokens`; internal routes move to a second listener); the mapping of today's routes to scopes is fixed in P-f's PR and reviewed by Root-2 before it opens.
- P-e is lead-owned in the fwdcompat lane.
- The per-peer cluster credential (Ed25519 key per node) is new cluster configuration; operators of existing clusters provision it before F.
- The `CageEnforcementRecord` audit happens in P-d; its outcome decides between registering `cage_receipt` and building a cage projection.

## Spec coverage

| Spec requirement | Task |
|---|---|
| D2 protocol-wide committed receipts, every producer on the `Rng` seam | 2, 6 to 14 |
| G1 one atomic format PR, inventory commit groups, one commit per producer's salt wiring | Shape, Commit Grouping |
| G3 salt source per producer, preimages for hash-only producers | 1, 10, 11, 14 |
| G4 `HttpReceipt` deletion with the SDK middleware | 12 |
| G13 three content preimage forms | 3, 6, 17 |
| G14 bare hex `receipt_id` | 3 |
| G15 duplicate salt rejection | 3, 17 |
| G18 strict decoding of every new block and the opening document | 3, 6, 17 |
| 7.6 body changes, commitment rules, `chain_digest`, `tenant_id` exclusion | 3, 6 |
| 7.7 `chio.receipt-disclosure.v1` | 3, 17 |
| 7.8 producer salt sources, relay replacement, Lambda extension | 1, 9, 13 |
| 8.4 evidence and metadata, salt failure, opening persistence | 4, 5, 8 |
| 10.1 to 10.3, 10.7 | 2 to 16 |
| 10.10 SDK verifiers | 3, 17 |
| 11.1, 11.2 | 2 to 17 |
| 11.3 `receipt_disclosure` (kernel-level backing) | Verdict-matrix scope |
| 11.5 gates and regenerated fixtures | 18, Verification |
| 13.3 step 2 (after item 1 and D17) | 1, D17 Coordination |
