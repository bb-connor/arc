# Relying-Party Wedge M1 Item 2 Implementation Plan: Committed Receipts

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land M1 item 2 of the relying-party wedge as one squash-merged PR: `chio.receipt.v1` has one format, committed. Every producer computes salted commitments to arguments and results inside its own signing boundary, with salts drawn from the `Rng` seam of the process that signs. `RedactionMode`, `parameter_hash`, `content_hash`, `sign_receipt_relaying_trusted_body` and `HttpReceipt` are deleted with every caller, every verifier opens commitments, and every signed fixture is regenerated once through `cs cargo xtask gen signed-fixtures`.

**Architecture:** `chio-core-types` gains `receipt/disclosure.rs` (commitments, salts, content preimages and the `chio.receipt-disclosure.v1` opening document) and the moved `Rng` seam. Producers stop building a signed body. They build a `ReceiptDraft` (the body without commitments) and pass `ReceiptPreimages` and an `Rng` to the one receipt signer, which draws salts, computes both commitments, signs through the item 1 wrapper and returns the receipt with its `ReceiptOpenings`. Relay adapters (FFI, WASM, mobile, ACP, HTTP) pass preimages, never hashes. The hosted kernel writes openings to a new `DisclosureStore`. The PR tip is the verified unit; intermediate commits need not build.

**Tech Stack:** Rust workspace (every cargo command through `cs`, defined under Global Constraints), JSON Schema draft 2020-12, `cargo xtask codegen` (Rust, TS, Go, Python), `cargo xtask gen signed-fixtures` (from item 1), `cargo xtask freeze-vectors`, Python reference generator `scripts/gen-signing-wrapper-vectors.py`, Go, TypeScript (npm), Python (uv), Kotlin (Gradle), .NET (dotnet), C++ (CMake through `scripts/check-chio-cpp.sh`), Miniflare for the Workers test.

**Spec:** `docs/superpowers/specs/2026-10-17-relying-party-wedge-design.md`, sections 2.2 (D2, D17), 2.5 (G1, G3, G4, G13, G14, G15, G18), 7.4 (producers without a root policy), 7.6, 7.7, 7.8, 8.4, 10.1 to 10.3, 10.7, 10.10, 11, 13.2, 13.3. Inputs from M0 and M1: `docs/superpowers/specs/relying-party-wedge/receipt-producer-inventory.md` (sections "Receipt producers", "Receipt producers outside the first grep", "RedactionMode mapping"), `docs/superpowers/specs/relying-party-wedge/protocol/protocol-6-committed-receipts.md`, `docs/superpowers/specs/relying-party-wedge/in-place-schemas/receipt/record.schema.json` and its README, `docs/superpowers/specs/relying-party-wedge/verdict-matrix/` (`receipt_disclosure`), `tests/bindings/vectors/receipt/committed/v1.json`, `scripts/gen-signing-wrapper-vectors.py`, and the item 1 plan `docs/superpowers/plans/2026-10-20-m1-item1-signing-wrapper.md`.

**Builds on:** #1715 (fwdcompat receipts, option 2: `deny_unknown_fields` across the receipt trees, `Decision` and `OperationTerminalState` through `lossless_serde`, commerce routing off the receipt bytes), the shared `lossless_serde!` decoder PR that the fwdcompat lane is opening (called "the shared decoder PR" below; not open at planning time, `gh pr list --repo bb-connor/arc --search lossless_serde` lists no such PR, so Task 1 records its number), and #1716 (closed receipt decode in the Go, Python and TypeScript verifiers). Receipt decode changes land in #1715 and the shared decoder PR first. Item 2 changes no decode mechanism of its own: every new receipt block is `deny_unknown_fields`, every new tagged enum and closed union (the relay `content` input, `SaltRef`, `CommitmentAlg`) decodes through the shared `lossless_serde!` decoder as that PR defines it, the commerce authority receipt route stays outside the signed bytes, and each SDK verifier's closed layer list gains the new blocks. If the shared decoder PR changes the macro's name, location or contract, item 2 follows it and adds no local helper (G18).

**Census base:** facts below were measured at `origin/main` `a93a2f69a3`, where neither item 1 nor #1715 is merged. Task 1 re-runs every census at the integrated base (the `origin/main` commit that contains item 1 and every predecessor in the merge order) and updates the counts in the PR body. Counts from any earlier base are planning figures only.

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

- M1 scope (spec 13.1 cut 1): every receipt in this PR is fully committed. `parameters_inline` and `result_inline` exist in the types, the schema and the verifiers, and the signer refuses to set them (no producer has a root policy in this PR, and item 4 rejects a non-empty `tools` map at load). Inline disclosure lands in M2.
- Merge order (precondition): #1674, #1601 (merged), #1607, #1715, the shared decoder PR, #1716, #1706 and the Root-2 K-stack in Root-2's order (T7 #1675, C6 #1682, native-ledger #1678, stop-error #1701, D5 #1269, KERN-TRACE-LOCK-FSYNC), then item 1, then this PR. #1708 and #1710 rebase-merge before this PR if they land first; otherwise they rebase on it. Anchored-root capability changes (item 3, the `root_anchor` member in the capability body) follow this PR. Root-2's order is not an approval of any candidate head.
- Preconditions (D17): the "D17 Coordination" list below is acknowledged by the lead and Root-2 on `ws2:~/lanes/claude-pr1160-evidence/lead2/sync.md` before the PR opens.
- One PR, squash-merged. Commits follow "Commit Grouping": the inventory's five groups in order, and inside them each producer's salt-source wiring in its own commit. Intermediate commits need not build; the PR tip is verified.
- Fixtures: every signed fixture is regenerated once, at the integrated base, by `cs cargo xtask gen signed-fixtures` (item 1 Task 11). No signed fixture is edited by hand, patched by a script or rewritten by any tool other than its owning generator. Fixture producers draw salts from `FixtureRng` (Task 2), so `--check` is reproducible.
- No legacy, compat or dual paths; everything is v1. No `parameter_hash` or `content_hash` alias, no `redaction_mode` reader, no relay signer that accepts a hash, no second HTTP receipt, no default trait method standing in for a declaration, no store migration from the current receipt table shape (the DDL changes in place).
- Fail-closed: salt generation failure, an unregistered `salt_ref`, a commitment that does not recompute, `tenant_id` beside `authority`, an inline field without a root policy and a decode error each refuse.
- Strict decoding (G18) for every type this PR adds or changes: `deny_unknown_fields` at every level, closed string enums for `alg`, `salt_ref` and `holder`, `lossless_serde!` for tagged enums, no `#[serde(flatten)]`. Opaque caller data (`parameters_inline`, `result_inline`, an opening's `payload`, `metadata`) stays opaque.
- Clock reads only through the approved seams; fixtures use fixed timestamps (`issued_at = 1792234800`). Run `python3 scripts/check-security-clocks.py`.
- Clippy denies `unwrap_used` and `expect_used` outside tests. Format with `cs cargo fmt --all`.
- No em dashes (U+2014) in any file. No narrative or meta comments; comments state invariants and contracts.
- Public-path rule: files under `spec/`, `docs/adr/`, `tests/`, `scripts/`, `crates/`, `sdks/`, `examples/` never mention milestones, the wedge, pilots or `docs/superpowers`.
- Build slots: on ws2, `cs` means `CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/var/tmp/claude-targets/m1i2 ~/lanes/cslot.sh`; on the x86 runner and host 3 it means `CARGO_INCREMENTAL=0 ~/cslot.sh` with that host's lane target dir. Every cargo command runs under `cs`: `cargo build`, `test`, `check`, `clippy`, `fmt`, `run` and `xtask`, and every script, Makefile target, generator, freeze or fixture command and SDK manifest build that reaches cargo directly or nested (`make codegen-check`, `scripts/check-bindings-parity.sh`, `scripts/check-chio-cpp.sh`, `scripts/check-sdk-parity.sh`, `scripts/check-adapter-no-bypass.sh`, `scripts/check-security-ci-contract.py`, `scripts/check-aws-lc-fork.py`, `wasm-pack`, every `--manifest-path` build). No command in this plan invokes cargo outside `cs`.
- Formal tools: no Lean, lake, Aeneas or Kani runs on ws2, including single harnesses. Kani runs only on the approved x86 runner under `cs`.
- Work happens on ws2 in worktree `~/lanes/m1i2` off fresh `origin/main` (fetched over https). Coder checks run under `cs`; heavy suites run on the integrators (`integ-x86`, `integ-h3`) per the coder/integrator split. Never `git stash`. Inspect `git diff --cached --stat -M` before every commit. Push explicit SHAs over https.
- Shared surfaces: before requesting merge, post `<UTC> <lane>: REVIEW? #<N> M1 item 2 committed receipts (core-types, kernel, store, CP, http-core, SDK middleware, every receipt fixture)` to `sync.md`, then `MERGING #<N>` with the 10-minute window and the OBJECT check.

## Review Focus

1. **A signing path that still accepts a hash or a commitment.** Expected: no public function in any crate takes a `content_hash`, `parameter_hash`, commitment value or a prebuilt `ChioReceiptBody` for signing; the only receipt signers take `ReceiptDraft`, `ReceiptPreimages` and `&dyn Rng`. `sign_receipt_relaying_trusted_body`, the WASM, mobile and C ABI relay exports and `ChioReceipt::sign(body, ..)` are gone. Pinned by Task 3 (`receipt_signers_take_preimages`, which calls every public receipt signer) and Task 1's grep re-run at the PR tip and Task 6 (`relay_api_has_no_hash_parameter` in each adapter).
2. **A salt that is not fresh, not 32 bytes, or not from the signing process.** Expected: two salts per receipt drawn from the producer's own `Rng`, refused when equal; fallible `Rng::fill_bytes`; no zero-fill fallback anywhere; `FixtureRng` reachable only from the allowlisted harness and fixture producers. Pinned by Task 2 (`equal_salts_refuse`, `rng_failure_refuses_signing`) and `scripts/check-fixture-rng.py` (Task 11).
3. **Plaintext surviving in a signed field.** Expected: for arguments and results built from random 16-byte markers, no marker (raw, hex or base64) appears in the canonical signed body, guard evidence, metadata or OCSF output; per-chunk stream digests never appear. Pinned by the marker property test (Task 5) run across every guard evidence producer and the OCSF projection.
4. **A verifier deriving the content preimage from the opening.** Expected: Rust, TS, Python, Go and C++ verifiers take the output from the caller, never from `payload`; `payload: null` is salt only. Pinned by the `parameters_opening_for_content`, `content_opening_absent` and `empty_output` vector cases in every language (Tasks 13, 14).
5. **A regenerated fixture that changed more than the committed fields.** Expected: in every regenerated receipt, the changed values are `action`, `content_commitment`, the removed `redaction_mode` and `content_hash`, the added `disclosure`, the signature, the receipt id (its id input changed) and derived digests traced to those. Pinned by the item 1 fixture diff aid, extended in Task 15.
6. **An HTTP receipt path left behind.** Expected: `git grep -n -E "HttpReceipt|http_receipt|httpReceipt|http-receipt|caller_identity_hash"` returns nothing outside `docs/superpowers`; the sidecar evaluate response carries a `chio.receipt.v1` receipt; every middleware SDK verifies it with the shared receipt verifier. Pinned by Task 9 Step 5.

---

## File Structure

| Path | Task | Responsibility |
|---|---|---|
| `crates/core/chio-core-types/src/rng.rs` (new; moved from `chio-kernel-core/src/rng.rs`) | 2 | `Rng` with fallible `fill_bytes`, `RngError`, `FixtureRng` behind the `fixture-rng` feature |
| `crates/core/chio-core-types/src/receipt/disclosure.rs` (new) | 2 | `Salt`, `SaltRef`, `CommitmentAlg`, `ReceiptCommitment`, `CommitmentDomain`, `ContentPreimage`, `commit`, `ReceiptDisclosure`, `Opening`, `open_receipt`, `OpeningReport` |
| `crates/core/chio-core-types/src/receipt/{body,decision,kinds,metadata,signing}.rs` | 2, 3 | committed body, `ToolCallAction`, `DisclosureBlock`, `ReceiptAuthority`, `ReceiptDraft`, `ReceiptPreimages`, `ReceiptOpenings`, `SignedReceipt`; `RedactionMode` deleted |
| `crates/core/chio-core-types/tests/{committed_receipt_vectors,committed_receipt_negatives,receipt_marker_property}.rs` (new) | 2, 3, 5, 13 | vector cross-check, strict-decode and signing refusals, marker property |
| `crates/kernel/chio-kernel-core/src/{receipts,rng,lib}.rs`, `src/guard.rs` | 3, 5 | committed `sign_receipt`, `sign_receipt_with_handle`, `ContentCommitmentMismatch`; relay signer and `rng.rs` deleted; `Guard::evidence_declaration` |
| `crates/kernel/chio-kernel/src/rng.rs` (new), `src/receipt_support/*`, `src/kernel/responses/*`, `src/kernel/signing_task.rs`, `src/kernel/{admission_terminal_receipt,effect_obligation,kernel_drop_guard,reconciliation,session_ops}*`, `src/disclosure_store.rs` (new), `src/kernel/mod.rs` (`Guard`) | 4, 5 | `OsEntropyRng`, kernel salt wiring, `DisclosureStore`, evidence and metadata allowlist |
| `crates/platform/chio-store-sqlite/src/disclosure_store.rs` (new), `src/receipt_store/bootstrap/open.rs` and readers | 4 | `disclosure_openings` table; `chio_tool_receipts.content_hash` replaced in place |
| `crates/kernel/chio-kernel-browser/src/{pure,wasm,rng}.rs`, `crates/kernel/chio-kernel-mobile/src/{lib.rs,rng.rs,chio_kernel_mobile.udl}`, `crates/sdk/chio-cpp-kernel-ffi/src/lib.rs` and header, `sdks/typescript/packages/{workers,edge,deno}`, `sdks/swift/Sources/chio_kernel_mobile/*` | 6 | preimage-taking relays, fallible RNG, regenerated bindings |
| `crates/security/chio-cage/src/receipt.rs`, `crates/platform/chio-control-plane/src/{keyring_runtime.rs,security/adapters/native_evidence.rs,security/response_simulation.rs,trust_control/config_and_public.rs,trust_control/finding_verified_fix.rs}`, `crates/kernel/chio-kernel/src/{response_simulation_report.rs,kernel/active_response_coordinator/execution_validation.inc}`, `crates/observability/chio-lineage/src/ingest_active_defense.rs`, `crates/platform/chio-control-plane/src/security/event_consumer/verification.rs` | 7 | security and control-plane producers and their readers |
| `crates/protocol/chio-acp-proxy/src/{interceptor,kernel_signer}.rs` | 8 | ACP preimage plumbing |
| `crates/platform/chio-http-core/src/{authority,receipt}.rs`, `crates/products/chio-api-protect/src/proxy/**`, `crates/protocol/chio-tower/src/{evaluator,service}.rs`, `crates/platform/chio-control-plane/src/evidence_export/{verification.rs,tests/http_receipts.rs}`, `crates/platform/chio-store-sqlite/src/{receipt_store/retained_read.rs,receipt_query_snapshot/export/metadata.rs}`, `spec/schemas/chio-http/v1/evaluate-response.schema.json` | 9 | `HttpReceipt` deleted; HTTP signs `chio.receipt.v1` |
| `sdks/python/{chio-sdk-python,chio-asgi,chio-django,chio-fastapi,chio-streaming,chio-langchain}`, `sdks/jvm/{chio-sdk-jvm,chio-spring-boot}`, `sdks/dotnet/ChioMiddleware`, `sdks/typescript/packages/{node-http,express,fastify,elysia,ai-sdk,chio-ai-sdk-middleware,conformance}`, `sdks/go/chio-go-http`, `examples/hello-*/smoke.sh` | 9 | HTTP middleware SDKs and examples on `chio.receipt.v1` |
| `crates/observability/chio-otel-receipt-exporter`, `crates/kernel/chio-runtime-harness`, `crates/products/chio-cli/src/cli/{dispatch/proof/fixture*.rs,process_host/**}`, `crates/products/chio-mercury`, `crates/products/chio-wall`, `crates/tooling/chio-conformance/src/native_suite.rs`, `crates/trust/chio-attest-loopback` | 10, 11 | group 5 producers |
| `crates/observability/chio-siem/src/**`, `crates/tooling/chio-conformance/verdict_matrix/src/driver.rs`, store query and export readers, `scripts/tests/check-receipt-query-http.test.py` | 12 | readers on commitments |
| `sdks/typescript/chio-ts/src/invariants/receipt.ts`, `sdks/python/chio-py/src/chio/invariants/receipt.py`, `sdks/go/chio-go/invariants/receipt.go`, `sdks/cpp/chio-cpp`, `crates/sdk/chio-bindings-ffi`, `sdks/python/packages/chio-bedrock` and the other SDK receipt readers in the census | 14 | verifiers: commitments, openings, closed decode of the new blocks |
| `spec/schemas/chio-wire/v1/receipt/record.schema.json` (moved in), new `spec/schemas/chio-wire/v1/receipt/receipt-disclosure.schema.json`, `spec/schemas/registry.json`, `spec/schemas/MANIFEST.sha256`, `spec/wire-schemas.lock`, generated code, `spec/errors/registry.yaml` | 2 | contract move-in and codegen |
| `tests/bindings/vectors/receipt/committed/v1.json`, `scripts/gen-signing-wrapper-vectors.py`, `tests/bindings/vectors/MANIFEST.sha256` | 13 | cross-check, padding negatives |
| `xtask/src/signed_fixtures.rs` (from item 1), `scripts/check-fixture-rng.py` (new) | 11, 15 | seeded fixture producers, regeneration |
| `spec/PROTOCOL.md` (section 6), `docs/superpowers/specs/relying-party-wedge/protocol/protocol-6-committed-receipts.md` (deleted on move), `docs/superpowers/specs/relying-party-wedge/in-place-schemas/receipt/record.schema.json` (moved), docs naming deleted APIs | 16 | contract text |
| `docs/formal/COVERAGE.md`, `formal/rust-verification/kani-public-harnesses.toml`, `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs` | 17 | formal touchpoints |

## Commit Grouping

One branch `feat/m1-committed-receipts`, one PR `feat(core-types): committed receipts for every producer`, squash-merged. Commits in this order (conventional messages, trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`). A "producer" is one signing entry point that owns a salt source: one row of the producer table in Task 1, which groups the inventory's 54 call sites by the `Rng` they draw from.

| # | Group | Commit | Task |
|---|---|---|---|
| 1 | 1 | `feat(core-types): move the Rng seam into core types and make it fallible` | 2 |
| 2 | 1 | `feat(core-types): committed receipt body, commitments and the receipt disclosure document` | 2 |
| 3 | 1 | `feat(schemas): move the committed receipt record schema in and add chio.receipt-disclosure.v1` | 2 |
| 4 | 1 | `feat(kernel-core): sign committed receipts from preimages and delete the trusted-body relay` | 3 |
| 5 | 2 | `feat(kernel): draw receipt salts from the OS RNG in the hosted kernel` | 4 |
| 6 | 2 | `feat(store): disclosure openings store and committed receipt columns` | 4 |
| 7 | 2 | `feat(kernel): declare guard evidence disclosure and drop undeclared evidence and metadata` | 5 |
| 8 | 3 | `feat(kernel-browser): sign committed receipts from preimages with Web Crypto salts` | 6 |
| 9 | 3 | `feat(kernel-mobile): sign committed receipts from preimages with OS RNG salts` | 6 |
| 10 | 3 | `feat(cpp-kernel-ffi): sign committed receipts from preimages with OS RNG salts` | 6 |
| 11 | 4 | `feat(cage): draw cage receipt salts from the host RNG` | 7 |
| 12 | 4 | `feat(control-plane): commit keyring enterprise receipt projections` | 7 |
| 13 | 4 | `feat(control-plane): commit native active-defense evidence receipts` | 7 |
| 14 | 4 | `feat(control-plane): commit response simulation receipts` | 7 |
| 15 | 4 | `feat(control-plane): commit SCIM deprovision receipts` | 7 |
| 16 | 4 | `feat(control-plane): pass verified-fix evidence preimages to the receipt signer` | 7 |
| 17 | 4 | `feat(acp-proxy): pass ACP session update preimages to the receipt signer` | 8 |
| 18 | 4 | `feat(http-core): sign chio.receipt.v1 for HTTP calls and delete HttpReceipt` | 9 |
| 19 | 4 | `feat(api-protect): sign committed sidecar receipts with OS RNG salts` | 9 |
| 20 | 4 | `refactor(tower): read chio.receipt.v1 from the HTTP authority` | 9 |
| 21 | 4 | `feat(sdks): HTTP middleware carries chio.receipt.v1` (Python, JVM, .NET, TS, Go, examples) | 9 |
| 22 | 5 | `feat(otel-exporter): commit span receipts with OS RNG salts` | 10 |
| 23 | 5 | `feat(cli): commit chio run evidence and swarm bootstrap receipts` | 10 |
| 24 | 5 | `feat(mercury): commit step receipts with OS RNG salts` | 10 |
| 25 | 5 | `feat(wall): commit wall receipts with OS RNG salts` | 10 |
| 26 | 5 | `test(runtime-harness): seed treaty proof receipt salts` | 11 |
| 27 | 5 | `test(cli): seed proof fixture receipt salts and re-sign from recorded preimages` | 11 |
| 28 | 5 | `test(conformance): seed native suite receipt salts` | 11 |
| 29 | 5 | `test(attest-loopback): seed loopback receipt salts` | 11 |
| 30 | 5 | `refactor: read commitments in SIEM, lineage, store queries and the verdict-matrix driver` | 12 |
| 31 | 5 | `test(vectors): cross-check committed receipt vectors and add padding negatives` | 13 |
| 32 | 5 | `feat(sdk): verify committed receipts and openings in every SDK` | 14 |
| 33 | 5 | `test: regenerate signed fixtures for committed receipts` | 15 |
| 34 | 5 | `docs(spec): specify committed receipts in PROTOCOL 6` | 16 |
| 35 | 5 | `chore(formal): refresh proof coverage` | 17 (last, after the final rebase) |

A diff touching `.github/workflows/` is handed to the lead to push from the Mac (ws2 has no workflow scope).

---

### Task 1: Base, census and coordination

**Files:** none changed. Output goes to `ws2:~/lanes/claude-pr1160-evidence/m1i2/census-<base>.md`.

- [ ] **Step 1: Preconditions.** `gh pr view <N> --repo bb-connor/arc --json state` reports `MERGED` for #1674, #1607, #1715, the shared decoder PR (find it with `gh pr list --repo bb-connor/arc --search lossless_serde` and record its number in the census), #1716, #1706, the K-stack in Root-2's order and the item 1 PR. If any is open, the lane waits; it does not reorder. Create the worktree at that integrated base: `git -C /home/connor/backbay/arc fetch -q https://github.com/bb-connor/arc.git main:refs/remotes/origin/main && git -C /home/connor/backbay/arc worktree add -b feat/m1-committed-receipts ~/lanes/m1i2 origin/main`.
- [ ] **Step 2: Re-run the inventory greps** from the inventory's Method section, adjusted for item 1's names, plus:
```bash
git grep -n -E "sign_receipt(_with_handle|_relaying_trusted_body)?\(|ChioReceipt::sign(_with_backend|_with_handle|_with_backend_using_handle|_with_bbs|_prepared_with_bbs)?\(|build_and_sign_receipt\(|core_sign_receipt|core_relay_trusted_body" -- crates sdks ':!**/tests/**' ':!*_tests.rs'
git grep -n -E "content_hash|parameter_hash|RedactionMode|redaction_mode|ToolCallAction::from_parameters|verify_hash\(" -- crates sdks xtask ':!**/_generated/**'
git grep -n -E "HttpReceipt|http_receipt|httpReceipt|http-receipt|caller_identity_hash" -- . ':!docs/superpowers'
git grep -n -E "impl [A-Za-z_:]*Guard for" -- crates sdks
git grep -n -E "GuardEvidence \{" -- crates ':!**/tests/**' ':!*tests.rs'
git grep -n -E "NullRng|fill_bytes|impl [A-Za-z_:]*Rng for" -- crates sdks
git grep -l -E '"content_hash"|"parameter_hash"|"redaction_mode"' -- '*.json' '*.ndjson' '*.jsonl'
```
  Expected at `a93a2f69a3`: 54 non-test producer call sites (inventory), `content_hash` in 423 files (1102 lines), `parameter_hash` in 289 (751, including the unrelated approval and admission-operation `parameter_hash` columns, which this PR does not touch), `RedactionMode|redaction_mode` in 299, `ToolCallAction` in 292, the relay signer in 27, `HttpReceipt` and its spellings in 103 files (417 lines), 89 `Guard` impls (48 non-test), 62 non-test `GuardEvidence` constructions, 893 JSON fixtures carrying `content_hash` (861 under `fixtures/proof-room/`), 189 Rust test files naming `content_hash`. Record each inventory row at its current `file:line`.
- [ ] **Step 3: Producer table.** Write the census table that the commit grouping uses: one row per producer, with its call sites, its salt source (spec 7.8 row), where its openings go (disclosure store, returned to the host, or fixture material) and how it obtains each preimage. Starting rows, from the inventory:

| Producer | Call sites | Salt source | Openings | Preimages |
|---|---|---|---|---|
| Portable signer (`chio-kernel-core`) | `receipts.rs` `sign_receipt`, `sign_receipt_with_handle` | host-supplied `Rng` | returned in `SignedReceipt` | passed in |
| Hosted kernel (`chio-kernel`) | the 20 kernel rows of the inventory (allow, deny, pending, cancelled, terminal, reconciliation, effect obligation, drop guard, session ops, signing task, backend signer) | `OsEntropyRng` injected at kernel construction | `DisclosureStore` | request arguments; `receipt_content_for_output` through `ReceiptSigningHandle` |
| Browser WASM | `pure.rs` signer, `wasm.rs` exports, TS workers, edge and deno | `WebCryptoRng` | returned to JS | passed in from JS |
| Mobile | `lib.rs` signer, UDL, Swift | `MobileRng` | returned to the host | passed in |
| C ABI | `chio-cpp-kernel-ffi` signer | `OsEntropyRng` inside the library | returned to the caller | passed in |
| Cage | `chio-cage/src/receipt.rs` | host `Rng` passed into `prepare_cage_receipt` | returned to the cage host | in scope |
| Keyring projection | `keyring_runtime.rs` | `OsEntropyRng` | returned, discarded (no store) | the signed key enterprise receipt |
| Native evidence | `native_evidence.rs` | `OsEntropyRng` | returned, discarded | the active-defense body |
| Response simulation | `response_simulation.rs` | `OsEntropyRng` | returned, discarded | the simulation report |
| SCIM deprovision | `config_and_public.rs` | `OsEntropyRng` | returned, discarded | the deprovision request and result |
| Verified-fix evidence | `finding_verified_fix.rs` | `OsEntropyRng` | returned, discarded | the evidence body (today only its hash reaches the signer) |
| ACP proxy | `interceptor.rs` (two), `kernel_signer.rs` | `OsEntropyRng` | returned, discarded | the session update and audit entry (today only `entry.content_hash`) |
| HTTP authority (`chio-http-core`) | `authority.rs` decision and final receipts (four construction sites) | `OsEntropyRng` | returned to the sidecar host | canonical HTTP request and response |
| `api protect` sidecar | `sidecar.rs` | `OsEntropyRng` | returned, discarded until M3 | in scope |
| OTel exporter | `sink.rs` | `OsEntropyRng` | returned, discarded | sanitized span attributes |
| `chio run` | `call_evidence/export.rs`, `outcomes_export.rs`, `run_evidence/export.rs`, `swarm/requests.rs` | `OsEntropyRng` | returned with the evidence export | in scope |
| Mercury | `builders.rs` | `OsEntropyRng` | returned, discarded | in scope |
| Wall | `commands.rs` | `OsEntropyRng` | returned, discarded | in scope |
| Runtime harness | `treaty.rs` | `FixtureRng` | fixture material | synthetic outcome label |
| Proof fixtures | `fixture.rs` (two), `fixture_agent_web.rs` | `FixtureRng` | fixture material | recorded preimages (two sites copy a recorded hash today) |
| Conformance native suite | `native_suite.rs` | `FixtureRng` | fixture material | fixed literal |
| Attest loopback | `lib.rs`, `package.rs` | `FixtureRng` | fixture material | vendor output label |

  The Lambda extension (`sdks/lambda/chio-lambda-extension`) emits an unsigned detect-only `EvaluateResponse` with no receipt body, hash or arguments at `a93a2f69a3`, so it is not a producer; Task 10 pins that.
- [ ] **Step 4: D17 check.** Post the "D17 Coordination" list below to `sync.md` as `<UTC> <lane>: D17 m1i2 byte changes: <list>; holding PR open until lead and Root-2 ACK`. Record the merge SHA of every predecessor; the PR is based on the commit that contains all of them.

---

### Task 2: Core types, the `Rng` seam and the contract move-in (commits 1 to 3)

**Files:**
- Create: `crates/core/chio-core-types/src/rng.rs`, `src/receipt/disclosure.rs`, `tests/committed_receipt_negatives.rs`, `spec/schemas/chio-wire/v1/receipt/receipt-disclosure.schema.json`
- Delete: `crates/kernel/chio-kernel-core/src/rng.rs`
- Modify: `src/receipt/{body,decision,kinds,metadata,signing,mod}.rs`, `src/lib.rs`, `crates/kernel/chio-kernel-core/src/lib.rs`, every `Rng` import and impl (`chio-kernel-browser`, `chio-kernel-mobile`, `chio-kernel-core`), `spec/schemas/chio-wire/v1/receipt/record.schema.json`, `spec/schemas/registry.json`, `spec/schemas/MANIFEST.sha256`, `spec/wire-schemas.lock`, generated code, `spec/errors/registry.yaml`

**Interfaces (produced; every later task consumes them):**

```rust
// rng.rs. The seam moves down one crate because chio-core-types signs receipts and the
// cage and attest-loopback producers do not depend on chio-kernel-core. Every import
// changes; chio-kernel-core does not re-export it.
pub trait Rng {
    /// Fills `dest` with cryptographically secure random bytes or fails. No implementation
    /// zero-fills on failure.
    fn fill_bytes(&self, dest: &mut [u8]) -> core::result::Result<(), RngError>;
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RngError(pub &'static str);
impl<T: Rng + ?Sized> Rng for &T { /* forwards */ }

/// Deterministic ChaCha20 stream from a 32-byte seed (`rand_chacha`). Output is fixture
/// material only. Compiled only with the `fixture-rng` feature, which only the harness,
/// conformance and fixture producers enable (Task 11 gate).
#[cfg(feature = "fixture-rng")]
pub struct FixtureRng { /* interior-mutable ChaCha20Rng */ }
#[cfg(feature = "fixture-rng")]
impl FixtureRng { pub fn from_seed(seed: [u8; 32]) -> Self; }
```

`NullRng` is deleted (no non-test user at the census base). The browser and mobile zero-fill fallbacks are deleted; both return `RngError`. The browser receipt path's all-zero seed probe is deleted with them.

```rust
// receipt/disclosure.rs
pub const SALT_LEN: usize = 32;
pub const PARAMETERS_COMMITMENT_DOMAIN: &[u8] = b"chio.receipt.parameters.v1\0";
pub const CONTENT_COMMITMENT_DOMAIN: &[u8] = b"chio.receipt.content.v1\0";
pub const CHAIN_DIGEST_DOMAIN: &[u8] = b"chio.receipt.chain-digest.v1\0";
pub const CHIO_RECEIPT_DISCLOSURE_SCHEMA: &str = "chio.receipt-disclosure.v1";

/// 32 secret bytes. Debug prints `Salt(..)`. Wire form `b64u:` plus unpadded base64url;
/// a padded form or any length other than 32 rejects at decode.
#[derive(Clone, PartialEq, Eq)]
pub struct Salt([u8; SALT_LEN]);
impl Salt { pub fn draw(rng: &dyn Rng) -> Result<Self>; pub fn as_bytes(&self) -> &[u8; SALT_LEN]; }

/// Closed. Serializes as `params`, `content`, `anchor.sub`, `anchor.tenant`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SaltRef { Params, Content, AnchorSubject, AnchorTenant }

/// Closed. Serializes as `sha256-salted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitmentAlg { Sha256Salted }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptCommitment { pub alg: CommitmentAlg, pub value: Sha256Digest, pub salt_ref: SaltRef }

/// The domain comes from the commitment's position, never from an opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentDomain { Parameters, Content, DelegationSubject, DelegationTenant }
impl CommitmentDomain { pub fn bytes(self) -> &'static [u8]; }

/// `SHA-256(domain || salt || preimage)`.
pub fn commit(domain: CommitmentDomain, salt: &Salt, preimage: &[u8]) -> Sha256Digest;

/// The three content preimage forms (G13). `Stream` holds each canonical chunk's SHA-256;
/// an empty `Stream` encodes as `Empty`.
pub enum ContentPreimage<'a> { Value(&'a serde_json::Value), Empty, Stream(&'a [[u8; 32]]) }
impl ContentPreimage<'_> { pub fn to_bytes(&self) -> Result<Vec<u8>>; }

/// `chio.receipt-disclosure.v1`, unsigned. `receipt_id` is bare lowercase hex (G14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptDisclosure { pub schema: DisclosureSchema, pub receipt_id: String, pub openings: Vec<Opening> }

/// `payload` is opaque caller data. `None` serializes as `null` (a salt-only opening).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Opening { pub salt_ref: SaltRef, pub salt: Salt, pub payload: Option<serde_json::Value> }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldVerdict { Verified, Rejected, Unverifiable }
pub struct OpeningReport { pub parameters: FieldVerdict, pub content: FieldVerdict, pub disclosure_valid: bool }

/// The caller supplies its own arguments and output; `payload` never supplies a content
/// preimage. A salt shared by two `salt_ref`s, a malformed salt or a `receipt_id` that is
/// not the receipt's id marks `disclosure_valid = false` and every field `Rejected` (G15).
pub fn open_receipt(receipt: &ChioReceipt, disclosure: &ReceiptDisclosure,
    own_parameters: Option<&serde_json::Value>, own_output: Option<ContentPreimage<'_>>) -> OpeningReport;
```

```rust
// receipt/decision.rs
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCallAction {
    pub parameter_commitment: ReceiptCommitment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters_inline: Option<serde_json::Map<String, serde_json::Value>>,
}
// ToolCallAction::from_parameters and verify_hash are deleted.

// receipt/body.rs: ChioReceiptBody, field order as the staged schema
//   removed: redaction_mode, content_hash
//   added:   content_commitment: ReceiptCommitment,
//            result_inline: Option<serde_json::Map<String, serde_json::Value>>,
//            disclosure: DisclosureBlock,
//            authority: Option<ReceiptAuthority>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureBlock {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<Sha256Digest>,
    pub parameter_inline_fields: Vec<JsonPointer>,
    pub result_inline_fields: Vec<JsonPointer>,
}
impl DisclosureBlock { pub const FULLY_COMMITTED: Self; }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptAuthority {
    pub root_anchor: RootAnchor,      // #1706, capability/anchor.rs
    pub chain_digest: Sha256Digest,
    pub chain_depth: u32,
    pub holder: HolderClass,          // #1706, root_authority/delegation_context.rs
}

/// Every body member except the two commitments, `result_inline` and `disclosure`.
pub struct ReceiptDraft { /* id, timestamp, capability_id, tool_server, tool_name, decision,
    receipt_kind, boundary_class, observation_outcome, tool_origin, actor_chain, policy_hash,
    evidence, metadata, trust_level, tenant_id, authority, kernel_key, bbs_projection_version */ }

pub struct ReceiptPreimages<'a> { pub parameters: &'a serde_json::Value, pub content: ContentPreimage<'a> }

/// The salts of one receipt. Debug prints the receipt id only.
pub struct ReceiptOpenings { pub receipt_id: String, pub parameters: Salt, pub content: Salt }
impl ReceiptOpenings {
    /// Salt-only openings for the caller copy and `caller` bundles.
    pub fn salt_only(&self) -> ReceiptDisclosure;
    /// Openings with payloads, for auditor bundles.
    pub fn with_payloads(&self, parameters: &serde_json::Value, content: Option<&serde_json::Value>) -> ReceiptDisclosure;
}

#[must_use]
pub struct SignedReceipt { pub receipt: ChioReceipt, pub openings: ReceiptOpenings }

impl ChioReceipt {
    /// Draws two salts from `rng` (refusing equal salts), computes both commitments from
    /// `preimages`, sets `disclosure` to `FULLY_COMMITTED`, checks the body, signs
    /// `chio.receipt.v1` through the item 1 wrapper. Refuses `tenant_id` beside `authority`.
    pub fn sign(draft: ReceiptDraft, preimages: ReceiptPreimages<'_>, rng: &dyn Rng, keypair: &Keypair) -> Result<SignedReceipt>;
    pub fn sign_with_backend(draft: ReceiptDraft, preimages: ReceiptPreimages<'_>, rng: &dyn Rng, backend: &dyn SigningBackend) -> Result<SignedReceipt>;
    pub fn sign_with_backend_using_handle(draft: ReceiptDraft, parameters: &serde_json::Value, rng: &dyn Rng, backend: &dyn SigningBackend, handle: ReceiptSigningHandle) -> Result<SignedReceipt>;
}
```

`ChioReceipt::sign_with_bbs` and `sign_prepared_with_bbs` take the same draft, preimages and `Rng` and keep the BBS signature inside the signing body. `ReceiptSigningHandle` holds a `ContentPreimage` it owns (`from_content_preimage`, `from_content`) instead of an unsalted digest. `RedactionMode` and `ReceiptSemanticFields.redaction_mode` are deleted; `ReceiptSemanticFields::trace_detect_only` and `advisory_only` lose their mode member (inventory "RedactionMode mapping": every target is fully committed). New `Error` variants: `SaltGeneration(RngError)`, `DuplicateSalt`, `TenantIdWithAuthority`, `InlineFieldsWithoutPolicy`, `CommitmentMismatch { field: SaltRef }`.

Contract move-in (in-place schemas README, move-in rule): `git mv` the staged `in-place-schemas/receipt/record.schema.json` over the live `spec/schemas/chio-wire/v1/receipt/record.schema.json` after removing the members later milestones own (`enforcement`, the `pdp_decision`, `prevent_external` and `delegated` values with their rule, `settlement`), re-diffing against the live file and carrying in #1715's `additionalProperties: false` layers and item 1's `algorithm` removal first. `content_commitment` is required (no `pdp_decision` kind exists in this PR). Add `receipt/receipt-disclosure.schema.json` (`additionalProperties: false` on the document and on each opening, `salt` pattern `^b64u:[A-Za-z0-9_-]{43}$`, `payload` unconstrained) and register `chio.receipt-disclosure.v1` as an unsigned artifact. Register `urn:chio:error:attest:receipt-tenant-id-with-authority` (first emitted here) in `spec/errors/registry.yaml`.

- [ ] **Step 1: Write the failing tests** in `crates/core/chio-core-types/tests/committed_receipt_negatives.rs`:
```rust
#![allow(clippy::expect_used, clippy::unwrap_used)]
#[test]
fn commitment_matches_layout() {
    let salt = Salt::from_bytes([7; 32]);
    let mut expected = Vec::new();
    expected.extend_from_slice(b"chio.receipt.parameters.v1\0");
    expected.extend_from_slice(&[7; 32]);
    expected.extend_from_slice(br#"{"a":1}"#);
    assert_eq!(commit(CommitmentDomain::Parameters, &salt, br#"{"a":1}"#), Sha256Digest::of(&expected));
}
#[test]
fn empty_output_preimage_is_zero_length() {
    assert!(ContentPreimage::Empty.to_bytes().unwrap().is_empty());
    assert!(ContentPreimage::Stream(&[]).to_bytes().unwrap().is_empty());
}
#[test]
fn equal_salts_refuse() { /* ConstantRng; ChioReceipt::sign errs with Error::DuplicateSalt; no signature */ }
#[test]
fn rng_failure_refuses_signing() { /* FailingRng; Err(Error::SaltGeneration(_)); no backend sign call */ }
#[test]
fn tenant_id_with_authority_refuses_signing() { /* Err(Error::TenantIdWithAuthority) */ }
#[test]
fn padded_blocks_fail_decoding() { /* "pad":0 added to parameter_commitment, content_commitment, disclosure, authority, authority.root_anchor, the disclosure document and one opening: each fails decode with the exact serde unknown-field error, over a valid wrapper signature */ }
#[test]
fn removed_members_fail_decoding() { /* "content_hash", "redaction_mode", "action.parameters", "action.parameter_hash" each fail decode */ }
#[test]
fn salt_wire_form_is_strict() { /* padded base64url, 31 bytes and 33 bytes each fail decode */ }
```
- [ ] **Step 2: Run and confirm failure.** `cs cargo test -p chio-core-types --test committed_receipt_negatives`. Expected: compile error (types missing).
- [ ] **Step 3: Implement** commit 1 (the `Rng` move and fallible signature, every impl and import), then commit 2 (the types above, `ChioReceipt::sign*`), then commit 3 (schemas, registry, `MANIFEST.sha256`, error registry). Regenerate code: `for lang in rust ts go python; do cs cargo xtask codegen --lang "$lang" || exit 1; done && cs cargo xtask snippets regen && python3 scripts/check-wire-schemas.py --update`.
- [ ] **Step 4: Run.** `cs cargo test -p chio-core-types --test committed_receipt_negatives --test wire_protocol_schema --test signed_artifact_schema --test receipt_strict_decode`, `cs cargo test -p chio-core-types --no-default-features --lib`, `bash scripts/check-chio-schema-registry.sh`, `python3 scripts/check-error-urn-registry.py`. Expected: PASS except golden-signature tests that Task 15 regenerates (list them).

---

### Task 3: Portable signer (commit 4)

**Files:** `crates/kernel/chio-kernel-core/src/receipts.rs`, `src/lib.rs`, `src/kani_public_harnesses.rs`, `tests/` that call the relay.

**Interfaces:**

```rust
pub enum ReceiptSigningError {
    /// The assembled body's commitment does not recompute from the drawn salt and the
    /// preimage. Checked before the signing call.
    ContentCommitmentMismatch { field: SaltRef },
    KernelKeyMismatch,
    SaltGeneration(RngError),
    DuplicateSalt,
    TenantIdWithAuthority,
    SigningFailed(String),
}
pub fn sign_receipt(draft: ReceiptDraft, preimages: ReceiptPreimages<'_>, rng: &dyn Rng, backend: &dyn SigningBackend)
    -> Result<SignedReceipt, ReceiptSigningError>;
pub fn sign_receipt_with_handle(draft: ReceiptDraft, parameters: &serde_json::Value, rng: &dyn Rng,
    backend: &dyn SigningBackend, handle: ReceiptSigningHandle) -> Result<SignedReceipt, ReceiptSigningError>;
```

Deleted: `sign_receipt_relaying_trusted_body`, `ContentHashMismatch`. Order inside the signer: kernel key check against `backend.public_key()?`, salt draws, commitment computation, recompute check, body validation (`validate_signable_semantics`, the `tenant_id` rule), wrapped signing.

- [ ] **Step 1: Failing tests** in `receipts.rs` tests: `commitment_recomputes_from_preimage` (sign, then `open_receipt` with the same arguments and output verifies both fields); `different_output_rejects` (open with a one-bit different output: content `Rejected`); `kernel_key_mismatch_refuses_before_salts` (a counting `Rng` records zero draws); `receipt_signers_take_preimages` (calls every public receipt signer in `chio_kernel_core` and `chio_core_types::receipt` with the new signatures, so a reintroduced body-only signer is a compile-visible API change in review).
- [ ] **Step 2: Implement and run.** `cs cargo test -p chio-kernel-core --no-fail-fast` and `cs cargo clippy -p chio-kernel-core --all-targets -- -D warnings`. Update the `#[cfg(kani)]` blocks by hand (the `mem::forget(body)` path moves to the draft). Expected: PASS.

---

### Task 4: Hosted kernel salt source and the disclosure store (commits 5, 6)

**Files:** `crates/kernel/chio-kernel/src/rng.rs` (new), `src/disclosure_store.rs` (new), `src/receipt_support/{signing,receipt_scopes}.rs`, `src/kernel/responses/{allow_responses,deny_responses,pending_responses,receipt_persistence,terminal_responses}.rs`, `src/kernel/{admission_terminal_receipt,effect_obligation,effect_obligation/recovery,kernel_drop_guard,reconciliation,session_ops,session_ops/protocol_refusal,session_ops/reports,signing_task}.rs`, `src/kernel/construction.rs`; `crates/platform/chio-store-sqlite/src/disclosure_store.rs` (new), `src/receipt_store/bootstrap/open.rs`, every store reader of `content_hash`; `crates/platform/chio-control-plane/src/lib.rs` (`build_kernel_with_clock`).

**Interfaces:**

```rust
// chio-kernel/src/rng.rs
/// OS CSPRNG through `getrandom`. The only `Rng` std producers inject.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropyRng;
impl chio_core_types::rng::Rng for OsEntropyRng { /* getrandom::getrandom(dest).map_err(..) */ }

// chio-kernel/src/disclosure_store.rs
pub trait DisclosureStore: Send + Sync {
    /// Writes both salts of one receipt keyed by `(receipt_id, salt_ref)`. Idempotent for
    /// identical salts; a different salt under an existing key refuses.
    fn put_openings(&self, openings: &ReceiptOpenings) -> Result<(), DisclosureStoreError>;
    fn openings(&self, receipt_id: &str) -> Result<Option<StoredOpenings>, DisclosureStoreError>;
    /// Records that this receipt's openings could not be stored. The commitments stay hiding.
    fn mark_lost(&self, receipt_id: &str) -> Result<(), DisclosureStoreError>;
    /// Erasure: deletes the openings; the signed receipt is untouched.
    fn erase(&self, receipt_id: &str) -> Result<(), DisclosureStoreError>;
}
pub enum StoredOpenings { Present(ReceiptOpenings), Lost }
```

- Kernel construction takes `rng: Arc<dyn Rng + Send + Sync>` and `disclosure_store: Option<Arc<dyn DisclosureStore>>`. `build_and_sign_receipt`, the signing task and every `sign_receipt_with_handle` caller pass the kernel's `Rng` and the request arguments as the parameter preimage. A kernel configured with a durable receipt store and no disclosure store refuses construction (open question 6). After signing, the kernel appends the receipt first, then calls `put_openings`; on its failure it calls `mark_lost`, emits the operator alert through the existing security alert path and returns the receipt (spec 8.4, open question 2).
- `chio-store-sqlite`: table `disclosure_openings (receipt_id TEXT NOT NULL, salt_ref TEXT NOT NULL CHECK (salt_ref IN ('params','content','anchor.sub','anchor.tenant')), salt BLOB CHECK (salt IS NULL OR length(salt) = 32), state TEXT NOT NULL CHECK (state IN ('present','lost')), PRIMARY KEY (receipt_id, salt_ref)) WITHOUT ROWID`, written through the existing serving writer. `erase` deletes rows. `chio_tool_receipts.content_hash TEXT NOT NULL` becomes `content_commitment TEXT NOT NULL` (the `sha256:` value) in place; every reader and query snapshot changes with it. No migration (house rule).
- Each hosted-kernel commit wires one producer: commit 5 is the kernel `Rng` wiring for all 20 kernel rows (they share `build_and_sign_receipt`, the signing task and `sign_receipt_with_handle`, so they are one producer); commit 6 is the store.

- [ ] **Step 1: Failing tests:** `kernel_receipt_openings_reach_store` (allow receipt; store holds both salts; `open_receipt` with the call's arguments and output verifies); `deny_receipt_commits_empty_output` (deny has `content_commitment` over the zero-length preimage); `disclosure_store_failure_appends_and_marks_lost` (faulting store: receipt appended, `StoredOpenings::Lost`, alert recorded); `erase_keeps_receipt_valid`; `durable_receipt_store_without_disclosure_store_refuses`; SQLite tests for the CHECK constraints and the salt-mismatch refusal; `stream_chunk_digests_absent` (streaming tool with three chunks: no chunk digest in the signed body, evidence or metadata).
- [ ] **Step 2: Implement, run** `cs cargo test -p chio-kernel --no-fail-fast`, `cs cargo test -p chio-store-sqlite --no-fail-fast`, clippy for both, and `cs cargo test -p chio-kernel --test durable_admission_sqlite` (real-SQLite kernel tests live there). Expected: PASS except golden signatures.

---

### Task 5: Guard evidence and metadata allowlist (commit 7)

**Files:** `crates/kernel/chio-kernel-core/src/guard.rs`, `crates/kernel/chio-kernel/src/kernel/mod.rs` (`Guard`), every `Guard` impl (48 non-test at the census base), `crates/kernel/chio-kernel/src/receipt_support/receipt_scopes.rs` (evidence assembly), the metadata merge, `crates/core/chio-core-types/tests/receipt_marker_property.rs` (new).

**Interfaces:**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceDisclosure { /// `details` never carries argument or result values.
    Safe, Unsafe }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardEvidenceDeclaration { pub details: EvidenceDisclosure, pub details_required: bool }
// Both Guard traits gain a required method (no default):
fn evidence_declaration(&self) -> GuardEvidenceDeclaration;
```

- At guard registration the kernel refuses a guard whose declaration is `{ details: Unsafe, details_required: true }` (spec 8.4 "fails at load").
- At receipt assembly the kernel drops `GuardEvidence.details` of every guard declared `Unsafe`. `guard_name` and `verdict` are always kept. A denied call's revocation entry id (spec 7.11) is a `Safe` field.
- Metadata: the signed `metadata` keeps only the reserved typed blocks of the metadata key registry (ADR-0018 item 7) that the producing component declares committed-safe; every other caller or hook key is dropped before signing (open question 5). Task 1 records each reserved key with its declaration.

- [ ] **Step 1: Failing tests:** `unsafe_required_guard_refuses_registration`; `undeclared_guard_evidence_field_dropped` (the kernel-level backing for staged `receipt-disclosure-003`); `receipt_marker_property` (proptest: arguments and results built from random 16-byte markers, run through every guard evidence producer in the workspace and the kernel's metadata merge, then `chio-siem` OCSF projection; assert no marker in raw, hex or base64 form in the canonical signed body, evidence, metadata or OCSF output; the backing for staged `receipt-disclosure-004`).
- [ ] **Step 2: Declare every guard.** Each impl states its declaration with a one-line invariant comment (what `details` holds). Guards whose `details` echo request content (path, URL, pattern match text) declare `Unsafe`.
- [ ] **Step 3: Run** `cs cargo test -p chio-kernel-core -p chio-kernel -p chio-guards -p chio-external-guards -p chio-security-kernel --no-fail-fast`, the property test with `PROPTEST_CASES=512`, and clippy. Expected: PASS.

---

### Task 6: FFI, WASM and mobile relays (commits 8 to 10)

**Files:** `crates/kernel/chio-kernel-browser/src/{pure,wasm,rng}.rs`, `tests/wasm_bindings.rs`; `crates/kernel/chio-kernel-mobile/src/{lib.rs,rng.rs,chio_kernel_mobile.udl}`; `crates/sdk/chio-cpp-kernel-ffi/src/lib.rs` and its header; `sdks/typescript/packages/{workers,edge,deno}/src/index.ts` and tests; `sdks/swift/Sources/chio_kernel_mobile/*` (regenerated).

**Interfaces:**

- Browser WASM: `#[wasm_bindgen] pub fn sign_receipt(draft_json: &str, parameters_json: &str, content: JsValue, signing_seed_hex: &str) -> Result<JsValue, JsError>` where `content` is `{ "kind": "value", "value": <json> }`, `{ "kind": "empty" }` or `{ "kind": "stream", "chunk_sha256": [<hex>, ..] }` (closed, decoded through `lossless_serde!`). Returns `{ "receipt": <ChioReceipt>, "openings": <chio.receipt-disclosure.v1 salt-only> }`. Salts from `WebCryptoRng`. `sign_receipt_relaying_trusted_body` export and `sign_receipt_relaying_trusted_body_pure` are deleted. `WebCryptoRng::try_new` already probes `globalThis.crypto` at the census base, so Workers no longer need `window`; the Miniflare test pins it.
- Mobile UniFFI: `sign_receipt(draft_json: String, parameters_json: String, content: ContentInput, signing_seed_hex: String) -> Result<SignedReceiptOutput, MobileError>`; UDL `dictionary ContentInput` and `SignedReceiptOutput`; the relay export and UDL entries are deleted; Swift bindings regenerated.
- C ABI: `ChioFfiResult chio_kernel_sign_receipt(const char *draft_json, const char *parameters_json, const char *content_json, const char *signing_seed_hex);` (`content_json` is the same closed object as the browser's); salts from `OsEntropyRng` inside the library; the relay symbol is deleted from the header and `tests/abi/*.symbols`.
- TS `workers`, `edge`, `deno`: `signReceipt(draft, parameters, content, signingSeedHex): { receipt, openings }`.

- [ ] **Step 1: Failing tests:** in each adapter, `relay_api_has_no_hash_parameter` (the exported signature list, read from the generated bindings or symbols file, has no hash or body-only signer); `signed_receipt_opens` (sign through the adapter, open with the same inputs); `rng_failure_refuses` (mobile and C ABI with an injected failing `Rng` in a test build). Miniflare test in `sdks/typescript/packages/workers`: the WASM build signs one receipt with salts from `globalThis.crypto`, and the opening verifies.
- [ ] **Step 2: Implement, run** `cs cargo test -p chio-kernel-browser -p chio-kernel-mobile -p chio-cpp-kernel-ffi --no-fail-fast`, `cs wasm-pack test --node crates/kernel/chio-kernel-browser`, the three TS packages' tests (under `cs` when their build reaches cargo or wasm-pack), the Miniflare test, `cs bash scripts/check-chio-cpp.sh`, and the Swift binding regeneration check. Expected: PASS.

---

### Task 7: Cage and control-plane producers (commits 11 to 16)

**Files:** listed in the File Structure row for Task 7.

Each commit converts one producer to `ChioReceipt::sign*` with a draft, its preimages and its salt source, and changes its readers in the same commit (inventory "RedactionMode mapping": each reader drops its mode check in the same commit as its producer).

| Commit | Producer | Preimages | Reader changed with it |
|---|---|---|---|
| 11 | Cage (`prepare_cage_receipt`) | the cage request as parameters; the cage outcome as content | cage receipt verification (`receipt.rs` reader) |
| 12 | Keyring projection (`key_enterprise_receipt_to_chio_receipt`) | the projected request; the signed key enterprise receipt as content | none |
| 13 | Native evidence (`build_signed_receipt`) | the action; the active-defense body as content (it already rides in `metadata.active_defense_body`, so the content commitment covers the same value) | `verify_native_security_receipt`, `execution_validation.inc` (both readers), `chio-lineage` active-defense ingest, `event_consumer/verification.rs` |
| 14 | Response simulation (`ResponseSimulationReport::receipt_body`) | the simulation request; the report as content | none |
| 15 | SCIM deprovision | the deprovision request; the deprovision result as content | none |
| 16 | Verified-fix evidence | the evidence body as content, carried from `finding_verified_fix.rs` to the signer over the existing call path instead of its hash (G3) | the verified-fix verifier, which now opens from the body it holds |

The cage takes `&dyn Rng` from its host (`chio-cage` gains no `chio-kernel` dependency; its std host passes `OsEntropyRng`). The control-plane producers use `OsEntropyRng`; their openings are returned and dropped (no disclosure store in those paths), so their commitments are permanently hiding by design.

- [ ] **Step 1:** Per commit: convert, add `<producer>_receipt_opens_with_its_preimages`, run `cs cargo test -p <crate> --no-fail-fast` and clippy. For commit 16, add `verified_fix_signer_refuses_hash_only_input` (the signer API has no hash parameter; the test builds from the body).
- [ ] **Step 2:** `cs cargo test -p chio-control-plane --no-fail-fast` (full) and `cs cargo test -p chio-lineage -p chio-cage --no-fail-fast`. Expected: PASS except golden signatures.

---

### Task 8: ACP proxy preimages (commit 17)

**Files:** `crates/protocol/chio-acp-proxy/src/{interceptor,kernel_signer}.rs` and tests.

**Interfaces:** `sign_acp_receipt(&self, update: &AcpSessionUpdate, entry: &AuditEntry, rng: &dyn Rng) -> Result<SignedReceipt>`. The parameter preimage is the canonical tool-call arguments of the session update; the content preimage is the canonical audit entry body that `entry.content_hash` hashes today. `entry.content_hash` stays as the audit log's own field and never reaches the receipt signer. `ReceiptSemanticFields::trace_detect_only` loses its mode member here.

- [ ] **Step 1:** `acp_receipt_commits_session_update_preimages` for both interceptor paths (tool call and tool call update); `acp_signer_has_no_hash_input`.
- [ ] **Step 2:** `cs cargo test -p chio-acp-proxy --no-fail-fast` and clippy. Expected: PASS.

---

### Task 9: `HttpReceipt` deletion and the HTTP middleware SDKs (commits 18 to 21)

**Files:** listed in the File Structure rows for Task 9.

**Interfaces:**

- `chio-http-core`: `HttpReceipt`, `HttpReceiptBody`, `HttpReceipt::sign`, the `ChioReceipt` projection (`receipt.rs:350` at the inventory commit) and `caller_identity_hash` are deleted. The authority signs through the shared kernel signer:
  ```rust
  pub struct HttpCallPreimages {
      /// `{"body": <request body>, "method": .., "request_id": .., "route": <route pattern>}`
      pub request: serde_json::Value,
      /// `{"body": <response body>, "status": <u16>}`; `None` before the upstream answers.
      pub response: Option<serde_json::Value>,
  }
  impl HttpAuthority {
      pub fn sign_decision_receipt(&self, draft: ReceiptDraft, preimages: &HttpCallPreimages) -> Result<SignedReceipt>;
      pub fn sign_final_receipt(&self, draft: ReceiptDraft, preimages: &HttpCallPreimages) -> Result<SignedReceipt>;
  }
  ```
  `tool_server = "http"`, `tool_name = "<METHOD> <route_pattern>"`. A JSON body is its parsed value; any other body is `{"b64u": <unpadded base64url of the raw bytes>}` (open question 7). The decision receipt commits the empty output; the final receipt commits the response object. Salts from `OsEntropyRng`.
- `chio-api-protect`: the sidecar `/v1/evaluate` response carries `{"receipt": <chio.receipt.v1>, "openings": <chio.receipt-disclosure.v1 salt-only>}` in place of the HTTP receipt. `spec/schemas/chio-http/v1/evaluate-response.schema.json` changes with it (`$ref` to the receipt record and disclosure schemas). `sidecar.rs` signs through `ChioReceipt::sign_with_backend` with `OsEntropyRng`.
- `chio-tower`: the evaluator and service read `SignedReceipt` from the authority and attach the receipt and salt-only openings to the response extensions.
- Readers: `chio-control-plane/src/evidence_export/verification.rs` and its `http_receipts.rs` tests, `chio-store-sqlite` `retained_read.rs` and `receipt_query_snapshot/export/metadata.rs` drop every HTTP receipt branch; one receipt kind remains.
- SDK middleware, each verifying the receipt with its language's shared receipt verifier (Task 14) and exposing the receipt and openings to the application:
  - Python: `chio_sdk` (`client.py`, `models.py`, `models_supplemental.py`, `testing.py`, `__init__.py`, README), `chio-asgi`, `chio-django`, `chio-fastapi`, `chio-streaming`, `chio-langchain` tests.
  - JVM: `chio-sdk-jvm` (`ChioClient.kt`, `ChioTypes.kt` and tests), `chio-spring-boot` (`ChioFilter.kt`).
  - .NET: `ChioMiddleware` (`ChioSidecarClient.cs`, `ChioTypes.cs`, tests).
  - TypeScript: `node-http`, `express`, `fastify`, `elysia`, `ai-sdk`, `chio-ai-sdk-middleware`, `conformance` (sources and e2e fixtures).
  - Go: `chio-go-http` (`types.go`, `types_helpers.go`, `sidecar.go`, tests).
  - Examples: the ten `examples/hello-*/smoke.sh` scripts assert the new response shape; `scripts/tests/check-receipt-query-http.test.py`.

- [ ] **Step 1: Failing tests:** `http_final_receipt_commits_request_and_response` (Rust, opens with the canonical request and response); `http_decision_receipt_commits_empty_output`; `evaluate_response_carries_chio_receipt` (api-protect); `tower_attaches_receipt_and_openings`; per SDK, `evaluate_response_receipt_verifies` against a recorded sidecar response produced by the Rust sidecar test (fixture written by its owning generator in Task 15).
- [ ] **Step 2: Implement** commits 18 to 21 in order.
- [ ] **Step 3: Run** `cs cargo test -p chio-http-core -p chio-api-protect -p chio-tower -p chio-control-plane -p chio-store-sqlite --no-fail-fast`, clippy; `uv run pytest` in each Python package above; `./gradlew test` in `sdks/jvm`; `dotnet test sdks/dotnet/ChioMiddleware`; the TS packages' tests and typecheck; `(cd sdks/go/chio-go-http && go test ./...)`; each example smoke script that CI runs.
- [ ] **Step 4:** `python3 scripts/check-trust-boundaries.py` (the HTTP receipt reader entries in `docs/security/trust-boundary-inventory.json` change with this commit).
- [ ] **Step 5:** `git grep -n -E "HttpReceipt|http_receipt|httpReceipt|http-receipt|caller_identity_hash" -- . ':!docs/superpowers'; test $? -eq 1`.

---

### Task 10: Group 5 std producers (commits 22 to 25)

**Files:** `crates/observability/chio-otel-receipt-exporter/src/sink.rs`; `crates/products/chio-cli/src/cli/process_host/{call_evidence/export.rs,call_evidence/outcomes_export.rs,run_evidence/export.rs,swarm/requests.rs}`; `crates/products/chio-mercury/src/commands/shared/builders.rs`; `crates/products/chio-wall/src/commands.rs`; `sdks/lambda/chio-lambda-extension/src/main.rs` (test only).

| Commit | Producer | Preimages | Openings |
|---|---|---|---|
| 22 | OTel exporter (`canonical_receipt_for_span`) | span arguments; sanitized span attributes as content | dropped |
| 23 | `chio run` (four sites, one producer) | call arguments; call outcome | written beside the evidence export as `chio.receipt-disclosure.v1` files with payloads, so the run's own operator can open them |
| 24 | Mercury | step input; step output | dropped |
| 25 | Wall | command input; command output | dropped |

- [ ] **Step 1:** Per commit, convert with `OsEntropyRng` and add `<producer>_receipt_opens`. Add `lambda_evaluate_response_carries_no_arguments` in the Lambda extension (it is not a producer; the test pins that its unsigned output carries no argument, hash or receipt member).
- [ ] **Step 2:** `cs cargo test -p chio-otel-receipt-exporter -p chio-mercury -p chio-wall --no-fail-fast`, `cs cargo test -p chio-cli --test <process-host tests touched>`, `cs cargo test --locked --manifest-path sdks/lambda/chio-lambda-extension/Cargo.toml`, clippy. Expected: PASS except golden signatures.

---

### Task 11: Harness, conformance and fixture producers (commits 26 to 29)

**Files:** `crates/kernel/chio-runtime-harness/src/treaty.rs`; `crates/products/chio-cli/src/cli/dispatch/proof/{fixture.rs,fixture_agent_web.rs}`; `crates/tooling/chio-conformance/src/native_suite.rs`; `crates/trust/chio-attest-loopback/src/{lib.rs,package.rs}`; their `Cargo.toml` (enable `chio-core-types/fixture-rng`); `scripts/check-fixture-rng.py` (new).

**Interfaces:**
- Each producer builds `FixtureRng::from_seed(seed)` with `seed = SHA-256("chio.fixture-rng.v1\0" || <producer label> || 0x00 || <fixture id>)`, so regeneration is deterministic per fixture.
- Proof fixtures: the commerce event receipt (`fixture.rs`, today copies `event_sha256`) and the agent-web re-sign (`fixture_agent_web.rs`, today copies a recorded hash) take the recorded event and agent-web output bodies from the fixture inputs and pass them as content preimages (G3). The settlement anchor reseal passes its existing preimage.
- `scripts/check-fixture-rng.py`: fails unless the set of crates whose `Cargo.toml` enables `fixture-rng` equals its embedded allowlist (`chio-runtime-harness`, `chio-cli`, `chio-conformance`, `chio-attest-loopback`, plus dev-dependencies) and every non-test `FixtureRng::from_seed` call site is one of the allowlisted functions. In `chio-cli` the feature is enabled only for the `proof fixture` module through a dedicated `fixture-producers` feature of the binary that release builds do not enable; the script checks `deploy/` and the release manifest build commands for its absence.

- [ ] **Step 1:** Convert each producer; `fixture_receipts_are_reproducible` (two runs of each producer with the same fixture id produce byte-identical receipts and openings).
- [ ] **Step 2:** `python3 scripts/check-fixture-rng.py`; `cs cargo test -p chio-runtime-harness -p chio-conformance -p chio-attest-loopback --no-fail-fast`; `cs cargo test -p chio-cli --test proof_cli_contract --test proof_verify`. Expected: PASS except golden fixtures.

---

### Task 12: Readers (commit 30)

**Files:** `crates/observability/chio-siem/src/{ocsf.rs,event.rs,alerting/projection.rs,sink_projection.rs}`; `crates/tooling/chio-conformance/verdict_matrix/src/driver.rs` and any live scenario asserting `parameter_hash` or `content_hash`; store query and export readers; `chio-proof-room` and `chio-commerce-order` receipt readers that name the removed members.

- OCSF 1.3.0 reads commitments only (spec 7.13: "In M1 the 1.3.0 projection is updated only to read commitments instead of the deleted fields"). `parameter_hash_valid` and `parameter_hash` projection members are deleted; the projection carries `parameter_commitment.value` and `content_commitment.value`, never inline values. `source_redaction_mode` is deleted.
- The verdict-matrix driver asserts commitments; the corpus index hash is re-pinned only if a scenario file changes.
- [ ] **Step 1:** `ocsf_projection_carries_commitments_only`; the marker property test from Task 5 covers the projection.
- [ ] **Step 2:** `cs cargo test -p chio-siem -p chio-conformance -p chio-proof-room -p chio-commerce-order --no-fail-fast`, clippy. Expected: PASS except golden fixtures.

---

### Task 13: Vector cross-check (commit 31)

**Files:** `crates/core/chio-core-types/tests/committed_receipt_vectors.rs` (new); `scripts/gen-signing-wrapper-vectors.py`; `tests/bindings/vectors/receipt/committed/v1.json`; `tests/bindings/vectors/MANIFEST.sha256`.

**Interfaces:**
- `committed_receipt_vectors.rs` reads `committed/v1.json`:
  - every `commitment_domains` entry equals the Rust constant;
  - for every case, Rust decodes `receipt` (or refuses it exactly when `receipt_valid` is false for a decode reason), verifies the wrapper signature as `signature_valid` says, and `open_receipt` with the case's `preimages` returns the case's `parameters`, `content` and `disclosure_valid`; the `authority_chain_depth_0`, `tenant_id_with_authority`, `subject_opening_as_tenant` and `subject_value_as_tenant` cases also open the delegation-context commitments with `CommitmentDomain::DelegationSubject` and `DelegationTenant`;
  - Rust signing with a scripted test `Rng` that yields the case's `fixture_salts` reproduces each positive receipt byte for byte (Ed25519 is deterministic);
  - `empty_output` uses the zero-length preimage (G13). If the file still carries a `null` preimage from #1537, regenerate it with the script first; the diff touches only that case.
- Padding negatives (spec 11.2 [M1]), generated by the Python script so the file stays single-sourced, each with a valid wrapper signature over the padded body: an added member in `parameter_commitment`, `content_commitment`, `disclosure`, `authority`, `authority.root_anchor`, the opening document and one opening. `expected_decode: false`.
- [ ] **Step 1:** Write the test; run `cs cargo test -p chio-core-types --test committed_receipt_vectors`. Expected: FAIL only on the missing padding cases.
- [ ] **Step 2:** Extend the script; `uv run --with-requirements scripts/gen-signing-wrapper-vectors.requirements.txt python3 -I scripts/gen-signing-wrapper-vectors.py write`, then `check`. Expected: `git diff tests/bindings/vectors/receipt/committed/v1.json` shows only added cases (plus the G13 case if it was stale). The script's `check` also validates every positive receipt against the moved-in `record.schema.json` and the `tenant_id_with_authority` case against its failure (in-place schemas README, "Checks").
- [ ] **Step 3:** `cs cargo xtask freeze-vectors`, then `--check`; rerun Step 1. Expected: PASS.

---

### Task 14: SDK verifiers (commit 32)

**Files:** `sdks/typescript/chio-ts/src/invariants/receipt.ts` and tests; `sdks/python/chio-py/src/chio/invariants/receipt.py` and tests; `sdks/go/chio-go/invariants/receipt.go` and tests; `crates/sdk/chio-bindings-ffi` (`chio_verify_receipt_json*`), `sdks/cpp/chio-cpp` receipt verification; `sdks/python/packages/chio-bedrock/src/chio_bedrock/receipt.py`; every other SDK receipt reader in the Task 1 census (Python adapters, JVM `chio-streaming-flink`, C++).

**Interfaces (per language, matching Rust):**
- `openReceipt(receipt, disclosure, ownParameters?, ownOutput?) -> { parameters, content, disclosureValid }` (TS), `open_receipt(...)` (Python), `OpenReceipt(...)` (Go), with `ownOutput` one of value, empty or stream chunk digests; never read from `payload`.
- The closed layer lists from #1716 gain `action.parameter_commitment`, `content_commitment`, `disclosure`, `authority`, `authority.root_anchor`, and lose `action.parameters`, `action.parameter_hash`, `content_hash`, `redaction_mode`. `parameters_inline`, `result_inline` and `metadata` stay open JSON. The disclosure document and each opening are closed. The refusal message keeps #1716's form, `unknown receipt member: <path>`.
- Salt decoding: `b64u:` plus 43 unpadded base64url characters decoding to 32 bytes; anything else fails.
- [ ] **Step 1: Failing tests first** in each language: every case of `committed/v1.json` returns its `expected` values; each padding negative refuses with the exact path; `salt_reused_across_fields` marks `disclosureValid = false`.
- [ ] **Step 2: Implement; run** `cs bash scripts/check-bindings-parity.sh`, `bash scripts/check-chio-py.sh`, `cs bash scripts/check-chio-cpp.sh`, `(cd sdks/go/chio-go && CGO_ENABLED=0 go test ./...)`, `(cd sdks/python/packages/chio-bedrock && uv run pytest)`, the `chio-ts` typecheck and tests, `cs bash scripts/check-sdk-parity.sh`, `bash scripts/check-consumer-sdk-parity.sh`. Expected: PASS.

---

### Task 15: Fixture regeneration (commit 33)

Every receipt fixture changes bytes, and every receipt id changes because its `ChioReceiptIdInput` changes. Item 1 regenerated every signed fixture once; this task regenerates once more on top of it with the same command: `cs cargo xtask gen signed-fixtures` runs each fixture set's owning generator and repeats until a pass changes nothing; `--check` runs one pass and fails without writing. No signed fixture is edited by hand or patched by a script. The PR body lists every changed fixture path and the generator that wrote it.

Generators this PR adds to `xtask/src/signed_fixtures.rs` (the item 1 table is otherwise unchanged):

| Fixture set | Generator |
|---|---|
| `tests/bindings/vectors/receipt/committed/v1.json` | `scripts/gen-signing-wrapper-vectors.py write` (already in Task 13; listed so `--check` covers it) |
| recorded sidecar evaluate responses used by the SDK middleware tests (Task 9) | the `#[ignore]` regenerator in `crates/products/chio-api-protect/tests/evaluate_response_fixtures.rs` (new) |
| `crates/platform/chio-control-plane/src/evidence_export/tests/**` HTTP receipt fixtures | deleted with the HTTP receipt branch; no regeneration |

- [ ] **Step 1:** After Tasks 2 to 14, run the full suites (Verification) and collect every golden failure; each maps to one generator row (item 1 table or above).
- [ ] **Step 2:** `cs cargo xtask gen signed-fixtures`, then run the lane-local review aid from item 1 (`ws2:~/lanes/claude-pr1160-evidence/m1i1/diff-signed-fixtures.py origin/main HEAD`, copied to `m1i2/` and extended): for every changed JSON or NDJSON fixture it allows only the committed-receipt member changes (`action`, `content_commitment`, `disclosure`, removed `redaction_mode` and `content_hash`), signatures, and ids and digests it traces to a changed receipt body; a changed receipt whose `action` does not recompute from its recorded fixture preimage and the fixture salt fails; an untraced derived change fails. Its output goes in the PR body.
- [ ] **Step 3:** `cs cargo xtask gen signed-fixtures --check`, `cs cargo xtask freeze-vectors --check`, `cs cargo run -p chio-cli --bin chio -- proof fixture regenerate --check`. Expected: PASS.

---

### Task 16: PROTOCOL and docs (commit 34)

- [ ] **Step 1:** Move `docs/superpowers/specs/relying-party-wedge/protocol/protocol-6-committed-receipts.md` into `spec/PROTOCOL.md` after "Receipt Identity And DAG", delete the staged file, remove its HTML comment, status line and "Sections in force" line. In the "Export profiles" part keep only what this PR implements in the type system (the profile names and the salt-only rule) and leave the manifest member text to item 6. Rewrite the section 6 receipt field table and the "WYSIWYS Signing Invariant" for commitments, delete every `redaction_mode`, `content_hash` and `parameter_hash` row, and delete the HTTP receipt text in `spec/HTTP-SUBSTRATE.md`, `spec/OPENAPI-INTEGRATION.md` and `spec/WIRE_PROTOCOL.md`.
- [ ] **Step 2:** Update docs naming deleted APIs: `git grep -n -E "HttpReceipt|content_hash|parameter_hash|redaction_mode|RedactionMode|sign_receipt_relaying_trusted_body|caller_identity_hash" -- docs spec sdks/*/README.md crates/*/*/README.md ':!docs/superpowers'`.
- [ ] **Step 3:** `grep -rn $'\xe2\x80\x94' <changed files>; test $? -eq 1`; `grep -n -i -E '\bM[0-3]\b|wedge|pilot|docs/superpowers' spec/PROTOCOL.md; test $? -eq 1`; `bash scripts/check-chio-owned-v1-only.sh && python3 scripts/check-native-host-docs.py`; `cs cargo test -p chio-spec-validate --no-fail-fast`.

---

### Task 17: Formal touchpoints and coverage (commit 35)

- [ ] **Step 1: Kani.** Update `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs` (its test backend and its `Rng` now return `Result`), the `#[cfg(kani)]` blocks in `receipts.rs` and `formal/rust-verification/kani-public-harnesses.toml` (`sign_receipt_relaying_trusted_body` entries removed). Add a harness `receipt_commitment_layout` over a pure `assemble_commitment_input(domain: &'static [u8], salt: [u8; 32], preimage: [u8; 8]) -> [u8; N]` on fixed buffers (no symbolic strings): the domain bytes, then the salt, then the preimage, at fixed offsets. `commit` calls it.
- [ ] **Step 2: Formal mirrors.** `cs cargo xtask check formal-mirrors`. When the `receipt/body.rs` or `receipt/decision.rs` mirror digests drift, confirm `formal/lean4/Chio/Chio/Core/Receipt.lean` models the action and content as opaque commitments and carries no `redaction_mode`, then `--bless` and say so in the PR body. If `Receipt.lean` names `content_hash` or `parameter_hash`, the rename lands in a `.lean` edit in this PR and the Lean gates run on the x86 runner, never on ws2. Formal-mirrors and proof-coverage are required.
- [ ] **Step 3: Coverage, last.** After the final rebase, from a clean tree in the real worktree: `cs cargo xtask gen proof-coverage` then `--check`; commit `docs/formal/COVERAGE.md`.

---

## D17 Coordination

This PR changes the signed bytes of every `chio.receipt.v1` receipt and deletes the only other receipt artifact. Root-2 and the lead check the list below against their in-flight work before the PR opens.

Signed artifacts whose bytes change:
1. Every `chio.receipt.v1` receipt from every producer: `action` becomes `{parameter_commitment}`, `content_hash` becomes `content_commitment`, `redaction_mode` becomes `disclosure`. Every receipt id changes, because `ChioReceiptIdInput` contains the body. Every artifact that embeds a receipt id, a receipt digest or a whole receipt changes transitively: child receipts and lineage statements, checkpoints and inclusion proofs, evidence export manifests and their `chio.evidence_export_commitment.v1` signatures, commerce authority receipt artifacts (#1715's route stays outside the receipt bytes), session compliance certificates and proof-room graph nodes, passports and bundle manifests.
2. `HttpReceipt` is deleted. The sidecar `/v1/evaluate` response (`chio-http/v1/evaluate-response`) carries `chio.receipt.v1` and a salt-only opening. Every HTTP middleware SDK and example changes in the same PR.
3. Relay APIs: the browser WASM, mobile UniFFI and C ABI receipt signers change signature and lose their relay exports; the TS workers, edge and deno packages and the Swift bindings change with them.
4. `Rng`: moves to `chio-core-types` with a fallible `fill_bytes`; `NullRng` is deleted. Any in-flight branch implementing or importing `chio_kernel_core::Rng` rebases onto the new path.
5. Guard trait: both `Guard` traits gain a required `evidence_declaration`. Any in-flight branch adding a guard implements it.
6. Store: `chio_tool_receipts.content_hash` becomes `content_commitment` in place, and `disclosure_openings` is added.

Shared files with in-flight work:
- #1715 and #1716 (fwdcompat receipts, lead): the receipt structs, `receipt_strict_decode.rs`, the commerce authority receipt decoder and the Go, Python and TypeScript `invariants/receipt.*`. Both land first; this PR extends their closed layer lists and keeps their refusal message form.
- The shared `lossless_serde!` decoder PR (fwdcompat lane, not yet open): every receipt decode change lands there first. This PR's new tagged enums and closed unions use that decoder and its refusal form; it touches no decoder code.
- Item 1 (signing wrapper): lands first; this PR signs through `sign_wrapped` and regenerates with its `gen signed-fixtures` command.
- #1706 (anchored-root types): lands first; `ReceiptAuthority` uses its `RootAnchor` and `HolderClass`.
- #1674 (`SigningBackend` collapse): lands first; `receipts.rs`, `receipt_support/signing.rs`, `receipt_persistence.rs`, `evidence_export/tests.rs` are shared.
- #1708 (concurrent durable receipt publication, Root-2): `receipt_persistence.rs`, `receipt_store.rs`, the publication tests. The disclosure-store write follows the publication order #1708 establishes.
- #1710 (settlement ledger hook): `receipt_store.rs`, `chio-store-sqlite` receipt store support and reconciliation, `chio-api-protect` proxy state. Whichever lands second rebases.
- #1682 (C6) and #1717: `chio-store-sqlite` receipt store and query snapshot files.
- K-stack (#1675, #1678, #1701, #1269, KERN-TRACE-LOCK-FSYNC): merged before item 1; this PR keeps every K-stack invariant test and regenerates only golden receipt bytes inside them.
- #1607 (coop2c): no receipt bytes; shares `spec/schemas/registry.json`, `MANIFEST.sha256` and `spec/wire-schemas.lock`. Lands first.
- Item 3 (`root_anchor` in the capability body): follows this PR. It fills `ReceiptAuthority` from verified capability state in the kernel (open question 3) and regenerates through the same command.

Fixtures whose bytes change: every receipt-bearing set in item 1's Task 11 table (about 893 JSON files carry `content_hash` at the census base, 861 of them under `fixtures/proof-room/`), the Rust golden receipts in about 189 test files, `tests/bindings/vectors/receipt/v1.json` and `MANIFEST.sha256`, the new evaluate-response fixtures, and `committed/v1.json` (added padding cases only).

Merge order (precondition): #1674, #1607, #1715, the shared decoder PR, #1716, #1706, the K-stack in Root-2's order, item 1; then this PR; then item 3's capability change. The census and every signed fixture are refreshed at the integrated base that contains all predecessors.

## Verification

Run at the PR head after the final rebase. Every cargo command, direct or nested, runs under `cs` (Global Constraints). Coder checks on ws2; heavy suites on `integ-x86` and `integ-h3`. Logs are kept under `ws2:~/lanes/claude-pr1160-evidence/m1i2/` with sha256 recorded in the PR body.

**Changed crates (integrators).** For every crate in `git diff --name-only origin/main...HEAD -- crates`: `cs cargo test -p <crate> --no-fail-fast` and `cs cargo clippy -p <crate> --all-targets -- -D warnings`. Plus `cs cargo test -p chio-core-types --features fips,pq --no-fail-fast`, `cs cargo test -p chio-core-types --no-default-features --lib`, `cs cargo test -p chio-kernel --test durable_admission_sqlite`, `cs cargo check --locked --workspace --all-targets`, `--all-features`, `cs cargo fmt --all --check`, and the CLAUDE.md one-liner once at the final tip with each step under `cs`: `cs cargo build --workspace && cs cargo test --workspace && cs cargo clippy --workspace -- -D warnings && cs cargo fmt --all -- --check`.

**Native-cage chio-cli and chio-conformance (required; lane-common "CLI/conformance full runs need the native cage").** `chio-core-types` and `chio-kernel` are upstream of both, so the full suites run on host 3 (or x86) with the setup copied from `ws2:~/lanes/claude-pr1160-evidence/root2/k6/verify-native-final-fa34a7dc65.sh`: self-contained node 24 and npm 9.2.0 first on `PATH`; `cs cargo build --locked --target x86_64-unknown-linux-musl -p chio-cage-init --bin chio-cage-init --features real-linux-enforcement` and `CHIO_CAGE_INIT` exported to it; the privileged `enforced_discovery` test; `scripts/prepare-native-python-runtime.py` and `scripts/prepare-enforced-native-fixture.py` with the fixture env exported; `CHIO_CAGE_SYSCALL_PROFILE=native-standard-v1`; `CHIO_CHECKOUT_ROOT` set; then `cs cargo test --locked --no-fail-fast -p chio-conformance` and `cs cargo test --locked --no-fail-fast -p chio-cli`. Required: rc=0 for both. Environment-only failures are not accepted.

**Final qualification at the new main.** Candidate integration and the final native qualification run at the `origin/main` commit this PR merges onto, not at an earlier base, and record that SHA. The final run covers the stop-error MCP routes (#1701), the CLI transport paths, `chio mcp serve-http` with `--auth-token` against the conformance peers, and `chio api protect` sidecar evaluation, in addition to the suites above.

**Gates.**
```bash
python3 scripts/check-security-clocks.py && python3 scripts/check-escape-hatches.py && python3 scripts/check-negative-assertions.py \
 && python3 scripts/check-trust-boundaries.py && python3 scripts/check-rust-file-hygiene.py && bash scripts/check-http-egress-contract.sh \
 && python3 scripts/check-error-urn-registry.py && cs bash scripts/check-adapter-no-bypass.sh \
 && python3 scripts/check-domain-separation.py && python3 scripts/check-signing-exemptions.py \
 && python3 scripts/check-fixture-rng.py \
 && python3 scripts/check-receipt-trace-negative-registry.py \
 && python3 scripts/check-kani-crypto-scope.py && python3 scripts/check-kani-public-harnesses.py
```
`check-domain-separation.py` covers the new commitment and chain-digest domains as hash domains (G5 keeps them in its scope).

**Wire-schemas, schema-registry and freeze gates.**
```bash
python3 scripts/check-wire-schemas.py && bash scripts/tests/check-wire-schemas.test.sh
bash scripts/check-chio-schema-registry.sh && bash scripts/tests/check-chio-schema-registry.test.sh && bash scripts/check-chio-owned-v1-only.sh
uv run --with jsonschema==4.26.0 --with referencing==0.37.0 python3 -I scripts/check-root-authority-schema-examples.py
python3 scripts/check-security-wire-vectors.py
cs make -C ~/lanes/m1i2 codegen-check && cs cargo xtask snippets regen --check
cs cargo xtask freeze-vectors --check
uv run --with-requirements scripts/gen-signing-wrapper-vectors.requirements.txt python3 -I scripts/gen-signing-wrapper-vectors.py check
cs cargo xtask gen signed-fixtures --check
cs cargo run -p chio-cli --bin chio -- proof fixture regenerate --check
cs cargo xtask eval-receipt-regen --check
cs cargo test -p chio-conformance --test vectors_schema_pair --no-fail-fast
cs cargo test -p chio-binding-helpers --test vector_fixtures --no-fail-fast
```
If `Cargo.lock` changes: the Cargo.lock digest pin in `scripts/check-security-ci-contract.py` and `deploy/docker/Dockerfile.security-evidence-runner`, then `git lfs pull` per lane-common, `cs python3 scripts/check-security-ci-contract.py` and `cs python3 scripts/check-aws-lc-fork.py`.

**Formal-mirrors and Kani.** `cs cargo xtask check formal-mirrors`. Kani 0.68 (the CI pin) runs only on the approved x86 runner, under `cs` (`CARGO_INCREMENTAL=0 ~/cslot.sh`), launched detached with `setsid -f` and a pid file through `~/lanes/claude-pr1160-evidence/q.sh ... < /dev/null`: every harness in `formal/rust-verification/kani-public-harnesses.toml` plus `receipt_commitment_layout`, through `scripts/run-kani-manifest.sh`. A single-harness rerun also runs on the x86 runner under `cs`; no Kani, Lean, lake or Aeneas runs on ws2. If Task 17 Step 2 edits `Receipt.lean`, the Lean gates run on the x86 runner. `cs cargo xtask gen proof-coverage --check` last.

**SDK builds.** `cs bash scripts/check-bindings-parity.sh` (node on `PATH` from mise shims), `bash scripts/check-chio-py.sh`, `cs bash scripts/check-chio-cpp.sh`, `(cd sdks/go/chio-go && CGO_ENABLED=0 go test ./...)`, `(cd sdks/go/chio-go-http && go test ./...)`, `(cd sdks/k8s/webhooks && go test ./...)`, `uv run pytest` in every Python package Task 9 or 14 touched, `./gradlew test` in `sdks/jvm`, `dotnet test sdks/dotnet/ChioMiddleware`, the TS packages' tests, typecheck and lint (including `workers`, `edge`, `deno` and the Miniflare test, under `cs` when they reach cargo or wasm-pack), `cs wasm-pack test --node crates/kernel/chio-kernel-browser`, the Swift binding regeneration check, `cs bash scripts/check-sdk-parity.sh`, `bash scripts/check-consumer-sdk-parity.sh`, `python3 scripts/tests/check-consumer-sdk-inventory.test.py`, `cs cargo test --locked --manifest-path sdks/lambda/chio-lambda-extension/Cargo.toml`, and every `examples/hello-*/smoke.sh` that CI runs.

Pre-existing reds on `main` are reported with `main`'s result at the same base for comparison.

## Verdict-matrix scope

The staged `receipt_disclosure` category stays staged in this PR. Every scenario in it starts `serve_http_edge` with a `root_policy`, a `tenant_index_key` and the `rust-mcp-serve-http` driver, none of which exist before items 4 and 7, and 007 to 010 are export scenarios that item 6 implements. This PR lands the kernel-level behavior and tests behind 001 to 006 (fully committed allow and deny receipts, the evidence drop, the marker property, the `tenant_id` refusal and the absent chunk digests, Tasks 2, 4 and 5) and registers `urn:chio:error:attest:receipt-tenant-id-with-authority`. The category moves into the live corpus with the driver (open question 4).

## Size

Spec 13.2 sizes item 2 at L, 26-37 engineer-days. Estimate from the census at `a93a2f69a3`:

| Part | Days |
|---|---|
| Core types: commitments, salts, opening document, body and action changes, `authority` and `tenant_id` rule, `RedactionMode` deletion, `Rng` move and fallible signature, schema move-in and four-language codegen, strict-decode negatives (Task 2) | 3-4 |
| Portable signer, relay deletion, handle on preimages (Task 3) | 1-2 |
| Hosted kernel salt wiring across 20 call sites, `DisclosureStore` and its SQLite table, receipt table column (Task 4) | 3-4 |
| Guard evidence declaration on 48 non-test guard impls, metadata allowlist, marker property test (Task 5) | 2-3 |
| FFI, WASM and mobile relays, TS wrappers, Swift, Miniflare (Task 6) | 2-3 |
| Cage, control-plane and ACP producers with preimage plumbing (Tasks 7, 8) | 3-4 |
| `HttpReceipt` deletion across 103 files: http-core, api-protect, tower, readers, evaluate-response schema, middleware in Python, JVM, .NET, TS, Go and ten example smokes (Task 9) | 5-7 |
| Group 5 std, harness and fixture producers, fixture RNG gate (Tasks 10, 11) | 2-3 |
| Readers: SIEM, lineage, store queries, verdict-matrix driver (Task 12) | 1-2 |
| Vector cross-check and padding negatives (Task 13) | 1 |
| SDK verifiers in TS, Python, Go, C++ and bedrock (Task 14) | 2-3 |
| Fixture regeneration, about 900 JSON fixtures and 189 Rust test files (Task 15) | 2-3 |
| PROTOCOL, docs, formal touchpoints (Tasks 16, 17) | 1-2 |
| Integration, native-cage runs, review rounds | 3-4 |
| Total | 31-45 |

Item 2 is L, 31-45 engineer-days, with a planning figure of 34 when the census holds at the real base. The range sits 5 to 8 days above spec 13.2 (26-37). Three items that 13.2 did not count make up the excess: the required `evidence_declaration` on every guard (house rules forbid a default method, so 48 impls change, 2-3 days), the fallible `Rng` move that removes the zero-fill fallbacks (spec 8.4 requires salt failure to fail signing, about 1 day), and the spread of `HttpReceipt` into ten example smokes and seven TS packages beyond the five SDKs G4 names (about 2 days). With item 1 at 26-40, the M1 total becomes 112-164 engineer-days (13.2's 104-148 plus 3-8 for item 1 and 5-8 for item 2).

## Open Questions

Each needs an owner decision. The plan is written against the recommended default.

1. **Where the `Rng` seam lives and whether it is fallible.** Spec 7.8 says "the existing `Rng` seam", which is `chio_kernel_core::Rng`, infallible, with zero-fill fallbacks in the browser and mobile adapters. `chio-core-types` signs receipts and the cage and attest-loopback producers do not depend on `chio-kernel-core`, and spec 8.4 requires salt failure to fail signing. **Default:** move the trait to `chio_core_types::rng` with `fill_bytes(&self, &mut [u8]) -> Result<(), RngError>`, update every import (no re-export), delete `NullRng` and both zero-fill fallbacks.
2. **Disclosure-store loss (spec Q-B5).** Append the receipt and mark the opening lost, or deny when the opening cannot be stored first. **Default:** spec 8.4 as written: the receipt is appended first, the opening is marked lost, an operator alert fires and the commitment stays permanently hiding. The write follows the receipt publication order of #1708.
3. **When the kernel fills `authority`.** Capabilities carry no `root_anchor` until item 3's capability change, which follows this PR. **Default:** this PR adds `ReceiptAuthority`, the `tenant_id` refusal, the schema and the vectors; every producer sets `authority: None`; item 3 fills it from verified capability state.
4. **`receipt_disclosure` verdict-matrix category.** **Default:** stays staged (section "Verdict-matrix scope"); this PR lands the kernel tests behind 001 to 006 and the error code; the category moves with the `rust-mcp-serve-http` driver, and 007 to 010 with item 6.
5. **Caller and hook metadata.** Spec 8.4 names guard evidence explicitly and metadata generally. **Default:** signed `metadata` keeps only the reserved typed blocks of the metadata key registry whose producers declare them committed-safe; every other caller or hook key is dropped before signing. Task 1 lists each reserved key and its declaration, and any feature that loses a key is named in the PR body.
6. **Disclosure store as a kernel requirement.** **Default:** a kernel built with a durable receipt store refuses construction without a disclosure store (paired like the receipt store requirement of `build_kernel`). Producers with no receipt store (control-plane projections, OTel exporter, Mercury, Wall, `api protect` until M3) return openings to the host, which drops them, so their commitments are permanently hiding.
7. **HTTP body preimage for non-JSON bodies.** G4 fixes the request and response members but not the encoding of a binary body inside canonical JSON. **Default:** a JSON body is its parsed value; any other body is `{"b64u": <unpadded base64url of the raw bytes>}`; an absent body is `null` inside the object (the object itself is the preimage, so the G13 `null` rule does not apply).

## Spec coverage

| Spec requirement | Task |
|---|---|
| D2 protocol-wide committed receipts, every producer on the `Rng` seam | 2 to 11 |
| G1 one PR, inventory commit groups, one commit per producer's salt wiring | Commit Grouping |
| G3 salt source per producer, preimages for hash-only producers, fixtures from recorded preimages | 1, 7, 8, 11 |
| G4 `HttpReceipt` deletion with the SDK middleware | 9 |
| G13 three content preimage forms | 2, 13, 14 |
| G14 bare hex `receipt_id` in the opening document | 2 |
| G15 duplicate salt rejection | 2, 13, 14 |
| G18 strict decoding of every new receipt block and the opening document | 2, 13, 14 |
| 7.6 body changes, commitment rules, `chain_digest`, `tenant_id` exclusion | 2, 3 |
| 7.7 `chio.receipt-disclosure.v1` | 2, 14 |
| 7.8 producer salt sources, relay replacement, Lambda extension | 1, 6, 10 |
| 8.4 privacy: evidence and metadata allowlist, salt failure, disclosure-store loss | 4, 5 |
| 10.1 to 10.3 core-types, kernel-core and producer changes | 2 to 12 |
| 10.7 `disclosure_openings` | 4 |
| 10.10 SDK verifiers for commitments, openings and strict decoding | 14 |
| 11.1 commitment and producer unit tests, marker property | 2 to 11 |
| 11.2 committed receipt vectors and padding negatives | 13 |
| 11.3 `receipt_disclosure` (kernel-level backing; category move deferred) | Verdict-matrix scope |
| 11.5 gates and regenerated fixtures listed in the PR | 15, Verification |
| 13.3 step 2 (after item 1 and the D17 coordination) | 1, D17 Coordination |
