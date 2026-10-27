# Relying-Party Wedge M1 Item 6 Implementation Plan: the Offline Verifier and Tenant Export

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land M1 item 6 of the relying-party wedge: a new Apache-2.0 crate `chio-bundle-verify` with the `chio-verify` binary that verifies an exported evidence bundle offline against a verifier-owned `chio.verifier-trust.v1` file and prints the per-column report, and provider-side export of `caller` and `auditor_hash_only` bundles for one tenant, carrying every root-authority artifact a verifier needs, including the provider identity projection (G17). `chio evidence verify` and `chio evidence import` delegate to the new crate, and the control-plane verifier is deleted.

**Architecture:** The pure evidence model (bundle, records, checkpoint and inclusion-proof types and their verification) moves out of the hosted `chio-kernel` into `chio-core-types` and `chio-kernel-core`, so the verifier's Chio dependencies are those two crates and the two leaf crates they build on: `chio-security-types` (strict serde, reached through `chio-core-types`) and `chio-errors` (the error-code registry behind `BundleVerifyError::code()`, depending only on `serde` and `thiserror`). `chio-bundle-verify` is a library plus `[[bin]] chio-verify`: it reads a bundle directory and a trust file, checks the signed export envelope, file hashes, every signature against pinned keys, every root against its delegation context, root policy and provider identity projection, every opening against its commitment, and reports one evidence class per column. It never reads the wall clock and has no network or database dependency. Export runs inside `serve-http` behind an admin route: the process that owns the tenant index key and the kernel signing backend selects the receipts, builds the package and signs its commitment, and the CLI verifies the signed package against the operator's own trust file and writes it only when that passes. No kernel seed lives on an operator host.

**Tech Stack:** Rust workspace (every cargo command through `cs`, defined under Global Constraints), JSON Schema draft 2020-12, `cargo xtask codegen` (Rust, TS, Go, Python), the verdict-matrix conformance corpus, Python repository gates.

**Spec:** `docs/superpowers/specs/2026-10-17-relying-party-wedge-design.md`, sections 1.1, 2.2 (D8), 2.5 (G12, G13, G14, G15, G17, G18, G19), 3.1 (G7), 4 (P9, C4, A1, A2, A3), 6.1, 7.0, 7.3, 7.4, 7.6, 7.7, 7.11, 7.12, 8.4, 9.4, 9.6, 9.8, 10.7, 10.8, 10.9, 11.1, 11.3, 11.4, 11.5, 11.6, 12 (M1), 13.1, 13.2, 13.3, 13.4. Inputs from M0 and item 1: `docs/superpowers/specs/relying-party-wedge/in-place-schemas/export/evidence-export-manifest.schema.json` and its README, `spec/schemas/chio-wire/v1/root_authority/verifier-trust.schema.json`, `docs/superpowers/specs/relying-party-wedge/protocol/protocol-6-committed-receipts.md` ("Export profiles"), `docs/superpowers/specs/relying-party-wedge/verdict-matrix/receipt_disclosure/receipt-disclosure-00{7,8,9}*.json` and `-010*.json`, `docs/superpowers/plans/2026-10-20-m1-item1-signing-wrapper.md`, `docs/cli/proof-verify.md`.

**Census base:** facts below were read at `origin/main` `a93a2f69a` (after #1718). No item 2 plan has merged at this base; this plan states its item 2 dependencies as interfaces item 6 consumes. Task 1 re-reads every fact at the actual base.

## Global Constraints

Quoted verbatim from the spec.

The verifier crate (spec 10.9):

> `crates/tooling/chio-bundle-verify` [M1] (library plus `[[bin]] chio-verify`, Apache-2.0): reads a bundle and a `chio.verifier-trust.v1` file, verifies everything offline, prints the column report (section 11.4). Depends on `chio-core-types` and `chio-kernel-core`; no tokio, no rusqlite, no network except the optional `--online` settlement lookup behind a feature [M3]. It never reads the wall clock: expiry and validity checks evaluate at the receipt's own timestamp. Added to the clock gate's fixed roots.

This plan reads "Depends on `chio-core-types` and `chio-kernel-core`" as the boundary against hosted Chio crates: the normal closure holds exactly four Chio crates besides the verifier itself, `chio-core-types`, `chio-kernel-core`, `chio-security-types` and `chio-errors`. The last two are leaf crates with no runtime, network, database or clock dependency. `scripts/check-offline-verifier-deps.py` allowlists exactly these four and refuses every other `chio-*` crate (Task 3).

Export scope (spec 2.2, D8):

> Export scope: "one customer" means one tenant. The provider keeps an HMAC-keyed tenant index with no plaintext tenant ids. Caller bundles include salts only for that tenant's receipts and principals.

Manifest members and roles (spec 7.12):

> - `disclosure_profile`: closed, one of `caller` (receipts for one tenant; salts for those receipts' parameters, content, and the tenant's own principals and tenant commitment; no payloads), `auditor_full` (salts and payloads, M2), `auditor_hash_only` (no salts, no payloads).
> - `tenant_tag`: required for `caller`; the bundle contains only receipts whose stored tag matches.
> - New artifact roles: `capability_presentation`, `delegation_context`, `root_policy`, `enterprise_provider_identity` (the identity projection of every provider record a bundle's roots name), `idp_key_snapshot`, `idp_artifact` (retained ID-JAG, auditor profiles only, D7, M2), `receipt_disclosure`, `revocation_entry`, `revocation_request` (M2), `settlement_closure` (M3), `pdp_decision_receipt` (M2).
> - The manifest is signed by the kernel key (existing commitment artifact pattern, `chio.evidence_export_commitment.v1`).

Provider identity offline (spec 9.8):

> **Offline evidence.** The enabled state is admission-time state and is not in any bundle. A verifier recomputes the provider identity digest from the exported projection and checks it against the rule; it does not learn whether the provider was enabled.

Export refusals (spec 8.4):

> Export refuses salt-only openings in auditor profiles, and refuses `caller` exports without a `tenant_tag`.

The tenant index key set rotates (item 2 key-set section, all-generation match mode), so one tenant has one tag per loaded generation. This plan reads `tenant_tag` in the quoted spec text as the tenant's tag set: selection and the manifest use every loaded generation (Decision 9), and Task 10 moves that wording into `spec/PROTOCOL.md`.

Policy export (spec 7.4):

> Exactly one policy is loaded. A root whose `root_policy_digest` names another policy denies. Every policy a bundle's roots reference is exported with the bundle.

The column table (spec 11.4):

> | identity root | exchange key pinned, root signature valid, root policy key pinned, policy matches the recorded claims, `context_digest` recomputes, section 7.1 bindings hold, and (M2) the retained ID-JAG verifies against a key pinned in the verifier's `idp_keys` | `observed` when the retained ID-JAG verifies only against the provider-signed snapshot; `asserted` for bearer anchors without a retained artifact; `rejected` on any mismatch |
> | delegation chain | every hop verified from the presentation with W1.1 and W1.2; no revocation entry in the bundle covers it | `rejected` |
> | decision | kernel key pinned, signature valid, kind coherent; `pdp_decision` only with a pinned PEP key | `observed` for `pdp_decision` without a pinned PEP |
> | content | commitment opened from the bundle and matches; every inline field authorized by the included root policy | `unverifiable` in `auditor_hash_only`; `rejected` on mismatch or unauthorized inline field |
> | settlement (M3) | inline settlement with matching digests, or exactly one valid closure; `--online` confirms the transaction | `asserted` without `--online` |

The preimage rule (spec 2.5 G13):

> The verifier derives the preimage from its own copy of the output, never from an opening's `payload`, so the literal `null` is never a preimage and cannot collide with a salt-only `payload: null` opening.

The M1 claim this item carries (spec 12):

> "A provider can export a bundle for one customer tenant that the tenant verifies offline with the Apache-2.0 `chio-verify` tool."

Cuts (spec 13.1): `auditor_full` (cut 3), ID-JAG retention (cut 4), presented chains deeper than the root (cut 5), caller-side revocation requests (cut 6) and the caller copy (cut 7) are M2. Spec 13.4: `auditor_hash_only` moves to M2 only with founder approval; this plan ships it.

Further constraints:

- No legacy, compat or dual paths; everything is v1. `chio evidence verify` and `chio evidence import` call `chio-bundle-verify` and nothing else; `crates/platform/chio-control-plane/src/evidence_export/verification.rs` and the verify half of `evidence_export.rs` are deleted in the PR that adds the delegation. The `--trusted-kernel-pubkey` and `--trusted-anchor-file` flags are replaced by `--trust <file>` in the same PR, with every caller (tests, `scripts/smoke/chio-cli-smoke.sh`, `chio-mercury`, trust-control import).
- License: `chio-bundle-verify` is Apache-2.0 through `license.workspace = true`, like every workspace crate (root `Cargo.toml` `[workspace.package] license = "Apache-2.0"`, root `LICENSE`). Its normal dependency closure stays inside the `deny.toml` `[licenses] allow` list with no `[[licenses.exceptions]]` entry (the uniffi MPL exceptions are outside its closure). The crate README names the license and the offline guarantee.
- Fail-closed: a parse failure, an unknown member, an unregistered schema id, a missing pinned key, a hash or signature mismatch, or a tampered opening never yields `verified`. The verifier returns a typed error or a `rejected` column, never a silent skip.
- Strict decoding (G18): every type the verifier reads decodes with unknown-member rejection at every level. No `#[serde(flatten)]`. New tagged enums use `chio_security_types::strict_serde` (`lossless_serde!`).
- Algorithm selection (G19): the verifier passes the pinned typed key from the trust file and the call-site schema id to `verify_wrapped*` (item 1). No member of a bundle selects a key, an algorithm or a schema id.
- Clock: `chio-bundle-verify` reads no clock. Every time check takes the receipt's `timestamp` (or the artifact's own time member) as a parameter. `crates/tooling/chio-bundle-verify/` joins `FIXED_ROOTS` in `scripts/check-security-clocks.py`. Export-side time reads go through the existing control-plane clock seam. Fixtures use fixed finite timestamps (`issued_at = 1792234800`).
- Error codes (G12): new codes live in the `attest` domain and are registered in `spec/errors/registry.yaml` by the PR that first emits them. No new domain.
- Clippy denies `unwrap_used` and `expect_used` outside tests. Format with `cs cargo fmt --all`.
- No em dashes (U+2014) in any file. No narrative or meta comments; comments state invariants and contracts.
- Public-path rule: files under `spec/`, `docs/adr/`, `docs/cli/`, `tests/`, `scripts/`, `crates/`, `sdks/` never mention milestones, the wedge, pilots or `docs/superpowers`.
- Build slots: on ws2, `cs` means `CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/var/tmp/claude-targets/m1i6 ~/lanes/cslot.sh`; on the x86 runner and host 3 it means `CARGO_INCREMENTAL=0 ~/cslot.sh` with that host's lane target dir. Every cargo command runs under `cs`: `cargo build`, `test`, `check`, `clippy`, `fmt`, `run`, `tree`, `metadata` and `xtask`, and every script, generator or Makefile target that reaches cargo directly or nested. No command in this plan invokes cargo outside `cs`.
- Formal tools: no Lean, lake, Aeneas or Kani runs on ws2, including single harnesses. This item adds no Kani harness and changes no `.lean` file.
- Work happens on ws2 in worktree `~/lanes/m1i6` off fresh `origin/main` (fetched over https). Never `git stash`. Inspect `git diff --cached --stat -M` before every commit. Push explicit SHAs over https. Heavy suites run on the integrators per the coder and integrator split.
- Shared surfaces: before requesting merge of each PR, post `<UTC> <lane>: REVIEW? #<N> M1 item 6 <part> (<surfaces>)` to `ws2:~/lanes/claude-pr1160-evidence/lead2/sync.md`, then `MERGING #<N>` with the 10-minute window and the OBJECT check.

## Review Focus

1. **A verifier path that reaches the network, a database or the clock.** Expected: `cs cargo tree -p chio-bundle-verify -e normal` contains no `tokio`, `rusqlite`, `reqwest`, `ureq`, `hyper`, `chio-kernel` (hosted), `chio-control-plane` or `chio-store-sqlite`, and no Chio crate other than `chio-core-types`, `chio-kernel-core`, `chio-security-types` and `chio-errors`; `check-security-clocks.py` covers the crate with no inventory entry; the air-gap run in Verification exits 0 inside a network namespace. Pinned in Task 3 by `scripts/check-offline-verifier-deps.py` and in Task 9 by the `unshare --net` run.
2. **A bundle member that chooses its own trust.** Expected: every key the verifier accepts comes from `chio.verifier-trust.v1`; the root policy's own `policy_key` and `exchange_keys` are checked against the trust file's `root_policy_keys` and `exchange_keys`, never trusted on their own; the provider identity digest is recomputed from the exported projection, never read. Pinned by the self-asserted-key negatives in Task 6.
3. **An opening that verifies from its own payload.** Expected: the content preimage comes only from the caller-supplied data file (or its absence, G13), the domain comes from the commitment's position (7.6), a duplicated salt marks the receipt as tampered disclosure (G15), and a `payload: null` opening in an `auditor_hash_only` bundle fails decoding of that bundle. Pinned in Task 7.
4. **A caller bundle that leaks another tenant.** Expected: every receipt, context, root, opening, snapshot, projection and revocation entry in a `caller` bundle is reachable from a receipt whose stored `(tag_key_id, tag)` is in the manifest `tenantTags` set, and that set holds one tag for every generation loaded at export; no salt for another tenant's commitment appears. Pinned by `caller_bundle_contains_only_own_tenant` (two tenants, marker values) in Task 8 and scenario 010.
5. **An exit class that disagrees with `chio proof verify`.** Expected: 0, 1, 2, 10, 20, 30, 40 and 50 mean the same thing in both tools; every `attest:bundle-*` and `attest:export-*` code maps to exactly one class; the message is never read. Pinned by `every_bundle_error_has_its_exit_class` in Task 4.
6. **A byte change hidden in the model move.** Expected: Task 2 changes no serialized byte: every export fixture, proof-room fixture and conformance snapshot is identical before and after. Pinned by `--check` runs of every fixture generator in Task 2.

---

## File Structure

| Path | Part | Task | Responsibility |
|---|---|---|---|
| `crates/core/chio-core-types/src/receipt/evidence.rs` (new), `src/receipt/checkpoint.rs` | 6a | 2 | portable evidence model: `EvidenceExportBundle`, `EvidenceExportQuery`, record types, `KernelCheckpoint`, `ReceiptInclusionProof`, `CheckpointTransparencySummary`, `CapabilitySnapshot`, `ReceiptReadBoundary`, `EvidenceExportManifest` and its member types |
| `crates/kernel/chio-kernel-core/src/evidence_verify.rs` (new) | 6a | 2 | pure checkpoint chain, inclusion proof, consistency proof and transparency verification moved from `chio-kernel/src/checkpoint.rs` and `evidence_export.rs` |
| `crates/kernel/chio-kernel/src/{checkpoint,evidence_export,capability_lineage}.rs` | 6a | 2 | keep store reads and checkpoint signing; re-import the moved types; no re-export shim |
| `crates/tooling/chio-bundle-verify/` (new: `Cargo.toml`, `README.md`, `src/lib.rs`, `src/read.rs`, `src/trust.rs`, `src/envelope.rs`, `src/package.rs`, `src/verify.rs`, `src/columns/{mod,identity_root,delegation_chain,decision,content}.rs`, `src/report.rs`, `src/error.rs`, `src/bin/chio-verify.rs`, `tests/`) | 6a, 6b, 6c | 3 to 8 | the verifier library and binary; Apache-2.0. 6c adds the profile and tenant-tag checks to the package layer (`verify_package`, `src/verify.rs`), their code to `src/error.rs`, `build_package` to `src/package.rs` and `tests/profile.rs` (Task 8) |
| `crates/core/chio-core-types/src/root_authority/verifier_trust.rs` (new) | 6a | 3 | `VerifierTrust` (`chio.verifier-trust.v1`), strict decode, load checks |
| `crates/platform/chio-control-plane/src/evidence_export/verification.rs` | 6a | 5 | deleted |
| `crates/platform/chio-control-plane/src/evidence_export.rs`, `evidence_export/{envelope,package_read}.rs` | 6a, 6c | 5, 8 | verify half deleted (6a); signing half and export assembly stay; profile and root-authority roles added (6c) |
| `crates/platform/chio-control-plane/src/trust_control/receipt_handlers.rs` | 6a | 5 | import verifies through `chio-bundle-verify` with a `VerifierTrust` |
| `crates/products/chio-cli/src/cli/types/receipt.rs`, `src/cli/dispatch/receipt_evidence.rs` | 6a, 6c | 5, 8 | `evidence verify --trust`, `evidence import --trust`; `evidence export --disclosure-profile --tenant-issuer --tenant-value --edge-url --trust` (the edge form takes no `--kernel-seed-file`) |
| `crates/products/chio-mercury/src/commands/shared/builders.rs`, `README.md`, `ARCHITECTURE.md` | 6a | 5 | read verified packages through `chio-bundle-verify` |
| `crates/products/chio-cli/tests/evidence_export.rs`, `tests/evidence_export/package_trust.rs`, `scripts/smoke/chio-cli-smoke.sh` | 6a | 5 | callers move to `--trust` |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/admin.rs`, `session_core.rs` | 6c | 8 | `POST /admin/evidence/export` on `serve-http` |
| `crates/platform/chio-control-plane/src/evidence_export/stores.rs` (new) | 6c | 8 | `ExportStores`: borrowed handles to the three sqlite stores, and the mapping from their typed errors: a missing-row variant maps to `urn:chio:error:attest:export-evidence-incomplete`, a storage error to the internal export failure. No trait. chio-store-sqlite is not modified by this item |
| `spec/schemas/chio-wire/v1/export/evidence-export-manifest.schema.json` (moved in), `spec/schemas/chio-wire/v1/export/bundle-verify-report.schema.json` (new), `spec/schemas/chio-wire/v1/export/verifier-caller-data.schema.json` (new), `spec/schemas/MANIFEST.sha256`, `spec/wire-schemas.lock`, generated code | 6a, 6b, 6c | 3, 4, 7, 8 | live schemas |
| `spec/errors/registry.yaml` | 6a, 6b, 6c | 4, 7, 8 | `attest:bundle-*` and `attest:export-*` codes |
| `spec/PROTOCOL.md` ("Export profiles" subsection moved in from the staged section 6 text) | 6c | 10 | contract text; the staged text already carries the `enterprise_provider_identity` role, the `tenant_tags` set and the enabled-state sentence (#1737) |
| `docs/cli/bundle-verify.md` (new), `docs/cli/evidence.md` (new) | 6a, 6c | 4, 10 | exit table and usage |
| `scripts/check-security-clocks.py`, `scripts/check-offline-verifier-deps.py` (new), `scripts/tests/check-offline-verifier-deps.test.py` (new), `.github/workflows/ci.yml` (one `run_gate` line, pushed by the lead from the Mac) | 6a | 3 | clock root and dependency closure gate |
| `crates/tooling/chio-conformance/verdict_matrix/scenarios/receipt_disclosure/receipt-disclosure-00{7,8,9}*.json`, `-010*.json`, `manifest.toml` | 6c | 9 | export scenarios moved in from staging and passing |
| `tests/bindings/vectors/export/v1.json` (new) | 6b | 7 | bundle-level vectors with expected column classes and exit codes |

License per path: every path above is in the Apache-2.0 workspace. No file in this item carries a different license header, and `chio-bundle-verify` adds no dependency outside the `deny.toml` allow list.

## Parts and Landing Order

Item 6 lands as three squash-merged PRs. The table is the answer to "which parts can land before items 1 and 2".

| Part | PR title | Depends on | Can land before item 1 | Can land before item 2 |
|---|---|---|---|---|
| 6a | `refactor(evidence): verify evidence bundles offline in chio-bundle-verify` (Tasks 1 to 5) | nothing in M1; Root-2's ACK of the `verification.rs` deletion (held file) before the code lane starts | yes, and it must: it merges before item 1's PR opens | yes |
| 6b | `feat(bundle-verify): verify anchored roots, committed receipts and openings offline` (Tasks 6, 7) | items 1, 2 and 3 (both parts, including `root_anchor` in the capability signing body) merged | no | no |
| 6c | `feat(evidence): export caller and auditor hash-only bundles for one tenant` (Tasks 8 to 10) | 6b, items 4 and 5 merged | no | no |

6a is byte-neutral: it moves types, moves verification code, adds a crate and replaces trust flags. It changes no signed byte and no fixture. It deletes `crates/platform/chio-control-plane/src/evidence_export/verification.rs`, a file Root-2 holds, so the 6a code lane starts only after Root-2's ACK is recorded on `sync.md`. It still touches files that item 1 and item 2 edit (`SignedExportEnvelope` verify call sites, `verify_http_receipt_evidence`, which item 2 deletes under G4), so 6a lands before item 1's PR opens, and therefore before item 2. Item 1's Task 1 census then includes the `chio-bundle-verify` call sites, and item 2 deletes `verify_http_receipt_evidence` from `chio-bundle-verify`.

6b must wait: the identity root column verifies `root_anchor` inside the signed capability body (item 3 part 2, after item 1), roots, policies and snapshots through `verify_wrapped` (item 1), and openings against commitments (item 2). Writing 6b before them would verify formats that do not exist yet. 6b is tested with bundles assembled from typed constructors in `tests/`, so it does not wait for item 4.

6c must wait: the roles it exports are rows that item 4 writes (anchored roots, delegation contexts, IdP key snapshots, tenant and subject tags, bearer roots), item 2 writes (disclosure openings) and item 5 writes (revocation entries with target kinds). Item 4 also provides historical root policy and provider identity record retention, stored by digest alongside `anchored_roots` and `idp_key_snapshots`, and the tenant tag with its `tag_key_id` beside each receipt row; 6c only reads them (Decision 3).

---

### Task 1: Base, census and coordination

**Files:** none changed. Output goes to `ws2:~/lanes/claude-pr1160-evidence/m1i6/census-<base>.md`.

- [ ] **Step 1: Preconditions per part.** For 6a, two preconditions hold before the code lane starts: (a) Root-2's ACK of the deletion of `crates/platform/chio-control-plane/src/evidence_export/verification.rs` (a Root-2 held file) is recorded on `sync.md`; (b) item 1's PR has not opened (`gh pr list --repo bb-connor/arc --search "signing wrapper in:title" --state all` returns nothing), because 6a lands before item 1's PR opens. If item 1's PR opens first, the lane stops and asks the lead. For 6b: items 1, 2 and 3 are `MERGED`. For 6c: 6b, items 4 and 5 are `MERGED`. Create the worktree at that base: `git -C /home/connor/swarm fetch -q https://github.com/bb-connor/arc.git +main:refs/remotes/origin/main && git -C /home/connor/swarm worktree add -b <branch> ~/lanes/m1i6 origin/main`.
- [ ] **Step 2: Census.**
```bash
git grep -n -E "EvidenceVerificationPolicy|load_verified_evidence_package(_summary)?|cmd_evidence_verify|validate_import_package_data|verify_checkpoint_transparency_records|validate_checkpoint_transparency_summary" -- crates scripts
git grep -n -E "pub (struct|enum|fn) (EvidenceExportBundle|EvidenceExportQuery|EvidenceToolReceiptRecord|EvidenceChildReceiptRecord|EvidenceUncheckpointedReceipt|EvidenceRetentionMetadata|EvidenceChildReceiptScope|EvidenceTransparencyClaims|KernelCheckpoint|ReceiptInclusionProof|CheckpointTransparencySummary|CapabilitySnapshot|ReceiptReadBoundary)\b" -- crates
git grep -n -E "trusted-kernel-pubkey|trusted-anchor-file|trusted_kernel_pubkey|trusted_anchor_file" -- crates scripts docs ':!docs/superpowers'
```
  Expected at `a93a2f69a`: the evidence model in `crates/kernel/chio-kernel/src/{evidence_export,checkpoint,capability_lineage}.rs`; `verification.rs` 730 lines; verify consumers in `chio-cli` (`receipt_evidence.rs:194,198`, `tests/evidence_export.rs`, `tests/evidence_export/package_trust.rs`), trust-control (`receipt_handlers.rs:436`), `chio-mercury` (`builders.rs:11-12`) and `scripts/smoke/chio-cli-smoke.sh:337,405,416`. Record every hit with `file:line`.
- [ ] **Step 3: Dependency census.** `cs cargo tree -p chio-kernel-core -e normal --prefix none | sort -u` and the same for `chio-core-types`: record that neither reaches `tokio`, `rusqlite` or an HTTP client (true at `a93a2f69a`).
- [ ] **Step 4: For 6c only, the item 2, 4 and 5 store census.** Record the table and column names that hold disclosure openings, anchored roots (rule id, subject tag, tenant tag), delegation contexts, context salts (`anchor.sub`, `anchor.tenant`), IdP key snapshots, capability presentations, revocation entries and the receipt tenant tag with its `tag_key_id`. Each read in Task 8 names one of them. Include the item 4 tables that hold historical root policies and provider identity records by digest. Also record the signature and error type of each plain read method Task 8 calls (the Interfaces block lists them); a method that is missing or returns another type is reported to the lead the same way. A role without a store row is an item 4 or item 5 gap, reported to the lead before Task 8 starts; 6c adds no store table.
- [ ] **Step 5: Coordination.** Post `<UTC> <lane>: m1i6 <part> heads-up: <surfaces>; byte change: <none|list>` to `sync.md`.

---

### Task 2: Move the evidence model out of the hosted kernel (6a)

**Files:**
- Create: `crates/core/chio-core-types/src/receipt/evidence.rs`; `crates/kernel/chio-kernel-core/src/evidence_verify.rs`
- Modify: `crates/core/chio-core-types/src/receipt/{mod,checkpoint}.rs`; `crates/kernel/chio-kernel-core/src/lib.rs`; `crates/kernel/chio-kernel/src/{checkpoint,evidence_export,capability_lineage,lib}.rs`; every importer from the Task 1 census

**Interfaces (moved, names and serde attributes unchanged):**
- `chio_core_types::receipt::evidence`: `EvidenceExportQuery`, `ReceiptReadBoundary`, `EvidenceExportBundle`, `EvidenceToolReceiptRecord`, `EvidenceChildReceiptRecord`, `EvidenceChildReceiptScope`, `EvidenceUncheckpointedReceipt`, `EvidenceRetentionMetadata`, `EvidenceTransparencyClaims`, `EvidencePublicationState`, `CapabilitySnapshot`, and the manifest types now private to the control plane (`EvidenceExportManifest`, `EvidenceExportCounts`, `EvidenceProofCoverage`, `EvidenceReceiptSemanticSummary`, `EvidenceExportFileHash`, `PolicyAttachmentMetadata`, `FederationPolicyAttachmentMetadata`, `EvidenceDisclosureNotice`), made `pub` because the verifier reads them.
- `chio_core_types::receipt::checkpoint`: `KernelCheckpoint`, `KernelCheckpointBody`, `ReceiptInclusionProof`, `CheckpointTransparencySummary` and the publication, witness, consistency-proof and equivocation records, beside the existing `CheckpointPublicationTrustAnchorBinding`.
- `chio_kernel_core::evidence_verify`: `verify_checkpoint_transparency_records`, `validate_checkpoint_transparency_summary`, `verify_inclusion_proof`, `build_evidence_transparency_claims`, each with an error type that does not mention `rusqlite` or `ReceiptStoreError`. Every function is pure and takes no clock.
- `chio-kernel` keeps the store-backed builders (`build_evidence_export_bundle`, checkpoint signing, `EvidenceExportError` with its `Sqlite` variant) and imports the moved types by path. No `pub use` re-export of a moved type is left in `chio-kernel`; every importer changes its path in the same commit.

- [ ] **Step 1: Snapshot bytes.** Before moving, run every fixture generator that serializes these types in `--check` mode and record pass: `cs cargo run -p chio-cli --bin chio -- proof fixture regenerate --check`, `cs cargo test -p chio-control-plane evidence_export --no-fail-fast`, `cs cargo test -p chio-cli --test evidence_export --no-fail-fast`.
- [ ] **Step 2: Move** the types and pure functions. `alloc` collections replace `std` ones in the moved code so `chio-kernel-core` keeps its `no_std + alloc` build.
- [ ] **Step 3: Run.** The Step 1 commands again (expected: PASS, no file written), plus `cs cargo check -p chio-kernel-core --no-default-features`, `cs cargo test -p chio-kernel-core -p chio-core-types -p chio-kernel --no-fail-fast`, `cs cargo clippy -p chio-kernel-core -p chio-core-types -p chio-kernel --all-targets -- -D warnings`. Expected: PASS.

---

### Task 3: The crate, the trust file and the dependency gate (6a)

**Files:**
- Create: `crates/tooling/chio-bundle-verify/{Cargo.toml,README.md,src/lib.rs,src/read.rs,src/trust.rs,src/envelope.rs,src/error.rs,src/bin/chio-verify.rs}`; `crates/core/chio-core-types/src/root_authority/verifier_trust.rs`; `scripts/check-offline-verifier-deps.py`; `scripts/tests/check-offline-verifier-deps.test.py`
- Modify: root `Cargo.toml` (`members`), `scripts/check-security-clocks.py` (`FIXED_ROOTS`), `.github/workflows/ci.yml` (one `run_gate` line, handed to the lead), `docs/security/trust-boundary-inventory.json` (the new reader entries)

**Interfaces:**

```toml
# crates/tooling/chio-bundle-verify/Cargo.toml
[package]
name = "chio-bundle-verify"
license.workspace = true
publish = false

[[bin]]
name = "chio-verify"
path = "src/bin/chio-verify.rs"

[dependencies]
chio-core-types = { workspace = true }
chio-errors = { workspace = true }
chio-kernel-core = { workspace = true }
chio-security-types = { workspace = true, features = ["std"] }
clap = { version = "4", features = ["derive"] }
serde = { workspace = true }
serde_json = { workspace = true }

[target.'cfg(unix)'.dependencies]
rustix = { workspace = true }
```

```rust
// chio-core-types/src/root_authority/verifier_trust.rs
pub const CHIO_VERIFIER_TRUST_SCHEMA: &str = "chio.verifier-trust.v1";

/// A verifier-owned trust file. Unsigned; the verifying party writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierTrust {
    pub schema: String,
    pub kernel_keys: Vec<PublicKey>,
    pub exchange_keys: Vec<PublicKey>,
    pub root_policy_keys: Vec<PublicKey>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub idp_keys: BTreeMap<Text, Vec<Jwk>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pep_keys: BTreeMap<Identifier, PublicKey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checkpoint_keys: Vec<PublicKey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_columns: Vec<ReportColumn>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportColumn { IdentityRoot, DelegationChain, Decision, Content, Settlement }

impl VerifierTrust {
    /// Strict decode plus every schema rule the generated types do not enforce:
    /// `schema` const, item bounds (kernel, exchange and root policy keys 1 to 64),
    /// uniqueness, no weak Ed25519 key, no key in two roles.
    pub fn load(bytes: &[u8]) -> Result<Self, VerifierTrustError>;
}
```

```rust
// chio-bundle-verify/src/lib.rs
pub struct BundleDir { /* root path, read through read.rs only */ }

/// Reads and strictly decodes every file the manifest lists; refuses a path
/// outside the bundle root, a symlink, a file not listed, and a listed file
/// whose length or SHA-256 differs.
pub fn read_bundle(dir: &Path) -> Result<ExportedBundle, BundleVerifyError>;

pub fn verify_bundle(
    bundle: &ExportedBundle,
    trust: &VerifierTrust,
    caller_data: Option<&CallerData>,
) -> Result<VerificationReport, BundleVerifyError>;
```

`scripts/check-offline-verifier-deps.py --metadata <FILE>` reads the output of `cargo metadata --format-version 1 --locked` (produced under `cs` on ws2 and by the CI job's own cargo step), resolves the normal dependency closure of `chio-bundle-verify` and fails when it contains a Chio crate outside `CHIO_ALLOWED` (`chio-bundle-verify`, `chio-core-types`, `chio-kernel-core`, `chio-security-types`, `chio-errors`), so `chio-kernel`, `chio-control-plane` and `chio-store-sqlite` refuse; any package of the `DENIED` list (async runtimes and event loops such as `tokio` and `mio`, HTTP clients and stacks such as `reqwest`, `ureq`, `hyper` and `h2`, SQL bindings such as `rusqlite`, `libsqlite3-sys` and `sqlx`); or a package whose `license` expression is outside the `deny.toml` allow list. No baseline file; the allowlist and the deny list live in the script.

- [ ] **Step 1: Failing tests.** `chio-core-types/tests/verifier_trust.rs`: the staged invalid example `verifier-trust.empty-kernel-keys` refuses; a padded member at top level and inside `idp_keys` refuses (G18); a key listed as both kernel and exchange key refuses; a weak Ed25519 key refuses. `scripts/tests/check-offline-verifier-deps.test.py`: a temp metadata document with `tokio` in the closure fails, one with an MPL-2.0 package fails, the clean closure passes.
- [ ] **Step 2: Implement** the type, the crate skeleton (`read_bundle` with path containment and hash checks; `verify_bundle` returning the report shell), the gate and the clock root.
- [ ] **Step 3: Run** `cs cargo test -p chio-core-types --test verifier_trust`, `cs cargo test -p chio-bundle-verify`, `cs cargo metadata --format-version 1 --locked > /var/tmp/claude-targets/m1i6/metadata.json && python3 scripts/check-offline-verifier-deps.py --metadata /var/tmp/claude-targets/m1i6/metadata.json && python3 scripts/tests/check-offline-verifier-deps.test.py`, `python3 scripts/check-security-clocks.py`. Expected: PASS.

---

### Task 4: Exit classes, error codes and the report (6a)

**Files:** `crates/tooling/chio-bundle-verify/src/{error,report}.rs`, `src/bin/chio-verify.rs`; `spec/errors/registry.yaml`; `spec/schemas/chio-wire/v1/export/bundle-verify-report.schema.json` (new); `docs/cli/bundle-verify.md` (new)

**Inputs (CLI):**

```text
chio-verify <BUNDLE_DIR> --trust <FILE> [--caller-data <FILE>] [--json]
```

- `<BUNDLE_DIR>`: an exported package directory (`manifest.json`, `export-envelope.json` and the listed files).
- `--trust`: a `chio.verifier-trust.v1` file. Required; there is no default trust.
- `--caller-data`: optional, `chio.verifier-caller-data.v1` (Task 7). Absent means the content column cannot exceed `unverifiable` for a `caller` bundle.
- `--json`: print the report as `chio.bundle-verify-report.v1` on stdout; print a rejection as one JSON error report on stderr whose `code` names it, as `chio proof verify --json` does.
- No `--online` in M1 (spec 10.9 places it in M3 behind a feature).

**Outputs:** a report with one row per tool receipt and five columns, each `{class, reason_code?}` where `class` is one of `verified`, `observed`, `asserted`, `unverifiable`, `rejected`, plus bundle-level members (`disclosure_profile`, `tenant_tags`, `tenant_confirmed`, `principals_confirmed`, `envelope_signer`, `required_columns`, `exit_class`); 6b adds `tenant_confirmed` and `principals_confirmed` (Task 7).

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass { Verified, Observed, Asserted, Unverifiable, Rejected }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitClass {
    Verified = 0,
    Unclassified = 1,
    Usage = 2,
    RequiredColumn = 10,
    Integrity = 20,
    ParseOrSchema = 30,
    NegativeCaseMismatch = 40,
    VerifierContext = 50,
}

impl BundleVerifyError {
    pub fn code(&self) -> &'static ErrorCodeSpec;
    pub fn exit_class(&self) -> ExitClass; // a function of `code()` alone
}
impl VerificationReport {
    pub fn exit_class(&self, trust: &VerifierTrust) -> ExitClass;
}
```

Exit table (the same numbers and meanings as `docs/cli/proof-verify.md`):

| Code | Class | Registry codes |
|---|---|---|
| 0 | verified | none; every column named in `required_columns` is `verified` and no integrity finding exists |
| 1 | unclassified | an error with no registry code, such as an unreadable bundle path |
| 2 | usage | argument errors |
| 10 | required column | `attest:bundle-required-column-unverified`: a column in `required_columns` is not `verified`, including a `rejected` delegation chain column caused by a covering revocation entry (column reason code `attest:bundle-root-revoked`, which is never an integrity finding) |
| 20 | integrity | `attest:bundle-envelope-invalid`, `bundle-file-hash-mismatch`, `bundle-signature-invalid`, `bundle-evidence-inconsistent`, `bundle-root-inconsistent`, `bundle-commitment-mismatch`, `bundle-disclosure-tampered`, `bundle-provider-identity-mismatch`, `bundle-root-not-valid-at-receipt`, `bundle-tenant-mismatch`, `bundle-tenant-tag-outside-set` |
| 30 | parse or schema | `attest:bundle-schema-invalid`, `CHIO-CLI-JSON`, `attest:signed-json-*` |
| 40 | negative case mismatch | reserved; `chio-verify` has no negative-case catalog and never exits 40 |
| 50 | verifier context or unsupported feature | `attest:bundle-trust-invalid` (the trust file fails `VerifierTrust::load`), `attest:bundle-trust-missing` (the bundle needs a key role the trust file leaves empty), `attest:bundle-feature-unsupported` (an `auditor_full` bundle, a presentation with ancestors, an `idp_artifact`, `pdp_decision_receipt`, `revocation_request` or `settlement_closure` role, or `settlement` in `required_columns`) |

Precedence: 30 and 50 stop before any column is computed; otherwise the report is complete and the exit is 20 when any integrity finding exists, else 10 when a required column is not `verified`, else 0. Every code above is registered with `domain: attest`, `consumed_by: [chio-bundle-verify, chio-cli]`. 6a registers the codes it emits (envelope, file hash, signature, evidence inconsistency, schema, trust, feature, required column); 6b registers the root, root validity at receipt, root revocation, commitment, disclosure, provider identity and tenant mismatch codes; 6c registers `attest:bundle-tenant-tag-outside-set` with the four `attest:export-*` codes (Task 8 Step 3).

- [ ] **Step 1: Failing tests** in `chio-bundle-verify/tests/exit_classes.rs`: `every_bundle_error_has_its_exit_class` (iterates every `BundleVerifyErrorKind` through the `KINDS` table and asserts that every kind with a registry code maps to its class above and none maps to 1; each part adds the rows for the codes it registers, and 6c adds `attest:bundle-tenant-tag-outside-set` mapped to 20); `integrity_beats_required_column`; `parse_failure_stops_before_columns`; `unpinned_kernel_key_is_verifier_context`.
- [ ] **Step 2: Implement; write the schema** (`additionalProperties: false` at every level) **and `docs/cli/bundle-verify.md`** with the table above.
- [ ] **Step 3: Run** `cs cargo test -p chio-bundle-verify --test exit_classes`, `python3 scripts/check-error-urn-registry.py`, `bash scripts/check-chio-schema-registry.sh`, `python3 scripts/check-wire-schemas.py`. Expected: PASS.

---

### Task 5: Today's bundle format through the new crate; delete the old verifier (6a)

**Preconditions (6a, checked in Task 1 Step 1 before the code lane starts):** Root-2's ACK of the deletion of `crates/platform/chio-control-plane/src/evidence_export/verification.rs` (a Root-2 held file) is recorded on `sync.md`, and item 1's PR has not opened; 6a lands before item 1's PR opens.

**Files:** `crates/tooling/chio-bundle-verify/src/{envelope,columns/decision}.rs`; delete `crates/platform/chio-control-plane/src/evidence_export/verification.rs` and the verify half of `evidence_export.rs` and `envelope.rs` (`EvidenceVerificationPolicy`, `verify_manifest`, `verify_payload`, `cmd_evidence_verify`, `validate_import_package_data`'s verification body, `load_verified_evidence_package*`); `trust_control/receipt_handlers.rs`; `chio-cli` `types/receipt.rs`, `dispatch/receipt_evidence.rs`, tests; `chio-mercury` builders and docs; `scripts/smoke/chio-cli-smoke.sh`

**Interfaces:**
- `chio_bundle_verify::verify_package(dir: &Path, trust: &VerifierTrust, embedded_http: Option<&dyn EmbeddedHttpReceiptVerifier>) -> Result<VerifiedPackage, BundleVerifyError>`: a receipt that embeds an HTTP receipt refuses as unsupported unless `embedded_http` is supplied (`chio evidence verify` and import pass the control-plane `HttpReceiptProjection`; the standalone `chio-verify` passes `None`). Item 2's G4 change (its Task 12, `HttpReceipt` deleted) removes the `embedded_http` argument with the embedded HTTP receipt check, which the item 2 plan calls `verify_http_receipt_evidence` and which is the `EmbeddedHttpReceiptVerifier` trait and its `HttpReceiptProjection` impl in this crate and the control plane. The rest of the package check: the envelope check (signer in `trust.kernel_keys`, `chio.evidence_export_commitment.v1` signature, manifest and payload digests), file inventory, receipt, child receipt and checkpoint signatures against `trust.kernel_keys`, checkpoint chain, inclusion proofs, transparency claims (with `trust.checkpoint_keys` and the anchor binding, Decision 5), query scope, disclosure notice, and the decision column. `VerifiedPackage` replaces `VerifiedEvidencePackage` and carries the verified bundle for import.
- `chio evidence verify --input <DIR> --trust <FILE> [--caller-data <FILE>]` and `chio --json evidence verify ...`: calls `chio_bundle_verify::verify_bundle` and exits with the Task 4 table. `chio evidence import --input <DIR> --trust <FILE>`: verifies with `verify_package`, then imports.
- `RemoteEvidenceImportRequest { package, trust: VerifierTrust }` replaces `verification: EvidenceVerificationPolicy` on the trust-control wire; trust-control's handler calls `verify_package` on the decoded package.
- Deleted flags: `--trusted-kernel-pubkey`, `--trusted-anchor-file` on `evidence verify` and `evidence import`.

- [ ] **Step 1: Port the tests.** Every test in `evidence_export/tests.rs` that exercises verification moves to `chio-bundle-verify/tests/package.rs` with its assertions unchanged (hybrid receipts without a policy floor, manifest count drift, mixed-tenant scope, checkpoint fork, anchored transparency claims, stale publication, disclosure notice stripping and tampering). The CLI tests and the smoke script change only their trust arguments.
- [ ] **Step 2: Implement and delete.** `git grep -n "verification.rs\|EvidenceVerificationPolicy\|trusted-kernel-pubkey"` returns nothing outside `docs/superpowers` and the changelog.
- [ ] **Step 3: Run** `cs cargo test -p chio-bundle-verify -p chio-control-plane -p chio-mercury --no-fail-fast`, `cs cargo test -p chio-cli --test evidence_export --no-fail-fast`, `bash scripts/smoke/chio-cli-smoke.sh` (with `cs` on its build step), `python3 scripts/check-trust-boundaries.py`. Expected: PASS.

---

### Task 6: Identity root, delegation chain and the provider identity role (6b)

**Files:** `crates/tooling/chio-bundle-verify/src/columns/{identity_root,delegation_chain}.rs`, `src/read.rs`; `crates/core/chio-core-types/src/receipt/evidence.rs` (`RootAuthorityEvidence`)

**Bundle members read (written by Task 8, typed here):**

```rust
/// Root-authority artifacts a bundle carries. Each list is canonical-JSON NDJSON
/// in the file the manifest names for its role, ordered by digest or id.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootAuthorityEvidence {
    pub presentations: Vec<CapabilityPresentation>,         // role capability_presentation; ancestors [] in M1
    pub delegation_contexts: Vec<DelegationContext>,        // role delegation_context
    pub root_policies: Vec<RootPolicy>,                     // role root_policy
    pub provider_identities: Vec<EnterpriseProviderIdentity>, // role enterprise_provider_identity
    pub idp_key_snapshots: Vec<IdpKeySnapshot>,             // role idp_key_snapshot
    pub revocation_entries: Vec<ExportedRevocationEntry>,   // role revocation_entry
}
```

`EvidenceExportBundle` gains `root_authority: RootAuthorityEvidence` and `disclosures: Vec<ReceiptDisclosure>`, so the existing envelope payload digest covers them.

**Identity root column, per receipt with an `authority` block (M1):**
1. Find the presentation whose root capability id equals the receipt's exercised capability; its root carries `root_anchor` equal byte for byte to `receipt.authority.root_anchor`.
2. Root signature verifies with `verify_wrapped(pinned, "chio.capability.v1", ..)` where `pinned` is the root's issuer and is in `trust.exchange_keys`. Not pinned: `attest:bundle-trust-missing` (exit 50).
3. The root policy whose digest equals `root_anchor.root_policy_digest` is in the bundle; `RootPolicy::load` with `trust.root_policy_keys` as the pinned set succeeds; the policy's own `policy_key` is in `trust.root_policy_keys`; the root's issuer is in the policy's `exchange_keys`; the receipt `timestamp` is inside `[valid_from, valid_until]`.
3a. Root validity at the receipt time. Let `t` be the receipt `timestamp` and `root` the presentation root capability. The root is valid at `t` only when `root.issued_at <= t < root.expires_at` (the lower bound is inclusive, the upper bound exclusive, matching capability verification). A root whose `issued_at` is after `t` or whose `expires_at` is at or before `t` is `rejected` with `attest:bundle-root-not-valid-at-receipt` (exit 20, integrity). Revocation is not part of this step and never yields this code: a covering revocation entry leaves the identity root column unchanged and is reported only by the delegation chain column below (spec 11.4). The check reads only the bundle and the receipt, never the clock, and applies to every receipt independently, so one root can be valid for one receipt in a bundle and not valid for another.
4. `check_root_consistency` (#1706) holds for the root, its anchor, the context whose digest equals `context_digest`, and the loaded policy.
5. Provider identity (G17), for provider-backed kinds: the bundle carries a projection whose recomputed `provider_identity_digest` equals the context's `provider_identity_digest` and the matched rule's `match.provider_identity_digest`; the projection's `issuer` equals the context's `issuer`. A missing projection or a differing digest is `rejected` with `attest:bundle-provider-identity-mismatch` (exit 20). The verifier reports nothing about the enabled state (spec 9.8).
6. For `oauth_id_jag`, `entra_jwt` and `oidc_jwt`, the context's `key_snapshot_digest` names a snapshot in the bundle whose signature verifies against a key in `trust.exchange_keys` (`chio.idp-key-snapshot.v1`), whose `issuer` equals the context's, and which contains the context's `kid`.
7. Result: `asserted` when 1 to 6 (including 3a) hold (no retained artifact exists in M1, spec 9.6); `rejected` with `attest:bundle-root-inconsistent` on any mismatch; `verified` is unreachable until retention (Decision 1). `operator_static_bearer` is at most `asserted` (spec 7.2).

A receipt without an `authority` block (producers without a root policy) has an `unverifiable` identity root column.

**Delegation chain column (M1, depth 0):** `verified` when the presentation has `ancestors: []`, the root verified in step 2 and valid at the receipt timestamp (step 3a), `receipt.authority.chain_depth == 0`, `chain_digest` recomputes over `[root]` (spec 7.6), and no exported revocation entry covers the root at or before the receipt timestamp (Decision 4). A covering entry makes the column `rejected` with reason code `attest:bundle-root-revoked`. That code is never an integrity finding: a covering entry makes the bundle exit 10 (`attest:bundle-required-column-unverified`) only when `delegation_chain` is in `required_columns`, and never 20. Non-empty `ancestors`: `attest:bundle-feature-unsupported` (exit 50).

- [ ] **Step 1: Failing tests** in `tests/identity_root.rs`, each over a bundle built from typed constructors with fixed keys and `issued_at = 1792234800`: one `asserted` case per M1 kind; a policy whose `policy_key` is not pinned (self-asserted key) exits 50; a root signed by a key outside the policy's `exchange_keys` is `rejected`; a projection with one changed member (`jwks_url`) is `rejected` with the provider identity code; a missing projection is `rejected`; a snapshot missing the context `kid` is `rejected`; a receipt timestamp outside the policy window is `rejected`; `root_not_yet_valid_at_receipt` (receipt `timestamp` one second before `root.issued_at`) is `rejected` with `attest:bundle-root-not-valid-at-receipt` and exits 20; `root_expired_at_receipt` (receipt `timestamp` equal to `root.expires_at`, and one second after it) is `rejected` with the same code and exit; `root_valid_at_receipt` (receipt `timestamp` equal to `root.issued_at`, and one second before `root.expires_at`) is `asserted`; `root_window_checked_per_receipt` (two receipts under one root, one inside and one after expiry, give `asserted` and `rejected`); `root_revoked_before_receipt_rejects_only_the_delegation_chain` (identity root `asserted`, delegation chain `rejected` with `attest:bundle-root-revoked`, no integrity finding; exit 10 with `required_columns = ["delegation_chain"]` and exit 0 with `required_columns = ["decision"]`); the verifier passes the same cases with the system clock set far from `t`; each `RootConsistencyError` variant reaches `rejected`; a padded context, projection, policy rule and presentation each exit 30 (G18); an artifact with an `algorithm` member exits 30 (G19). In `tests/delegation_chain.rs`: depth 0 `verified`; ancestors present exits 50; a covering `capability_id`, `root_policy_rule` and `replay_key` entry each make the column `rejected` with `attest:bundle-root-revoked` and the bundle exit 10, never 20, when `delegation_chain` is required; an entry dated after the receipt does not; a root not valid at the receipt timestamp makes the delegation chain column `rejected`, not `verified`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** `cs cargo test -p chio-bundle-verify --no-fail-fast`, `cs cargo clippy -p chio-bundle-verify --all-targets -- -D warnings`. Expected: PASS.

---

### Task 7: Content column, openings and caller data (6b)

**Files:** `crates/tooling/chio-bundle-verify/src/columns/content.rs`, `src/caller_data.rs`, `src/report.rs` (`tenant_confirmed`, `principals_confirmed`); `spec/schemas/chio-wire/v1/export/verifier-caller-data.schema.json` (new); `spec/schemas/chio-wire/v1/export/bundle-verify-report.schema.json` (the two confirmation members, required booleans); `tests/bindings/vectors/export/v1.json` (new) and its generator test; `tests/bindings/vectors/MANIFEST.sha256`

**Interfaces:**

```rust
/// `chio.verifier-caller-data.v1`: the caller's own copies, written by the caller.
/// Unsigned. Each entry names one receipt; values are caller data (opaque).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerData {
    pub schema: String,
    pub tenant: Option<CallerTenant>,          // { issuer, value }
    pub principals: Vec<CallerPrincipal>,      // { issuer, subject }
    pub calls: Vec<CallerCall>,                // { receipt_id, parameters?, output? }
}
pub enum CallerOutput { Value(serde_json::Value), Empty, Stream(Vec<serde_json::Value>) }
```

Rules:
- Openings: the bundle's `ReceiptDisclosure` for a receipt decodes strictly; `receipt_id` is bare lowercase hex (G14); a salt that appears under two `salt_ref` values marks the receipt as tampered disclosure (G15, `attest:bundle-disclosure-tampered`, exit 20).
- Parameters and content: the domain comes from the commitment's position (`chio.receipt.parameters.v1\0`, `chio.receipt.content.v1\0`); the preimage comes from `CallerData.calls` (canonical arguments; for outputs the G13 three forms), never from an opening `payload`. Match: `verified`. Mismatch: `rejected`, `attest:bundle-commitment-mismatch` (exit 20). No caller entry for that receipt: `unverifiable`.
- `auditor_hash_only`: the bundle carries no `receipt_disclosure` role; an opening found in such a bundle exits 30. Content is `unverifiable`.
- `caller`: openings carry salts and `payload: null` only; a non-null payload in a `caller` bundle exits 30.
- Inline fields: in M1 every receipt is fully committed (spec 13.1 cut 1); a receipt with a non-empty inline list is `rejected` with `attest:bundle-commitment-mismatch`.
- Tenant and principal confirmation (spec 7.12): the report carries two bundle-level members, and neither is ever vacuously true. The confirmation set is the commitments covering the exported tool receipts: for each exported receipt, the delegation context its `authority` block names. Each member is `true` only when the set is nonempty, covers every exported receipt and every commitment in it opens; otherwise it is `false`. An empty bundle, a bundle whose receipts carry no `authority` block (producers without a root policy), a bundle in which any exported receipt has no `authority` block, no exported context or no opening of the needed kind, and caller data without the needed values all leave the member `false`. Missing evidence never becomes an integrity finding.
  - `tenant_confirmed`: with `CallerData.tenant` present, the verifier opens the tenant commitment (domain `chio.delegation-context.tenant.v1\0`, salt from the `anchor.tenant` opening) of every context in the set with `tenant.value`. `true` only under the rule above. A tenant commitment whose opening is present but does not open with `tenant.value`: `attest:bundle-tenant-mismatch` (exit 20). No `CallerData.tenant`: `false`.
  - `principals_confirmed`: `true` only under the rule above, with every context's subject commitment (salt from the `anchor.sub` opening) opening against a principal in `CallerData.principals`; `false` when no principal is supplied or when a subject opens against no supplied principal. The report names which principal each receipt was attributed to, or that it is unattributed (user story C4). A supplied principal that opens no subject leaves its receipts unattributed and is not an integrity finding.
  - Neither member changes the exit class; a relying party reads both from the report. A subject opening never opens a tenant commitment (field-specific domains).

- [ ] **Step 1: Failing tests** in `tests/content.rs`: params and value-output round trip `verified`; empty output and stream output (G13 forms) `verified`; a one-bit change in salt, caller argument or domain `rejected`; a duplicated salt across two `salt_ref` values exits 20 (G15); a `payload: null` opening is never used as a preimage (G13 negative from the #1537 regenerated vectors); hash-only bundle with an opening exits 30; caller bundle with a payload exits 30; tenant confirmation true for the right tenant value and exit 20 for another; a subject opening presented as a tenant opening fails; `tenant_unconfirmed_when_one_tenant_commitment_is_unopened` (one context without an `anchor.tenant` opening gives `tenant_confirmed: false`); `principals_unconfirmed_when_a_principal_is_missing` (caller data omits the principal of one context: `principals_confirmed: false`, that receipt unattributed, exit unchanged); `principals_unconfirmed_for_a_wrong_principal` (caller data names a principal that opens no subject: `principals_confirmed: false`, exit unchanged); `principals_unconfirmed_without_principals` (no `CallerData.principals`: `principals_confirmed: false`); `tenant_and_principals_confirmed` (every exported receipt is anchored and every commitment opens: both `true`); `confirmations_false_for_an_empty_bundle` (no exported receipt, with tenant and principals supplied: both `false`, exit unchanged); `confirmations_false_for_an_unanchored_only_bundle` (every receipt without an `authority` block, with tenant and principals supplied: both `false`, exit unchanged); `confirmations_false_when_one_receipt_lacks_a_commitment` (two anchored receipts whose commitments open and one receipt without an `authority` block: both `false`, no integrity finding).
- [ ] **Step 2: Vectors.** `tests/bindings/vectors/export/v1.json`: bundle-level cases (a directory tree per case under `tests/bindings/vectors/export/v1/`) with `expected_exit` and `expected_columns`, generated by an `#[ignore]` regenerator in `chio-bundle-verify/tests/vector_fixtures.rs` from typed constructors; `cs cargo xtask freeze-vectors`.
- [ ] **Step 3: Run** `cs cargo test -p chio-bundle-verify --no-fail-fast`, `cs cargo test -p chio-bundle-verify --test vector_fixtures -- --ignored` then without `--ignored`, `cs cargo xtask freeze-vectors --check`. Expected: PASS.

---

### Task 8: Provider export API, profiles and roles (6c)

**Files:** `crates/platform/chio-control-plane/src/evidence_export.rs`, `evidence_export/{package_write,root_authority,stores}.rs` (new module); `crates/protocol/chio-mcp-remote/src/remote_mcp/{admin,session_core}.rs`; `crates/products/chio-cli/src/cli/{types/receipt,dispatch/receipt_evidence}.rs`; `crates/tooling/chio-bundle-verify/src/{verify,error,package}.rs` and `tests/profile.rs` (new: the profile and tenant-tag checks, `build_package`); `crates/core/chio-core-types/src/receipt/evidence.rs` (`EvidenceExportCounts.erased_openings`); `spec/schemas/chio-wire/v1/export/evidence-export-manifest.schema.json` (moved in); `spec/errors/registry.yaml`

**Interfaces:**

```rust
// chio-core-types::receipt::evidence
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureProfile { Caller, AuditorFull, AuditorHashOnly }

pub enum ArtifactRole {
    CapabilityPresentation, DelegationContext, RootPolicy, EnterpriseProviderIdentity,
    IdpKeySnapshot, IdpArtifact, ReceiptDisclosure, RevocationEntry, RevocationRequest,
    SettlementClosure, PdpDecisionReceipt,
}
```

`EvidenceExportManifest` gains `disclosure_profile: DisclosureProfile`, `tenant_tags: Option<Vec<KeyedIndexValue>>` (present, non-empty and sorted by `key_id` exactly for `caller`; `KeyedIndexValue` is the item 2 key-set type) and `artifacts: Vec<ArtifactEntry { role, path }>`. `EvidenceExportCounts` gains `erased_openings: u64` (manifest `counts.erasedOpenings`, required): the number of exported tool receipts that carry no opening because their openings were erased; it is 0 in every `auditor_hash_only` bundle.

```rust
// chio-core-types::receipt::evidence
/// One selected receipt and the tenant tag stored beside its row.
pub struct TenantTaggedReceipt { pub record: EvidenceToolReceiptRecord, pub tag: KeyedIndexValue }
```

```rust
// chio-control-plane::evidence_export
pub enum ExportDisclosure {
    Caller { tenant_tags: Vec<KeyedIndexValue> },
    AuditorHashOnly,
}

/// The serve-http state database, as three borrowed store handles. A plain
/// struct: the reads are inherent methods of the sqlite stores, which
/// chio-control-plane depends on (the reverse edge would be a cycle), so no
/// trait sits between them.
pub struct ExportStores<'a> {
    pub exchange: &'a SqliteRootExchangeStore,  // item 4
    pub receipts: &'a SqliteReceiptStore,      // item 2
    pub revocations: &'a SqliteRevocationStore, // item 5
}

/// Builds the unsigned bundle for one export. Every artifact is reached from a
/// selected receipt; nothing else is read. An `AuditorHashOnly` assembly that
/// would carry any salt refuses with `export-salt-only-opening` before anything
/// is built or signed.
pub fn assemble_export(
    stores: ExportStores<'_>,
    receipts: &dyn ReceiptStore,
    query: EvidenceExportQuery,
    disclosure: ExportDisclosure,
) -> Result<EvidenceExportBundle, CliError>;

// chio-bundle-verify::package (6c splits 6a's `write_package`)
/// The package's files and its signed `chio.evidence_export_commitment.v1`
/// envelope, built in memory and signed through the kernel signing backend.
/// `write_package` writes the result into an empty directory; `serve-http`
/// returns it from the export route.
pub fn build_package(contents: PackageContents<'_>, signer: &dyn SigningBackend) -> Result<PackageFiles, BundleVerifyError>;
pub struct PackageFiles { pub manifest: EvidenceExportManifest, pub files: Vec<PackageFile> }
pub struct PackageFile { pub path: String, pub bytes: Vec<u8> }
```

The reads `assemble_export` calls are plain inherent methods that chio-store-sqlite owns. Items 2, 4 and 5 add them (item 4 F13 and its "Reads for item 6" list, item 5 Task 3); this item adds none and defines no store trait. Every method returns shared `chio-core-types` types and a typed error from chio-store-sqlite, with a typed missing-row variant and never `Option`:

```rust
// chio-store-sqlite, SqliteRootExchangeStore (item 4), error RootExchangeStoreError
pub fn presentation(&self, root_capability_id: &str) -> Result<CapabilityPresentation, RootExchangeStoreError>;
pub fn delegation_context(&self, digest: &Sha256Digest) -> Result<DelegationContext, RootExchangeStoreError>;
pub fn root_policy(&self, digest: &Sha256Digest) -> Result<RootPolicy, RootExchangeStoreError>;
pub fn provider_identity(&self, digest: &Sha256Digest) -> Result<EnterpriseProviderIdentity, RootExchangeStoreError>;
pub fn idp_key_snapshot(&self, digest: &Sha256Digest) -> Result<IdpKeySnapshot, RootExchangeStoreError>;
pub fn context_openings(&self, context_digest: &Sha256Digest) -> Result<ContextOpenings, RootExchangeStoreError>;
/// Every receipt whose stored `(tag_key_id, tag)` is in `tags`, each with that stored tag.
pub fn receipts_for_tenant(&self, tags: &[KeyedIndexValue], query: &EvidenceExportQuery) -> Result<Vec<TenantTaggedReceipt>, RootExchangeStoreError>;

// chio-store-sqlite, SqliteReceiptStore (item 2), error ReceiptStoreError; the item 2 trait method
fn read_openings(&self, receipt_id: &str, scope: &OpeningReadScope) -> Result<OpeningState, ReceiptStoreError>;

// chio-store-sqlite, SqliteRevocationStore (item 5), error RevocationStoreError
pub fn revocations_covering(&self, roots: &[RevocationCoverageRoot]) -> Result<Vec<RevocationCoverage>, RevocationStoreError>;
```

`CapabilityPresentation`, `DelegationContext`, `RootPolicy`, `EnterpriseProviderIdentity`, `IdpKeySnapshot`, `ContextOpenings`, `ReceiptDisclosure`, `OpeningReadScope`, `OpeningState`, `EvidenceToolReceiptRecord` and `TenantTaggedReceipt` live in `chio-core-types` (the first five under `root_authority`, `ReceiptDisclosure`, `OpeningReadScope` and `OpeningState` in `receipt::disclosure` from item 2, the rest in `receipt::evidence` from Task 2; item 4 adds `TenantTaggedReceipt` with `receipts_for_tenant`), and `RevocationCoverageRoot` and `RevocationCoverage` live in `chio-core-types` `root_authority::revocation_entry` beside `RevocationEntry` (item 5). The store errors stay in chio-store-sqlite: only control-plane maps them, and it already depends on that crate.

The mapping in `evidence_export/stores.rs` is the only glue. Control-plane builds `RevocationCoverageRoot` from each presentation's root capability id and the capability ids the bundle carries, and wraps each returned `RevocationCoverage` as an `ExportedRevocationEntry`. Any missing-row variant (`AnchoredRootMissing { capability_id }`, a missing context, policy, projection, snapshot or context opening) and `OpeningState::Unknown` from `read_openings` fail the whole export with `urn:chio:error:attest:export-evidence-incomplete`, so a partial bundle is never written. A storage error maps to the existing internal export failure. A record from `receipts_for_tenant` whose `tag` is not in the requested set also fails the export with the internal export failure, so the exporter never writes a tag the verifier would reject.

Profile rules:
- `caller`: receipts are exactly those whose stored `(tag_key_id, tag)` is in the tag set. The set holds `derive_in(&key_id, IndexDomain::TenantTag, issuer || 0x00 || value)` for every `key_id` in `TenantIndexKeySet::key_ids()` (`derive_in` prefixes the `chio.tenant-tag.v1\0` domain itself, so the preimage excludes it), so receipts tagged under a retired generation are selected with the active one. The manifest's `tenant_tags` is that set, sorted by `key_id`. Openings carry the `params`, `content`, `anchor.sub` and `anchor.tenant` salts with `payload: null`. The receipt salts come from `read_openings` with an `OpeningReadScope` naming `params` and `content`: `OpeningState::Present` gives the salt-only disclosure (`ReceiptOpenings::salt_only`); `OpeningState::Erased` exports the receipt without a `receipt_disclosure` entry and counts it in `counts.erasedOpenings`; `OpeningState::Unknown` fails the export (above). Item 2 writes openings in the receipt's append transaction, so no opening is lost apart from its receipt (item 2 open question 2) and erasure is the only state without salts.
- `auditor_hash_only`: no `receipt_disclosure` role, no salts, no `tenant_tags` and no `disclosure/receipt-tenant-tags.ndjson`. The request has no member that asks for an opening. `assemble_export` refuses an auditor assembly that would carry any salt (a receipt disclosure, a context opening or any other salt member) with `urn:chio:error:attest:export-salt-only-opening` before anything is built, signed or returned (scenario 008, reached through the `rust-kernel` driver's fault injection).
- `auditor_full`: refused in M1 with `urn:chio:error:attest:export-profile-unavailable`. The route and the CLI parse `profile` as the closed `DisclosureProfile` enum, so `auditor_full` decodes and reaches this refusal; any other string is a request schema error.
- `caller` without a tenant: refused with `urn:chio:error:attest:export-tenant-tag-required` (scenario 009).
- `query.tenant` (the plaintext receipt `tenant_id` filter) with `caller` is refused: the tenant is selected only by tag (Decision 2).
- A selected receipt whose context, policy, projection or snapshot is missing from the store fails the export with `urn:chio:error:attest:export-evidence-incomplete`. There is no partial bundle.

The provider identity role (G17): for every exported context with a `provider_record_id`, the bundle carries the `chio.enterprise-provider-identity.v1` projection whose digest equals the context's `provider_identity_digest`. The exporter reads the projection by digest from the retention item 4 provides, never from the live registry, because the live record may have changed identity under a re-signed policy (Decision 3). The role is `enterprise_provider_identity` and its file is `root-authority/provider-identities.ndjson`. The staged manifest schema and the staged "Export profiles" text already carry this role (#1737); this task carries the role over with the schema move-in, and Task 10 carries it over with the PROTOCOL "Export profiles" subsection.

Bundle files added (each listed in `files` and, for a role, in `artifacts`): `root-authority/presentations.ndjson`, `root-authority/delegation-contexts.ndjson`, `root-authority/root-policies.ndjson`, `root-authority/provider-identities.ndjson`, `root-authority/idp-key-snapshots.ndjson`, `disclosure/receipt-tenant-tags.ndjson` (`caller` only: one `{receipt_id, tag: KeyedIndexValue}` row per exported receipt, the `tag` of its `TenantTaggedReceipt` from `receipts_for_tenant`), `disclosure/openings.ndjson`, `revocations.ndjson`.

Provider side:
- `serve-http` gains `POST /admin/evidence/export` (admin authentication as `/admin/revocations`). Body: `{"profile": DisclosureProfile, "tenant": {"issuer": "...", "value": "..."} | null, "query": EvidenceExportQuery, "require_proofs": bool}`, where `profile` is one of `caller`, `auditor_full` and `auditor_hash_only`. The body has no member that asks for an opening. The handler computes the tenant's tag set with the in-process index key set (spec 7.12): `derive_in(&key_id, IndexDomain::TenantTag, issuer || 0x00 || value)` for each `key_id` in `key_ids()`. It assembles the bundle through the serving database, builds the package with `build_package` and signs its `chio.evidence_export_commitment.v1` envelope through its kernel signing backend, the signer of its receipts. The response is the signed package: `{"files": [{"path": "<relative path>", "b64u": "<file bytes>"}]}`, every file the manifest lists plus `manifest.json` and `export-envelope.json`. NUL in `issuer` or `value` is refused (spec 7). The export adds no artifact type: the envelope is the existing commitment.
- `chio evidence export --edge-url <URL> --admin-token-file <FILE> --disclosure-profile <caller|auditor_full|auditor_hash_only> [--tenant-issuer <ISS> --tenant-value <VALUE>] --trust <FILE> --output <DIR>`: calls the route, decodes the response strictly (an unknown member, a path that is not relative with normal components only, or a duplicate path refuses), writes the files into a new private temporary directory beside `--output`, runs the self check there and renames the directory to `--output` only when the check passes. The edge form takes no `--kernel-seed-file`: no kernel seed lives on an operator host. `--disclosure-profile` parses as `DisclosureProfile`, is required for every export and has no default; `auditor_full` reaches the route's `export-profile-unavailable` refusal.
- Self check (fail-closed). The CLI verifies the returned package with the trusted verify of 6a: `chio_bundle_verify::verify_bundle` (what `chio-verify` runs; `chio evidence verify` runs the same `verify_package` plus `report`) over the temporary directory with the `VerifierTrust` read from `--trust` by `read_trust_file`, and `VerificationReport::exit_class(&trust)` must be `ExitClass::Verified`. Every key the check accepts comes from that file, never from the route response or the bundle: a package signed by a kernel key outside the operator's `kernel_keys` refuses with `attest:bundle-trust-missing`. The check covers the package layer (envelope, file inventory and hashes, kernel-signed receipts, child receipts and checkpoints, checkpoint chain, inclusion proofs, transparency, query scope, manifest counts and the profile rules below) and every column, so for a bundle with anchored roots the operator's trust file carries the roles the bundle needs (`exchange_keys`, `root_policy_keys`); an empty needed role refuses with `attest:bundle-trust-missing` (exit 50, Decision 6), and a column named in the file's `required_columns` that is not `verified` refuses with exit 10 (the export takes no caller data, so a file that requires `content` refuses every caller export). Any refusal removes the temporary directory, writes nothing at `--output` and exits with the check's class.

Verifier side (6c work in `chio-bundle-verify`, in the package layer `verify_package`, so the export self check, `chio evidence import` and `chio-verify` apply the same rules; Task 7's opening and payload profile rules run in the same layer):
- `caller` bundles: `chio-bundle-verify` checks that `tenant_tags` is non-empty, sorted by `key_id` and has one entry per `key_id`, that `disclosure/receipt-tenant-tags.ndjson` has exactly one row for each exported receipt, and that every row's `(key_id, tag)` is in `tenant_tags`. Any failure is `urn:chio:error:attest:bundle-tenant-tag-outside-set` (exit 20, in Task 4's code table, registered by this task and pinned by `every_bundle_error_has_its_exit_class`). The number of exported tool receipts without a `receipt_disclosure` entry equals `counts.erasedOpenings`; a difference is `attest:bundle-evidence-inconsistent` (exit 20, the manifest-count check of `verify_manifest_counts`). The verifier has no index key, so it cannot recompute a tag or prove the set covers every generation; it proves that no exported receipt lies outside the exporter's declared set. Completeness across generations is the exporter's duty (the set is computed from `key_ids()` and the store query is bound to it) and is pinned by the rotation tests in Step 1.
- `auditor_hash_only` bundles: `files` and `artifacts` list no `disclosure/receipt-tenant-tags.ndjson` and no `receipt_disclosure` role, and the manifest carries no `tenant_tags`; a present tag file, role or member is `attest:bundle-schema-invalid` (exit 30), as for an opening in such a bundle (Task 7). `counts.erasedOpenings` other than 0 is `attest:bundle-evidence-inconsistent` (exit 20).

- [ ] **Step 1: Failing tests.** `chio-control-plane` `evidence_export/tests.rs`: `caller_bundle_contains_only_own_tenant` (two tenants with 16-byte random marker principals and tenant values; no marker, raw, hex or base64, from tenant B appears anywhere in tenant A's bundle, and no salt for a tenant B commitment appears); `caller_export_after_rotation_includes_older_generation_receipts` (append receipts for the tenant under generation N, rotate to N+1 with N retired and loaded, append more, export; every receipt from both generations is present, the manifest `tenant_tags` holds one entry per generation sorted by `key_id`, and `chio-bundle-verify` exits 0); `caller_export_after_rotation_excludes_other_tenant_in_every_generation` (a second tenant's receipts under both generations stay out); `manifest_omitting_a_generation_fails_verification` (the same bundle with the generation N entry removed from `tenant_tags` fails with `attest:bundle-tenant-tag-outside-set`, exit 20, and so does a bundle whose `receipt-tenant-tags.ndjson` row carries a tag outside the set or has no row for a receipt); `auditor_hash_only_has_no_salts` (no salt, no `receipt_disclosure` role, no `tenant_tags` and no `disclosure/receipt-tenant-tags.ndjson` in the bundle); `auditor_assembly_with_injected_opening_refused` (a fault injection adds a salt-only opening to an `auditor_hash_only` assembly: `export-salt-only-opening`, nothing built, signed or returned); `caller_without_tenant_refused`; `auditor_full_refused` (through the route and the CLI, each returning `export-profile-unavailable`, never a request parse error); `erased_opening_exported_without_opening_and_counted` (one of three receipts erased before export: the bundle carries two disclosures, `counts.erasedOpenings` is 1, and `chio-bundle-verify` exits 0); `unknown_opening_fails_export` (a receipt with no openings row fails with `export-evidence-incomplete` and no bundle is written); `store_tag_outside_requested_set_fails_export`; `self_check_runs_trusted_verification` (a caller export with anchored roots passes against a `--trust` file carrying the kernel, exchange and root policy keys with `required_columns = ["decision", "delegation_chain"]`, and the package appears at `--output`); `self_check_failure_writes_nothing` (an envelope signed by a kernel key outside the file's `kernel_keys`, an anchored bundle against a file with empty `root_policy_keys`, and a file whose `required_columns` names `content` each refuse with `attest:bundle-trust-missing`, `attest:bundle-trust-missing` and `attest:bundle-required-column-unverified` respectively, and each leaves nothing at `--output` and no temporary directory); `route_returns_the_signed_package` (the route response decodes to the manifest, the envelope and every listed file, and its envelope verifies under the serving kernel key); `cli_refuses_an_unsafe_response_path` (an absolute path, a `..` component and a duplicate path each refuse before any file is written); `edge_export_takes_no_kernel_seed` (`--kernel-seed-file` with `--edge-url` is a usage error); `caller_with_plaintext_tenant_query_refused`; `missing_provider_identity_fails_export`; `each_store_missing_row_variant_maps_to_export_evidence_incomplete` (one fixture per missing row kind, including `AnchoredRootMissing { capability_id }` from `revocations_covering`, each with no bundle written); `projection_exported_by_digest_after_registry_identity_change` (record changes under a re-signed policy; the bundle carries the old projection for old roots and the new one for new roots); every exported bundle verifies with `chio-bundle-verify` and exits 0 with `required_columns = ["decision", "delegation_chain"]`. `chio-mcp-remote`: route refuses without admin auth; NUL refused; neither the index key nor the kernel seed appears in the response or logs. `chio-bundle-verify` `tests/profile.rs`: `caller_tag_row_outside_set_is_tag_code`, `caller_missing_tag_row_is_tag_code`, `caller_unsorted_tenant_tags_is_tag_code`, `caller_erased_count_mismatch_is_evidence_inconsistent`, `auditor_bundle_with_tenant_tag_file_refused` (exit 30, also with the file listed only in `files`), `auditor_bundle_with_tenant_tags_member_refused`, `auditor_bundle_with_nonzero_erased_count_refused`, and `verify_package_applies_profile_rules` (each case refuses through `verify_package` as well as `chio-verify`).
- [ ] **Step 2: Move the manifest schema in** per the staged README move-in rule (`git mv` over the live path; the staged role enum already carries `enterprise_provider_identity` (#1737); replace the single `tenantTag` member with a `tenantTags` array of keyed index values (`minItems` 1, present exactly for `caller`), add the required `erasedOpenings` count (`integer`, `minimum` 0) to `counts`, refresh `MANIFEST.sha256`, regenerate code in four languages, make `wire_protocol_schema.rs` green).
- [ ] **Step 3: Implement**; register the four `attest:export-*` codes and `attest:bundle-tenant-tag-outside-set` (`consumed_by: [chio-bundle-verify, chio-cli]`), and add its `BundleVerifyErrorKind` row (exit 20) to the `KINDS` table of `tests/exit_classes.rs`.
- [ ] **Step 4: Run** `cs cargo test -p chio-control-plane -p chio-mcp-remote -p chio-bundle-verify --no-fail-fast`, `cs cargo clippy -p chio-bundle-verify --all-targets -- -D warnings`, `cs cargo tree -p chio-store-sqlite -e normal --prefix none | grep -c chio-control-plane` (expected: 0), `cs cargo test -p chio-cli --test evidence_export --no-fail-fast`, `for lang in rust ts go python; do cs cargo xtask codegen --lang "$lang" || exit 1; done`, `cs make -C ~/lanes/m1i6 codegen-check`, `python3 scripts/check-wire-schemas.py`, `bash scripts/check-chio-schema-registry.sh`, `python3 scripts/check-error-urn-registry.py`. Expected: PASS.

---

### Task 9: Conformance scenarios and the air-gap run (6c)

**Files:** `crates/tooling/chio-conformance/verdict_matrix/scenarios/receipt_disclosure/` (scenarios 007 to 010 moved from staging), `manifest.toml` (counts and index hash re-pinned), the `export` operation in the `rust-kernel` and `rust-mcp-serve-http` drivers

- [ ] **Step 1:** Move the four export scenarios. If item 2 has already created the `receipt_disclosure` category, these four join it; otherwise the category is created here with only these four and item 2 adds the rest. The `export` operation runs Task 8's route, and for `allow` scenarios also runs `chio-verify` on the output and requires exit 0. Scenario 008 runs in process: the `rust-kernel` driver's fault injection adds a salt-only opening to an auditor assembly, and its `requires` names `rust-kernel` only (Decision 11).
- [ ] **Step 2:** `cs cargo test -p chio-conformance --no-fail-fast` (native cage, see Verification). Expected: the four pass in `rust-kernel`, and 007, 009 and 010 also pass in `rust-mcp-serve-http` once item 7's driver exists; until then, `rust-kernel` only, and the PR body says so. 008 is `rust-kernel` only in both cases.
- [ ] **Step 3: Air-gap run (spec 11.6, recorded).** On ws2, build `chio-verify` once under `cs`, copy the binary, a `caller` bundle, an `auditor_hash_only` bundle, a trust file and caller data into a scratch directory, then `unshare --net --map-root-user ./chio-verify <bundle> --trust trust.json [--caller-data caller.json] --json`. Expected: exit 0 for the caller bundle (decision, delegation chain and content `verified`), exit 0 for the hash-only bundle with `required_columns = ["decision", "delegation_chain"]` and content `unverifiable`. The manual second-person run on a separate machine stays in item 7's live runs.

---

### Task 10: PROTOCOL, CLI docs and claims (6c)

- [ ] **Step 1:** Move the staged "Export profiles" subsection into `spec/PROTOCOL.md` section 6 as staged: it already carries the `enterprise_provider_identity` role, the sentence that the provider's enabled state is not in any bundle, the `tenant_tags` set (#1737; Decision 9) and the `tenant_confirmed` and `principals_confirmed` sentence (Decision 10). Write `docs/cli/evidence.md` (export flags, profiles, refusals) and keep `docs/cli/bundle-verify.md` current.
- [ ] **Step 2:** `docs/reference/CLAIM_REGISTRY.md`: no row is added by this PR. The spec 12 M1 statement enters only with item 7's recorded live run.
- [ ] **Step 3:** `grep -rn $'\xe2\x80\x94' <changed files>; test $? -eq 1`; `grep -n -i -E '\bM[0-3]\b|wedge|pilot|docs/superpowers' spec/PROTOCOL.md docs/cli/*.md crates/tooling/chio-bundle-verify/README.md; test $? -eq 1`; `bash scripts/check-chio-owned-v1-only.sh`; `cs cargo test -p chio-spec-validate --no-fail-fast`.

---

## Verification

Run at each PR head after the final rebase. Every cargo command, direct or nested, runs under `cs` with `CARGO_INCREMENTAL=0` (Global Constraints). Coder checks on ws2; heavy suites on `integ-x86` and `integ-h3`. Logs go to `ws2:~/lanes/claude-pr1160-evidence/m1i6/` with sha256 recorded in the PR body.

**Changed crates.** For every crate in `git diff --name-only origin/main...HEAD -- crates`: `cs cargo test -p <crate> --no-fail-fast` and `cs cargo clippy -p <crate> --all-targets -- -D warnings`. Plus `cs cargo check --locked --workspace --all-targets`, `cs cargo check -p chio-kernel-core --no-default-features`, `cs cargo fmt --all --check`, and the CLAUDE.md one-liner once per PR at the final tip with each step under `cs`: `cs cargo build --workspace && cs cargo test --workspace && cs cargo clippy --workspace -- -D warnings && cs cargo fmt --all -- --check`.

**Native-cage chio-cli and chio-conformance (required for 6a and 6c, which change the CLI; 6b when it changes `chio evidence verify` output).** On host 3 (or x86) with the setup from `ws2:~/lanes/claude-pr1160-evidence/root2/k6/verify-native-final-fa34a7dc65.sh`: node 24 and npm 9.2.0 first on `PATH`; `cs cargo build --locked --target x86_64-unknown-linux-musl -p chio-cage-init --bin chio-cage-init --features real-linux-enforcement` with `CHIO_CAGE_INIT` exported; the privileged `enforced_discovery` test; `scripts/prepare-native-python-runtime.py` and `scripts/prepare-enforced-native-fixture.py` with the fixture env exported; `CHIO_CAGE_SYSCALL_PROFILE=native-standard-v1`; `CHIO_CHECKOUT_ROOT` set; then `cs cargo test --locked --no-fail-fast -p chio-conformance` and `cs cargo test --locked --no-fail-fast -p chio-cli`. Required: rc=0 for both. Environment-only failures are not accepted. The final run is at the `origin/main` commit the PR merges onto and records that SHA.

**Gates.**
```bash
python3 scripts/check-security-clocks.py && python3 scripts/check-escape-hatches.py && python3 scripts/check-negative-assertions.py \
 && python3 scripts/check-trust-boundaries.py && python3 scripts/check-rust-file-hygiene.py && bash scripts/check-http-egress-contract.sh \
 && python3 scripts/check-error-urn-registry.py && cs bash scripts/check-adapter-no-bypass.sh \
 && cs cargo metadata --format-version 1 --locked > /var/tmp/claude-targets/m1i6/metadata.json \
 && python3 scripts/check-offline-verifier-deps.py --metadata /var/tmp/claude-targets/m1i6/metadata.json && python3 scripts/tests/check-offline-verifier-deps.test.py \
 && python3 scripts/check-domain-separation.py
```

**Schema, vector and fixture gates.**
```bash
python3 scripts/check-wire-schemas.py && bash scripts/tests/check-wire-schemas.test.sh
bash scripts/check-chio-schema-registry.sh && bash scripts/check-chio-owned-v1-only.sh
uv run --with jsonschema==4.26.0 --with referencing==0.37.0 python3 -I scripts/check-root-authority-schema-examples.py
cs make -C ~/lanes/m1i6 codegen-check && cs cargo xtask snippets regen --check
cs cargo xtask freeze-vectors --check
cs cargo run -p chio-cli --bin chio -- proof fixture regenerate --check
cs cargo test -p chio-conformance --test vectors_schema_pair --no-fail-fast
```
For 6a, the fixture `--check` runs are the byte-neutrality proof (Review Focus 6): they must pass with no regeneration.

**Dependency and license.** `cs cargo tree -p chio-bundle-verify -e normal --prefix none | sort -u` is attached to the PR body; `cs cargo deny check licenses bans` passes (the cargo-deny job also runs `check-cargo-deny-duplicate-baseline.py`).

**Air gap.** Task 9 Step 3, in the 6c PR body.

**Formal.** `cs cargo xtask check formal-mirrors` (expected: no drift; this item adds no Kani harness and changes no `.lean` file, so no Kani or Lean runs anywhere and none on ws2). `cs cargo xtask gen proof-coverage --check` last; if it fails after the final rebase, regenerate and commit `docs/formal/COVERAGE.md` as the last commit.

Pre-existing reds on `main` are reported with `main`'s result at the same base.

## Size

Spec 13.2 sizes item 6 at M, 7-11 engineer-days, including the provider identity role (+0 to +1 from G17). Estimate from the census:

| Part | Days |
|---|---|
| Evidence model move out of `chio-kernel`, byte-neutral (Task 2) | 2-3 |
| Crate, trust file type, dependency gate, clock root (Task 3) | 1 |
| Exit classes, error codes, report schema, CLI doc (Task 4) | 1 |
| Port today's verification, delete `verification.rs`, move verify, import, mercury and smoke callers to `--trust` (Task 5) | 1-2 |
| Identity root and delegation chain columns with the provider identity role (Task 6) | 2-3 |
| Content column, openings, caller data, bundle vectors (Task 7) | 1-2 |
| Export profiles, roles, admin route, CLI, manifest schema move-in; reads of the item 4 retention; tag-set selection and its verifier check (Task 8) | 2.5 |
| Scenarios 007 to 010, air-gap run, PROTOCOL and docs (Tasks 9, 10) | 1 |
| Integration, native-cage runs, review rounds across three PRs | 1-2 |
| Total | 12.5-17.5 |

Item 6 is L, 12.5-17.5 engineer-days (the range straddles 15, so it takes the larger label), against 13.2's M, 7-11. Historical policy and provider identity retention is item 4's work and is not counted here, and so are the store read methods Task 8 calls (items 2, 4 and 5 own them); Task 8 adds the `ExportStores` mapping and no trait, so its 2.5 days are unchanged. The excess of 5.5 to 6.5 days has four sources 13.2 did not count: moving the evidence model out of the hosted kernel so the verifier can avoid `tokio` and `rusqlite` (2-3), replacing every verify and import caller of the control-plane verifier, including trust-control and `chio-mercury` (about 1), splitting the item into three PRs around items 1 to 5 (about 1), and rotation-safe caller selection (0.5). Dropping `auditor_hash_only` (spec 13.4, founder approval) would save about 1 day. This estimate is part of the M1 total of 152-218 engineer-days, which counts every merged M1 item plan, including item 2's 66-93.

## Decisions

Decisions 1 to 9 are the lead's, accepted on 2026-10-20 (approval of #1719), with decision 3 amended so that item 4 provides the retention. The signer in decision 7 and decisions 10 and 11 are owner decisions. Each entry states the question and the decision this plan implements.

1. **Identity root ceiling in M1 (Task 6).** Spec 11.4 lists `verified` conditions that include the M2 retained ID-JAG, and spec 9.6 says the column is `asserted` without a retained artifact. With retention cut to M2, no M1 bundle can make the identity root column `verified`, so a trust file that requires it always exits 10. Decision: the column is `asserted` at best in M1; `docs/cli/bundle-verify.md` and the example trust file require `decision`, `delegation_chain` and `content` only; `verified` becomes reachable with M2 retention and pinned `idp_keys`. Rejected alternative: let `required_columns` name a minimum class per column (a change to the M0 `chio.verifier-trust.v1` schema).
2. **Tenant selection input (Task 8).** Spec 10.8 names `chio evidence export --disclosure-profile --tenant`, but `--tenant` already filters on the plaintext receipt `tenant_id`, which a receipt with `authority` omits. Decision: `--tenant-issuer` and `--tenant-value` select a `caller` bundle by the tenant's tag set, computed inside `serve-http`; the existing `--tenant` stays the plaintext filter for receipts without `authority` and is refused together with `caller`.
3. **Retained root policies, provider identity projections and receipt tenant tags (Task 8, depends on item 4).** A bundle must carry every policy and every projection its roots reference (spec 7.4, 7.12), but `serve-http` loads one policy and reads the live registry, and spec 10.7 lists no table for past policies or projections. Selecting a tenant's receipts also needs a tenant tag beside each receipt row. Decision: item 4 provides historical root policy and provider identity record retention, stored by digest alongside `anchored_roots` and `idp_key_snapshots`, and the receipt append writes the tenant tag, with its `tag_key_id`, from the root row. 6c only reads them and adds no table.
4. **Revocation coverage offline (Task 6).** A verifier cannot recompute a subject or tenant tag (it has no index key), so it cannot match `anchor_subject` and `tenant_tag` entries to roots on its own. Decision: each exported entry carries the item 5 entry plus an unsigned `covered_capability_ids` list computed at export; the verifier recomputes coverage itself for `capability_id`, `root_policy_rule` and `replay_key` targets and requires the exporter's list to agree, and reports tag-target coverage as provider-asserted. A covering entry counts only when its `revoked_at` is at or before the receipt timestamp.
5. **Checkpoint anchor binding in the trust file (Task 5).** Today `chio evidence verify --trusted-anchor-file` supplies a `CheckpointPublicationTrustAnchorBinding` that `chio.verifier-trust.v1` has no member for. Decision: add an optional `checkpoint_trust_anchor` member to `chio.verifier-trust.v1` in place (unshipped, v1), so one verifier-owned file carries all trust; no second trust flag.
6. **Trust-file key minimums for bundles without roots (Task 3).** The M0 schema requires at least one exchange key and one root policy key, but bundles from producers without a root policy (`chio run`, `chio mcp serve`, `api protect` before M3) contain no roots. Decision: keep `kernel_keys` at 1 to 64 and allow 0 to 64 for `exchange_keys` and `root_policy_keys`; a bundle with anchored receipts and an empty role exits 50 with `attest:bundle-trust-missing`. This changes the staged invalid example `verifier-trust.empty-kernel-keys` description only.
7. **Where export runs (Task 8).** The state directory is held under an exclusive lock by the running `serve-http` (D4), and the index key never leaves that process (spec 7.12). Decision: export runs inside `serve-http` behind `POST /admin/evidence/export`, and `serve-http` builds the package and signs its `chio.evidence_export_commitment.v1` envelope through its kernel signing backend, so the process that selected the tenant's receipts is the process that signs them. The route returns the signed package; the CLI verifies it with the trusted verify (`verify_bundle` and the exit class) against the operator's `--trust` file, never against a key from the response, and writes it to `--output` only when that passes. `chio evidence export --edge-url` takes no `--kernel-seed-file`, no kernel seed lives on an operator host, and no artifact type is added. Rejected alternatives: an offline `chio evidence export --state-dir` that takes the lock itself and therefore needs the edge stopped; the CLI signing an unsigned bundle from the route with a local seed, either after authenticating the response under a second pinned edge key (a new signed artifact and key role) or with only TLS and admin authentication protecting it (a kernel signature over bytes the signer cannot check for tenant scope).
8. **New unsigned schema ids (Tasks 4, 7).** The report and the caller-data input need wire shapes the spec does not name. Decision: `chio.bundle-verify-report.v1` and `chio.verifier-caller-data.v1` under `spec/schemas/chio-wire/v1/export/`, unsigned, so neither enters `KNOWN_SIGNED_ARTIFACT_SCHEMAS`.
9. **Caller selection spans every loaded tag generation (Task 8).** The tenant index key set rotates and item 4 stores one tenant tag with its `key_id` per receipt, so a single tag selects only the receipts of one generation, and an export after a rotation would omit the older ones while still verifying. Decision: selection uses the tenant's tag set, `derive_in(&key_id, IndexDomain::TenantTag, issuer || 0x00 || value)` over `key_ids()`; the store query matches `(tag_key_id, tag)` against that set; the manifest carries `tenant_tags: Vec<KeyedIndexValue>` sorted by `key_id`; the bundle carries each receipt's stored tag, and the offline verifier checks every one is in the manifest set. Cost: about 0.5 day in Task 8. Rejected alternative: select by the active generation only, which silently drops earlier receipts.
10. **Which commitments confirm the tenant (Task 7).** Spec 7.12 says a tenant confirms a bundle "by opening the subject and tenant commitments with the included salts". Decision: `chio.bundle-verify-report.v1` carries `tenant_confirmed` and `principals_confirmed`, and neither is ever vacuously true. Each is true only when the commitments covering the exported receipts form a nonempty set that covers every exported receipt, and every one of them opens: tenant commitments with `CallerData.tenant`, subject commitments against a supplied `CallerData` principal. An empty bundle, an unanchored receipt, a missing context or opening, or missing caller data leaves the member false without an integrity finding. Neither changes the exit class. Spec 7.12 and the staged "Export profiles" sentence name both members. Rejected alternatives: one `tenant_confirmed` that also requires every subject to open, which a caller that lists only some principals never reaches; tenant commitments alone, which drops the subject half of the spec sentence.
11. **How an auditor export refuses an opening (Tasks 8, 9).** Spec 8.4 refuses salt-only openings in auditor profiles. Decision: the export request has no member that asks for an opening; `assemble_export` refuses an auditor assembly that would carry any salt with `export-salt-only-opening` before anything is built, signed or returned. Scenario 008 reaches the guard through in-process fault injection in the `rust-kernel` driver, and its `requires` names `rust-kernel` only. Rejected alternative: a required `openings: "none" | "salt_only"` request member whose only valid value is implied by the profile.

## Spec coverage

| Spec requirement | Task |
|---|---|
| 10.9 crate, Apache-2.0, deps, no clock, clock gate root | 2, 3 |
| 7.12 `chio.verifier-trust.v1` | 3 |
| 11.4 column classes and `required_columns` exit | 4, 6, 7 |
| 7.12 manifest members, roles (including `enterprise_provider_identity`), kernel-signed commitment | 8 |
| D8 tenant scope, tags, caller salts only | 8 |
| 8.4 export refusals | 8 |
| 7.7, G13, G14, G15 openings and preimages | 7 |
| G17, 9.8 provider identity role and offline digest | 6, 8 |
| G18, G19 strict decoding and pinned-key algorithm | 3, 6, 7 |
| 10.7 delete `verification.rs` and the verify half | 5 |
| 10.8 `chio evidence verify` delegates, `chio evidence export --disclosure-profile` | 5, 8 |
| 11.1 tenant export unit tests | 8 |
| 11.3 `receipt_disclosure` 007 to 010 | 9 |
| 11.5 clock gate and repository gates | 3, Verification |
| 11.6 offline run of `caller` and `auditor_hash_only` bundles | 9 (scripted), item 7 (second person) |
| 13.1 cuts 3 to 7 refused or exit 50 | 4, 6, 8 |
| 13.3 step 6 order | Parts and Landing Order |
