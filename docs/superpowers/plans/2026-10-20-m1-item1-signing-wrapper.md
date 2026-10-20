# Relying-Party Wedge M1 Item 1 Implementation Plan: the Signing Wrapper

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land M1 item 1 of the relying-party wedge as one squash-merged PR: every signature over Chio-defined bytes signs the 88-byte signing wrapper, algorithm selection comes only from the pinned typed key, every wrapper id is registered with a schema, the unsigned `algorithm` members are gone, generic SDK signing takes a schema id, and every signed fixture is regenerated.

**Architecture:** `chio-core-types` gains one wrapper constructor, one signing helper (`SigningBackend::sign_wrapped`) and one verification helper (`verify_wrapped`). Raw signing becomes unreachable outside the closed exempt set through a `SigningMessage` type that only the wrapper or a named `ExemptFormat` can produce. Every artifact type keeps its own `sign` / `verify_signature` method names; only their bodies change. Registration lands in the same PR as the code that signs under each id (spec 2.5 G11). The PR tip is the verified unit; intermediate commits need not build.

**Tech Stack:** Rust workspace (every cargo command through `cs`, defined under Global Constraints), JSON Schema draft 2020-12, `cargo xtask codegen` (Rust, TS, Go, Python), `cargo xtask freeze-vectors`, Python reference generator `scripts/gen-signing-wrapper-vectors.py` (`cryptography==44.0.3`), Go, TypeScript (npm), Python (uv), C++ (CMake through `scripts/check-chio-cpp.sh`).

**Spec:** `docs/superpowers/specs/2026-10-17-relying-party-wedge-design.md`, sections 2.2 (D6, D16, D17), 2.5 (G2, G5, G6/G8, G7, G9, G10, G11, G16, G18, G19), 7.0, 10.1, 10.10, 11, 13.2, 13.3. Inputs from M0: `docs/superpowers/plans/2026-10-17-relying-party-wedge-m0.md`, `docs/superpowers/specs/relying-party-wedge/receipt-producer-inventory.md` (sections "Wrapper schema ids" and "Signing sites outside the named helpers"), `docs/superpowers/specs/relying-party-wedge/protocol/protocol-4.5-signing-wrapper.md`, `docs/adr/ADR-0039-customer-hosted-root-exchange.md`, `tests/bindings/vectors/signing/wrapper/v1.json`, `scripts/gen-signing-wrapper-vectors.py`.

**Census base:** facts below were measured at `origin/main` `59393b862c`. Task 1 re-runs every census at the actual integrated base, the `origin/main` commit that contains every predecessor in the merge order, and updates the counts in the PR body. Counts from any earlier base are planning figures only.

## Global Constraints

Quoted verbatim from the spec.

The wrapper layout and its domain tag (spec 7.0):

```text
wrapper = "chio.signing-wrapper.v1" || 0x00          (24 bytes)
       || SHA-256(utf8(schema_id))                     (32 bytes)
       || SHA-256(canonical_body)                      (32 bytes)
```

The closed exempt set (spec 7.0):

> Exempt formats (closed list, G2): JWS signing inputs (RFC 7515, including local AS tokens, JWTs and SD-JWT), DSSE pre-authentication encoding, Sigstore Rekor entries and HTTP message signatures (RFC 9421). Their signing bytes are fixed by the external standard and they do not use the wrapper. Every other signing site does.

The G19 algorithm rule (spec 2.5):

> A verifier derives the signature algorithm only from the pinned, typed key it verifies against, never from any member of the artifact. The unsigned top-level `algorithm` member (`CapabilityToken.algorithm` and `ChioReceipt.algorithm`, plus the same optional member on the other `chio-core-types` and `chio-credit` envelopes) is deleted in M1 item 1, the wrapper PR, with every caller. After it, an `algorithm` member, added or altered, fails strict decoding (G18) before any verifier is chosen, and no member can change which verifier runs.

Further constraints:

- Owner decisions (2026-10-20, lead approval on #1703):
  - G19 scope: every unsigned signature `algorithm` member is deleted, in every crate. Only key-record attributes (`KeyLogEventBody.algorithm`, `KeyRecord.algorithm`) stay; they describe a registered key and never select a verifier.
  - Registration: a payload id is registered only when a non-test path signs that payload through the wrapper. Export payload ids that no non-test path signs are deferred and listed in Task 6.
  - Raw-site ids: `chio.finding.operator-purchase-job.v1`, `chio.wasm-module.v1` and `chio.tee-capture-frame.v1`.
  - The revocation epoch root signs under `chio.trust.passport-revocation-root.v1`, registered by #1607. `chio.epoch-root.v1` does not exist.
  - Receipt `deny_unknown_fields` lands through the lead's fwdcompat receipt change, before this PR.
  - Runtime-attestation evidence ids live in a closed vendor list in `chio-appraisal`; an id outside it fails closed.
  - Fixtures: fwdcompat's receipt fixture regeneration lands first. This PR regenerates every signed fixture once, on top of it, with one generator command (`cs cargo xtask gen signed-fixtures`) that only runs each fixture set's owning generator. No signed fixture is edited by hand, patched by a script or rewritten by any tool other than its owning generator.
  - Receipt decoding (Q5): fwdcompat's strict receipt decoding lands first, and routing metadata travels outside the signed receipt bytes. This PR builds on that order only. A change to it changes fixture and merge qualification scope and requires a new heads-up to Root-2 on `sync.md` before work continues.
- Merge order (precondition): Root-2's kernel order is T7 #1675, C6 #1682, native-ledger #1678, stop-error #1701, D5 #1269, then KERN-TRACE-LOCK-FSYNC, each subject to its complete qualification and the main merge windows. Those six, #1674, #1601, #1607 and the fwdcompat receipt change all merge before this PR. Anchored-root capability changes (M1 item 3) merge after this PR. Root-2's order is not an approval of any candidate head or its merge readiness.
- Preconditions (D16, D17): every PR in the merge order above is merged, starting with #1674 (the `SigningBackend` collapse). The D17 coordination below is acknowledged by the lead and Root-2 on `ws2:~/lanes/claude-pr1160-evidence/lead2/sync.md` before the PR opens. #1489 is merged (2026-10-19T03:03Z); `chio.dpop_proof.v2` is already absent from `spec/schemas/registry.json`.
- One PR, squash-merged. Commits follow the groups in "Commit Grouping". Intermediate commits need not build; the PR tip is verified.
- Algorithms (spec 7.0): Ed25519 signs the 88 wrapper bytes. ML-DSA-65 signs the 88 wrapper bytes with an empty FIPS 204 context. P-256 is ECDSA with SHA-256 over the wrapper, P-384 ECDSA with SHA-384. Hybrid signs the same 88 bytes with both halves. Signature encodings are unchanged.
- Schema id from verification context only (spec 7.0): the verifier passes the id of the type it expects at the call site. No verifier reads `schema_id` from the artifact.
- Signature prefixes are dropped (G5): after a NUL-terminated byte prefix the body is the canonical JSON that followed it; for a `{domain, body}` object it is `body`; for a `(DOMAIN, signer, body)` tuple it is `{"body": body, "signer": signer}`. A signature over a digest of a Chio object signs the wrapper over the object's canonical body. Hash, id, key-id, envelope-hash and commitment domains are unchanged.
- One id per signed artifact (G6, G8). Where an artifact carries a `schema` member it equals its wrapper id. The four `SignedKeyLogEvent` authorization roles keep `chio.key-log.event.v1`.
- Every wrapper id is in `spec/schemas/registry.json` and `KNOWN_SIGNED_ARTIFACT_SCHEMAS` before the wrapper signs or verifies it (G11). Both helpers refuse any other id with a typed error.
- No legacy, compat or dual paths; everything is v1. No deprecated alias, no "old signature" fallback, no second verifier, no feature flag that restores body signing.
- Fail-closed: an unregistered id, an unreadable identity, an algorithm mismatch or a decode error denies. `verify_wrapped` returns `Result<()>`, never `Ok(false)`.
- Strict decoding (G18) for the envelopes this PR touches: an `algorithm` member, added or altered, fails decoding. New tagged enums use `chio_security_types::strict_serde` (`lossless_serde!`). No `#[serde(flatten)]` in any type this PR changes.
- Clock reads only through the approved seams; fixtures use fixed timestamps. Run `python3 scripts/check-security-clocks.py`.
- Clippy denies `unwrap_used` and `expect_used` outside tests. Format with `cs cargo fmt --all`.
- No em dashes (U+2014) in any file. No narrative or meta comments; comments state invariants and contracts.
- Public-path rule: files under `spec/`, `docs/adr/`, `tests/`, `scripts/`, `crates/`, `sdks/` never mention milestones, the wedge, pilots or `docs/superpowers`.
- Build slots: on ws2, `cs` means `CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/var/tmp/claude-targets/m1i1 ~/lanes/cslot.sh`; on the x86 runner and host 3 it means `CARGO_INCREMENTAL=0 ~/cslot.sh` with that host's lane target dir. Every cargo command runs under `cs`: `cargo build`, `test`, `check`, `clippy`, `fmt`, `run` and `xtask`, and every script, Makefile target, generator, freeze or fixture command and SDK manifest build that reaches cargo directly or nested (`make codegen-check`, `scripts/check-bindings-parity.sh`, `scripts/check-chio-cpp.sh`, `scripts/check-sdk-parity.sh`, `scripts/check-adapter-no-bypass.sh`, `scripts/check-security-ci-contract.py`, `scripts/check-aws-lc-fork.py`, every `--manifest-path` build). No command in this plan invokes cargo outside `cs`.
- Formal tools: no Lean, lake, Aeneas or Kani runs on ws2, including single harnesses. Kani runs only on the approved x86 runner under `cs`.
- Work happens on ws2 in worktree `~/lanes/m1i1` off fresh `origin/main` (fetched over https). Coder checks run under `cs`; heavy suites run on the integrators (`integ-x86`, `integ-h3`) per the 10-20 coder/integrator split. Never `git stash`. Inspect `git diff --cached --stat -M` before every commit. Push explicit SHAs over https.
- Shared surfaces: before requesting merge, post `<UTC> <lane>: REVIEW? #<N> M1 item 1 signing wrapper (core-types, kernel, store, CP, every signed fixture)` to `sync.md`, then `MERGING #<N>` with the 10-minute window and the OBJECT check.

## Review Focus

1. **A signing path that still reaches raw bytes.** Expected: outside `chio-core-types`, every `SigningBackend::sign_bytes*` call and every `Keypair` signature takes a `SigningMessage`, and the only public `SigningMessage` constructor besides the wrapper is `SigningMessage::exempt(ExemptFormat, &[u8])`, called only from the exempt sites in the Task 8 table, each the allowed number of times. A remote or rotating backend forwards the typed `SigningMessage` and never a raw byte string. Pinned in Task 2 by the type change, in Task 7 by the pinned signing routes and in Task 8 by `check-signing-exemptions.py` (observed exempt call sites, with multiplicity, equal the allowlist).
2. **A verifier that picks its algorithm, schema id or key from the artifact.** Expected: `verify_wrapped` takes `&PublicKey` from the caller's pinned trust and `&str` schema id from the call site; the receipt crypto floor reads `pinned.algorithm()`; no `algorithm` member survives on a signature envelope. Pinned by the G19 vectors (Task 10) and `verifier_choice_ignores_algorithm_member` (Task 4).
3. **A regenerated fixture that changed more than its signature.** Expected: for every regenerated file, the only changed values are signatures, removed `algorithm` members, the replaced G6 `schema` members, and derived ids and digests that each trace to the producer whose input bytes changed. Pinned in Task 11 by the fixture diff aid run over the regeneration commit, and by `wrapper/v1.json` keeping every existing case byte-identical.
4. **An id registered with a schema that does not validate the live serialization.** Expected: every new registry row's schema validates the artifact the Rust type emits. Pinned by `signed_artifact_registration.rs` (Task 6), which serializes one fixture instance per newly registered id and validates it against its `schemaFile`.
5. **`#[cfg(kani)]`, `fips` and `pq` code that the default check never compiles** still calling the deleted helpers. Expected: updated by hand. Pinned by `cs cargo check --workspace --all-targets --all-features`, `cs cargo test -p chio-core-types --features fips,pq`, `check-kani-public-harnesses.py` and the x86 Kani run in Verification.
6. **SDK verifiers accepting what Rust rejects.** Expected: TS, Python, Go, C++ (FFI), the k8s webhook and chio-bedrock reject an `algorithm` member, an unregistered schema id and an algorithm-prefix mismatch, and pass every case in `signing/wrapper/v1.json`. Pinned by the SDK vector runners in Task 9.

---

## File Structure

| Path | Task | Responsibility |
|---|---|---|
| `crates/core/chio-core-types/src/crypto/wrapper.rs` (new) | 2 | `SigningWrapper`, `SigningMessage`, `ExemptFormat`, wrapper constants |
| `crates/core/chio-core-types/src/crypto.rs` | 2, 3, 4 | trait `sign_wrapped*`, free functions, `verify_wrapped*`, deleted helpers, `algorithm`-free docs |
| `crates/core/chio-core-types/src/signed_artifact.rs` | 6 | `SignedArtifactSchemaSpec` without `Option`, every wrapper id, `registered_wrapper_schema` |
| `crates/core/chio-core-types/src/receipt/{body,crypto_floor,lineage,metadata}.rs`, `capability/{token,governance,aggregate_invocation,cumulative_approval,attenuation}.rs`, `recovery/*`, `security_event.rs`, `declassification.rs`, `session/anchor.rs`, `economic_continuity*.rs` | 4, 5, 7 | artifact signers and verifiers on the wrapper; `algorithm` members deleted |
| `crates/core/chio-core-types/src/manifest.rs` | 5 | `ToolManifest`, `ToolManifestBody`, `ToolManifest::sign` deleted (G9) |
| `crates/core/chio-core-types/tests/{signing_wrapper_vectors,signing_wrapper_negatives,signed_artifact_registration}.rs` (new) | 3, 4, 6, 10 | vector cross-check, G19 and exempt negatives, registration parity |
| `crates/sdk/chio-binding-helpers/src/signing.rs`, `crates/sdk/chio-bindings-ffi/{src/lib.rs,include/chio/chio_ffi.h}`, `tests/abi/chio-bindings-ffi.symbols` | 9 | wrapped signer and verifier `(schema_id, json, seed)`; raw UTF-8 signer deleted |
| `sdks/cpp/chio-cpp/{include/chio/invariants.hpp,src/invariants.cpp,src/dpop.cpp,tests/sdk_tests.cpp}` | 9 | C++ wrappers, DPoP on the wrapper |
| `sdks/python/chio-py/src/chio/invariants/{signing,capability,receipt,__init__}.py`, `sdks/python/packages/chio-bedrock/src/chio_bedrock/receipt.py` | 9 | Python wrapper signer and verifiers |
| `sdks/typescript/chio-ts/src/invariants/{signing,crypto,capability,receipt,index}.ts`, `sdks/typescript/chio-ts/src/dpop.ts` | 9 | TS wrapper signer, verifiers, DPoP |
| `sdks/go/chio-go/invariants/{signing,capability,receipt}.go`, `sdks/k8s/webhooks/capability.go` | 9 | Go wrapper verifier; raw UTF-8 helpers deleted |
| `xtask/src/codegen/` (signed-id emitter) and generated `signed_artifact_schemas` files in TS, Python, Go | 6, 9 | SDK copy of `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, `--check` mode |
| about 60 crates holding the wrapper-table and raw-site rows | 7, 8 | call-site migration |
| `spec/schemas/registry.json`, `spec/schemas/MANIFEST.sha256`, new schema files under `spec/schemas/chio-wire/v1/**`, `spec/wire-schemas.lock`, generated code in four languages | 6 | registration of every wrapper id and every `SignedExportEnvelope` payload id |
| 52 schema files carrying a signature `algorithm` member | 5 | member deleted (G19) |
| `scripts/gen-signing-wrapper-vectors.py`, `tests/bindings/vectors/signing/wrapper/v1.json`, `tests/bindings/vectors/signing/wrapper/pq-v1.json` (new), `tests/bindings/vectors/signing/v1.json`, `tests/bindings/vectors/MANIFEST.sha256` | 9, 10 | vectors |
| `scripts/check-signing-exemptions.py` (new), `scripts/check-domain-separation.py`, `.github/workflows/ci.yml` (one line, pushed by the lead from the Mac) | 8 | exempt-site gate; signature-domain constants out of the domain gate's scope |
| `xtask/src/cli.rs` and a new `xtask/src/signed_fixtures.rs` | 11 | `cargo xtask gen signed-fixtures [--check]`, the one regeneration command |
| every signed fixture in Task 11 | 11 | regenerated |
| `spec/PROTOCOL.md` (4.1, new 4.5), `docs/superpowers/specs/relying-party-wedge/protocol/protocol-4.5-signing-wrapper.md` (deleted on move), `docs/superpowers/specs/relying-party-wedge/in-place-schemas/{capability/token,receipt/record}.schema.json`, `spec/ietf/generated/appendix-b.md` and the draft renderings | 12 | contract text |
| `docs/formal/COVERAGE.md`, `formal/rust-verification/kani-public-harnesses.toml`, `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs` | 13 | formal touchpoints |

## Commit Grouping

One branch `feat/m1-signing-wrapper`, one PR `feat(core-types): sign every Chio artifact through the signing wrapper`, squash-merged. Commits in this order (conventional messages, trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`):

| # | Commit | Tasks |
|---|---|---|
| 1 | `feat(core-types): add the signing wrapper and route core artifacts through it` | 2, 3, 4, 5 (core-types part) |
| 2 | `feat(schemas): register every wrapper and signed export payload id` | 6 |
| 3 | `refactor(kernel): sign kernel artifacts through the signing wrapper` (kernel, kernel-core, browser, mobile, cpp-kernel-ffi, process, swarm-authority) | 7 |
| 4 | `refactor(security): sign security artifacts through the signing wrapper` (keyring, secret-broker, decoy, cage, G6 members) | 7 |
| 5 | `refactor(platform): sign platform artifacts through the signing wrapper` (control-plane, store-sqlite, http-core, workflow, manifest, transaction-passport) | 7 |
| 6 | `refactor: sign economy, trust, protocol, product and tooling artifacts through the signing wrapper` | 7 |
| 7 | `refactor: resolve every raw signing site to a wrapper id or a named exemption` | 8 |
| 8 | `feat(sdk): sign and verify through the wrapper with a registered schema id` | 9 |
| 9 | `test(vectors): cross-check the reference wrapper vectors and add algorithm negatives` | 10 |
| 10 | `test: regenerate signed fixtures for the signing wrapper` | 11 |
| 11 | `docs(spec): specify the signing wrapper in PROTOCOL 4.5` | 12 |
| 12 | `chore(formal): refresh proof coverage` | 13 (last, after the final rebase) |

A diff touching `.github/workflows/` is handed to the lead to push from the Mac (ws2 has no workflow scope).

---

### Task 1: Base, census and coordination

**Files:** none changed. Output goes to `ws2:~/lanes/claude-pr1160-evidence/m1i1/census-<base>.md`.

- [ ] **Step 1: Preconditions.** `gh pr view <N> --repo bb-connor/arc --json state` reports `MERGED` for #1674, #1601, #1607, #1723, #1706, #1709, the fwdcompat receipt change, #1675, #1682, #1678, #1701 and #1269, and KERN-TRACE-LOCK-FSYNC is merged. If any is open, the lane waits; it does not reorder. Create the worktree at that integrated base: `git -C /home/connor/backbay/arc fetch -q https://github.com/bb-connor/arc.git main:refs/remotes/origin/main && git -C /home/connor/backbay/arc worktree add -b feat/m1-signing-wrapper ~/lanes/m1i1 origin/main`.
- [ ] **Step 2: Re-run the inventory greps at the integrated base** from the inventory's Method section plus:
```bash
git grep -n -E "\.sign\(|\.sign_bytes(_with_identity|_for_identity)?\(|sign_canonical|sign_shared_canonical|verify_canonical|verify_shared_canonical|\.verify(_strict)?\(" -- crates sdks/lambda ':!**/tests/**' ':!*_tests.rs' ':!**/tests.rs' ':!**/benches/**'
git grep -n -E "algorithm: (Option<)?SigningAlgorithm" -- crates
grep -rl '"algorithm"' spec/schemas
git grep -h -o -E "SignedExportEnvelope<[A-Za-z0-9_]+>" -- crates ':!**/tests/**' | sort -u
```
  Expected at `59393b862c`: 143 canonical-signing, 83 `sign_bytes*`, about 102 raw `Keypair::sign`, 117 canonical-verify and about 118 raw-verify non-test call sites; 74 `algorithm: SigningAlgorithm` fields; 52 schema files with an `algorithm` property; 165 distinct `SignedExportEnvelope` payload types. Record each row of the inventory tables with its current `file:line`, and record every exempt caller in the Task 8 table that signs through a remote or rotating backend (input to the Task 7 route table).
  The census includes the two root-authority verification sites that #1706 adds before this PR: `RootPolicy` load in `crates/core/chio-core-types/src/root_authority/root_policy.rs` (`load`) and `IdpKeySnapshot::verify_signature` in `root_authority/idp_key_snapshot.rs`. Both move to `verify_wrapped` with `CHIO_ROOT_POLICY_SCHEMA` and `CHIO_IDP_KEY_SNAPSHOT_SCHEMA`, against the pinned key the caller passes.
  The census also includes the verify sites that #1709 (ID-JAG root exchange) adds before this PR and one verify site that predates it. All are Ed25519 `verify_strict` calls over a JWS signing input and become `verify_exempt(.., ExemptFormat::JwsSigningInput, ..)`: `VerifyingKey::verify` in `crates/protocol/chio-mcp-remote/src/remote_mcp/root_exchange/jws.rs` (the `KeyMaterial::Ed25519` / `JwsAlgorithm::EdDSA` arm, lines 226-227 at #1709 head `79b3ef905c`) and `verify_ed25519_jwt_signature` in `remote_mcp/session_identity.rs` (line 56, called from `oauth/jwt_support.rs` and `oauth/local_server.rs`). The `.verify(_strict)?(` grep also matches `jws.rs:223`, `:225`, `:251` and `:262`, the `p256`, `p384` and `rsa` crate verifiers over JWS input. They are outside the Chio signing API and out of scope: classify them in the census as external-crate JWS verify and do not convert them. Line numbers are re-anchored at the integrated base.
- [ ] **Step 3: D17 check.** Post the "D17 Coordination" list below to `sync.md` as `<UTC> <lane>: D17 m1i1 byte changes: <list>; holding PR open until lead and Root-2 ACK`. Record the merge SHA of every predecessor in the merge order; the PR is based on the commit that contains all of them.

---

### Task 2: Wrapper types and the collapsed trait (commit 1)

**Files:**
- Create: `crates/core/chio-core-types/src/crypto/wrapper.rs`
- Modify: `crates/core/chio-core-types/src/crypto.rs` (trait, `Keypair`, `Ed25519Backend`, `fips_backends`, `#[cfg(kani)]` blocks), `src/lib.rs` (exports)

**Interfaces (produced; every later task consumes them):**

```rust
// crypto/wrapper.rs
pub const SIGNING_WRAPPER_PREFIX: &[u8; 24] = b"chio.signing-wrapper.v1\0";
pub const SIGNING_WRAPPER_LEN: usize = 88;

/// The 88 bytes every Chio signature covers.
pub struct SigningWrapper([u8; SIGNING_WRAPPER_LEN]);
impl SigningWrapper {
    /// Refuses `schema_id` unless `registered_wrapper_schema(schema_id)` holds.
    pub fn new(schema_id: &str, canonical_body: &CanonicalBytes<CanonicalJsonWitness>) -> Result<Self>;
    pub fn as_bytes(&self) -> &[u8; SIGNING_WRAPPER_LEN];
}

/// External formats whose signing bytes a standard fixes (spec 7.0, closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExemptFormat { JwsSigningInput, DssePae, RekorEntry, HttpMessageSignature }

/// The only input a signer accepts.
pub struct SigningMessage<'a>(SigningMessageInner<'a>);
enum SigningMessageInner<'a> { Wrapper(&'a SigningWrapper), Exempt(ExemptFormat, &'a [u8]) }
impl<'a> SigningMessage<'a> {
    pub fn exempt(format: ExemptFormat, bytes: &'a [u8]) -> Self;
    pub(crate) fn wrapper(wrapper: &'a SigningWrapper) -> Self;
    pub fn as_bytes(&self) -> &[u8];
}
```

```rust
// crypto.rs, on the collapsed trait from #1674
pub trait SigningBackend: Send + Sync {
    fn public_key(&self) -> Result<PublicKey>;
    fn sign_bytes(&self, message: SigningMessage<'_>) -> Result<Signature>;
    fn sign_bytes_with_identity(&self, message: SigningMessage<'_>) -> Result<SigningOutcome>; // default, as #1674
    fn sign_bytes_for_identity(&self, expected: &PublicKey, message: SigningMessage<'_>) -> Result<SigningOutcome>; // default
    /// Builds the wrapper and signs it; refuses an unregistered id before any signing.
    fn sign_wrapped(&self, schema_id: &str, canonical: &CanonicalBytes<CanonicalJsonWitness>) -> Result<SigningOutcome>; // default
    fn sign_wrapped_for_identity(&self, expected: &PublicKey, schema_id: &str, canonical: &CanonicalBytes<CanonicalJsonWitness>) -> Result<SigningOutcome>; // default
}

impl Keypair {
    pub fn sign_wrapped(&self, schema_id: &str, canonical: &CanonicalBytes<CanonicalJsonWitness>) -> Result<Signature>;
    pub fn sign_exempt(&self, format: ExemptFormat, bytes: &[u8]) -> Signature;
    pub(crate) fn sign(&self, message: SigningMessage<'_>) -> Signature;
}
```

Deleted in the same commit: `SigningBackend::sign_canonical_bytes` and its overrides (`chio-kernel` `signing_authority.rs`, `chio-control-plane` `keyring_runtime.rs`, the forwarding test double), public `Keypair::sign(&[u8])`, `Keypair::sign_canonical`, `Keypair::sign_canonical_shared`, `Keypair::sign_shared_canonical`. Rotating backends (`chio-keyring` router, `KeyringAuthoritySigningBackend`, `SharedSigningBackend`, `MigrationGuardedSigningBackend`) override `sign_bytes_with_identity` and `sign_bytes_for_identity` as today and inherit `sign_wrapped*`, so the wrapper is built once outside the selector lease and signed inside it.

- [ ] **Step 1: Write the failing tests** in `crates/core/chio-core-types/tests/signing_wrapper_negatives.rs`:
```rust
#![allow(clippy::expect_used, clippy::unwrap_used)]
#[test]
fn wrapper_is_88_bytes_with_nul_at_23() {
    let body = CanonicalBytes::from_serializable(&serde_json::json!({"a":1})).unwrap();
    let w = SigningWrapper::new("chio.receipt.v1", &body).unwrap();
    assert_eq!(w.as_bytes().len(), 88);
    assert_eq!(&w.as_bytes()[..24], SIGNING_WRAPPER_PREFIX);
    assert_eq!(w.as_bytes()[23], 0);
}
#[test]
fn unregistered_schema_id_refuses_before_signing() {
    let backend = CountingBackend::new(Keypair::from_seed(&[1; 32]));
    let body = CanonicalBytes::from_serializable(&serde_json::json!({"a":1})).unwrap();
    assert!(matches!(backend.sign_wrapped("chio.unregistered-fixture.v1", &body), Err(Error::UnregisteredSchemaId(_))));
    assert_eq!(backend.sign_calls(), 0);
}
#[test]
fn unreadable_identity_refuses_wrapped_signing() { /* #1674 UnreadableIdentity double; sign_wrapped errs; no sign_bytes call */ }
```
- [ ] **Step 2: Run and confirm failure.** `cs cargo test -p chio-core-types --test signing_wrapper_negatives`. Expected: compile error (types missing).
- [ ] **Step 3: Implement** `wrapper.rs`, the trait methods and the `Keypair` methods. `SigningWrapper::new` hashes with the crate's existing SHA-256. P-256 and P-384 backends pass the 88 bytes to `ECDSA_P256_SHA256_ASN1_SIGNING` and `ECDSA_P384_SHA384_ASN1_SIGNING` unchanged (the primitive hashes once). Update every `impl SigningBackend` in core-types and the `#[cfg(kani)]` blocks.
- [ ] **Step 4: Run.** `cs cargo test -p chio-core-types --test signing_wrapper_negatives`. Expected: PASS.

---

### Task 3: Free functions and the verification helper (commit 1)

**Files:** Modify `crates/core/chio-core-types/src/crypto.rs`.

**Interfaces:**

```rust
pub fn sign_wrapped<T: Serialize>(backend: &dyn SigningBackend, schema_id: &str, value: &T)
    -> Result<(SigningOutcome, CanonicalBytes<CanonicalJsonWitness>)>;
pub fn sign_wrapped_for_identity<T: Serialize>(backend: &dyn SigningBackend, expected: &PublicKey, schema_id: &str, value: &T)
    -> Result<(SigningOutcome, CanonicalBytes<CanonicalJsonWitness>)>;
pub fn sign_shared_wrapped(backend: &dyn SigningBackend, schema_id: &str, canonical: SharedCanonicalBytes)
    -> Result<SignedCanonicalPayload>;

/// `pinned` is the key the caller trusts; its encoding alone selects the algorithm.
/// Order: id registered, signature algorithm equals `pinned.algorithm()`, strict cryptographic check.
pub fn verify_wrapped<T: Serialize>(pinned: &PublicKey, schema_id: &str, value: &T, signature: &Signature) -> Result<()>;
pub fn verify_wrapped_bytes(pinned: &PublicKey, schema_id: &str, canonical: &CanonicalBytes<CanonicalJsonWitness>, signature: &Signature) -> Result<()>;
pub fn verify_exempt(pinned: &PublicKey, format: ExemptFormat, bytes: &[u8], signature: &Signature) -> Result<()>;
```

New `Error` variants: `UnregisteredSchemaId(String)`, `SignatureAlgorithmMismatch { key: SigningAlgorithm, signature: SigningAlgorithm }`, `SignatureRejected`. Verification is strict for every algorithm (Ed25519 rejects weak keys and small-order points; hybrid requires both halves).

Deleted: `sign_canonical_with_backend`, `sign_canonical_with_backend_for_identity`, `sign_shared_canonical_with_backend`, `sign_canonical_with_backend_shared`, `PublicKey::verify_canonical`, `verify_canonical_strict`, `verify_shared_canonical`, `verify_canonical_bytes`; `PublicKey::verify` and `verify_strict` become `pub(crate)`.

- [ ] **Step 1: Failing tests** in `signing_wrapper_negatives.rs`: `schema_id_substitution_rejects` (sign as `chio.capability.v1`, verify as `chio.receipt.v1`, expect `SignatureRejected`); `algorithm_prefix_mismatch_rejects_before_crypto` (Ed25519 pinned key, P-256 signature, expect `SignatureAlgorithmMismatch`); `stripped_hybrid_rejects` (`--features pq`: pinned hybrid key, classical half only); `mldsa_nonempty_context_rejects` (`--features pq`); `raw_body_signature_rejects` (a signature over the canonical body without the wrapper, made with `sign_exempt`).
- [ ] **Step 2: Run, confirm failure, implement, run** with `cs cargo test -p chio-core-types --test signing_wrapper_negatives` and `--features fips,pq`. Expected: PASS.

---

### Task 4: G19 algorithm members, crypto floor (commits 1, 3 to 6)

**Files:** every struct with a signature-descriptor `algorithm` member (74 Rust fields at the census base) and every caller; `crates/core/chio-core-types/src/crypto.rs` (`is_default_algorithm`, `is_default_optional_algorithm` deleted); `src/receipt/crypto_floor.rs`.

Classification rule for the census rows:
- Delete: an `algorithm` member that describes the signature of the envelope carrying it, signed or unsigned. Covers `CapabilityToken`, `ChioReceipt`, `ReceiptLineageStatement`, `GovernedApprovalToken`, `ThresholdApprovalProposal`, `AggregateBudgetRoot*`, `CumulativeApprovalRoot*`, the recovery disclosure grant wire, `chio-credit` `IouEnvelope`, `SignedReceivableIou`, and the required members on `SessionComplianceCertificate`, `SignedProvenance`, `KeyringArtifactSignature`, `KeyringSigningResult`, `RequestProof`, the secret-broker envelopes, the control-plane active-response authority envelopes, the keyring checkpoint, time-anchor and readiness proofs, and `chio-revocation-oracle` `RootSignature.algorithm: String`.
- Keep: members that describe another object, not the signature over this one: `KeyLogEventBody.algorithm` and `KeyRecord.algorithm` (registered key attributes, checked equal to the typed key's algorithm, never used to choose a verifier) and the BBS `algorithm: "bbs"` constant inside `bbsReceiptSignature`.

**Interfaces:**
- `ReceiptCryptoFloor` check: `ensure_receipt_signature_algorithm_allowed(pinned: SigningAlgorithm, signature: SigningAlgorithm, floor)`; `ReceiptFloorVerifyError::AlgorithmMismatch` is deleted and a mismatch maps to `Crypto(Error::SignatureAlgorithmMismatch)`.
- `ChioReceipt::verify_signature_with_floor(&self, pinned: &PublicKey, floor)`.

- [ ] **Step 1: Failing tests** in `signing_wrapper_negatives.rs`: `capability_with_algorithm_member_fails_decoding` and `receipt_with_algorithm_member_fails_decoding` (both with `"algorithm":"ed25519"` added and with `"algorithm":"p256"` altered, over a body whose wrapper signature is valid); `verifier_choice_ignores_algorithm_member` (P-256 pinned key, artifact JSON with `"algorithm":"ed25519"` and an Ed25519 signature: decoding fails; with the member removed, verification fails with `SignatureAlgorithmMismatch`).
- Receipt-ID stability: a receipt id is a hash of `ChioReceiptIdInput`. An unchanged `ChioReceiptIdInput` keeps its id when only the receipt's outer signature changes. When the id input contains nested signatures, signature-derived commitments or other regenerated material (child receipt signatures, lineage statement signatures, checkpoint or commitment digests over signed bytes), its bytes change transitively and the id changes with them. `receipt_id_survives_outer_signature_change` re-signs a fixed receipt under the wrapper and asserts the id is unchanged; `receipt_id_follows_nested_signature_change` changes one nested signature in the id input and asserts the id changes.

- [ ] **Step 2: Delete the members and helpers; fix callers.** `ChioReceipt` carries `#[serde(deny_unknown_fields)]` from the fwdcompat receipt change, which is merged before this PR rebases; `CapabilityToken` already denies unknown fields.
- [ ] **Step 3: Schemas.** Delete the signature `algorithm` property from the 52 census schema files that the rule above deletes, and from the staged `docs/superpowers/specs/relying-party-wedge/in-place-schemas/capability/token.schema.json` and `receipt/record.schema.json` (top-level member only; the BBS constant stays). Regenerate code (Task 6 Step 5).
- [ ] **Step 4: SDK types.** TS `receipt.ts` (`Omit<ChioReceipt, "algorithm" | "signature">` becomes `Omit<ChioReceipt, "signature">`), Python and Go receipt and capability models drop the member (Task 9).
- [ ] **Step 5: Run** `cs cargo test -p chio-core-types --no-fail-fast` and `--features fips,pq`. Expected: PASS.

---

### Task 5: Core-types artifacts and the `ToolManifest` deletion (commit 1)

**Files:** `crates/core/chio-core-types/src/` rows of the wrapper table and raw-site table (capability token, delegation link, governance, declassification, receipt, child receipt, lineage statement, `SignedExportEnvelope`, recovery macro, security event, session anchor, aggregate and cumulative roots, economic continuity); `src/manifest.rs`.

**Interfaces:**
- Each artifact keeps its method names (`sign`, `sign_with_backend`, `verify_signature`, ...). Bodies call `sign_wrapped*` / `verify_wrapped*` with the id from the wrapper table.
- `SignedExportEnvelope<T: SignedExportPayload>` with
  ```rust
  pub trait SignedExportPayload: Serialize { const SCHEMA_ID: &'static str; }
  ```
  `sign`, `sign_with_backend` and `verify_signature(&self, pinned: &PublicKey)` use `T::SCHEMA_ID`. `SignedExportEnvelope<serde_json::Value>` is not constructible for signing; its two non-test users (`chio-runtime-core` `SignedRuntimePheromoneQueryReport`, `chio-finding-market-store-postgres` readback) move to their typed payloads.
- Prefix drops (G5): `SignedDeclassificationGrant`, `SignedSecurityEvent`, the `signed_authority!` recovery macro and `domain_message(ROOT_SIGNATURE_DOMAIN, ..)` in `aggregate_invocation.rs` and `cumulative_approval.rs` sign the canonical body after the prefix; their `*_SIGNATURE_DOMAIN` byte constants are deleted.
- G9: delete `ToolManifest`, `ToolManifestBody`, `ToolManifest::sign` and their tests; keep `ToolDefinition` and the other shared tool types. `git grep -n "chio_core_types::.*ToolManifest\b\|core::ToolManifest\b"` returns only chio-manifest's own type.

- [ ] **Step 1:** Convert each core-types row; delete the manifest types.
- [ ] **Step 2:** `cs cargo test -p chio-core-types --no-fail-fast`, `--features fips,pq`, `cs cargo clippy -p chio-core-types --all-targets -- -D warnings`. Expected: PASS except the golden-signature tests that Task 11 regenerates (list them).

---

### Task 6: Registration (commit 2)

**Files:** `crates/core/chio-core-types/src/signed_artifact.rs`; `crates/core/chio-core-types/tests/signed_artifact_schema.rs`; new `tests/signed_artifact_registration.rs`; `spec/schemas/registry.json`; new schema files; `spec/schemas/MANIFEST.sha256`; `spec/schemas/chio-wire/v1/README.md`; `spec/schemas/chio-wire/v1/security/exported-signed-artifact-schema-map.json`; `spec/fixtures/shared-security-identifiers.json`; `spec/wire-schemas.lock`; generated code; `xtask/src/codegen/` signed-id emitter.

**Interfaces:**
- `type SignedArtifactSchemaSpec = (&'static str, &'static str, &'static str);` (schema, artifact kind, introducedBy). The `Option` and the test's `internal_only_schemas` exemption are deleted: every entry is registered.
- `pub const KNOWN_SIGNED_ARTIFACT_SCHEMAS: &[&str]` (unchanged name) holds exactly the wrapper ids. `pub fn registered_wrapper_schema(schema_id: &str) -> bool` is what `SigningWrapper::new` and `verify_wrapped*` call.
- The four runtime-attestation evidence ids (`chio.runtime-attestation.azure-maa.jwt.v1`, `aws-nitro-attestation.v1`, `google-confidential-vm.jwt.v1`, `enterprise-verifier.json.v1`) are vendor or JWS formats, not wrapper ids. They leave `KNOWN_SIGNED_ARTIFACT_SCHEMAS` and move to `pub const RUNTIME_ATTESTATION_EVIDENCE_FORMATS: &[&str]` in `chio-appraisal`. The appraisal validator accepts an evidence format only when it is in that closed list and returns a typed error for any other id.
- Ids registered here, each with `introducedBy: "signing-wrapper-v1"`, a `schemaFile` that validates the live serialization, and a `KNOWN_SIGNED_ARTIFACT_SCHEMAS` entry:
  - The 63 ids of spec 2.5 G11 and G16. Four of them (`chio.root-policy.v1`, `chio.idp-key-snapshot.v1`, `chio.revocation-request.v1`, `chio.settlement-closure.v1`) were registered by M0 PR 4, so 59 rows are added: `chio.delegation-link.v1`, `chio.governed-upstream-call-chain-proof.v1`, `chio.call_chain_continuation.v1`, `chio.governed-approval-token.v1`, `chio.child-request-receipt.v1`, `chio.session_anchor.v1`, `chio.credit.iou-envelope.v1`, `chio.channel.signature.v1`, `chio.signed-admission-terminal-projection.v1`, `chio.authority-lifecycle.v1`, `chio.authority-snapshot.v1`, `chio.session-compliance-certificate.v1`, `chio.execution_nonce.v1`, `chio.active-response-submission.v1`, `chio.active-response-artifact-authority-attestation.v1`, `chio.process.container-launch.v1`, `chio.swarm.delegation-witness-hop-signature.v1`, `chio.certify.check.v1`, `chio.federation-policy.v1`, `chio.active-response-policy-authority-request.v1`, `chio.active-response-policy-authority-response.v1`, `chio.budget-snapshot-anchor-commitment.v1`, `chio.enterprise-migration-transition.v1`, `chio.work-subdivision.v1`, `chio.work-offer.v1`, `chio.work-selection.v1`, `chio.work-dispatch-permit.v1`, `chio.workflow-receipt.v1`, `chio.federated-delegation-policy.v1`, `chio.process.swarm-profile.v1`, `chio.ag-ui-receipt.v1`, `chio.mcp.operator-approval.v1`, `chio.mcp.session-credential.v1`, `chio.mcp.session-credential-call.v1`, `chio.provenance-stamp.v1`, `chio.signed-watermark-envelope.v1`, `chio.key-log.witness-statement.v1`, `chio.trace-observation.v1`, `chio.reputation-credential.v1`, `chio.cross-issuer-migration.v1`, `chio.public-issuer-discovery.v1`, `chio.public-verifier-discovery.v1`, `chio.public-discovery-transparency.v1`, `chio.financial-agent-passport-presentation-response.v1`, `chio.agent-passport-presentation-response.v1`, `chio.passport-verifier-policy.v1`, `chio.passkey-capability.v1`, `chio.frost.dkg-package.v1`, `chio.tee-bless-audit.v1`, `chio.runtime.tool-server-ack-signature.v1`, `chio.checkpoint_statement.v1`, `chio.evidence_export_commitment.v1`, `chio.operation_execution_nonce.v1`, `chio.stop-operator-config.v1`, `chio.stop-operator-config-approval.v1`, `chio.signer-readiness-probe.v1`, `chio.finding-pool.store-identity-proof.v1`, `chio.compliance.certificate.v1`, `chio.federation-kernel-handshake.v1`. (`chio.fincred.*.v1` in the staged table is the five registered family ids.)
  - The raw-site ids from Task 8 that are not yet registered (`chio.finding.operator-purchase-job.v1`, `chio.wasm-module.v1`, `chio.tee-capture-frame.v1`). `chio.trust.passport-revocation-root.v1` is registered by #1607.
  - Every `SignedExportPayload::SCHEMA_ID` that a non-test path signs through the wrapper and that is not already registered. At the census base 165 payload types appear in `SignedExportEnvelope<T>`; 117 are signed by a non-test path. Of those, 20 ids are registered and about 70 are not: 57 existing `schema` member values, 13 payloads without a `schema` member that take `chio.<kebab type name without Body and V1 suffixes>.v1` (`AssignmentAcknowledgementBodyV1` becomes `chio.assignment-acknowledgement.v1`; the nine `Outcome*BodyV1` payloads, the three `Assignment*BodyV1` payloads and `FindingStatusOperatorAuthorization`), and up to 5 whose id the census could not resolve (`CapitalExecutionInstructionArtifact`, `ComptrollerSurfaceReport`, `LiabilityClaimPayoutInstructionArtifact`, `LiabilityClaimSettlementInstructionArtifact`, `RuntimeAdmissionReport`). `chio.registry.namespace.v0` registers as `chio.registry.namespace.v1` (v1 only). The compiler-driven list in Step 1 is exact.
- Deferred, not registered in this PR: the export payloads that no non-test path signs. At the census base: `AutonomousComparisonReport`, `AutonomousDriftReport`, `AutonomousExecutionDecisionArtifact`, `AutonomousPricingAuthorityEnvelopeArtifact`, `AutonomousPricingDecisionArtifact`, `AutonomousPricingInputArtifact`, `AutonomousRollbackPlanArtifact`, `CapitalPoolOptimizationArtifact`, `CapitalPoolSimulationReport`, `CrossIssuerLifecycleResult`, `EntryActivationDecision`, `EvidenceSourceCheckpointV1`, `FederatedReputationClearingArtifact`, `FederationActivationExchangeArtifact`, `FederationQualificationMatrix`, `FederationQuorumReport`, `FinancialCrossIssuerMigration`, `FinancialCrossIssuerTrustPack`, `FinancialPassportPresentationChallenge`, `FinancialPassportSourceManifest`, `FinancialSourceCheckpointBodyV1`, `FinancialSourceCompletenessAttestationBodyV1`, `FindingAuditEpoch`, `FindingAuditRoundAuthorization`, `FindingCurrentListingAssertion`, `FindingKeyRevocation`, `FindingPoolDebitAuthorization`, `HostedAggregateCheckpointBody`, `HostedArchiveManifestBody`, `HostedAuthorityTransitionBody`, `HostedGcReceiptBody`, `HostedJournalCheckpointBody`, `HostedLegalHoldBody`, `HostedPrincipalLifecycleBody`, `HostedPrincipalReplicationEventBody`, `HostedQuotaAlertBody`, `HostedRestoreVerificationBody`, `IdentityInteropQualificationMatrix`, `IssuerLifecycleCheckpoint`, `IssuerLifecycleGenerationPin`, `LifecycleCheckpointPin`, `ParametricContestV1`, `ParametricPayoutIntentV1`, `PublicIdentityProfileArtifact`, `PublicWalletDirectoryEntryArtifact`, `PublicWalletRoutingManifestArtifact`, `Web3SettlementDispatchArtifact`, `Web3SettlementExecutionReceiptArtifact`. `SignedExportEnvelope::sign` and `verify_signature` refuse a deferred payload with `UnregisteredSchemaId`. A test that signs a deferred payload asserts that refusal. A deferred payload is registered in the PR that adds its first non-test signer.
- `chio.broker-authority-rpc.v1` and `chio.active-response-policy-authority.v1` are not registered; Task 7 replaces them (G6).
- SDK copy: `cs cargo xtask codegen --lang <ts|python|go>` also writes `sdks/typescript/chio-ts/src/invariants/_generated/signed_artifact_schemas.ts`, `sdks/python/chio-py/src/chio/invariants/_generated_signed_artifact_schemas.py` and `sdks/go/chio-go/invariants/signed_artifact_schemas_gen.go` from `chio_core_types::KNOWN_SIGNED_ARTIFACT_SCHEMAS`; `--check` fails on drift.

- [ ] **Step 1: Exact list.** After Tasks 5 and 7 compile, run `cs cargo test -p chio-core-types --test signed_artifact_registration known_ids_are_registered -- --nocapture`. It prints every id in `KNOWN_SIGNED_ARTIFACT_SCHEMAS` missing from `registry.json`. Expected first run: FAIL with the list above.
- [ ] **Step 2: Write the registration test** `signed_artifact_registration.rs`: (a) `known_ids_are_registered`; (b) `registered_rows_validate_live_serialization`: for each id added by this PR, a fixture instance built by the type's constructor (fixed keys, `issued_at = 1792234800`) serializes to JSON that validates against the row's `schemaFile` (Draft 2020-12 through the `jsonschema` dev-dependency already used by `wire_protocol_schema.rs`); (c) `wrapper_ids_are_unique_per_type`.
- [ ] **Step 3: Write the schemas**, one file per id under the directory of its artifact family in `spec/schemas/chio-wire/v1/` (`$id` sibling convention, `additionalProperties: false` at every level, `schema` member `const` to the id where the type carries one). Reuse an existing schema file where one already describes the type (`execution_nonce.schema.json`, `budget-snapshot-anchor-provenance.schema.json`, `receipt-inclusion-proof.schema.json` `$defs`).
- [ ] **Step 4: Register and hash.** Add rows in the file's existing order; regenerate `MANIFEST.sha256` in the form `check-chio-schema-registry.sh` recomputes; update the v1 README index and `exported-signed-artifact-schema-map.json`.
- [ ] **Step 5: Codegen.** From `~/lanes/m1i1`: `for lang in rust ts go python; do cs cargo xtask codegen --lang "$lang" || exit 1; done && cs cargo xtask snippets regen`; then `python3 scripts/check-wire-schemas.py --update`.
- [ ] **Step 6: Run** `bash scripts/check-chio-schema-registry.sh && bash scripts/tests/check-chio-schema-registry.test.sh && python3 scripts/check-wire-schemas.py && cs make -C ~/lanes/m1i1 codegen-check` and `cs cargo test -p chio-core-types --test signed_artifact_registration --test signed_artifact_schema --test claim_registry_integrity --test wire_protocol_schema`. Expected: PASS.

---

### Task 7: Wrapper-table call sites outside core-types (commits 3 to 6)

**Files:** every row of the inventory's `## Wrapper schema ids` table outside `chio-core-types`, plus each row's verifier.

**Interfaces:**
- Each signer calls `sign_wrapped*` or `Keypair::sign_wrapped` with its table id; each verifier calls `verify_wrapped*` with the same id and the key from its trust context.
- Prefix drops (G5), each byte constant deleted: chio-keyring (checkpoint, activation commit, witness statement, enterprise receipt, event, readiness proofs, artifact signature, time anchor), chio-decoy watermark, chio-secret-broker (`{domain, body}` objects and `SignedBrokerAuditRunnerAuthorization`), `SignedAdmissionTerminalProjectionV1`, the two kernel active-response artifacts, the control-plane active-response authority request and response, chio-federation-authority `DkgPackage`, chio-workflow `Signed<T>` (canonical body `{"body": body, "signer": signer}`).
- G6 member replacement: `chio-secret-broker` `AUTHORITY_RPC_SCHEMA` is deleted; the request body's `schema` is `chio.broker-authority-request.v1` and the response body's is `chio.broker-authority-response.v1`. `chio-security-types` `ACTIVE_RESPONSE_AUTHORITY_SCHEMA` is replaced by `ACTIVE_RESPONSE_AUTHORITY_REQUEST_SCHEMA = "chio.active-response-policy-authority-request.v1"` and `ACTIVE_RESPONSE_AUTHORITY_RESPONSE_SCHEMA = "chio.active-response-policy-authority-response.v1"`. The health output's `protocol` member names the protocol, not a signed artifact; it reads the new constant `ACTIVE_RESPONSE_AUTHORITY_PROTOCOL = "chio.active-response-policy-authority.v1"`, which is never a wrapper id and never a `schema` member. Schema files `broker-authority-{request,response}-body-v1.schema.json` and the generated code follow; the golden byte strings in `chio-control-plane/src/security/active_response_authority/tests.rs` regenerate in Task 11.
- DPoP: `chio-kernel/src/dpop.rs` signs and verifies `chio.dpop_proof.v1` through the wrapper; the `Keypair::sign` over canonical bytes at the old `dpop.rs:135` becomes `sign_wrapped`.
- Kernel portable signer: `chio-kernel-core` `sign_receipt` and `sign_receipt_relaying_trusted_body` keep their names and signatures; their bodies reach `ChioReceipt::sign_with_backend`. WASM, mobile and C ABI relays change no API.
- Signing routes through remote and rotating backends: a `SigningMessage` crosses every backend boundary with its kind intact. Rotating backends (`chio-keyring` router, `KeyringAuthoritySigningBackend`, `SharedSigningBackend`, `MigrationGuardedSigningBackend`) forward the same `SigningMessage`. `chio-signing-remote` sends a typed request, `{"kind":"wrapper","message":<hex>}` or `{"kind":"exempt","format":<ExemptFormat>,"message":<hex>}`, and no backend method, wire request or endpoint takes untyped bytes.
- Chio-operated signing endpoints (census grep `git grep -n "sign_bytes\|sign_wrapped" -- crates/platform crates/trust/chio-signing-remote crates/products ':!**/tests/**'`) accept exactly two pinned routes:
  - Wrapper route: `kind` is `wrapper` and the message is 88 bytes starting with `SIGNING_WRAPPER_PREFIX`.
  - Exempt route: `kind` is `exempt`, the `(signing key, ExemptFormat)` pair is in the endpoint's pinned route table, and the message parses as that format (JWS signing input: two base64url segments joined by `.`; DSSE PAE: the `DSSEv1` encoding with consistent lengths; Rekor entry and HTTP message signature base: their standard structure). The route table lists exactly the Task 8 exempt callers that sign through a remote or rotating backend, as recorded in Task 1; it is closed and lives in code.
  - Every other request is refused with a typed error before any signing call. There is no raw-byte route and no fallback from a refused route to another route.
- Remote route tests, at each such endpoint: `remote_signing_accepts_pinned_exempt_route` (an external-format message from a pinned exempt caller, for example a JWS signing input from the local AS, signs and verifies with `verify_exempt`); `remote_signing_refuses_arbitrary_bytes` (arbitrary bytes, a wrapper-kind message that is not 88 prefixed bytes, an exempt format absent from the route table and well-formed exempt bytes declared under the wrong format each refuse, and the backend records no signing call).
- K-stack invariants: every existing K-stack invariant test (custody, stop withholding, required fingerprints, fencing, terminal projection and dispatch ordering) is preserved with its assertions unchanged; only golden signature bytes inside them regenerate, through their owning generators. Custody, stop withholding, required fingerprints and fencing are never simplified, relaxed or bypassed to make a regeneration pass. Wrapper-specific refusal cases are added at the real boundaries where each kernel artifact is verified: kernel checkpoint verification, stop operator config and approval load, caller dispatch authorization and delivery report verification, both execution nonce checks at admission, admission terminal projection read, active-response submission proof and artifact attestation checks, session compliance certificate verification, authority lifecycle and snapshot verification, and terminal outcome commitment verification. Each case presents a signature over the raw canonical body and a signature under another registered id, and asserts refusal at that boundary.

- [ ] **Step 1:** Convert crate by crate in commit-group order, adding the remote route tests and the K-stack boundary refusal cases with the crate that owns each boundary. After each crate: `cs cargo test -p <crate> --no-fail-fast` and `cs cargo clippy -p <crate> --all-targets -- -D warnings`; record tests that fail only on golden signatures for Task 11.
- [ ] **Step 2:** `cs cargo check --locked --workspace --all-targets` and `--all-features`. Expected: PASS.

---

### Task 8: Raw signing sites (commit 7)

**Files:** every row of the inventory's "Signing sites outside the named helpers" table; new `scripts/check-signing-exemptions.py`; `scripts/check-domain-separation.py`; `.github/workflows/ci.yml` (one `run_gate` line beside `check-domain-separation.py`).

Resolution table (re-anchored to current lines in Task 1):

| site | resolution |
|---|---|
| `chio-core-types/src/capability/aggregate_invocation.rs` (`domain_message(ROOT_SIGNATURE_DOMAIN, ..)`) | `chio.aggregate-budget-root.v1` over the body |
| `chio-core-types/src/capability/cumulative_approval.rs` | `chio.cumulative-approval-root.v1` over the body |
| `chio-core-types/src/economic_continuity.rs` `signing_bytes()` | `chio.economy.state-batch.v1` |
| `chio-core-types/src/economic_continuity/anchor.rs` (two sites) | `chio.economy.anchor-view.v1`; `chio.economy.effect-dispatch-commit.v1` |
| `chio-anchor/src/witness/rekor.rs` | exempt, `ExemptFormat::RekorEntry` |
| `chio-kernel/src/admission_operation/execution_nonce/profile.rs` | `chio.operation_execution_nonce.v1` |
| `chio-kernel/src/caller_delivery.rs` (two sites) | `chio.caller-dispatch-authorization.v1`; `chio.caller-delivery-report.v1` |
| `chio-kernel/src/checkpoint/builders.rs` (kernel checkpoint) | `chio.checkpoint_statement.v1` |
| `chio-kernel/src/stop/config.rs` (two sites) | `chio.stop-operator-config-approval.v1` over the approval object without its signature; `chio.stop-operator-config.v1` |
| `chio-kernel/src/tool_outcome/release/terminal.rs` | `chio.channel.terminal-outcome-commitment.v1` (registered) |
| `chio-control-plane/src/fiscal_runtime_readiness.rs` (`FiscalRuntimeReadinessBuilder::sign`, body in `chio-fiscal/src/lifecycle/readiness.rs`) | `chio.fiscal.consumer-readiness.v1` (registered) |
| `chio-control-plane/src/security/adapters/native_evidence.rs` readiness probe | `chio.signer-readiness-probe.v1` over `{"probe":"native_security_receipt","schema":"chio.signer-readiness-probe.v1"}` |
| `chio-control-plane/src/security/response_simulation.rs` readiness probe | `chio.signer-readiness-probe.v1` over `{"probe":"response_simulation","schema":"chio.signer-readiness-probe.v1"}` |
| `chio-control-plane/src/trust_control/finding_operator_purchase.rs` (`buyer_signature` over `ask_digest`) | `chio.finding.operator-purchase-job.v1` over the canonical ask body that `ask_digest` hashes |
| `chio-store-sqlite/src/finding_pool_ledger/qualification.rs` (`challenge`) | `chio.finding-pool.store-identity-proof.v1` over a canonical `{"challenge": <hex>, "schema": ...}` object |
| `chio-store-sqlite/src/fiscal_store.rs` (`FiscalProposalAdmissionBuilder::sign`) | `chio.fiscal.proposal-admission.v1` (registered) |
| `chio-cli/src/cli/dispatch/proof/collect.rs`, `proof/export.rs` (`signed_payload`) | exempt, `ExemptFormat::DssePae` |
| `chio-cli/src/guards/sign.rs` and the verifier in `chio-wasm-guards/src/manifest.rs` | `chio.wasm-module.v1` over `{"module_hash","module_name","signer_public_key","version"}`; the newline-joined `chio-wasm-guard-v1` message and `SIGNED_MODULE_DOMAIN` are deleted |
| `chio-acp-proxy/src/compliance.rs` | `chio.compliance.certificate.v1` |
| `chio-mcp-remote/src/remote_mcp/oauth/helpers.rs` (local AS) | exempt, `ExemptFormat::JwsSigningInput` |
| `chio-binding-helpers/src/signing.rs` UTF-8 signer | deleted (Task 9) |
| `chio-keyring/src/router.rs` (`canonical`) | the router takes `schema_id: &str` and signs through `sign_wrapped` |
| `chio-credentials/src/oid4vp.rs`, `portable_sd_jwt.rs` | exempt, `ExemptFormat::JwsSigningInput` |
| `chio-mcp-remote/src/remote_mcp/root_exchange/jws.rs` (`VerifyingKey::verify`, EdDSA arm; lands with #1709) | exempt, `verify_exempt(.., ExemptFormat::JwsSigningInput, ..)`; the `p256`, `p384` and `rsa` verifiers in the same function are external crates and stay |
| `chio-mcp-remote/src/remote_mcp/session_identity.rs` (`verify_ed25519_jwt_signature`, EdDSA bearer JWTs) | exempt, `verify_exempt(.., ExemptFormat::JwsSigningInput, ..)` |
| `chio-disclosure-lineage/src/verifier.rs` (`digest.as_bytes()`) | `chio.lineage.signed-subgraph.v1` (registered) over the subgraph digest material object, not its digest; the `sig-ed25519:<key>:<sig>` encoding is unchanged |
| `chio-federation-authority/src/frost_ceremony/sealing.rs` | `chio.frost.dkg-round2-sealed.v1` (registered) |
| `chio-federation/src/bilateral.rs`, `bilateral_dsse/sign.rs` (5 sites), `bilateral_dsse/typestate_handlers.rs`, `chio-federation-transport-iroh/src/lanes/bilateral.rs` | exempt, `ExemptFormat::DssePae` |
| `chio-federation/src/trust_establishment.rs` | `chio.federation-kernel-handshake.v1` |
| `chio-revocation-oracle/src/signer.rs` (`SignedEpochRoot`) | `chio.trust.passport-revocation-root.v1` (registered by #1607) over the canonical `EpochRoot`; `DOMAIN_SEPARATION_CONTEXT` and `RootSignature.algorithm` deleted |
| `chio-tee/src/capture.rs` (`sign_frame`) | `chio.tee-capture-frame.v1` over the frame signing payload; the `ed25519:<base64>` encoding is unchanged |

**Interfaces:**
- `scripts/check-signing-exemptions.py`: finds every non-test call of `SigningMessage::exempt`, `Keypair::sign_exempt` and `verify_exempt` under `crates/` in every spelling: fully qualified paths, `use`-imported names, renamed imports (`use ... as alias`), grouped imports and method-call syntax. Its embedded allowlist names each allowed call site as `(file, enclosing fn, ExemptFormat, count)`, one entry per exempt row above, including `(root_exchange/jws.rs, VerifyingKey::verify, JwsSigningInput, 1)` and `(remote_mcp/session_identity.rs, verify_ed25519_jwt_signature, JwsSigningInput, 1)`. The gate compares call sites with multiplicity and fails unless the observed sites equal the allowlist exactly: an extra call in an already-allowed file or function fails, a missing call fails and a changed format fails. A call whose spelling or format the scanner cannot resolve fails. No baseline file; the allowlist lives in the script.
- `scripts/check-domain-separation.py`: its scope becomes hash, id, key-id, envelope-hash and commitment domains; a production `&[u8]` constant whose name contains `SIGNATURE` and `DOMAIN` fails (signature domains no longer exist). Run `--ratchet` once to drop entries for deleted constants.

- [ ] **Step 1:** Convert each row; run each owning crate's tests and clippy. Update the #1709 test sites in `crates/protocol/chio-mcp-remote/tests/root_exchange_id_jag.rs`: `:75` (`IdpKeySnapshot` signed with `sign_canonical`) becomes `sign_wrapped` under `CHIO_IDP_KEY_SNAPSHOT_SCHEMA`; `:236` (`RootPolicy` signed with `sign_canonical`) becomes `sign_wrapped` under `CHIO_ROOT_POLICY_SCHEMA`; `:109` and `:733` (Ed25519 `Keypair::sign` over a JWS signing input) become `sign_exempt(ExemptFormat::JwsSigningInput, ..)`. Test sites are outside the exemption gate.
- [ ] **Step 2:** Write `check-signing-exemptions.py` and its behavior test `scripts/tests/check-signing-exemptions.test.py`, which builds temp trees and asserts: the clean allowlisted tree passes; an extra raw exemption call in an already-allowed file fails; an extra call in an already-allowed function fails; a call through an imported name (`use chio_core_types::crypto::SigningMessage;` then `SigningMessage::exempt(..)`), through a renamed import and through a fully qualified path is each detected and counted, and an extra one of each fails; a removed allowlisted call fails; a call in an unlisted file fails. Run both. Expected: PASS.
- [ ] **Step 3:** `python3 scripts/check-domain-separation.py && bash scripts/tests/check-domain-separation.test.sh`. Expected: PASS.

---

### Task 9: Binding helper, FFI and SDKs (commit 8)

**Interfaces:**
- `chio-binding-helpers`:
  ```rust
  pub fn sign_wrapped_json_ed25519(schema_id: &str, input_json: &str, seed_hex: &str) -> Result<WrappedJsonSignature>;
  pub fn verify_wrapped_json(schema_id: &str, input_json: &str, public_key_hex: &str, signature_hex: &str) -> Result<()>;
  pub fn public_key_from_seed_ed25519(seed_hex: &str) -> Result<String>;
  pub struct WrappedJsonSignature { pub schema_id: String, pub canonical_json: String, pub public_key_hex: String, pub signature_hex: String }
  ```
  An id outside `KNOWN_SIGNED_ARTIFACT_SCHEMAS` returns `Error::UnregisteredSchemaId`. Deleted: `sign_utf8_message_ed25519`, `verify_utf8_message_ed25519`, `sign_json_str_ed25519`, `verify_json_str_signature_ed25519`, `Utf8MessageSignature`, `CanonicalJsonSignature`.
- FFI (`chio-bindings-ffi`, `chio_ffi.h`, `tests/abi/chio-bindings-ffi.symbols`):
  ```c
  ChioFfiResult chio_sign_wrapped_json_ed25519(const char *schema_id, const char *input_json, const char *seed_hex);
  ChioFfiResult chio_verify_wrapped_json(const char *schema_id, const char *input_json, const char *public_key_hex, const char *signature_hex);
  ChioFfiResult chio_public_key_from_seed_ed25519(const char *seed_hex);
  ```
  Deleted: `chio_sign_utf8_message_ed25519`, `chio_verify_utf8_message_ed25519`, `chio_sign_json_ed25519` and their verify twin. The four FFI entries in `docs/security/trust-boundary-inventory.json` change with them.
- C++ (`chio::invariants`): `Result<std::string> sign_wrapped_json_ed25519(std::string_view schema_id, std::string_view input_json, std::string_view seed_hex)`, `Result<bool> verify_wrapped_json(...)` (true only on the FFI's success), `Result<std::string> public_key_from_seed_ed25519(std::string_view seed_hex)`. `src/dpop.cpp` uses `public_key_from_seed_ed25519` where it signed `"derive_key"`, and `sign_wrapped_json_ed25519("chio.dpop_proof.v1", body, seed)` for the proof.
- Python (`chio.invariants`): `sign_wrapped_json_ed25519(schema_id, input_text, seed_hex) -> dict[str, str]`, `verify_wrapped_json(schema_id, input_text, public_key_hex, signature_hex) -> None` (raises `ChioInvariantError`), `public_key_from_seed_ed25519(seed_hex) -> str`; capability and receipt verifiers use `verify_wrapped_json` with `chio.capability.v1` / `chio.receipt.v1` and the delegation-link id. `chio-bedrock` `receipt.py` verifies through `chio.invariants`.
- TypeScript (`chio-ts`): `signWrappedJsonEd25519(schemaId, inputJson, seedHex)`, `verifyWrappedJson(schemaId, inputJson, publicKeyHex, signatureHex): void` (throws), `publicKeyFromSeedEd25519(seedHex)`; `verifyCapability`, `verifyReceipt` and `signDpopProof` move to them.
- Go (`chio-go/invariants`): `SignWrappedJSONEd25519(schemaID, input, seedHex string) (WrappedSignature, error)`, `VerifyWrappedJSON(schemaID, input, publicKeyHex, signatureHex string) error`, `PublicKeyFromSeedEd25519(seedHex string) (string, error)`; `SignUTF8MessageEd25519`, `VerifyUTF8MessageEd25519`, `SignJSONStringEd25519`, `VerifyJSONStringSignatureEd25519` deleted. `sdks/k8s/webhooks/capability.go` verifies the wrapper over the capability signing body.
- Every SDK capability and receipt decoder rejects a top-level member outside the type's closed set, which covers `algorithm` (G19). Nested strictness of section 7 types follows in later items.
- `tests/bindings/vectors/signing/v1.json`: `utf8_cases` deleted; each `json_cases` entry gains `schema_id` and a wrapped signature; regenerated by the `#[ignore]` regenerator in `chio-binding-helpers/tests/vector_fixtures.rs`.

- [ ] **Step 1: Failing tests first** in each language: the wrapped signer reproduces `signing/v1.json`; an unregistered id fails; a capability with an `algorithm` member fails; every case of `signing/wrapper/v1.json` verifies as `expected_verify` says (Ed25519 cases in TS, Python, Go and C++; P-256 and P-384 cases are skipped in the SDKs until default-build P-256 lands, and that skip is asserted to cover exactly the `p256`/`p384` ids).
- [ ] **Step 2: Implement; regenerate `signing/v1.json`.**
- [ ] **Step 3: Run** `cs bash scripts/check-bindings-parity.sh`, `bash scripts/check-chio-py.sh`, `cs bash scripts/check-chio-cpp.sh`, `(cd sdks/go/chio-go && CGO_ENABLED=0 go test ./...)`, `(cd sdks/k8s/webhooks && go test ./...)`, `(cd sdks/python/packages/chio-bedrock && uv run pytest)`, `cs bash scripts/check-sdk-parity.sh`, `bash scripts/check-consumer-sdk-parity.sh`, `python3 scripts/check-trust-boundaries.py`. Expected: PASS.

---

### Task 10: Vector cross-check against M0 (commit 9)

**Files:** `crates/core/chio-core-types/tests/signing_wrapper_vectors.rs` (new); `scripts/gen-signing-wrapper-vectors.py`; `tests/bindings/vectors/signing/wrapper/v1.json`; new `tests/bindings/vectors/signing/wrapper/pq-v1.json`; `xtask` subcommand `gen signing-wrapper-pq-vectors [--check]`; `tests/bindings/vectors/MANIFEST.sha256`.

**Interfaces:**
- `signing_wrapper_vectors.rs` reads `wrapper/v1.json`:
  - `prefix_hex` equals `SIGNING_WRAPPER_PREFIX`.
  - For every `wrapper_cases` entry: if `schema_id` is in `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, `SigningWrapper::new(schema_id, canonical_body)` equals `wrapper_hex`; otherwise it returns `UnregisteredSchemaId`.
  - Every id in `KNOWN_SIGNED_ARTIFACT_SCHEMAS` has a `wrapper_cases` entry.
  - Every `signature_cases` entry: `verify_wrapped_bytes(public_key, verify_schema_id, canonical_body, signature)` is `Ok(())` exactly when `expected_verify` is true. Ed25519 cases always; P-256 and P-384 cases under `--features fips` (asserted count 2 x 7 positives plus their negatives).
  - The Rust Ed25519 signer reproduces every Ed25519 positive signature byte for byte (Ed25519 is deterministic).
- G19 additions to `wrapper/v1.json` (generated by the Python script so the file stays single-sourced): `capability-algorithm-added`, `capability-algorithm-altered`, `receipt-algorithm-added`, `receipt-algorithm-altered` (each `expected_decode: false` with a valid wrapper signature over the padded body), and `p256-key/ed25519-signature/algorithm-member` (P-256 pinned key, body carrying `"algorithm":"ed25519"`, Ed25519 signature: rejects on the encoding prefix).
- `gen-signing-wrapper-vectors.py`: delete `SECTION_4_5_UNREGISTERED_IDS` and `EXCLUDED_WRAPPER_IDS` (every id is now in the registry); `wrapper_cases` is one case per registry id. Regeneration may only add cases.
- `pq-v1.json`: ML-DSA-65 and hybrid (Ed25519 + ML-DSA-65) positive cases for `chio.receipt.v1` and `chio.capability.v1` with a fixed seed, plus stripped-hybrid and non-empty-context negatives. ML-DSA signing is hedged, so `--check` verifies the stored cases instead of byte-comparing a regeneration.

- [ ] **Step 1:** Write `signing_wrapper_vectors.rs`; run `cs cargo test -p chio-core-types --test signing_wrapper_vectors` and `--features fips`. Expected: FAIL only on the missing G19 cases.
- [ ] **Step 2:** Extend the script, run `uv run --with-requirements scripts/gen-signing-wrapper-vectors.requirements.txt python3 -I scripts/gen-signing-wrapper-vectors.py write` then `check`. Expected: `git diff tests/bindings/vectors/signing/wrapper/v1.json` shows only added cases.
- [ ] **Step 3:** Generate `pq-v1.json`; `cs cargo xtask gen signing-wrapper-pq-vectors --check`; `cs cargo xtask freeze-vectors`, then `--check`. Rerun Step 1 with `--features fips,pq`. Expected: PASS.

---

### Task 11: Fixture regeneration (commit 10)

Every signed fixture changes bytes. fwdcompat's receipt fixture regeneration is merged first; this task regenerates once on top of it, at the integrated base. One command rewrites every set: `cs cargo xtask gen signed-fixtures` runs the generators in the table below in order and repeats until a pass changes nothing; `--check` runs one pass and fails without writing when any fixture would change. Signed fixtures regenerate only through their owning generators; no signed fixture is edited by hand or patched by a script. The PR body lists every changed fixture path and the generator that wrote it.

| Fixture set (count at the census base) | Generator |
|---|---|
| `fixtures/proof-room/**` (3027 files with a signature member) | `cs cargo run -p chio-cli --bin chio -- proof fixture regenerate`, then `--check` |
| `tests/bindings/vectors/{capability,receipt,manifest,eval}/v1.json`, `capability/security-binding-v1.json`, `signing/v1.json` | `#[ignore]` regenerators in `crates/sdk/chio-binding-helpers/tests/vector_fixtures.rs` (`cs cargo test -p chio-binding-helpers --test vector_fixtures -- --ignored`) |
| `tests/bindings/vectors/security/broker/**` | `cs cargo xtask gen broker-receipt-vectors` |
| `tests/bindings/vectors/security/cage/**` | `cs cargo xtask gen cage-vectors` |
| `tests/bindings/vectors/security/{key-log,signed-wire,active-defense}/**`, `crates/tooling/chio-conformance/vectors/security/watermark/v1.json` | the owning crate's regeneration test (`chio-keyring/tests/semantic_vectors.rs`, `chio-secret-broker` vector tests, `chio-core-types/tests/security_generated_vectors.rs`, `chio-decoy/tests/watermark_vectors.rs`); `python3 scripts/check-security-wire-vectors.py` |
| `spec/vectors/recovery/v1/*.json` | `cs cargo xtask gen recovery-authority-vectors` |
| `tests/bindings/fixtures/{dpop-authority-v1,protocol-primitives-v1,manifest-consumers}.json` | the regeneration paths in `chio-kernel/src/dpop/authority/tests.rs`, `chio-core-types/tests/protocol_primitives_generated.rs` |
| `crates/products/chio-cli/tests/fixtures/replay/**`, `crates/sdk/chio-eval-receipt/tests/fixtures/*`, `examples/eval-receipt-ingest/metr/out/*` | `cs cargo xtask eval-receipt-regen` |
| `crates/core/chio-adversarial-suite/cases/**` (20 files) | the suite's case builder (`crates/core/chio-arena/src/promote.rs` path) |
| `crates/kernel/chio-kernel/tests/fixtures/stop_operator_config/*` | `chio-kernel/src/stop/config/tests.rs` regeneration |
| `crates/trust/chio-attest-loopback/fixtures/*`, `crates/trust/chio-attest-verify/tests/fixtures/v318/*`, `examples/chio-3vendor/fixtures/**`, `examples/internet-of-agents-web3-network/app/tests/fixtures/good-bundle/**` (then `stamp-fixture-hashes.mjs`), `examples/hello-receipt-verify/fixtures/**`, `docs/demo/fixtures/allow-receipt.json`, `docs/standards/CHIO_*_EXAMPLE.json`, `fuzz/corpus/{capability_receipt,eval_receipt_bundle,federation_trust_establishment,fuzz_merkle_checkpoint}/*`, `formal/tla/trace/fixtures/*.ndjson`, `sdks/python/chio-temporal/tests/fixtures/caller_delivery_golden_v1.json`, `spec/eval/receipt-format.v1.json` | the generator named in each directory's README or test; Task 1 records any set without one and Step 1 below builds it from the owning type's constructor |
| Golden signatures inside Rust sources (for example `chio-control-plane/src/security/active_response_authority/tests.rs`) | rewritten from the test's own builder |
| `spec/ietf/generated/appendix-b.md` and the draft renderings | `python3 spec/ietf/tools/render_vectors.py` and `python3 spec/ietf/tools/test_render_vectors.py` |

- [ ] **Step 1:** After Tasks 2 to 10, run the full test suites (Verification) and collect every golden-signature failure. Each maps to one row above.
- [ ] **Step 2:** Add the `gen signed-fixtures` subcommand to `xtask/src/cli.rs` (one function calling each generator in the table), run `cs cargo xtask gen signed-fixtures`, then run the lane-local review aid `ws2:~/lanes/claude-pr1160-evidence/m1i1/diff-signed-fixtures.py origin/main HEAD` (not committed): for every changed JSON or NDJSON fixture it parses before and after and fails on any difference other than signature members, the `algorithm` members removed by Task 4, the G6 `schema` values and traced derived values. It never ignores a digest or id member by name. Each changed id, digest or commitment is traced to its producer: the aid recomputes it from the regenerated inputs with the producing function and records which changed input (an outer signature, a nested signature or a signature-derived commitment) moved it. A receipt id that changes while its `ChioReceiptIdInput` bytes are unchanged fails. An untraced derived change fails. Expected: every derived change traced. Its output goes in the PR body.
- [ ] **Step 3:** `cs cargo xtask gen signed-fixtures --check` and `cs cargo xtask freeze-vectors --check`. Expected: PASS.

---

### Task 12: PROTOCOL and docs (commit 11)

- [ ] **Step 1:** Move `docs/superpowers/specs/relying-party-wedge/protocol/protocol-4.5-signing-wrapper.md` into `spec/PROTOCOL.md` after 4.4, delete the staged file, remove the status line and the "Sections in force" line, add the four raw-site ids from Task 8 to the table, and delete the "Any other artifact type" row in favor of the registry sentence that follows it. Rewrite 4.1 so signatures cover the wrapper, not the canonical body. Remove `algorithm` from the receipt and capability field tables in PROTOCOL 5 and 6.
- [ ] **Step 2:** Update docs naming deleted APIs: `git grep -n "sign_canonical\|verify_canonical\|sign_utf8_message\|sign_json_str\|signUtf8Message\|SignUTF8Message\|ToolManifestBody\|\"algorithm\"" -- docs spec sdks/*/README.md crates/*/*/README.md ':!docs/superpowers'`.
- [ ] **Step 3:** `grep -rn $'\xe2\x80\x94' <changed files>; test $? -eq 1`; `grep -n -i -E '\bM[0-3]\b|wedge|pilot|docs/superpowers' spec/PROTOCOL.md; test $? -eq 1`; `bash scripts/check-chio-owned-v1-only.sh && python3 scripts/check-native-host-docs.py`; `cs cargo test -p chio-spec-validate --no-fail-fast`.

---

### Task 13: Formal touchpoints and coverage (commit 12)

- [ ] **Step 1: Kani.** Update `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs` (its test backend implements `sign_bytes(SigningMessage)`), the `#[cfg(kani)]` blocks in `crypto.rs` and `chio-kernel-core/src/receipts.rs`, and `formal/rust-verification/kani-public-harnesses.toml` (`chio_core_types::crypto::PublicKey::verify_canonical` becomes `chio_core_types::crypto::verify_wrapped_bytes`). Add a harness `signing_wrapper_layout` over a pure `assemble_wrapper(schema_digest: [u8; 32], body_digest: [u8; 32]) -> [u8; 88]` (fixed buffers; no symbolic strings): bytes 0..24 equal the prefix, byte 23 is 0, bytes 24..56 and 56..88 equal the inputs. `SigningWrapper::new` calls `assemble_wrapper`.
- [ ] **Step 2: Formal mirrors.** `cs cargo xtask check formal-mirrors`. If the `capability/token.rs` or `receipt/body.rs` mirror digests drift, confirm `formal/lean4/Chio/Chio/Core/Capability.lean` and `Receipt.lean` model no `algorithm` member and keep signatures opaque, then `--bless` and say so in the PR body. Source-anchor refresh (`formal-mirrors --bless`, the `kani-public-harnesses.toml` path update) is review evidence that the anchors point at the new code; it is not proof execution. Proofs execute only in the x86 Kani run in Verification. No `.lean` file changes, so the Lean gates are not required; no Lean, lake or Aeneas runs on ws2. Formal-mirrors and proof-coverage are required.
- [ ] **Step 3: Coverage, last.** After the final rebase, from a clean tree in the real worktree: `cs cargo xtask gen proof-coverage` then `--check`; commit `docs/formal/COVERAGE.md`.

---

## D17 Coordination

This PR changes the signed bytes of every artifact that Chio signs, except the exempt formats. Root-2 and the lead check the list below against their in-flight work before the PR opens.

Signed artifacts whose bytes change:
1. Capabilities (`chio.capability.v1`) and delegation links (`chio.delegation-link.v1`): every capability signature, every issued token, every capability fixture; the top-level `algorithm` member disappears from the JSON.
2. Receipts (`chio.receipt.v1`), child receipts and lineage statements: every receipt signature and every receipt fixture; `algorithm` disappears. A receipt whose `ChioReceiptIdInput` is unchanged keeps its id when only its outer signature changes. A receipt whose id input carries nested signatures, signature-derived commitments or other regenerated material gets a new id, because those input bytes change transitively; Task 11 traces each such change to its producer.
3. Chio DPoP proofs (`chio.dpop_proof.v1`, #1489 landed): kernel signer and verifier (`chio-kernel/src/dpop.rs`), TS `signDpopProof`, C++ `sign_dpop_proof`; fixtures `tests/bindings/fixtures/dpop-authority-v1.json`, `chio-kernel/src/dpop/authority/tests.rs`, `chio-kernel/src/admission_operation/dpop_claim/tests.rs`, `sdks/cpp/chio-cpp/tests/sdk_tests.cpp`.
4. Revocation roots (coop2c, #1607 open): `chio-revocation-oracle` `SignedEpochRoot` signs under `chio.trust.passport-revocation-root.v1`, drops its `chio-revocation-oracle:v1:epoch-root` prefix and `RootSignature.algorithm`; #1607's `sign_passport_revocation_root`, its partner mirror verification and `spec/vectors/passport-revocation/v1/{root.positive,root.unknown-field.negative}.json` change with it.
5. Kernel artifacts touched by the K-stack: the kernel checkpoint, stop operator config and approvals, caller dispatch authorization and delivery report, execution nonces (both), admission terminal projection, active-response submission proof and artifact attestation, session compliance certificate, authority lifecycle and snapshot, terminal outcome commitment. K-stack PRs that touch the same files, all merged before this PR: T7 #1675 (active-response proof and dispatch, `execution_validation.inc`, `tests/security_receipts.rs`), C6 #1682 (`receipt_store.rs`, `receipt_namespace.rs`), native-ledger #1678, stop-error #1701, D5 #1269 and KERN-TRACE-LOCK-FSYNC. This PR keeps every K-stack invariant test and adds wrapper refusal cases at the kernel boundaries (Task 7).
6. Security artifacts: every key-log, keyring, secret-broker, decoy watermark, cage and security-event signature; `chio.broker-authority-rpc.v1` and `chio.active-response-policy-authority.v1` member values are replaced (G6).
7. Every other row of the inventory wrapper table and the raw-site table (economy, trust, protocol, products, tooling), and every `SignedExportEnvelope<T>` payload.
8. SDK-produced signatures: the C++, Python, TS and Go generic signers take a schema id; the UTF-8 signers are gone.

Fixtures whose bytes change: every set in Task 11. Shared with in-flight work:
- `tests/bindings/vectors/receipt/v1.json` and `tests/bindings/vectors/MANIFEST.sha256`: also changed by #1601 (trust level). #1601 lands first; this PR regenerates after it.
- `fixtures/proof-room/**` (3027 signed files) and receipt fixtures generally: also touched by the fwdcompat RECEIPT-UNKNOWN-FIELDS change (receipt `deny_unknown_fields`, commerce schema tag off receipt bytes, about 389 fixtures). fwdcompat lands first, including its receipt fixture regeneration and receipt `deny_unknown_fields`; this PR regenerates once on top of it.
- `spec/vectors/passport-revocation/v1/*`, `spec/schemas/registry.json`, `spec/schemas/MANIFEST.sha256`, `spec/wire-schemas.lock`: also changed by #1607. #1607 lands first.
- `tests/bindings/fixtures/dpop-authority-v1.json`: owned by the DPoP lane; #1489 is merged, so no conflict, bytes only.
- M1 item 3 lands in two parts. #1706 adds the anchored-root types and the root-authority artifacts with no verifier and no signed-byte change, and merges before this PR. The `root_anchor` member in the capability signing body merges after this PR. It rebases on this PR and regenerates capability fixtures through `cs cargo xtask gen signed-fixtures`.

Merge order (precondition for this PR): #1674, #1601, #1607, the wedge PRs #1723, #1706 and #1709 in that order (#1713 follows #1709), and fwdcompat receipts; the K-stack in Root-2's order, T7 #1675, C6 #1682, native-ledger #1678, stop-error #1701, D5 #1269, then KERN-TRACE-LOCK-FSYNC; then this PR. Anchored-root capability changes (M1 item 3) and M1 item 2 follow this PR. The census and every signed fixture are refreshed at the integrated base that contains all predecessors.

## Verification

Run at the PR head after the final rebase. Every cargo command, direct or nested, runs under `cs` (Global Constraints). Coder checks on ws2; heavy suites on `integ-x86` and `integ-h3`. Logs are kept under `ws2:~/lanes/claude-pr1160-evidence/m1i1/` with sha256 recorded in the PR body.

**Changed crates (integrators).** For every crate in `git diff --name-only origin/main...HEAD -- crates`: `cs cargo test -p <crate> --no-fail-fast` and `cs cargo clippy -p <crate> --all-targets -- -D warnings`. Plus `cs cargo test -p chio-core-types --features fips,pq --no-fail-fast`, `cs cargo check --locked --workspace --all-targets`, `--all-features`, `cs cargo fmt --all --check`, and the CLAUDE.md one-liner once at the final tip with each step under `cs`: `cs cargo build --workspace && cs cargo test --workspace && cs cargo clippy --workspace -- -D warnings && cs cargo fmt --all -- --check`.

**Native-cage chio-cli and chio-conformance (required; lane-common "CLI/conformance full runs need the native cage").** `chio-core-types` is upstream of both, so the full suites run on host 3 (or x86) with the setup copied from `ws2:~/lanes/claude-pr1160-evidence/root2/k6/verify-native-final-fa34a7dc65.sh`: self-contained node 24 and npm 9.2.0 first on `PATH`; `cs cargo build --locked --target x86_64-unknown-linux-musl -p chio-cage-init --bin chio-cage-init --features real-linux-enforcement` and `CHIO_CAGE_INIT` exported to it; the privileged `enforced_discovery` test; `scripts/prepare-native-python-runtime.py` and `scripts/prepare-enforced-native-fixture.py` with the fixture env exported; `CHIO_CAGE_SYSCALL_PROFILE=native-standard-v1`; `CHIO_CHECKOUT_ROOT` set; then `cs cargo test --locked --no-fail-fast -p chio-conformance` and `cs cargo test --locked --no-fail-fast -p chio-cli`. Required: rc=0 for both. Environment-only failures are not accepted.

**Final qualification at the new main.** Candidate integration and the final native qualification run at the `origin/main` commit this PR merges onto, not at an earlier base; evidence from an earlier base keeps its own source provenance and does not count as final. The final run covers the stop-error MCP routes (#1701) and the CLI transport paths in addition to the suites above, and records the main SHA it ran against.

**Gates.**
```bash
python3 scripts/check-security-clocks.py && python3 scripts/check-escape-hatches.py && python3 scripts/check-negative-assertions.py \
 && python3 scripts/check-trust-boundaries.py && python3 scripts/check-rust-file-hygiene.py && bash scripts/check-http-egress-contract.sh \
 && python3 scripts/check-error-urn-registry.py && cs bash scripts/check-adapter-no-bypass.sh \
 && python3 scripts/check-domain-separation.py && bash scripts/tests/check-domain-separation.test.sh \
 && python3 scripts/check-signing-exemptions.py && python3 scripts/tests/check-signing-exemptions.test.py \
 && python3 scripts/check-kani-crypto-scope.py && python3 scripts/check-kani-public-harnesses.py
```

**Wire-schemas, schema-registry and freeze gates.**
```bash
python3 scripts/check-wire-schemas.py && bash scripts/tests/check-wire-schemas.test.sh
bash scripts/check-chio-schema-registry.sh && bash scripts/tests/check-chio-schema-registry.test.sh && bash scripts/check-chio-owned-v1-only.sh
uv run --with jsonschema==4.26.0 --with referencing==0.37.0 python3 -I scripts/check-root-authority-schema-examples.py
python3 scripts/check-security-wire-vectors.py
cs make -C ~/lanes/m1i1 codegen-check && cs cargo xtask snippets regen --check
cs cargo xtask freeze-vectors --check
uv run --with-requirements scripts/gen-signing-wrapper-vectors.requirements.txt python3 -I scripts/gen-signing-wrapper-vectors.py check
cs cargo xtask gen signing-wrapper-pq-vectors --check
cs cargo run -p chio-cli --bin chio -- proof fixture regenerate --check
cs cargo xtask eval-receipt-regen --check
cs cargo test -p chio-conformance --test vectors_schema_pair --no-fail-fast
cs cargo test -p chio-binding-helpers --test vector_fixtures --no-fail-fast
```
If `Cargo.lock` changes: the Cargo.lock digest pin in `scripts/check-security-ci-contract.py` and `deploy/docker/Dockerfile.security-evidence-runner`, then `git lfs pull` per lane-common and `cs python3 scripts/check-security-ci-contract.py`, and `cs python3 scripts/check-aws-lc-fork.py`.

**Formal-mirrors and Kani.** `cs cargo xtask check formal-mirrors`. Kani 0.68 (the CI pin) runs only on the approved x86 runner, under `cs` (`CARGO_INCREMENTAL=0 ~/cslot.sh`), launched detached with `setsid -f` and a pid file through `~/lanes/claude-pr1160-evidence/q.sh ... < /dev/null`: every harness in `formal/rust-verification/kani-public-harnesses.toml` plus the new `signing_wrapper_layout` harness, through `scripts/run-kani-manifest.sh`. A single-harness rerun also runs on the x86 runner under `cs`; no Kani, Lean, lake or Aeneas runs on ws2. `cs cargo xtask gen proof-coverage --check` last. No Lean gates are required because no `.lean` file changes.

**SDK builds.** `cs bash scripts/check-bindings-parity.sh` (node on `PATH` from mise shims), `bash scripts/check-chio-py.sh`, `cs bash scripts/check-chio-cpp.sh`, `(cd sdks/go/chio-go && CGO_ENABLED=0 go test ./...)`, `(cd sdks/k8s/webhooks && go test ./...)`, `(cd sdks/python/packages/chio-bedrock && uv run pytest)`, the `chio-ts` package's own typecheck and lint scripts, `cs bash scripts/check-sdk-parity.sh`, `bash scripts/check-consumer-sdk-parity.sh`, `python3 scripts/tests/check-consumer-sdk-inventory.test.py`, the TS packages that wrap the browser WASM (`sdks/typescript/packages/{workers,edge,deno}` tests, under `cs` when their build step reaches cargo or wasm-pack), and `cs cargo test --locked --manifest-path sdks/lambda/chio-lambda-extension/Cargo.toml`.

Pre-existing reds on `main` are reported with `main`'s result at the same base for comparison.

## Size

Spec 13.2 sizes item 1 at L, 23-32 engineer-days. Estimate from the census:

| Part | Days |
|---|---|
| Wrapper types, trait, free functions, verifier, deletions, crypto floor (Tasks 2, 3) | 2-3 |
| `algorithm` members: 74 fields, 52 schemas, SDK types, negatives (Task 4) | 2-3 |
| Core-types artifacts and `ToolManifest` deletion (Task 5) | 1-2 |
| Registration: 59 table ids, 3 raw-site ids and about 70 signed export payload ids with schemas and four-language codegen; 48 export payloads deferred (Task 6) | 4-6 |
| Wrapper-table call sites in about 60 crates, about 450 signing and verifying call sites, G5 and G6 (Task 7) | 5-7 |
| Raw sites and the exemption gate (Task 8) | 2-3 |
| Binding helper, FFI, C++, Python, TS, Go, webhook, bedrock, DPoP signers (Task 9) | 3-4 |
| Vector cross-check, G19 vectors, PQ vectors (Task 10) | 1-2 |
| Fixture regeneration, about 3200 signed files (Task 11) | 2-4 |
| PROTOCOL, docs, formal touchpoints (Tasks 12, 13) | 1-2 |
| Integration, native-cage runs, review rounds | 3-4 |
| Total | 26-40 |

Item 1 is L, 26-40 engineer-days, with a planning figure of 28 when the census holds at the real base. The range sits 3 to 8 days above spec 13.2 (23-32). The remaining excess over 13.2 is the registration of about 70 signed export payload ids, which 13.2 did not count; deferring the 48 unsigned payloads removes the rest. The M1 total is 107-156 engineer-days (13.2's 104-148 with item 1 at 26-40); the earlier 109-159 figure no longer holds.

## Decisions

The owner decisions of 2026-10-20 and the D17 execution rules are recorded under Global Constraints and applied in Tasks 1, 4, 6, 7, 8, 11 and 13, in D17 Coordination and in Verification. Q5 is settled: fwdcompat's strict receipt decoding lands first, with routing metadata outside the signed receipt bytes. No open question remains for this item.

## Spec coverage

| Spec requirement | Task |
|---|---|
| 7.0 wrapper layout, algorithms, exempt set, one signing and one verification helper | 2, 3, 8 |
| D6, D16 (on the collapsed trait) | 1, 2 |
| G2 every raw site resolved | 8 |
| G5 prefixes dropped | 5, 7, 8 |
| G6, G8 one id per artifact, shared members replaced | 7 |
| G7 generic SDK signing with schema id, UTF-8 signer deleted | 9 |
| G9 core `ToolManifest` deleted | 5 |
| G10 DPoP on `chio.dpop_proof.v1` | 7 |
| G11, G16 registration with schemas, export payload ids, `KNOWN_SIGNED_ARTIFACT_SCHEMAS` | 6 |
| G18 strict decoding of the envelopes this PR touches | 4, 9 |
| G19 algorithm only from the pinned key, members deleted, negatives | 4, 10 |
| 10.1 core-types changes for item 1 | 2 to 6 |
| 10.10 SDK verifiers (wrapper, G19, vectors) | 9 |
| 11.1 signing-wrapper unit tests | 2, 3, 4 |
| 11.2 vectors cross-checked by Rust, G19 vectors, PQ vectors | 10 |
| 11.5 gates and regenerated fixtures listed in the PR | 11, Verification |
| 13.3 step 1 (item 1 first, after D17 coordination) | 1, D17 Coordination |
