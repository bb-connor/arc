# Relying-Party Wedge M0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land milestone M0 of the relying-party wedge: the byte-neutral `SigningBackend` collapse, the customer-hosted root exchange ADR, the protocol text, JSON schemas, reference vectors, producer inventory and staged verdict-matrix scenarios that M1 builds on.

**Architecture:** One Rust PR collapses `SigningBackend` identity to a single fallible `public_key()` across the workspace without changing any signed byte (D16, parallel lead's trait plan). Four contract PRs then add text, schemas and vectors that no running code reads yet: new artifact schemas go live under `spec/schemas/chio-wire/v1/`, while every in-place change to an existing v1 artifact and every new verdict-matrix scenario is staged under `docs/superpowers/specs/relying-party-wedge/` and moved into place by the M1 code PR that implements it (see "Spec gaps resolved" at the end).

**Tech Stack:** Rust workspace (cargo via `~/lanes/cslot.sh` on workstation-2), JSON Schema draft 2020-12, Python 3 stdlib plus `cryptography==44.0.3`, `jsonschema==4.26.0`, `referencing==0.37.0` (the versions already pinned in `.github/workflows/apalache-safety.yml` and `ci.yml`), `cargo xtask codegen`, `cargo xtask freeze-vectors`.

**Spec:** `docs/superpowers/specs/2026-10-17-relying-party-wedge-design.md` (merged as #1522 at `d0c8444520`), as corrected by the founder on 2026-10-17 (static bearer and generic Entra kept; see Global Constraints). Parallel lead's trait plan: `ws2:~/lanes/claude-pr1160-evidence/keyring/trait-plan.md`.

## Global Constraints

- Preconditions (D17): no M0 PR opens before #1496 and #1489 are merged on `main`. Rebase every M0 branch onto `main` after both land. PR 1 also avoids files owned by in-flight lanes kn2 (#1489), w12 and coop2c; if one of those is still open when PR 1 is ready, rebase after it merges instead of editing its files.
- Founder correction (2026-10-17): the `--auth-token` static bearer mode and generic Entra (AzureAd profile) intake are KEPT. Static bearer maps to an operator-issued root naming an explicitly configured principal. Generic Entra maps to an anchored root under the one-root-per-token `(issuer, uti)` rule. Entra Agent ID is added in M2 alongside generic Entra. No M0 artifact (ADR, PROTOCOL, schema, scenario, inventory) may describe deleting either path. Take the exact anchor-kind names for these two from the spec fix PR; until it merges, use `operator_static_bearer` and `entra_jwt` and replace them if the fix PR chooses other names. Tasks 3, 5, 6 and 7 do not open their PRs until the spec fix PR has merged.
- No legacy, compat or dual paths. Everything is v1. No deprecated aliases, no infallible twin of a fallible accessor, no "compatibility identity" wording.
- Strict decoding (spec 2.5 G18, G19): new tagged-enum Rust types use `chio_security_types::strict_serde` (`lossless_serde!`, from #1551) for padding refusal, never a local helper. Every new signed type rejects unknown fields at every level. The algorithm is derived only from the pinned key, never from an artifact member.
- Fail-closed: an identity read error denies, refuses issuance or refuses signing. Never substitute a stale or default key. The only allowed error-to-value mapping is an empty trust set.
- No em dashes (U+2014) in any file. Check: `grep -rn $'\xe2\x80\x94' <changed files>` prints nothing.
- No narrative or meta comments. Comments state invariants and contracts only.
- Clippy denies `unwrap_used` and `expect_used` in non-test code. Test files may use the existing `#![allow(clippy::expect_used, clippy::unwrap_used)]` header pattern.
- Clock reads only through the approved seams. Fixtures and vectors use fixed finite timestamps (for example `1792234800`), never `SystemTime::now()`. Run `python3 scripts/check-security-clocks.py` on every Rust PR.
- Format Rust with `cargo fmt --all` (never standalone `rustfmt`).
- Public-path rule: `spec/`, `docs/adr/`, `tests/`, `scripts/` and `crates/` are mirrored to the public `backbay-labs/chio`. Files there must not mention milestones (M0 to M3), the wedge spec path, "wedge", pilots or private strategy. Unimplemented contract text carries the status line defined in Task 5. Planning material lives under `docs/superpowers/` (withheld by `scripts/mirror-exclude.txt`).
- Commits: conventional commits; message ends with a blank line then `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Identity `bb-connor` / `connor@backbay.io` (check `git config user.email` in the worktree). Inspect `git diff --cached --stat -M` before every commit. Never `git stash`.
- Where work happens: all edits, builds and git on workstation-2 in a per-PR worktree created by the coordinator off `origin/main`. Every cargo command goes through `~/lanes/cslot.sh` with `CARGO_TARGET_DIR=~/lanes/s0-targets/m0-<pr>`; the workspace check uses `CARGO_TARGET_DIR=~/lanes/s0-targets/workspace`. JS, Python and Go tooling runs as `ssh workstation-2 'bash -lc "cd <wt> && ..."'`. Nothing is checked out or built on the Mac.
- Push from ws2 with `git push https://github.com/bb-connor/arc.git <branch>`. A diff that touches `.github/workflows/` is pushed by the coordinator from the Mac. Open PRs from the Mac with `gh pr create --repo bb-connor/arc`; body ends with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`. Never cancel a CI run.
- Merge verify list (from `ws2:~/lanes/s0-common.md`, required before merge, results quoted in the PR body): full lib and integration tests of every changed crate (`cslot cargo test -p <crate> --no-fail-fast`); `cslot cargo clippy -p <crate> --all-targets -- -D warnings`; `cargo fmt --all --check`; `cslot cargo check --locked --workspace --all-targets`; gates that exist: clocks, escape-hatches, negative-assertions, trust-boundaries, rust-file-hygiene, http-egress-contract, error-urn-registry, wire-schemas, chio-schema-registry; if `Cargo.lock` changes, security-ci-contract and `scripts/check-aws-lc-fork.py`; adapter-no-bypass when a kernel or adapter crate changes; TS and Python packages run their own test, lint and typecheck. Pre-existing reds on `main` are reported with `main`'s result for comparison.
- Shared surfaces: before opening a PR that touches `chio-core-types`, `chio-kernel`, `chio-kernel-core`, `chio-keyring`, `chio-control-plane`, `spec/PROTOCOL.md`, `spec/schemas/registry.json` or `tests/bindings/vectors/`, append one line to `ws2:~/lanes/claude-pr1160-evidence/lead2/sync.md` of the form `<UTC> arc-5b: REVIEW? #<N> <one-line scope>` and wait for the parallel lead's `REVIEW #<N> OK` line before requesting merge.

## Review Focus

1. **Feature-gated and `cfg(kani)` code that the default workspace check never compiles** (the `fips` P-256/P-384 backends, `#[cfg(kani)]` blocks in `crypto.rs` at about lines 594-600 and in `chio-kernel-core/src/receipts.rs`, `kani_public_harnesses.rs`) still calling `algorithm()` or `current_public_key()`. Expected: every such site updated. Pinned in Task 1 by `--all-features` workspace check, `cargo test -p chio-core-types --features fips`, a grep step and `check-kani-public-harnesses.py`.
2. **A converted call site that turns an identity error into a key** (for example `unwrap_or(stale_key)` or logging the error and continuing). Expected: signing and issuance deny; trust sets become empty. Pinned in Task 1 by failing-identity tests in core-types, kernel (`CapabilityAuthority`, `receipt_signing_public_key`) and keyring.
3. **A fixture or snapshot silently re-blessed in the "byte-neutral" PR.** Expected: zero changed fixture, snapshot or vector files. Pinned in Task 1 by the fixture-path diff check plus `freeze-vectors --check`.
4. **The Python reference canonicalizer diverging from RFC 8785** on non-ASCII keys (UTF-16 sort order), floats or integers above 2^53. Expected: the script refuses inputs outside its safe subset instead of emitting wrong bytes. Pinned in Task 8 by reproducing every in-subset case of `tests/bindings/vectors/canonical/v1.json` and a refusal test.
5. **ECDSA over the wrapper hashed twice or with the wrong hash** (P-384 signed with SHA-256, or ECDSA-SHA256 over `SHA-256(wrapper)`). Expected: P-256 is ECDSA with SHA-256 over the 88 wrapper bytes, P-384 is ECDSA with SHA-384, and a pre-hashed digest signature verifies identically. Pinned in Task 8 by self-checks and a double-hash negative vector.

---

## File Structure

| Path | PR | Responsibility |
|---|---|---|
| `crates/core/chio-core-types/src/crypto.rs` | 1 | Collapsed `SigningBackend` trait, static backends, trait docs |
| `crates/core/chio-core-types/tests/signing_backend_identity.rs` (new) | 1 | Fallible-identity contract tests |
| 26 further crates per the trait-plan census | 1 | Callers and impls of the collapsed trait |
| `docs/superpowers/specs/relying-party-wedge/receipt-producer-inventory.md` (new) | 2 | Receipt producers, `RedactionMode` mapping, wrapper schema-id table |
| `docs/superpowers/specs/relying-party-wedge/verdict-matrix/{anchored_root,receipt_disclosure,revocation_local}/*.json` (new, 48 files: 24, 12, 12) | 2 | Staged M1 scenarios |
| `docs/superpowers/specs/relying-party-wedge/verdict-matrix/README.md` (new) | 2 | Script vocabulary, proposed reason URNs, move-in instructions |
| `docs/adr/ADR-0039-customer-hosted-root-exchange.md` (new), `docs/adr/README.md` | 3 | ADR (D12) |
| `spec/PROTOCOL.md`, `spec/WIRE_PROTOCOL.md` | 3 | Contract text with status lines |
| `spec/schemas/chio-wire/v1/root-authority/*.schema.json` (new) | 4 | Root policy, delegation context, IdP key snapshot, verifier trust, revocation request |
| `spec/schemas/chio-wire/v1/capability/presentation.schema.json` (new) | 4 | Capability presentation |
| `spec/schemas/chio-wire/v1/receipt/{disclosure,settlement-closure}.schema.json` (new) | 4 | Receipt disclosure opening, settlement closure |
| `spec/schemas/chio-wire/v1/root-authority/examples/{valid,invalid}/*.json` (new) | 4 | Positive and negative schema instances |
| `scripts/check-root-authority-schema-examples.py` (new), `.github/workflows/ci.yml` (one line) | 4 | Validates the examples |
| `spec/schemas/registry.json`, `spec/schemas/MANIFEST.sha256`, generated code in four languages | 4 | Registration and codegen; removal of the `chio.security-event-body.v1` row (spec 2.5 G8) |
| `docs/superpowers/specs/relying-party-wedge/in-place-schemas/*.schema.json` (new) | 4 | Staged target shapes of existing v1 schemas |
| `scripts/gen-signing-wrapper-vectors.py` (new) | 5 | Reference generator and checker |
| `tests/bindings/vectors/signing/wrapper-v1.json`, `tests/bindings/vectors/receipt/committed-v1.json` (new), `tests/bindings/vectors/MANIFEST.sha256` | 5 | Vectors |

## PR Grouping

| PR | Tasks | Branch | Title | Depends on |
|---|---|---|---|---|
| 1 | 1 | `refactor/m0-signing-backend-collapse` | `refactor(core-types): collapse SigningBackend identity to one fallible public_key` | #1496, #1489 merged |
| 2 | 2, 3 | `docs/m0-rp-inventory` | `docs(superpowers): receipt producer inventory and staged root-authority scenarios` | spec fix PR merged |
| 3 | 4, 5 | `docs/m0-rp-contract` | `docs(spec): customer-hosted root exchange ADR and root-authority contract text` | PR 2 |
| 4 | 6, 7 | `feat/m0-rp-schemas` | `feat(schemas): root-authority artifact schemas` | PR 3 |
| 5 | 8, 9 | `test/m0-rp-vectors` | `test(vectors): signing-wrapper and committed-receipt reference vectors` | PR 4 |

PRs 2 to 5 contain no hand-written Rust and do not depend on PR 1; the coordinator may draft them while PR 1 is in review. Merge order is PR 1 first (D16: the collapse lands before M1 item 1), then 2, 3, 4, 5.

Verify commands (run in the PR's ws2 worktree `$W`; `cs` = `~/lanes/cslot.sh`; `T=~/lanes/s0-targets/m0-<pr>`):

**PR 1**
```bash
cd $W && git fetch -q https://github.com/bb-connor/arc.git main:refs/remotes/origin/main
CRATES=$(git diff --name-only origin/main...HEAD -- crates | awk -F/ '{print $1"/"$2"/"$3"/Cargo.toml"}' | sort -u | xargs -n1 sed -n 's/^name = "\(.*\)"$/\1/p;T;q')
for c in $CRATES; do CARGO_TARGET_DIR=$T cs cargo test -p $c --no-fail-fast; CARGO_TARGET_DIR=$T cs cargo clippy -p $c --all-targets -- -D warnings; done
CARGO_TARGET_DIR=$T cs cargo test -p chio-core-types --features fips --no-fail-fast
cargo fmt --all --check
CARGO_TARGET_DIR=~/lanes/s0-targets/workspace cs cargo check --locked --workspace --all-targets
CARGO_TARGET_DIR=~/lanes/s0-targets/workspace cs cargo check --locked --workspace --all-targets --all-features
python3 scripts/check-security-clocks.py && python3 scripts/check-escape-hatches.py && python3 scripts/check-negative-assertions.py && python3 scripts/check-trust-boundaries.py && python3 scripts/check-rust-file-hygiene.py && bash scripts/check-http-egress-contract.sh && python3 scripts/check-error-urn-registry.py && python3 scripts/check-wire-schemas.py && bash scripts/check-chio-schema-registry.sh && bash scripts/check-adapter-no-bypass.sh && python3 scripts/check-domain-separation.py && python3 scripts/check-kani-crypto-scope.py && python3 scripts/check-kani-public-harnesses.py
CARGO_TARGET_DIR=$T cs cargo xtask check formal-mirrors && CARGO_TARGET_DIR=$T cs cargo xtask gen proof-coverage --check && CARGO_TARGET_DIR=$T cs cargo xtask freeze-vectors --check
git diff --name-only origin/main...HEAD | grep -E '\.(json|ndjson|snap|bin|cbor|hex)$|/fixtures/|/snapshots/|^tests/bindings/' ; test $? -eq 1   # byte-neutral: prints nothing
```
Kernel, control-plane and cli suites run on the x86 worker per the lead's practice (launch with `setsid -f`, `< /dev/null` inside ssh heredocs, tar logs back before stopping the worker).

**PR 2**
```bash
git diff --name-only origin/main...HEAD | grep -v '^docs/superpowers/' ; test $? -eq 1
grep -rn $'\xe2\x80\x94' docs/superpowers/specs/relying-party-wedge ; test $? -eq 1
python3 -I -c 'import json,pathlib,sys; [json.loads(p.read_bytes()) for p in pathlib.Path(sys.argv[1]).rglob("*.json")]' docs/superpowers/specs/relying-party-wedge/verdict-matrix
```

**PR 3**
```bash
grep -n $'\xe2\x80\x94' spec/PROTOCOL.md spec/WIRE_PROTOCOL.md docs/adr/ADR-0039-customer-hosted-root-exchange.md docs/adr/README.md ; test $? -eq 1
grep -n -i -E '\bM[0-3]\b|wedge|pilot|docs/superpowers' spec/PROTOCOL.md spec/WIRE_PROTOCOL.md docs/adr/ADR-0039-customer-hosted-root-exchange.md ; test $? -eq 1
bash scripts/check-chio-owned-v1-only.sh && python3 scripts/check-native-host-docs.py
CARGO_TARGET_DIR=$T cs cargo test -p chio-spec-validate --no-fail-fast
CARGO_TARGET_DIR=$T cs cargo test -p chio-core-types --test claim_registry_integrity --no-fail-fast
```

**PR 4**
```bash
bash scripts/check-chio-schema-registry.sh && bash scripts/tests/check-chio-schema-registry.test.sh && bash scripts/check-chio-owned-v1-only.sh
uv run --with jsonschema==4.26.0 --with referencing==0.37.0 python3 -I scripts/check-root-authority-schema-examples.py
bash -lc "cd $W && make codegen-check && cargo xtask snippets regen --check"
CARGO_TARGET_DIR=$T cs cargo test -p chio-core-types --no-fail-fast && CARGO_TARGET_DIR=$T cs cargo clippy -p chio-core-types --all-targets -- -D warnings
CARGO_TARGET_DIR=~/lanes/s0-targets/workspace cs cargo check --locked --workspace --all-targets
python3 scripts/check-wire-schemas.py && cargo fmt --all --check
# plus the own test, lint and typecheck of every SDK package whose generated file changed
```

**PR 5**
```bash
uv run --with cryptography==44.0.3 --with jsonschema==4.26.0 --with referencing==0.37.0 python3 -I scripts/gen-signing-wrapper-vectors.py check
CARGO_TARGET_DIR=$T cs cargo xtask freeze-vectors --check
CARGO_TARGET_DIR=$T cs cargo test -p chio-conformance --test vectors_schema_pair --no-fail-fast
CARGO_TARGET_DIR=$T cs cargo test -p chio-binding-helpers --test vector_fixtures --no-fail-fast
bash -lc "cd $W && ./scripts/check-bindings-parity.sh"
```

---

### Task 1: `SigningBackend` collapse (PR 1, D16, parallel lead's trait plan)

Follows `ws2:~/lanes/claude-pr1160-evidence/keyring/trait-plan.md` (base `3356f1adc0`; prerequisites #1511 and #1513 are merged). Census from the lead's compiler probe: 136 first-layer error sites in 26 files, 36 trait impls in 9 crates, about 1.5k to 2.5k changed lines, 27 candidate crates. Byte-neutral: no signed byte, fixture or vector changes. `sign_canonical_bytes` stays (deleted in M1 with the wrapper).

**Files:**
- Modify: `crates/core/chio-core-types/src/crypto.rs:896-1020` (trait, `SigningOutcome` docs, `Ed25519Backend`, `P256Backend`, `P384Backend`, `HybridBackend`, `#[cfg(kani)]` blocks)
- Create: `crates/core/chio-core-types/tests/signing_backend_identity.rs`
- Modify (core-types callers and tests): `src/signer_binding.rs`, `src/capability/*`, `src/receipt/*`, `tests/{crypto_wire_bounds,signer_binding,wire_protocol_schema,hybrid_bitflip,capability_hybrid}.rs`
- Modify (leaf crates): `chio-custody-hw`, `chio-attest-verify`, `chio-finding`, `chio-decoy`, `chio-kernel-core` (`src/receipts.rs`, `src/kani_public_harnesses.rs`), `chio-signing-remote`, `chio-attest-loopback`, `chio-cage`
- Modify: `crates/security/chio-keyring/src/router.rs:484-650`, `src/witness.rs`, `src/runtime.rs`, `src/sqlite_parts/part_01.rs`, `src/sqlite/synchronization_tests.rs`
- Modify: `crates/kernel/chio-kernel/src/kernel/signing_authority.rs:142-200`, `src/kernel/threshold_issuance.rs:14`, `src/authority.rs:350-360,530-540,636-660,1205-1225`, and every `receipt_signing_public_key` and `authority_public_key` caller
- Modify: `chio-secret-broker`, `chio-security-kernel`, `chio-federation` (`src/trust_establishment.rs:676`), `chio-federation-transport-iroh`, `chio-store-sqlite`, `chio-credit`, `chio-active-response-authority`, `chio-tool-call-fabric`
- Modify: `crates/platform/chio-control-plane/src/keyring_runtime.rs:43-80,1760-1830`, `src/issuance/authority.rs:148`, `src/issuance/tests.rs:333`, `src/security/orchestration.rs:699`, `src/security/response_simulation.rs:202`; `chio-cli`, `chio-finding-worker`, `chio-finding-hosted-edge`, `chio-finding-market-server`, `chio-conformance`, `chio-kernel-browser`, `chio-core`
- Modify: docs naming the deleted methods (`git grep -n "current_public_key\|SigningBackend::algorithm\|\.algorithm()" -- docs spec sdks crates/*/*/README.md`)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces (M1 item 1 builds on this exact shape):
  ```rust
  pub trait SigningBackend: Send + Sync {
      fn public_key(&self) -> Result<PublicKey>;
      fn sign_bytes(&self, message: &[u8]) -> Result<Signature>;
      fn sign_bytes_with_identity(&self, message: &[u8]) -> Result<SigningOutcome>;   // default
      fn sign_bytes_for_identity(&self, expected: &PublicKey, message: &[u8]) -> Result<SigningOutcome>; // default
      fn sign_canonical_bytes(&self, canonical: &CanonicalBytes<CanonicalJsonWitness>) -> Result<Signature>; // default
  }
  ```
  Deleted: `algorithm()`, `current_public_key()`. Algorithm comes from `public_key()?.algorithm()` or `SigningOutcome::algorithm`. Static backends return `Ok(..)`; no inherent infallible accessor on them (holders of a concrete `Keypair` keep `Keypair::public_key()`).
- Cascade signatures:
  - `ChioKernel::receipt_signing_public_key(&self) -> Result<chio_core::PublicKey, KernelError>` (error mapped to `KernelError::ReceiptSigningFailed(e.to_string())`)
  - `ChioKernel::threshold_proposal_signing_key(&self) -> Result<chio_core::PublicKey, KernelError>` (same variant)
  - `CapabilityAuthority::authority_public_key(&self) -> Result<PublicKey, KernelError>` (map to `KernelError::CapabilityIssuanceFailed`); default `trusted_public_keys` returns `self.authority_public_key().map(|k| vec![k]).unwrap_or_default()` (empty trust on error); doc comment states the identity is the key the authority signs with now
  - `TrustEstablishment::local_public_key(&self) -> Result<PublicKey, chio_core::Error>` (use the struct's real name in `trust_establishment.rs`)
  - control-plane `signer_public_key` and `ProductionResponseSimulator::signing_identity` return `Result<chio_core::PublicKey, chio_core::Error>`
  - Forwarders (`SharedSigningBackend`, `MigrationGuardedSigningBackend`, `KeyringAuthoritySigningBackend`) delete the removed methods and forward `public_key()`; `HybridBackend::new` reads `classical.public_key()?`
  - Keyring router: `public_key()` is one fallible selector read; `selected_public_key` and the `PoisonError` recovery read are deleted.

- [ ] **Step 1: Confirm preconditions and base.** On ws2: `gh pr view 1496 --repo bb-connor/arc --json state` and same for 1489 report `MERGED`; the coordinator's worktree is on fresh `origin/main`. Post `<UTC> arc-5b: lane start m0-collapse (SigningBackend collapse per keyring/trait-plan.md, byte-neutral)` to `sync.md`.

- [ ] **Step 2: Write the failing core-types tests** in `crates/core/chio-core-types/tests/signing_backend_identity.rs`:

```rust
#![allow(clippy::expect_used, clippy::unwrap_used)]
struct UnreadableIdentity { signed: AtomicBool }
impl SigningBackend for UnreadableIdentity {
    fn public_key(&self) -> Result<PublicKey> { Err(Error::InvalidPublicKey("selector unreadable".into())) }
    fn sign_bytes(&self, _: &[u8]) -> Result<Signature> { self.signed.store(true, SeqCst); Err(Error::InvalidSignature("unreachable".into())) }
}

#[test]
fn identity_signing_fails_before_signing_when_identity_is_unreadable() {
    let backend = UnreadableIdentity { signed: AtomicBool::new(false) };
    let err = backend.sign_bytes_with_identity(b"m").unwrap_err();
    assert!(matches!(err, Error::InvalidPublicKey(ref m) if m == "selector unreadable"));
    let key = Keypair::from_seed(&[7u8; 32]).public_key();
    assert!(backend.sign_bytes_for_identity(&key, b"m").is_err());
    assert!(!backend.signed.load(SeqCst));
}

#[test]
fn static_backends_report_identity_through_fallible_public_key() {
    let kp = Keypair::from_seed(&[7u8; 32]);
    let backend = Ed25519Backend::new(kp.clone());
    assert_eq!(backend.public_key().unwrap(), kp.public_key());
    assert_eq!(backend.public_key().unwrap().algorithm(), SigningAlgorithm::Ed25519);
    let outcome = backend.sign_bytes_with_identity(b"m").unwrap();
    assert_eq!(outcome.public_key, kp.public_key());
    assert_eq!(outcome.algorithm, SigningAlgorithm::Ed25519);
}
```
(Use the crate's existing seed constructor name if it differs from `from_seed`.)

- [ ] **Step 3: Run and confirm failure.** `CARGO_TARGET_DIR=$T cs cargo test -p chio-core-types --test signing_backend_identity`. Expected: compile error (`public_key` returns `PublicKey`, `UnreadableIdentity` missing `algorithm`).

- [ ] **Step 4: Change the trait and core-types** (trait-plan order item 1). Default `sign_bytes_with_identity` reads `let public_key = self.public_key()?; let algorithm = public_key.algorithm();` then signs and verifies as today. Update the four static backends, `#[cfg(kani)]` blocks in `crypto.rs`, and every core-types caller and test. Rewrite the trait and `SigningOutcome` docs to drop the "compatibility identity" text.

- [ ] **Step 5: Run core-types.** `cs cargo test -p chio-core-types --no-fail-fast` and `cs cargo test -p chio-core-types --features fips --no-fail-fast`. Expected: PASS, including Step 2 tests.

- [ ] **Step 6: Leaf crates** (trait-plan order item 2): custody-hw, attest-verify, finding, decoy, kernel-core, signing-remote, attest-loopback, cage. Then grep `#[cfg(kani)]` regions in `chio-kernel-core/src/receipts.rs` and `src/kani_public_harnesses.rs` for `.algorithm()`, `.public_key()` on backends and `current_public_key` and update by hand (cargo never compiles them). Run each crate's tests and clippy.

- [ ] **Step 7: Keyring** (order item 3). Add to the router tests: `keyring_public_key_errors_when_selector_lock_is_poisoned` (poison the selector `RwLock` by panicking a thread that holds the write guard, then assert `backend.public_key().is_err()` and `backend.sign_bytes_with_identity(b"m").is_err()`). Expected FAIL before the router change only if poison is currently recovered; it passes after. Then make the change and run `cs cargo test -p chio-keyring --no-fail-fast`.

- [ ] **Step 8: Kernel and the remaining trust crates** (order item 4). Rewrite the existing `UnreadableSelectorBackend` test double in `authority.rs` (~line 1205) so `public_key()` returns `Err(InvalidPublicKey("selector unavailable"))`; keep `governed_authority_without_a_current_key_trusts_nothing_and_refuses_issuance` and add the assertion `assert!(matches!(authority.authority_public_key(), Err(KernelError::CapabilityIssuanceFailed(_))))`. Add `receipt_signing_public_key_fails_closed_on_unreadable_identity` in the `signing_authority` tests, installing the double as the receipt backend through the existing test construction path, asserting `Err(KernelError::ReceiptSigningFailed(_))` and that no receipt is appended. Then convert secret-broker, security-kernel, federation, federation-transport-iroh, store-sqlite, credit, active-response-authority, tool-call-fabric. Run each crate.

- [ ] **Step 9: Control plane, products, docs** (order items 5 and 6): control-plane, cli, finding-worker, finding-hosted-edge, finding-market-server, conformance, kernel-browser, chio-core; then docs that name the deleted methods.

- [ ] **Step 10: Full PR 1 verify list** (PR Grouping section). Expected: every command passes; the byte-neutral check prints nothing; `--all-features` check passes.

- [ ] **Step 11: Format, review the index, commit, push.**
```bash
cargo fmt --all && git add -A crates docs spec && git diff --cached --stat -M
git commit -m "refactor(core-types): collapse SigningBackend identity to one fallible public_key" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push https://github.com/bb-connor/arc.git refactor/m0-signing-backend-collapse
```
Layer commits inside the branch are allowed; the PR lands as one squash merge so `main` never carries a half-collapsed trait.

- [ ] **Step 12: REVIEW? and PR.** Post `<UTC> arc-5b: REVIEW? #<N> SigningBackend collapse, byte-neutral, touches kernel/keyring/control-plane`. PR body: trait-plan reference, census numbers, verify commands with pass lines, the empty byte-neutral diff, and "No signed bytes change; the signing wrapper is a later change."

---

### Task 2: Receipt producer and signed-artifact inventory (PR 2)

Spec 7.6 item 3, 10.3 "M0 task", 12 M0 exit "producer inventory checked in".

**Files:**
- Create: `docs/superpowers/specs/relying-party-wedge/receipt-producer-inventory.md`

**Interfaces:**
- Consumes: nothing.
- Produces three tables later tasks read by heading name:
  - `## Receipt producers`: columns `producer | crate:file:line | signing entry point | holds content preimage (yes/no) | salt source (spec 7.8 row) | commit order`. "Commit order" is the commit group inside the single squash-merged M1 item 2 PR (spec 2.5 G1).
  - `## RedactionMode mapping`: one row per non-test `RedactionMode::Summary` or `RedactionMode::Redacted` producer or reader, columns `file:line | current mode | target (fully committed, or committed with inline fields after inline disclosure exists) | reason`. Known rows at `d0482967b8`: `receipt/metadata.rs:63,75`, `chio-kernel/.../execution_validation.inc:494,675`, `response_simulation_report.rs:130`, `chio-lineage/src/ingest_active_defense.rs:199`, `chio-otel-receipt-exporter/src/sink.rs:268`, `chio-control-plane/src/keyring_runtime.rs:1129`, `security/adapters/native_evidence.rs:112,584`, `security/event_consumer/verification.rs:319`, `chio-cage/src/receipt.rs:345,421`.
  - `## Wrapper schema ids`: columns `signed artifact type | signing helper or call site | wrapper schema_id | registered in registry.json (yes / assign)`. Every signed canonical-JSON artifact type reached through `sign_canonical_with_backend*`, `sign_shared_canonical_with_backend`, `sign_canonical_bytes`, `sign_bytes_with_identity` over canonical bytes, or `Keypair` canonical signing. Types with no registered id get an assigned `chio.<name>.v1` id (at least `DelegationLink` -> `chio.delegation-link.v1`; Chio DPoP proofs use `chio.dpop_proof.v1`, spec 2.5 G10). Task 5 copies this table into PROTOCOL 4.5; Task 8 uses its ids. The spec 2.5 decisions reconcile the table and the staged 4.5 table.

- [ ] **Step 1: Generate the raw lists** on ws2 at the rebased `origin/main`:
```bash
git grep -n -E "sign_receipt(_with_handle|_relaying_trusted_body)?\(|ChioReceipt::sign(_with_backend|_with_handle|_with_backend_using_handle|_with_bbs|_prepared_with_bbs)?\(" origin/main -- crates sdks ':!**/tests/**' ':!*_tests.rs'
git grep -n "RedactionMode::\(Summary\|Redacted\)" origin/main -- crates sdks ':!**/tests/**'
git grep -n -E "sign_canonical_with_backend|sign_shared_canonical_with_backend|sign_canonical_bytes|sign_canonical\(" origin/main -- crates ':!**/tests/**'
```
Include out-of-workspace emitters (`sdks/lambda/chio-lambda-extension`) and the FFI/WASM relay users (`chio-kernel-browser`, `chio-kernel-mobile`, `chio-cpp-kernel-ffi`, `chio-bindings-ffi`).

- [ ] **Step 2: Write the three tables.** Every row cites `file:line` at the inventoried commit, recorded in the doc header as `Inventoried at origin/main <sha>`. Completeness check: the count of rows in `## Receipt producers` equals the count of distinct non-test call sites from the first grep.

- [ ] **Step 3: Commit** (`docs(superpowers): inventory receipt producers and wrapper schema ids`) with the trailer.

---

### Task 3: Staged verdict-matrix scenarios for the three M1 categories (PR 2)

Spec 11.3, 12 M0 exit "scenario files written (expected to fail)". The live corpus cannot hold them yet: `ScenarioCategory` in `crates/tooling/chio-conformance/verdict_matrix/src/lib.rs:49` is a closed enum, `manifest.toml` pins counts and an index hash, and `rust-kernel` is a required driver. "Expected to fail" in M0 therefore means staged and not executed.

**Files:**
- Create: `docs/superpowers/specs/relying-party-wedge/verdict-matrix/README.md`
- Create: 24 files under `.../verdict-matrix/anchored_root/` and 12 each under `.../receipt_disclosure/` and `.../revocation_local/` (anchored_root 013 to 016 added by the gap PR and 017 to 024 by the registry and strict-decoding PR, spec 2.5 "Count")

**Interfaces:**
- Consumes: anchor-kind names from the spec fix PR (Global Constraints).
- Produces: scenario files in the existing `chio.verdict-matrix.scenario.v1` shape (`schema, id, title, category, description, tags, requires, script, expected{verdict, reason_code, scope_set}`), one JSON object per line-free file, with `category` set to the new value (`anchored_root`, `receipt_disclosure`, `revocation_local`) and `requires: ["rust-kernel", "rust-mcp-serve-http"]`. `script` uses `{"operation": "tool.call" | "exchange" | "export" | "policy.load", "setup": [<named fixtures>], "mutation": <named mutation or null>}`; the README defines every fixture and mutation name used. M1 moves each directory into `verdict_matrix/scenarios/`, adds the enum variants and `SCENARIOS.md` values, and re-pins `manifest.toml`.

Scenario ids and expected verdicts (reason URNs use existing error domains per spec 2.5 G12 and are registered in `spec/errors/registry.yaml` by the M1 PR that first emits each):

| Category | Id suffix | Verdict | reason_code |
|---|---|---|---|
| anchored_root | 001-id-jag-allow | allow | (allow code used by existing allow scenarios) |
| | 002-oidc-jwt-allow | allow | same |
| | 003-introspection-allow | allow | same |
| | 004-local-as-allow | allow | same |
| | 005-operator-root-allow | allow | same |
| | 006-static-bearer-configured-principal-allow | allow | same |
| | 007-entra-generic-one-root-per-uti-allow | allow | same |
| | 008-public-client-jwt-bearer-deny | deny | `urn:chio:error:transport:exchange-client-unauthenticated` |
| | 009-replayed-id-jag-jti-deny | deny | `urn:chio:error:transport:exchange-replay` |
| | 010-root-without-anchor-deny | deny | `urn:chio:error:capability:root-anchor-missing` |
| | 011-expires-after-assertion-exp-deny | deny | `urn:chio:error:capability:root-anchor-lifetime` |
| | 012-entra-uti-bound-to-other-token-deny | deny | `urn:chio:error:transport:exchange-replay` |
| | 013-entra-multi-tenant-issuer-deny | deny | `urn:chio:error:transport:exchange-issuer-not-allowed` |
| | 014-entra-uti-reuse-after-root-expiry-deny | deny | `urn:chio:error:transport:exchange-replay` |
| | 015-entra-issuer-on-oidc-jwt-rule-rejected-at-load | deny | `urn:chio:error:policy:root-policy-entra-issuer-on-oidc-rule` |
| | 016-root-signed-by-unlisted-exchange-key-deny | deny | `urn:chio:error:capability:root-exchange-key-untrusted` |
| | 017-provider-disabled-after-root-issued-deny | deny | `urn:chio:error:capability:root-provider-unavailable` |
| | 018-provider-removed-before-exchange-deny | deny | `urn:chio:error:transport:exchange-provider-unavailable` |
| | 019-provider-registry-unreadable-at-exchange-deny | deny | `urn:chio:error:transport:exchange-provider-registry-unreadable` |
| | 020-provider-identity-changed-without-policy-deny | deny | `urn:chio:error:transport:exchange-provider-identity-mismatch` |
| | 021-provider-registry-unreadable-at-admission-deny | deny | `urn:chio:error:capability:root-provider-unavailable` |
| | 022-root-anchor-unknown-member-deny | deny | `urn:chio:error:capability:strict-decode-rejected` |
| | 023-capability-algorithm-member-deny | deny | `urn:chio:error:capability:strict-decode-rejected` |
| | 024-root-policy-unknown-member-rejected-at-load | deny | `urn:chio:error:policy:root-policy-strict-decode-rejected` |
| receipt_disclosure | 001-allow-receipt-fully-committed | allow | allow code |
| | 002-deny-receipt-fully-committed | deny | existing scope-deny code |
| | 003-undeclared-guard-evidence-field-dropped | allow | allow code |
| | 004-argument-marker-absent-from-metadata | allow | allow code |
| | 005-tenant-id-with-authority-fails-signing | deny | `urn:chio:error:attest:receipt-tenant-id-with-authority` |
| | 006-stream-chunk-digests-absent | allow | allow code |
| | 007-auditor-hash-only-export-has-no-salts | allow | allow code |
| | 008-auditor-salt-only-opening-refused | deny | `urn:chio:error:attest:export-salt-only-opening` |
| | 009-caller-export-requires-tenant-tag | deny | `urn:chio:error:attest:export-tenant-tag-required` |
| | 010-caller-export-contains-only-own-tenant | allow | allow code |
| | 011-inline-tools-map-rejected-at-load | deny | `urn:chio:error:policy:root-policy-inline-disclosure-unavailable` |
| | 012-inline-pointer-rejected-at-load | deny | same as 011 |
| revocation_local | 001-capability-id-denies-next-call | deny | existing capability-revoked code |
| | 002-capability-cascade-denies-descendant | deny | same |
| | 003-root-policy-rule-denies | deny | same |
| | 004-anchor-subject-denies | deny | same |
| | 005-tenant-tag-denies | deny | same |
| | 006-replay-key-denies | deny | same |
| | 007-matching-revocation-blocks-mint | deny | `urn:chio:error:transport:exchange-revoked` |
| | 008-store-error-denies | deny | `urn:chio:error:kernel:revocation-store` (converted from `CHIO-KERNEL-REVOCATION-STORE` in M1 item 5) |
| | 009-acknowledged-revocation-seen-by-later-admission | deny | capability-revoked code |
| | 010a-revocation-before-capture-denies | deny | capability-revoked code (replaces 010 in M1 item 5) |
| | 010b-revocation-after-capture-before-receipt-check-denies | deny | capability-revoked code (replaces 010 in M1 item 5) |
| | 010c-revocation-after-receipt-check-appends-allowed | allow | allow code (replaces 010 in M1 item 5) |
| | 011-subject-revocation-stores-tag-only | deny | capability-revoked code |
| | 012-unrelated-subject-unaffected | allow | allow code |

Scenarios 011 and 012 of `receipt_disclosure` flip to allow when inline disclosure lands (README states this). Fixture timestamps are fixed (`issued_at = 1792234800`).

- [ ] **Step 1: Write README.md** defining the fixture names (IdP stub JWKS, ID-JAG minter, confidential client key, static bearer token plus configured principal, generic Entra token with `uti`, root policy fixture), the mutation names, the URN proposals above, and the move-in checklist for M1.
- [ ] **Step 2: Write the 48 files.** Copy existing `reason_code` values for allow and revocation denies from `verdict_matrix/scenarios/capability_subset/` and `revocation_propagation/`.
- [ ] **Step 3: Validate** with the PR 2 JSON-parse command plus: every file has `schema == "chio.verdict-matrix.scenario.v1"`, a unique `id`, and the category of its directory (one `python3 -I -c` loop; expected: no output).
- [ ] **Step 4: Commit** (`docs(superpowers): stage root-authority verdict-matrix scenarios`), then open PR 2. No REVIEW? needed (not a shared surface).

---

### Task 4: ADR-0039 customer-hosted root exchange (PR 3, D12, merged as #1533)

**Files:**
- Create: `docs/adr/ADR-0039-customer-hosted-root-exchange.md` (0039, because ADR-0038 reserves 0023 to 0037)
- Modify: `docs/adr/README.md` (append item 22)

**Interfaces:**
- Consumes: spec section 15 outline, corrected per Global Constraints.
- Produces: an ADR with `- Status: Proposed` (the founder changes it to `Accepted`; Task 5's 8.2 edit depends on that), sections Context, Decision, Scope, Security properties, Standards pinned, Consequences, Alternatives rejected.

- [ ] **Step 1: Write the ADR** from spec section 15 with these corrections: Decision says every `serve-http` root is exchange-issued and anchored and direct unanchored issuance is removed; it does not remove static bearer. Scope lists the bearer intakes generic OIDC JWT, introspection, generic Entra (one root per `(issuer, uti)`), Entra Agent ID, and static bearer (operator-issued root naming an explicitly configured principal), all ending in the same exchange. Consequences list self-exchange, seed-derived federation subject keys and direct issuance as removed, and the enterprise provider registry replaced by root policy rules only if the spec fix PR keeps that deletion. No milestone labels; the qualification consequence reads "the hosted-edge qualification lane re-runs on the anchored flow and the qualified label is suspended, publicly, until it passes."
- [ ] **Step 2: Check** with the PR 3 em-dash and public-path greps. Expected: no output.
- [ ] **Step 3: Commit** (`docs(adr): propose the customer-hosted root exchange`).

---

### Task 5: PROTOCOL and WIRE_PROTOCOL contract text (PR 3, spec 10.10)

**Coordinator override (2026-10-17):** while the founder has not ruled on mirror policy for unimplemented formats, the new PROTOCOL and WIRE_PROTOCOL subsections are written as staged files under `docs/superpowers/specs/relying-party-wedge/protocol/` (one file per target section, each naming its insertion point) instead of editing `spec/PROTOCOL.md` and `spec/WIRE_PROTOCOL.md`. Each M1 code PR moves its section into place. The ADR still lands in `docs/adr/`. The verify greps below then apply to the staged files and the ADR.

`spec/PROTOCOL.md` describes the shipped contract. Text for formats no code implements yet is added as new subsections, each opening with this exact line:

> Status: specified, not implemented. Implementations emit and accept the formats in the sections this one names until this line is removed.

Existing text that describes current behavior (section 6 field table, WYSIWYS exception paragraph, 10.3, the section 14 gap line) is not rewritten in M0; the code PR that changes the behavior rewrites it and removes the status line.

**Files:**
- Modify: `spec/PROTOCOL.md` (insert after 4.4, after 5.5, after "Receipt Identity And DAG", in 6.1, after 6.6, in 8.2 when the ADR is accepted)
- Modify: `spec/WIRE_PROTOCOL.md` (new 3.6 after 3.5)

**Interfaces:**
- Consumes: Task 2 `## Wrapper schema ids` table; Task 4 ADR path; anchor-kind names per Global Constraints.
- Produces (anchors later tasks and M1 PRs cite):
  - `### 4.5 Signing Wrapper`: spec 7.0 verbatim in substance: 88-byte layout `"chio.signing-wrapper.v1" || 0x00 || SHA-256(utf8(schema_id)) || SHA-256(canonical_body)`; schema id from verification context only; domain separation from JWS; algorithm binding; Ed25519 over wrapper bytes; ML-DSA-65 over wrapper bytes with empty context; P-256 ECDSA with SHA-256 over the wrapper, P-384 ECDSA with SHA-384; hybrid signs the same 88 bytes with both halves; signature encodings unchanged; the schema-id table from Task 2.
  - `### 5.6 Anchored Roots And The Relying-Party Exchange`: `root_anchor` (7.1), anchor kinds (7.2, with the corrected kind set: `oauth_id_jag`, `oidc_jwt`, `oauth_introspection`, `chio_local_as`, `chio_operator_key`, static bearer kind, generic Entra kind, `entra_agent_id`), delegation context (7.3), root policy and IdP key snapshot (7.4), capability presentation (7.5), revocation targets and caller revocation request (7.11), tenant and subject tags and verifier trust (7.12), fail-closed rules (8.1 to 8.3), and a "Deployment limits" paragraph (one process per state directory, advisory lock, local filesystem, stop-then-start, backup rewinds replay).
  - `### Committed Receipts And Disclosure` (unnumbered, after "Receipt Identity And DAG"): 7.6 commitments, `disclosure`, `authority`, `tenant_id` exclusion; 7.7 openings; 7.8 producer salt sources; 7.12 export profiles.
  - In 6.1, a paragraph `pdp_decision receipts` (7.9) under the status line.
  - `### 6.7 Settlement Block And Closure` (7.10, typed asset, testnet allowlist rule).
  - 8.2: after the founder marks the ADR Accepted, replace "blocked until the OAuth AS ADR or equivalent decision note is accepted" with a sentence naming the ADR and its scope. If not yet accepted when PR 3 is ready, leave 8.2 unchanged and say so in the PR body.
  - WIRE_PROTOCOL `### 3.6 Capability Presentation And Receipt Copy`: `_meta.chioCapability` (presentation, same duplicate-key and original-bytes discipline as `_meta.chioDpopProof`) and `_meta.chioReceipt` (signed receipt plus `chio.receipt-disclosure.v1` opening), with the status line.
- Key encoding: all keys use the existing `PublicKey::to_hex` form (bare 64-hex Ed25519, `p256:<130 hex>`, `p384:<194 hex>`, `hybrid:...`). The spec's `ed25519:` examples are illustrative.

- [ ] **Step 1: Write the PROTOCOL subsections** in the order above.
- [ ] **Step 2: Write WIRE_PROTOCOL 3.6.**
- [ ] **Step 3: Run the PR 3 verify commands.** Expected: all pass; the `chio-spec-validate` ladder test still finds its markers.
- [ ] **Step 4: Commit** (`docs(spec): specify the signing wrapper, anchored roots and committed receipts`), post `REVIEW? #<N> PROTOCOL 4.5/5.6/6.x text, no code`, open PR 3.

---

### Task 6: New-artifact JSON schemas, registry and codegen (PR 4)

**Files:**
- Create under `spec/schemas/chio-wire/v1/`: `root-authority/root-policy.schema.json`, `root-authority/delegation-context.schema.json`, `root-authority/idp-key-snapshot.schema.json`, `root-authority/verifier-trust.schema.json`, `root-authority/revocation-request.schema.json`, `root-authority/root-anchor.schema.json` (shared `$defs`: `RootAnchor`, `AnchorKind`, `Commitment`, `Digest`, `PublicKeyHex`), `capability/presentation.schema.json`, `receipt/disclosure.schema.json`, `receipt/settlement-closure.schema.json`
- Create: `spec/schemas/chio-wire/v1/root-authority/examples/valid/*.json`, `.../examples/invalid/*.json`
- Create: `scripts/check-root-authority-schema-examples.py`
- Modify: `spec/schemas/registry.json`, `spec/schemas/MANIFEST.sha256`, `spec/schemas/chio-wire/v1/README.md`, `.github/workflows/ci.yml` (one `run_gate` line beside `check-chio-schema-registry.sh` at about line 258; coordinator pushes)
- Regenerate: `crates/core/chio-core-types/src/_generated/chio_wire_v1.rs` and the Python, TS and Go generated outputs (`make codegen` lanes)

**Interfaces:**
- Consumes: Task 5 text (field names and rules); Global Constraints kind names.
- Produces:
  - `$id` = `https://chio-protocol.dev/schemas/chio-wire/v1/<dir>/<file>` (sibling convention of `capability/token.schema.json`).
  - Every object `additionalProperties: false`; `schema` member `const` to its id; closed enums for `kind`, `holder` (`edge_session`, `caller`), `disclosure.default` (`committed` only), `recorded_claims` values (`plain`, `committed`), settlement `state` and `rail_refs[].kind`; digests `^sha256:[0-9a-f]{64}$`; salts `^b64u:[A-Za-z0-9_-]{43}$` (32 bytes, unpadded); amounts `^(0|[1-9][0-9]*)$`; timestamps non-negative integers; `max_clock_skew_secs` maximum 60; no provider identity member (issuer, `jwks_url`, inline `jwks`, introspection endpoint) in any schema except `chio.enterprise-provider-identity.v1`, because that identity lives in the enterprise provider registry record and rules reference `provider_record_id` plus `provider_identity_digest` (digest pattern as above); `allowed_algs` items exclude `none` and `HS*`; public keys reuse the issuer-key pattern from `capability/token.schema.json`.
  - Optional ID-JAG retention slot present (D7): `retain_idp_artifact` on rules, `artifact_retained` in the context anchor.
  - Registry rows (signed artifacts only), `introducedBy: "root-authority-v1"`: `chio.root-policy.v1` (`root_policy`), `chio.idp-key-snapshot.v1` (`idp_key_snapshot`), `chio.revocation-request.v1` (`revocation_request`), `chio.settlement-closure.v1` (`settlement_closure`). `KNOWN_SIGNED_ARTIFACT_SCHEMAS` is not touched (Rust lands with the types; the parity tests only check Rust-to-registry).
  - Registry removal (spec 2.5 G8): delete the `chio.security-event-body.v1` row. The body schema file stays; it is already the `payloadSchemaFile` of `chio.signed-security-event.v1`, and no Rust constant names the body id. The `chio.dpop_proof.v2` row is not touched here; its removal follows #1489 in the parallel lead's lane (spec 2.5 G10).
  - Not registered here (spec 2.5 G11): the existing wrapper ids that are not yet in the registry. M1 item 1 registers each with its Rust type and schema, in the wrapper PR.
  - No error-domain change (spec 2.5 G12).
  - `check-root-authority-schema-examples.py`: validates every `examples/valid/*.json` against the schema named by its `schema` member (Draft 2020-12, local `referencing` registry over `spec/schemas/chio-wire/v1`) and requires every `examples/invalid/*.json` to fail; exits non-zero otherwise.

- [ ] **Step 1: Write the invalid examples first** (one file per rule): root policy with `default: "inline"`; rule with `allowed_algs: ["HS256"]`; `max_clock_skew_secs: 61`; a rule that carries a provider endpoint member instead of `provider_record_id` and `provider_identity_digest`; unknown anchor kind; delegation context with an extra member; salt with `=` padding; salt of 31 bytes; digest in uppercase hex; settlement closure with `state: "refunded"`; presentation missing `leaf`; verifier trust with unknown member.
- [ ] **Step 2: Write the check script and run it.** `uv run --with jsonschema==4.26.0 --with referencing==0.37.0 python3 -I scripts/check-root-authority-schema-examples.py`. Expected: FAIL (schemas missing).
- [ ] **Step 3: Write the schemas and the valid examples** (one per schema, using the spec section 7 examples with corrected key encoding and fixed timestamps). Run the check. Expected: PASS.
- [ ] **Step 4: Register and hash.** Add the four registry rows and remove the `chio.security-event-body.v1` row (keep the file's ordering), regenerate `MANIFEST.sha256` deterministically (the format `check-chio-schema-registry.sh` recomputes), update the v1 README index.
- [ ] **Step 5: Regenerate code.** `bash -lc "cd $W && cargo xtask codegen --lang rust && cargo xtask codegen --lang python && cargo xtask codegen --lang ts && cargo xtask codegen --lang go"`. If a generator needs xtask post-processing changes for a new schema, simplify the schema construct instead; if that is impossible, stop and report to the coordinator (no hand edits to generated files or xtask in M0).
- [ ] **Step 6: Run the PR 4 verify commands.** Expected: all pass; `wire_protocol_schema.rs` unchanged and green (live receipts still validate against the unchanged `record.schema.json`).
- [ ] **Step 7: Commit** (`feat(schemas): add root-authority artifact schemas`).

---

### Task 7: Staged in-place target schemas (PR 4)

These existing v1 schemas change in place, and `crates/core/chio-core-types/tests/wire_protocol_schema.rs` validates live serialization against them, so they move only with the code that changes the bytes.

**Files:**
- Create under `docs/superpowers/specs/relying-party-wedge/in-place-schemas/`: `capability/token.schema.json` (adds `root_anchor` by `$ref` to `root-authority/root-anchor.schema.json`), `receipt/record.schema.json` (commitments, `parameters_inline`, `result_inline`, `disclosure`, `authority`, no `redaction_mode`, no `parameters` or `parameter_hash` or `content_hash`, `tenant_id` forbidden when `authority` present, plus `enforcement` and `pdp_decision` kind values and `settlement`, each marked in `description` with the change that introduces it), `capability/revocation.schema.json` (target kinds of 7.11), `capability/grant.schema.json` (`MonetaryAmount.asset` grammar `^(iso4217:[A-Z]{3}|caip19:[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128})$`), `export/evidence-export-manifest.schema.json` (new file for the in-place `chio.evidence_export_manifest.v1` members: `disclosure_profile`, `tenant_tag`, new roles), `README.md` (which code change moves each file, and that the move replaces the live file in the same PR)

**Interfaces:**
- Consumes: Task 6 `$defs` in `root-authority/root-anchor.schema.json`.
- Produces: complete target files (not patches), each starting from the current live file at the rebased `origin/main`, so the M1 PR does `git mv` plus `MANIFEST.sha256` refresh.

- [ ] **Step 1: Copy the live files** into the staging tree and apply the section 7.1, 7.6, 7.9, 7.10, 7.11 and 7.12 changes.
- [ ] **Step 2: Validate** Task 9's positive receipt vectors against the staged `record.schema.json` (done in Task 9 Step 3); here run a parse check and confirm `grep -c redaction_mode` on the staged record schema is 0.
- [ ] **Step 3: Commit** (`docs(superpowers): stage in-place v1 schema targets`), post `REVIEW? #<N> new chio-wire schemas, registry rows, codegen regen`, open PR 4.

---

### Task 8: Reference script and signing-wrapper vectors (PR 5, spec 11.2)

**Files:**
- Create: `scripts/gen-signing-wrapper-vectors.py` (single file; `python3 -I` drops the script directory from `sys.path`)
- Create: `tests/bindings/vectors/signing/wrapper-v1.json`
- Modify: `tests/bindings/vectors/MANIFEST.sha256` (via `cargo xtask freeze-vectors`)

**Interfaces:**
- Consumes: Task 2 wrapper schema-id table; Task 5 section 4.5.
- Produces:
  - CLI: `gen-signing-wrapper-vectors.py write` (rewrites both vector files) and `gen-signing-wrapper-vectors.py check` (regenerates in memory, byte-compares, runs self-checks; non-zero on any difference).
  - `canonical_json(value) -> bytes`: RFC 8785 restricted to objects with ASCII keys, strings, booleans, null and integers in `[-(2**53-1), 2**53-1]`; raises `ValueError` on floats, larger integers or non-ASCII keys.
  - `wrapper(schema_id: str, canonical_body: bytes) -> bytes` (88 bytes).
  - `wrapper-v1.json`: `{"generated_by": "scripts/gen-signing-wrapper-vectors.py", "prefix_hex": "<hex of chio.signing-wrapper.v1 NUL>", "keys": {"ed25519": {"seed_hex", "public_key"}, "p256": {"scalar_hex", "public_key"}, "p384": {...}}, "wrapper_cases": [{"id", "schema_id", "canonical_body", "wrapper_hex"}], "signature_cases": [{"id", "description", "algorithm", "signed_schema_id", "verify_schema_id", "canonical_body", "public_key", "signature", "expected_verify"}]}`. Keys and signatures use Chio `to_hex` encodings. Fixed keys: Ed25519 seed `0x01 * 32`, P-256 scalar `0x02 * 32`, P-384 scalar `0x03 * 48`.
  - `wrapper_cases`: one per schema id in `spec/schemas/registry.json` plus every id in the staged PROTOCOL 4.5 table (`docs/superpowers/specs/relying-party-wedge/protocol/protocol-4.5-signing-wrapper.md`), over the fixed body `{"a":1}`. Excluded: `chio.security-event-body.v1` and `chio.dpop_proof.v2` (spec 2.5 G8, G10) and the exempt formats (G2), which have no wrapper.
  - `signature_cases`: for each of `ed25519`, `p256`, `p384` and each of `chio.receipt.v1`, `chio.capability.v1`, `chio.delegation-link.v1`, `chio.root-policy.v1`, `chio.idp-key-snapshot.v1`, `chio.revocation-request.v1`, `chio.settlement-closure.v1`: one positive case; plus negatives: schema-id substitution (signed as `chio.capability.v1`, verified as `chio.receipt.v1`), algorithm-prefix mismatch (Ed25519 key, `p256:` signature), signature over the raw body instead of the wrapper, one-bit body change, P-256 signature over `SHA-256(wrapper)` hashed again (double hash).
  - ML-DSA-65 and hybrid cases are not generated here (no ML-DSA in `cryptography==44.0.3`); M1 adds them from Rust in `signing/wrapper-pq-v1.json`.

- [ ] **Step 1: Confirm the toolchain.** `uv run --with cryptography==44.0.3 python3 -I -c "from cryptography.hazmat.primitives.asymmetric import ec; from cryptography.hazmat.primitives import hashes; ec.ECDSA(hashes.SHA256(), deterministic_signing=True)"`. Expected: exit 0. If not, stop and report (ECDSA vectors must be RFC 6979 deterministic so `check` can byte-compare).
- [ ] **Step 2: Write the self-checks first** inside the script (run by `check`): `canonical_json` reproduces `canonical_json` for every case of `tests/bindings/vectors/canonical/v1.json` inside the subset and raises `ValueError` for `{"é":1}`, `1.5` and `2**53`; `len(wrapper(...)) == 88` and `wrapper(...)[23] == 0`; for each P-256 positive case, verification succeeds with `ec.ECDSA(hashes.SHA256())` over the wrapper and with `ec.ECDSA(utils.Prehashed(hashes.SHA256()))` over `sha256(wrapper)`; P-384 likewise with SHA-384; the double-hash negative fails both. Run `check`. Expected: FAIL (vector file missing).
- [ ] **Step 3: Implement generation, run `write`, then `check`.** Expected: PASS; a second `write` produces no diff.
- [ ] **Step 4: Refresh the manifest.** `CARGO_TARGET_DIR=$T cs cargo xtask freeze-vectors` then `--check`. Expected: in sync.
- [ ] **Step 5: Commit** (`test(vectors): add signing-wrapper reference vectors`).

---

### Task 9: Committed-receipt vectors (PR 5, spec 11.2)

**Files:**
- Modify: `scripts/gen-signing-wrapper-vectors.py` (receipt section)
- Create: `tests/bindings/vectors/receipt/committed-v1.json`
- Modify: `tests/bindings/vectors/MANIFEST.sha256`

**Interfaces:**
- Consumes: Task 8 `canonical_json`, `wrapper`, keys; Task 7 staged `record.schema.json`; Task 6 `receipt/disclosure.schema.json`.
- Produces: `committed-v1.json` = `{"generated_by", "kernel_key", "cases": [{"id", "description", "receipt", "disclosure", "preimages": {"parameters_canonical", "content_preimage_hex"}, "expected": {"signature_valid", "parameters", "content", "receipt_valid"}}]}` where `parameters` and `content` are `verified`, `rejected` or `unverifiable`. Commitment: `SHA-256(domain || salt || preimage)` with domains `chio.receipt.parameters.v1\0` and `chio.receipt.content.v1\0`. Fixture salts are fixed (`params` = `0x10 * 32`, `content` = `0x11 * 32`, `anchor.sub` = `0x12 * 32`, `anchor.tenant` = `0x13 * 32`) and documented as fixture material. Receipt id follows PROTOCOL "Receipt Identity And DAG" unchanged; the signature is over `wrapper("chio.receipt.v1", canonical(ChioReceiptSigningBody))`.
- Cases: value output; empty output (`null` preimage); stream output (concatenated per-chunk digest preimage); receipt with `authority` block at `chain_depth` 0; deny receipt; negatives: one-bit salt change, one-bit payload change, parameters opening presented for the content commitment (domain swap), salt of 31 bytes, padded `b64u` salt, subject opening presented as tenant opening, `tenant_id` present alongside `authority` (`receipt_valid: false`), body-only signature without wrapper.

- [ ] **Step 1: Write the self-check first:** the script's receipt-id function reproduces the `id` of every case in the existing `tests/bindings/vectors/receipt/v1.json` (current format). Run `check`. Expected: FAIL until the id function and the new file exist.
- [ ] **Step 2: Implement the receipt section and the negatives; run `write` then `check`.** Expected: PASS.
- [ ] **Step 3: Validate** every positive `receipt` against the staged `record.schema.json` and every `disclosure` against `receipt/disclosure.schema.json` inside `check` (jsonschema with a local registry spanning `spec/schemas/chio-wire/v1` and the staging tree). Expected: PASS; the `tenant_id`-with-`authority` case fails schema validation.
- [ ] **Step 4: Refresh the manifest and run the PR 5 verify commands.** Expected: all pass; existing vector consumers unchanged.
- [ ] **Step 5: Commit** (`test(vectors): add committed-receipt reference vectors`), post `REVIEW? #<N> signing-wrapper and committed-receipt vectors (fix future bytes; coordinate with #1489 DPoP and coop2c fixtures)`, open PR 5.

---

## Spec coverage

| M0 exit item (spec 12) | Task |
|---|---|
| ADR accepted | 4 (Proposed; acceptance is the founder's) |
| PROTOCOL and WIRE_PROTOCOL text: wrapper, committed receipts, salt sources, anchored roots, deployment limits | 5 |
| JSON schemas for every section 7 artifact, ID-JAG retention slot | 6 (new), 7 (in-place, staged) |
| Signing-wrapper and committed-receipt vectors from the reference script | 8, 9 |
| Producer inventory | 2 |
| Scenario files for the three M1 categories | 3 (staged) |
| `SigningBackend` collapse, byte-neutral | 1 |

## Spec gaps resolved in this plan

1. In-place schema changes (`token`, `record`, `revocation`, `grant`, export manifest) cannot merge in M0 without code, because `wire_protocol_schema.rs` validates live serialization against them and four-language codegen derives from `chio-wire/v1`. They are staged under `docs/superpowers/specs/relying-party-wedge/in-place-schemas/` and moved in by the implementing PR.
2. Verdict-matrix scenarios cannot enter the live corpus (closed `ScenarioCategory`, pinned index hash, required `rust-kernel` driver). Staged under `docs/superpowers/.../verdict-matrix/`.
3. PROTOCOL describes shipped behavior; rewriting section 6, 10.3 or 14 in M0 would contradict `main`. New subsections carry a status line; rewrites land with code.
4. The wrapper binds a registered schema id, but `DelegationLink` has none. Task 2 assigns ids and Task 5 publishes the table; registration happens in M1 with the Rust types.
5. ML-DSA-65 and hybrid wrapper vectors cannot come from the pinned Python library. M0 covers Ed25519, P-256 and P-384; M1 adds PQ vectors from Rust.
6. Spec examples write keys as `ed25519:<hex>`; Chio's encoding is bare 64-hex for Ed25519. Schemas and vectors use `PublicKey::to_hex`.
7. New `chio-wire/v1` schemas regenerate code in four languages. Generated output only; no hand-written code.
8. Founder correction: static bearer and generic Entra stay and gain anchor kinds. All M0 artifacts follow the correction; kind names come from the spec fix PR.
9. The twelve inventory gaps (G1 to G12) and the `anchored_root` count are decided in spec section 2.5. Effect on this plan: Task 3 stages 48 scenarios with reason codes in existing error domains; Task 6 removes the `chio.security-event-body.v1` registry row and registers no existing wrapper id (M1 item 1 does, with the Rust types); Task 8 takes its ids from the reconciled staged 4.5 table. M0 size is unchanged; M1 grows to 100-141 engineer-days.
