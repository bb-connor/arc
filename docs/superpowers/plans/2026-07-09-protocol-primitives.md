# Capability Protocol Primitives Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deepen the capability model with three primitives: use-count burns (a capability spendable a bounded number of times), `chio-quorum` (m-of-n co-signed invocation of caveat-marked operations), and `chio-proof-carry` (requests that carry a verifiable proof the kernel checks before dispatch).

**Architecture:** A `use_limit` field on `CapabilityToken` (protocol-normative) plus a monotonic `BurnLedger` the kernel checks alongside expiry. A caveat-discharge seam in `chio-core-types` replaces the current blanket rejection of caveat-bearing tokens, unblocking both `chio-quorum`'s new `RequireQuorum` caveat and the `Declassify` caveat from the active-defense arc. Two small crates under `crates/security/` implement quorum envelope collection and proof verification, both with enforcement in the kernel and collection/generation outside the TCB.

**Tech Stack:** Rust (workspace, edition 2021), `serde`, canonical JSON via `chio_core_types::canonical`, `Keypair`/`PublicKey`/`Signature` from `chio_core_types::crypto`, the existing `ExecutionNonceStore` pattern from `chio-store-sqlite` for the burn ledger, `cargo test`/`clippy`/`fmt`.

## Global Constraints

Copied verbatim from the spec and house rules. Every task's requirements implicitly include this section.

- No em dashes (U+2014) anywhere. Use hyphens or parentheses.
- Fail-closed: a spent capability is denied; a sub-threshold or duplicate-signer quorum is denied; a missing or non-binding proof is denied; a caveat kind with no wired enforcement is rejected at admission.
- Clippy: `unwrap_used = "deny"` and `expect_used = "deny"`. No `unwrap`/`expect`/`unsafe` in new code.
- Serialization: canonical JSON (RFC 8785). New optional token fields use `#[serde(default, skip_serializing_if = "Option::is_none")]` so tokens that do not set them serialize (and therefore verify) exactly as before.
- Commits: conventional commits.
- New crates use the workspace template (`version.workspace = true`, `publish = false`, `[lints] workspace = true`).
- Threat-row framing: mechanisms that make rows closable, not closures.
- Verify each phase with: `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`.

## Cross-arc dependency

The caveat-discharge seam in Task 2 is shared. The active-defense arc's `Declassify` caveat (plan `2026-07-09-security-active-defense.md`, Task 2) adds the `Declassify` enum variant but does not change admission; a `Declassify`-bearing capability is rejected at admission (`crates/core/chio-core-types/src/capability/token.rs:379-384`) until Task 2 here lands. Land Task 2 before relying on either caveat in a running kernel.

---

## File Structure

**Foundation (existing crates, modified):**
- `crates/core/chio-core-types/src/capability/token.rs`: add `use_limit: Option<u32>`; replace the blanket caveat rejection with an admission allowlist.
- `crates/core/chio-core-types/src/capability/caveat.rs`: add `CaveatKind::RequireQuorum`.
- `crates/core/chio-core-types/src/capability/discharge.rs` (create): the `caveat_admission_supported` allowlist and `CaveatError`.

**Burns:**
- `crates/security/chio-burn/` (create): `src/ledger.rs` (the `BurnLedger` trait and in-memory monotonic counter), `src/check.rs` (the spend decision), `src/event.rs` (the `Burn` event body).

**`crates/security/chio-quorum/` (create):**
- `src/requirement.rs`: `QuorumRequirement { m, n, signers }` and parsing from the caveat predicate.
- `src/envelope.rs`: collect m-of-n signed authorization envelopes.
- `src/verify.rs`: threshold, distinctness, and request-binding checks.
- `src/event.rs`: the `QuorumSatisfied` event body.

**`crates/security/chio-proof-carry/` (create):**
- `src/proof.rs`: the `ProofEnvelope` bound to a canonical request.
- `src/verify.rs`: signed policy-satisfaction verification.
- `src/event.rs`: the `ProofVerified` event body.

**Gates, evidence, spec, workspace (create/modify):**
- `scripts/check-burn-monotonic.sh`, `scripts/check-quorum-distinct-signers.sh`, `scripts/check-proof-request-binding.sh`
- `crates/core/chio-adversarial-suite/cases/burn_replay/`, `.../quorum_forgery/`, `.../proof_forgery/`
- Root `Cargo.toml` (modify): register three members.
- `spec/PROTOCOL.md` (section 5), `spec/SECURITY.md` (section 2).

---

## Phase 0: capability-model foundation

### Task 1: `use_limit` on CapabilityToken

**Files:**
- Modify: `crates/core/chio-core-types/src/capability/token.rs`
- Test: inline

**Interfaces:**
- Produces: `CapabilityToken.use_limit: Option<u32>`. `None` means unbounded (today's behavior). `Some(n)` means the capability may be spent at most `n` times. The field is included in the signing body only when present, so existing tokens verify unchanged.
- Fail-closed until enforced: adding the field does not enforce it. Until the burn check is wired into `verify_capability_full` (Task 7b), the kernel MUST reject a token whose `use_limit` is `Some` rather than admit it unenforced, so there is never a window where a `use_limit = 1` token can be replayed. Admission and enforcement land together in Task 7b.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn use_limit_defaults_to_none_and_roundtrips() {
    let json = r#"{"schema":"chio.capability.v1","useLimit":5}"#;
    let value: serde_json::Value = serde_json::from_str(json).expect("parse");
    assert_eq!(value.get("useLimit").and_then(|v| v.as_u64()), Some(5));
    // A token constructed without use_limit omits it on the wire.
    // (Full construction is exercised by existing token tests; this asserts
    // the serde shape of the new field.)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-core-types use_limit`
Expected: FAIL (field not recognized, or test module missing).

- [ ] **Step 3: Write minimal implementation**

Add the field to `CapabilityToken` (after `budget_share_bps`, before `signature`):

```rust
    /// Maximum number of times this capability may be spent. `None` is
    /// unbounded. Enforced by the kernel via a monotonic burn ledger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_limit: Option<u32>,
```

Add the same field to the attenuation signing-body struct(s) in this file that mirror the token (the exploration notes `CapabilityTokenAttenuationBody` and the signing-input struct near line 117 and line 132), so the field is covered by the signature when set. Then run `cargo build -p chio-core-types` and add `use_limit: None,` to every `CapabilityToken { .. }` construction site the compiler flags (these are mechanical; the field is `None` everywhere except where a caller opts in).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-core-types use_limit && cargo build -p chio-core-types`
Expected: PASS and clean build.

- [ ] **Step 5: Commit**

```bash
git add crates/core/chio-core-types/src/capability/token.rs
git commit -m "feat(core-types): add optional use_limit to CapabilityToken"
```

### Task 2: Caveat admission allowlist and `RequireQuorum` kind

**Files:**
- Create: `crates/core/chio-core-types/src/capability/discharge.rs`
- Modify: `crates/core/chio-core-types/src/capability/caveat.rs`, `crates/core/chio-core-types/src/capability/mod.rs`, `crates/core/chio-core-types/src/capability/token.rs`
- Test: inline in `discharge.rs`

**Interfaces:**
- Produces: `CaveatKind::RequireQuorum`; `pub fn caveat_admission_supported(kind: CaveatKind) -> bool` returning true only for kinds with a wired enforcement layer (`Declassify` via `chio-flow`, `RequireQuorum` via `chio-quorum`); `CaveatError`. The token sign path rejects only caveats whose kind is not admission-supported, replacing today's blanket rejection.
- Security invariant: a supported caveat MUST be enforced by its owning layer at the relevant boundary. The kernel refuses to dispatch a caveat-bearing capability unless the enforcing guard is registered and returns satisfied (the quorum gate is wired in Task 7b; the FlowGuard covers `Declassify`). Marking a kind admission-supported without its enforcement wired would be a bypass, so `RequireQuorum` stays effectively denied until Task 7b lands. This prevents a supported-but-ignored caveat from silently broadening access.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::caveat::CaveatKind;

    #[test]
    fn only_enforced_kinds_are_admission_supported() {
        assert!(caveat_admission_supported(CaveatKind::Declassify));
        assert!(caveat_admission_supported(CaveatKind::RequireQuorum));
        // Legacy kinds have no enforcement path yet: still rejected.
        assert!(!caveat_admission_supported(CaveatKind::RestrictTool));
        assert!(!caveat_admission_supported(CaveatKind::RestrictGeo));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-core-types caveat_admission`
Expected: FAIL (`RequireQuorum` and `caveat_admission_supported` missing).

- [ ] **Step 3: Write minimal implementation**

In `caveat.rs`, add to `CaveatKind` (after `Declassify` from the active-defense arc; if that variant is not present yet, add both):

```rust
    /// Requires an m-of-n co-signed authorization envelope before an
    /// operation carrying this caveat is dispatched. Enforced by chio-quorum.
    RequireQuorum,
```

`discharge.rs`:

```rust
//! Caveat admission: which caveat kinds have a wired enforcement layer and may
//! therefore appear on an admitted capability. A caveat whose kind is not
//! listed here is rejected fail-closed, preserving the invariant that no
//! restriction is ever silently ignored.

use crate::capability::caveat::CaveatKind;

/// Error raised when a caveat cannot be admitted or discharged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaveatError {
    /// The caveat kind has no enforcement layer and is rejected.
    Unenforced(CaveatKind),
    /// The caveat predicate is malformed for its kind.
    Malformed { kind: CaveatKind, detail: String },
}

/// Whether a caveat kind may appear on an admitted capability. True only for
/// kinds whose enforcement layer exists: `Declassify` (chio-flow) and
/// `RequireQuorum` (chio-quorum). All other kinds are rejected until they gain
/// an enforcement path.
#[must_use]
pub fn caveat_admission_supported(kind: CaveatKind) -> bool {
    matches!(kind, CaveatKind::Declassify | CaveatKind::RequireQuorum)
}
```

Register `pub mod discharge;` in `capability/mod.rs`. Then in `token.rs`, replace the blanket rejection at the sign path (the `if !body.caveats.is_empty()` block near line 379) with a per-caveat admission check:

```rust
        for caveat in &body.caveats {
            if !crate::capability::discharge::caveat_admission_supported(caveat.kind) {
                return Err(Error::AttenuationViolation {
                    reason: "capability carries a caveat with no enforcement layer".to_string(),
                });
            }
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-core-types caveat_admission && cargo build -p chio-core-types`
Expected: PASS and clean build.

- [ ] **Step 5: Commit**

```bash
git add crates/core/chio-core-types/src/capability/discharge.rs crates/core/chio-core-types/src/capability/caveat.rs crates/core/chio-core-types/src/capability/mod.rs crates/core/chio-core-types/src/capability/token.rs
git commit -m "feat(core-types): admit only enforced caveat kinds; add RequireQuorum"
```

---

## Phase 1: use-count burns

### Task 3: Burn ledger

**Files:**
- Create: `crates/security/chio-burn/Cargo.toml`, `src/lib.rs`, `src/ledger.rs`
- Modify: root `Cargo.toml` (`members`)
- Test: inline in `ledger.rs`

**Interfaces:**
- Produces: `BurnLedger` trait with `fn spend(&self, capability_id: &str) -> u32` (returns the new monotonically increasing count) and `fn count(&self, capability_id: &str) -> u32`; `InMemoryBurnLedger` implementing it with a `Mutex<HashMap>`. The counter never rewinds. This mirrors the `ExecutionNonceStore` monotonic-reservation pattern from `chio-store-sqlite`; a SQLite backend is a later addition behind the same trait.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spend_increments_monotonically() {
        let ledger = InMemoryBurnLedger::new();
        assert_eq!(ledger.count("cap-1"), 0);
        assert_eq!(ledger.spend("cap-1"), 1);
        assert_eq!(ledger.spend("cap-1"), 2);
        assert_eq!(ledger.count("cap-1"), 2);
        // Independent capabilities have independent counters.
        assert_eq!(ledger.spend("cap-2"), 1);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-burn ledger`
Expected: FAIL (crate missing).

- [ ] **Step 3: Write minimal implementation**

`Cargo.toml`:

```toml
[package]
name = "chio-burn"
description = "Chio use-count burn ledger for spend-bounded capabilities"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[lib]
name = "chio_burn"

[dependencies]
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }

[lints]
workspace = true
```

`src/lib.rs`:

```rust
//! Use-count burns: a monotonic per-capability spend counter the kernel checks
//! against a capability's declared use_limit.

pub mod check;
pub mod event;
pub mod ledger;
```

`src/ledger.rs`:

```rust
//! The burn ledger. Monotonic per-capability counters that never rewind.

use std::collections::HashMap;
use std::sync::Mutex;

/// Records how many times each capability has been spent.
pub trait BurnLedger: Send + Sync {
    /// Increment and return the new spend count for a capability.
    fn spend(&self, capability_id: &str) -> u32;
    /// The current spend count for a capability.
    fn count(&self, capability_id: &str) -> u32;
}

/// In-process reference ledger.
#[derive(Default)]
pub struct InMemoryBurnLedger {
    counts: Mutex<HashMap<String, u32>>,
}

impl InMemoryBurnLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl BurnLedger for InMemoryBurnLedger {
    fn spend(&self, capability_id: &str) -> u32 {
        match self.counts.lock() {
            Ok(mut map) => {
                let entry = map.entry(capability_id.to_string()).or_insert(0);
                *entry = entry.saturating_add(1);
                *entry
            }
            // Poisoned lock: report saturated so the caller denies (fail-closed).
            Err(_) => u32::MAX,
        }
    }

    fn count(&self, capability_id: &str) -> u32 {
        match self.counts.lock() {
            Ok(map) => map.get(capability_id).copied().unwrap_or(0),
            Err(_) => u32::MAX,
        }
    }
}
```

Add the member to root `Cargo.toml`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-burn ledger`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-burn Cargo.toml
git commit -m "feat(burn): add monotonic burn ledger"
```

### Task 4: Spend decision and burn event

**Files:**
- Create: `crates/security/chio-burn/src/check.rs`, `src/event.rs`
- Test: inline in both

**Interfaces:**
- Consumes: `crate::ledger::BurnLedger`.
- Produces: `pub fn try_spend(ledger: &dyn BurnLedger, capability_id: &str, use_limit: Option<u32>) -> BurnDecision` with `BurnDecision { Allowed { spend_index: u32, remaining: Option<u32> }, Denied { spend_index: u32 } }`. Both variants carry the post-increment `spend_index` so the caller populates an accurate `Burn` receipt without a second, racy ledger read. `None` limit is always allowed. `Some(n)` denies once the post-increment count exceeds `n`. `Burn { capability_id, spend_index, remaining }` is the canonical-JSON event body.

- [ ] **Step 1: Write the failing test**

```rust
// check.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::InMemoryBurnLedger;

    #[test]
    fn unbounded_capability_always_allowed() {
        let ledger = InMemoryBurnLedger::new();
        assert_eq!(
            try_spend(&ledger, "c", None),
            BurnDecision::Allowed { spend_index: 1, remaining: None }
        );
    }

    #[test]
    fn bounded_capability_denies_after_limit_and_reports_index() {
        let ledger = InMemoryBurnLedger::new();
        assert_eq!(
            try_spend(&ledger, "c", Some(2)),
            BurnDecision::Allowed { spend_index: 1, remaining: Some(1) }
        );
        assert!(matches!(try_spend(&ledger, "c", Some(2)), BurnDecision::Allowed { .. }));
        // The third spend is denied and still reports its index for the receipt.
        assert_eq!(try_spend(&ledger, "c", Some(2)), BurnDecision::Denied { spend_index: 3 });
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-burn check`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

`src/check.rs`:

```rust
//! The spend decision: increment the ledger and compare against the declared
//! use_limit. Fail-closed: exceeding the limit denies.

use crate::ledger::BurnLedger;

/// The outcome of attempting to spend a capability. Both variants carry the
/// post-increment `spend_index` so the caller can populate an accurate signed
/// `Burn` receipt without a second, racy ledger read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BurnDecision {
    Allowed { spend_index: u32, remaining: Option<u32> },
    Denied { spend_index: u32 },
}

/// Attempt to spend a capability once. `None` limit is unbounded.
#[must_use]
pub fn try_spend(
    ledger: &dyn BurnLedger,
    capability_id: &str,
    use_limit: Option<u32>,
) -> BurnDecision {
    let spent = ledger.spend(capability_id);
    match use_limit {
        None => BurnDecision::Allowed { spend_index: spent, remaining: None },
        Some(limit) => {
            if spent <= limit {
                BurnDecision::Allowed { spend_index: spent, remaining: Some(limit - spent) }
            } else {
                BurnDecision::Denied { spend_index: spent }
            }
        }
    }
}
```

`src/event.rs`:

```rust
//! The Burn event body, emitted on each spend as a signed receipt.

use serde::{Deserialize, Serialize};

/// Records one spend of a use-limited capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Burn {
    pub capability_id: String,
    pub spend_index: u32,
    pub remaining: Option<u32>,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-burn`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-burn/src/check.rs crates/security/chio-burn/src/event.rs
git commit -m "feat(burn): add spend decision and Burn event"
```

---

## Phase 2: chio-quorum

### Task 5: Crate scaffold and quorum requirement

**Files:**
- Create: `crates/security/chio-quorum/Cargo.toml`, `src/lib.rs`, `src/requirement.rs`
- Modify: root `Cargo.toml` (`members`)
- Test: inline in `requirement.rs`

**Interfaces:**
- Consumes: `chio_core_types::crypto::PublicKey`.
- Produces: `QuorumRequirement { m: u8, n: u8, signers: Vec<String> }` (signer ids are hex public keys) with `pub fn parse(predicate: &str) -> Result<QuorumRequirement, QuorumError>`. The caveat predicate encodes `m-of-n:key1,key2,...` (for example `2-of-3:aa..,bb..,cc..`).

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_m_of_n_predicate() {
        let req = QuorumRequirement::parse("2-of-3:aa,bb,cc").expect("parse");
        assert_eq!(req.m, 2);
        assert_eq!(req.n, 3);
        assert_eq!(req.signers.len(), 3);
    }

    #[test]
    fn rejects_threshold_above_signer_count() {
        assert!(QuorumRequirement::parse("3-of-2:aa,bb").is_err());
    }

    #[test]
    fn rejects_duplicate_or_empty_signers() {
        assert!(QuorumRequirement::parse("2-of-3:aa,aa,bb").is_err());
        assert!(QuorumRequirement::parse("1-of-2:aa,").is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-quorum requirement`
Expected: FAIL (crate missing).

- [ ] **Step 3: Write minimal implementation**

`Cargo.toml`:

```toml
[package]
name = "chio-quorum"
description = "Chio m-of-n co-signed invocation for caveat-marked operations"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[lib]
name = "chio_quorum"

[dependencies]
chio-core-types = { workspace = true }
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }

[lints]
workspace = true
```

`src/lib.rs`:

```rust
//! m-of-n co-signed invocation. A RequireQuorum caveat on a capability blocks
//! dispatch until a threshold of distinct authorized signers has signed the
//! canonical request.

pub mod envelope;
pub mod event;
pub mod requirement;
pub mod verify;
```

`src/requirement.rs`:

```rust
//! The quorum requirement parsed from a RequireQuorum caveat predicate.

use std::collections::BTreeSet;

/// Parse error for a quorum predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumError {
    pub detail: String,
}

/// An m-of-n signing requirement over a declared signer set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumRequirement {
    pub m: u8,
    pub n: u8,
    pub signers: Vec<String>,
}

impl QuorumRequirement {
    /// Parse `m-of-n:key1,key2,...`.
    pub fn parse(predicate: &str) -> Result<Self, QuorumError> {
        let (threshold, signer_list) = predicate
            .split_once(':')
            .ok_or_else(|| QuorumError { detail: "missing ':' separator".to_string() })?;
        let (m_str, n_str) = threshold
            .split_once("-of-")
            .ok_or_else(|| QuorumError { detail: "expected m-of-n".to_string() })?;
        let m: u8 = m_str.parse().map_err(|_| QuorumError { detail: "bad m".to_string() })?;
        let n: u8 = n_str.parse().map_err(|_| QuorumError { detail: "bad n".to_string() })?;
        let signers: Vec<String> = signer_list.split(',').map(|s| s.trim().to_string()).collect();
        if m == 0 || m > n {
            return Err(QuorumError { detail: "require 1 <= m <= n".to_string() });
        }
        if signers.len() != n as usize {
            return Err(QuorumError { detail: "signer count must equal n".to_string() });
        }
        if signers.iter().any(String::is_empty) {
            return Err(QuorumError { detail: "signer ids must be non-empty".to_string() });
        }
        // Duplicate signer ids weaken the m-of-n independence model: reject them
        // so a declared set never looks larger than its real signer count.
        if signers.iter().collect::<BTreeSet<_>>().len() != signers.len() {
            return Err(QuorumError { detail: "signer ids must be distinct".to_string() });
        }
        Ok(Self { m, n, signers })
    }
}
```

Add the member to root `Cargo.toml`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-quorum requirement`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-quorum Cargo.toml
git commit -m "feat(quorum): scaffold with m-of-n requirement parsing"
```

### Task 6: Envelope verification

**Files:**
- Create: `crates/security/chio-quorum/src/envelope.rs`, `src/verify.rs`, `src/event.rs`
- Test: inline in `verify.rs`

**Interfaces:**
- Consumes: `crate::requirement::QuorumRequirement`.
- Produces: `SignedApproval { signer_id: String, request_hash: String, signature_hex: String }` (`signer_id` is the signer's hex public key; `signature_hex` signs `request_hash`); `pub fn quorum_satisfied(req: &QuorumRequirement, request_hash: &str, approvals: &[SignedApproval]) -> bool` (at least `m` distinct authorized signers each produced a signature over this exact request hash that verifies under their key); `QuorumSatisfied { request_hash, signers }` event body. A fabricated approval carrying an authorized `signer_id` but no valid signature is not counted, so an agent cannot satisfy the quorum alone.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::crypto::Keypair;
    use crate::requirement::QuorumRequirement;

    fn key(seed: u8) -> Keypair {
        Keypair::from_seed(&[seed; 32])
    }

    fn req(keys: &[&Keypair], m: u8) -> QuorumRequirement {
        let signers = keys.iter().map(|k| k.public_key().to_hex()).collect();
        QuorumRequirement { m, n: keys.len() as u8, signers }
    }

    fn approval(kp: &Keypair, hash: &str) -> SignedApproval {
        SignedApproval {
            signer_id: kp.public_key().to_hex(),
            request_hash: hash.to_string(),
            signature_hex: kp.sign(hash.as_bytes()).to_hex(),
        }
    }

    #[test]
    fn two_valid_distinct_signatures_satisfy() {
        let (a, b, c) = (key(1), key(2), key(3));
        let req = req(&[&a, &b, &c], 2);
        assert!(quorum_satisfied(&req, "h1", &[approval(&a, "h1"), approval(&b, "h1")]));
    }

    #[test]
    fn forged_signature_is_not_counted() {
        let (a, b, c) = (key(1), key(2), key(3));
        let req = req(&[&a, &b, &c], 2);
        // Claims b as signer but carries a's signature: does not verify under b.
        let forged = SignedApproval {
            signer_id: b.public_key().to_hex(),
            request_hash: "h1".to_string(),
            signature_hex: a.sign("h1".as_bytes()).to_hex(),
        };
        assert!(!quorum_satisfied(&req, "h1", &[approval(&a, "h1"), forged]));
    }

    #[test]
    fn duplicate_signer_does_not_count_twice() {
        let (a, b, c) = (key(1), key(2), key(3));
        let req = req(&[&a, &b, &c], 2);
        assert!(!quorum_satisfied(&req, "h1", &[approval(&a, "h1"), approval(&a, "h1")]));
    }

    #[test]
    fn approval_for_other_request_is_ignored() {
        let (a, b, c) = (key(1), key(2), key(3));
        let req = req(&[&a, &b, &c], 2);
        assert!(!quorum_satisfied(&req, "h1", &[approval(&a, "h1"), approval(&b, "OTHER")]));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-quorum verify`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

`src/envelope.rs`:

```rust
//! A signed authorization approval. Binds a signer to the exact request hash
//! with a signature the verifier checks before counting the approval.

use serde::{Deserialize, Serialize};

/// One signer's approval of a specific request. `signer_id` is the signer's hex
/// public key; `signature_hex` is its signature over `request_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedApproval {
    pub signer_id: String,
    pub request_hash: String,
    pub signature_hex: String,
}
```

`src/verify.rs`:

```rust
//! Quorum verification: at least m distinct authorized signers each produced a
//! valid signature over this exact request. Fail-closed on anything short of
//! that, including forged or unverifiable signatures.

use std::collections::BTreeSet;

use chio_core_types::crypto::{PublicKey, Signature};

use crate::envelope::SignedApproval;
use crate::requirement::QuorumRequirement;

/// Whether the approvals satisfy the quorum for `request_hash`. An approval is
/// counted only if its signer is authorized, it binds to this exact request,
/// and its signature verifies under the signer's key. Distinct signers only, so
/// duplicate approvals from one signer cannot reach the threshold, and a
/// fabricated approval carrying an authorized id but no valid signature is
/// ignored.
#[must_use]
pub fn quorum_satisfied(
    req: &QuorumRequirement,
    request_hash: &str,
    approvals: &[SignedApproval],
) -> bool {
    let authorized: BTreeSet<&str> = req.signers.iter().map(String::as_str).collect();
    let mut counted: BTreeSet<&str> = BTreeSet::new();
    for approval in approvals {
        if approval.request_hash != request_hash {
            continue;
        }
        let signer = approval.signer_id.as_str();
        if !authorized.contains(signer) {
            continue;
        }
        // The signer id is the signer's hex public key; verify its signature
        // over the request hash before counting the approval.
        let Ok(key) = PublicKey::from_hex(signer) else { continue };
        let Ok(sig) = Signature::from_hex(&approval.signature_hex) else { continue };
        if key.verify(request_hash.as_bytes(), &sig) {
            counted.insert(signer);
        }
    }
    counted.len() >= req.m as usize
}
```

`src/event.rs`:

```rust
//! The QuorumSatisfied event body, emitted when a quorum gate passes.

use serde::{Deserialize, Serialize};

/// Records which signers satisfied a quorum for a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuorumSatisfied {
    pub request_hash: String,
    pub signers: Vec<String>,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-quorum verify`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-quorum/src/envelope.rs crates/security/chio-quorum/src/verify.rs crates/security/chio-quorum/src/event.rs
git commit -m "feat(quorum): verify threshold, distinctness, and request binding"
```

---

## Phase 3: chio-proof-carry

### Task 7: Crate scaffold, proof envelope, verification

**Files:**
- Create: `crates/security/chio-proof-carry/Cargo.toml`, `src/lib.rs`, `src/proof.rs`, `src/verify.rs`, `src/event.rs`
- Modify: root `Cargo.toml` (`members`)
- Test: inline

**Interfaces:**
- Consumes: `chio_core_types::crypto::{PublicKey, Signature, Keypair}`.
- Produces: `ProofEnvelope { request_hash: String, claim: String, signer: String, signature_hex: String }`; `pub fn signing_message(request_hash: &str, claim: &str) -> Vec<u8>` (length-prefixed, unambiguous) and `pub fn verify(envelope: &ProofEnvelope, request_hash: &str, key: &PublicKey) -> bool` (the proof must bind to this exact request, declare `key` as its signer, and verify under `key` over the length-prefixed message); `ProofVerified { request_hash, claim }` event body. This is the research-scoped primitive: one concrete signed policy-satisfaction attestation, with a trait seam left for richer proof systems.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::crypto::Keypair;

    #[test]
    fn proof_bound_to_request_and_signer_verifies() {
        let kp = Keypair::generate();
        let request_hash = "h1";
        let claim = "policy:pii-cleared";
        let sig = kp.sign(&signing_message(request_hash, claim));
        let envelope = ProofEnvelope {
            request_hash: request_hash.to_string(),
            claim: claim.to_string(),
            signer: kp.public_key().to_hex(),
            signature_hex: sig.to_hex(),
        };
        assert!(verify(&envelope, "h1", &kp.public_key()));
        // A proof lifted onto a different request fails.
        assert!(!verify(&envelope, "OTHER", &kp.public_key()));
        // A proof verified under a key other than its declared signer fails.
        let other = Keypair::from_seed(&[9u8; 32]);
        assert!(!verify(&envelope, "h1", &other.public_key()));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-proof-carry`
Expected: FAIL (crate missing).

- [ ] **Step 3: Write minimal implementation**

`Cargo.toml`:

```toml
[package]
name = "chio-proof-carry"
description = "Chio proof-carrying requests (research-scoped)"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[lib]
name = "chio_proof_carry"

[dependencies]
chio-core-types = { workspace = true }
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }

[lints]
workspace = true
```

`src/lib.rs`:

```rust
//! Proof-carrying requests: a request may carry a verifiable proof that it
//! satisfies a policy, which the kernel checks before dispatch. Research-
//! scoped: one concrete signed-attestation form plus a seam for richer proofs.

pub mod event;
pub mod proof;
pub mod verify;
```

`src/proof.rs`:

```rust
//! The proof envelope attached to a request.

use serde::{Deserialize, Serialize};

/// A signed policy-satisfaction attestation bound to a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofEnvelope {
    pub request_hash: String,
    pub claim: String,
    pub signer: String,
    pub signature_hex: String,
}
```

`src/verify.rs`:

```rust
//! Proof verification: the proof must bind to the exact request, declare the
//! expected signer, and verify under that key over an unambiguous encoding.
//! Fail-closed on any mismatch.

use chio_core_types::crypto::{PublicKey, Signature};

use crate::proof::ProofEnvelope;

/// The unambiguous signing message: length-prefixed request hash and claim, so
/// no two `(request_hash, claim)` pairs share an encoding (a signature over one
/// pair cannot be reinterpreted as another with the same concatenation).
#[must_use]
pub fn signing_message(request_hash: &str, claim: &str) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&(request_hash.len() as u64).to_le_bytes());
    message.extend_from_slice(request_hash.as_bytes());
    message.extend_from_slice(&(claim.len() as u64).to_le_bytes());
    message.extend_from_slice(claim.as_bytes());
    message
}

/// Whether the proof binds to `request_hash`, declares `key` as its signer, and
/// verifies under `key`. Comparing `envelope.signer` to `key` stops a proof
/// from claiming one signer while being verified under another.
#[must_use]
pub fn verify(envelope: &ProofEnvelope, request_hash: &str, key: &PublicKey) -> bool {
    if envelope.request_hash != request_hash {
        return false;
    }
    if envelope.signer != key.to_hex() {
        return false;
    }
    let Ok(signature) = Signature::from_hex(&envelope.signature_hex) else {
        return false;
    };
    key.verify(&signing_message(&envelope.request_hash, &envelope.claim), &signature)
}
```

`src/event.rs`:

```rust
//! The ProofVerified event body.

use serde::{Deserialize, Serialize};

/// Records that a request's carried proof verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofVerified {
    pub request_hash: String,
    pub claim: String,
}
```

Add the member to root `Cargo.toml`. Confirm `Signature::from_hex` and `PublicKey::verify` signatures against `crates/core/chio-core-types/src/crypto.rs` (the exploration cites `verify(&self, message, signature) -> bool` at line 451 and `Signature::from_hex` at line 692).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-proof-carry`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-proof-carry Cargo.toml
git commit -m "feat(proof-carry): add request-bound signed proof verification"
```

### Task 7b: Kernel enforcement wiring (deployment gate)

Admission (Tasks 1-2) without enforcement is a bypass: a `use_limit = 1` token
could be replayed and a `RequireQuorum` token could dispatch with no approvals.
The existing `verify_capability_full` in `crates/kernel/chio-kernel-core/src/capability_verify.rs`
performs base verification, delegation, chain binding, and budget admission
only; it calls neither `try_spend` nor a quorum gate. This task wires both, so
enforcement lands with admission rather than after it. Until it lands, Tasks 1
and 2 keep `use_limit` and `RequireQuorum` fail-closed (rejected), so there is no
unenforced window.

**Files:**
- Modify: `crates/kernel/chio-kernel-core/src/capability_verify.rs` (burn check), the dispatch/guard-pipeline path that admits caveats (quorum gate), and the crates' `Cargo.toml` to depend on `chio-burn` and `chio-quorum`.
- Test: `crates/kernel/chio-kernel/tests/burn_enforcement.rs`, `.../quorum_enforcement.rs`.

- [ ] **Step 1: Write the failing enforcement tests**

```rust
// burn_enforcement.rs (shape; adapt to the real kernel test harness)
#[test]
fn use_limit_one_token_is_denied_on_second_use() {
    let ledger = chio_burn::ledger::InMemoryBurnLedger::new();
    let cap_id = "cap-burn-1";
    assert!(matches!(
        chio_burn::check::try_spend(&ledger, cap_id, Some(1)),
        chio_burn::check::BurnDecision::Allowed { .. }
    ));
    assert!(matches!(
        chio_burn::check::try_spend(&ledger, cap_id, Some(1)),
        chio_burn::check::BurnDecision::Denied { .. }
    ));
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p chio-kernel burn_enforcement`
Expected: FAIL until the kernel consults the ledger (the standalone `try_spend` test passes, but the kernel-path test that a second dispatch is denied fails until wired).

- [ ] **Step 3: Wire enforcement**

1. In `verify_capability_full` (or the dispatch step that owns a `BurnLedger`), after expiry and caveat checks, call `try_spend(ledger, &token.id, token.use_limit)` and deny on `BurnDecision::Denied`, emitting a `Burn` receipt with the returned `spend_index`.
2. In the caveat-admission path, for a `RequireQuorum` caveat parse the requirement, collect the presented `SignedApproval`s, and deny unless `chio_quorum::verify::quorum_satisfied` returns true; emit a `QuorumSatisfied` receipt on success. A caveat-bearing capability with no registered quorum gate denies.
3. For an operation that declares a proof requirement, verify the carried `ProofEnvelope` via `chio_proof_carry::verify::verify` and deny when the proof is missing or does not verify. Proof-carrying is mandatory for those operations, not optional; a missing proof denies. Add a kernel-path test that a proof-requiring operation with a missing or invalid proof is denied.

- [ ] **Step 4: Run the enforcement tests**

Run: `cargo test -p chio-kernel burn_enforcement && cargo test -p chio-kernel quorum_enforcement && cargo test -p chio-kernel proof_enforcement`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/kernel crates/security
git commit -m "feat(kernel): enforce use-count burns and quorum caveats at admission"
```

---

## Phase 4: Gates, evidence, spec

### Task 8: Release gates, kernel-gate invariant note, adversarial corpus

**Files:**
- Create: `scripts/check-burn-monotonic.sh`, `scripts/check-quorum-distinct-signers.sh`, `scripts/check-proof-request-binding.sh`
- Create: `crates/core/chio-adversarial-suite/cases/burn_replay/burn-replay-001.json`, `.../quorum_forgery/quorum-forgery-001.json`, `.../proof_forgery/proof-forgery-001.json`
- Test: run each script; run the suite

**Interfaces:**
- Produces: three fail-closed gates and three adversarial cases. Also documents the kernel-gate integration invariant (wired in Task 7b): the kernel refuses to dispatch a `RequireQuorum`-bearing capability unless a quorum gate ran and returned satisfied, and denies a `use_limit` token whose burn ledger is exhausted, so a supported caveat or a spent capability is never silently honored.

- [ ] **Step 1: Write the three gate scripts**

`scripts/check-burn-monotonic.sh`:

```bash
#!/usr/bin/env bash
# Fail-closed gate: the burn ledger must saturate (never rewind) and try_spend
# must deny past the limit.
set -euo pipefail
grep -q "saturating_add(1)" crates/security/chio-burn/src/ledger.rs \
  || { echo "FAIL: burn counter is not monotonic" >&2; exit 1; }
grep -q "BurnDecision::Denied" crates/security/chio-burn/src/check.rs \
  || { echo "FAIL: try_spend has no deny path" >&2; exit 1; }
echo "OK: burns are monotonic and bounded"
```

`scripts/check-quorum-distinct-signers.sh`:

```bash
#!/usr/bin/env bash
# Fail-closed gate: quorum must count DISTINCT signers (a set), not raw approvals.
set -euo pipefail
grep -q "BTreeSet" crates/security/chio-quorum/src/verify.rs \
  || { echo "FAIL: quorum does not dedupe signers" >&2; exit 1; }
echo "OK: quorum counts distinct signers"
```

`scripts/check-proof-request-binding.sh`:

```bash
#!/usr/bin/env bash
# Fail-closed gate: proof verification must reject a proof whose request_hash
# does not match.
set -euo pipefail
grep -q "envelope.request_hash != request_hash" crates/security/chio-proof-carry/src/verify.rs \
  || { echo "FAIL: proof is not request-bound" >&2; exit 1; }
echo "OK: proofs bind to the request"
```

- [ ] **Step 2: Run the three gates**

Run: `bash scripts/check-burn-monotonic.sh && bash scripts/check-quorum-distinct-signers.sh && bash scripts/check-proof-request-binding.sh`
Expected: three OK lines.

- [ ] **Step 3: Write the three adversarial cases**

Read an existing case (`sed -n '1,40p' $(find crates/core/chio-adversarial-suite/cases -name '*.json' | head -1)`) and mirror its schema. Encode: `burn_replay` (a rewound burn counter reused after exhaustion), `quorum_forgery` (two approvals from one signer claiming quorum), `proof_forgery` (a valid proof lifted onto a different request hash). Register them in the suite index if one exists.

- [ ] **Step 4: Run the suite and gates**

Run: `cargo test -p chio-adversarial-suite && bash scripts/check-burn-monotonic.sh`
Expected: PASS and OK.

- [ ] **Step 5: Commit**

```bash
chmod +x scripts/check-burn-monotonic.sh scripts/check-quorum-distinct-signers.sh scripts/check-proof-request-binding.sh
git add scripts/check-burn-monotonic.sh scripts/check-quorum-distinct-signers.sh scripts/check-proof-request-binding.sh crates/core/chio-adversarial-suite/cases/
git commit -m "feat(security): add protocol-pack release gates and adversarial cases"
```

### Task 9: Spec deltas and workspace verification

**Files:**
- Modify: `spec/PROTOCOL.md` (section 5, Capability Contract), `spec/SECURITY.md` (section 2, Threat Register)
- Test: whole workspace

**Interfaces:**
- Produces: normative sections for use-count burns (the `use_limit` field and the monotonic-counter enforcement contract), the `RequireQuorum` caveat and quorum envelope format, the proof-carrying request envelope and its pre-dispatch verification contract, and the three new receipt subtypes (`Burn`, `QuorumSatisfied`, `ProofVerified`) emitted through the existing receipt machinery via the `ChioReceipt.metadata` field.

- [ ] **Step 1: Add the capability-primitive sections to `spec/PROTOCOL.md`**

Under section 5 (Capability Contract), add subsections for `use_limit` semantics (spend-bounded, monotonic, fail-closed past limit), the `RequireQuorum` caveat (predicate format `m-of-n:keys`, m distinct authorized signers over the canonical request), and proof-carrying requests (envelope bound to the canonical request hash, verified before dispatch). Under section 6 (Receipt Contract), note the three new event bodies carried in receipt metadata. Use hyphens, not em dashes.

- [ ] **Step 2: Add the threat-register notes to `spec/SECURITY.md`**

In section 2, cross-reference how burns and quorum harden `capability_token_theft`, `delegation_chain_abuse`, and `kernel_impersonation`, framed as mechanisms not closures.

- [ ] **Step 3: Run the full workspace one-liner**

Run: `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`
Expected: all green.

- [ ] **Step 4: Run all three gates**

Run: `bash scripts/check-burn-monotonic.sh && bash scripts/check-quorum-distinct-signers.sh && bash scripts/check-proof-request-binding.sh`
Expected: three OK lines.

- [ ] **Step 5: Commit**

```bash
git add spec/PROTOCOL.md spec/SECURITY.md
git commit -m "docs(spec): specify use-count burns, quorum caveat, and proof-carrying requests"
```

---

## Self-Review

**Spec coverage:** use-count burns (Tasks 1, 3, 4); caveat-discharge foundation and `RequireQuorum` (Task 2); `chio-quorum` requirement/envelope/verify/event (Tasks 5, 6); `chio-proof-carry` proof/verify/event (Task 7); gates and adversarial corpus (Task 8); spec deltas and workspace registration (Task 9). Threat rows `capability_token_theft`, `delegation_chain_abuse`, `kernel_impersonation` map to burns and quorum, framed as mechanisms.

**Cross-arc dependency handled:** Task 2 is the shared caveat-admission change that both `Declassify` (active-defense arc) and `RequireQuorum` (this arc) require; the header calls out that the active-defense plan's `Declassify` caveat depends on it.

**Kernel enforcement is required, not deferred:** Task 7b wires `try_spend` into `verify_capability_full` and the quorum gate into the caveat-admission path, and it lands with admission (Tasks 1-2 keep `use_limit` and `RequireQuorum` fail-closed until it does). Quorum approvals carry and verify real signatures as of Task 6 (`quorum_satisfied` checks each signature under the signer's key), so signature verification is not deferred.

**Deferred items made explicit (not silent gaps):** the SQLite burn ledger (Task 3 ships the trait and in-memory impl); a dedicated approval-collection transport (Task 6 verifies presented approvals; how they are gathered from co-signers is an integration detail); richer proof systems for `chio-proof-carry` (Task 7 ships one concrete signed-attestation form plus the module seam).

**Placeholder scan:** no `TBD`/`TODO`/`implement later` in any step. Tasks 1, 2, and 7 instruct the implementer to confirm exact upstream names/line numbers against cited files, which are verification instructions, not placeholders.

**Type consistency:** `BurnLedger::spend`/`count` match across Tasks 3-4; `BurnDecision` variants match Tasks 4 and 8; `QuorumRequirement` fields match Tasks 5-6; `SignedApproval`/`quorum_satisfied` match Task 6 and the gate in Task 8; `ProofEnvelope`/`verify` match Task 7 and the gate in Task 8. Crypto surface verified against the exploration: `Keypair::generate`/`sign`, `PublicKey::verify(&self, message, signature) -> bool`, `PublicKey::to_hex`, `Signature::to_hex`/`from_hex`. `CaveatKind` extension and the token caveat-rejection replacement are anchored to `crates/core/chio-core-types/src/capability/token.rs:379-384`.
