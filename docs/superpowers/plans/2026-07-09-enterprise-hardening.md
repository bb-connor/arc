# Enterprise Hardening Pack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three `crates/security/` crates that close operational-trust gaps: `chio-keyring` (authority-key rotation with an append-only Merkle transparency log), `chio-secret-broker` (ephemeral capability-bound credential leases), and `chio-cage` (OS sandbox profiles compiled from the signed manifest).

**Architecture:** All three reuse existing primitives. `chio-keyring` mirrors the `EpochRootSigner`/`SignedEpochRoot` pattern from `chio-revocation-oracle`. `chio-secret-broker` reuses `SecretLeakGuard` from `chio-guards` at the lease boundary and defines a `SecretBackend` trait with a local reference implementation. `chio-cage` compiles `chio-manifest` `RequiredPermissions` into a portable `SandboxProfile`, with a Linux reference `Sandbox` implementation (seccomp-BPF plus Landlock) gated behind a target check and fail-closed everywhere else.

**Tech Stack:** Rust (workspace, edition 2021), `serde`, `sha2`, `ed25519-dalek` via `chio_core_types::crypto` (`Keypair`, `PublicKey`, `Signature`), `rustix` (new workspace dependency, Linux sandbox syscalls), `cargo test`/`clippy`/`fmt`.

## Global Constraints

Copied verbatim from the spec and house rules. Every task's requirements implicitly include this section.

- No em dashes (U+2014) anywhere in code, comments, or docs. Use hyphens (`-`) or parentheses.
- Fail-closed: a signing key absent from the transparency log is rejected; a lease past its capability is dead; a tool server with no derivable sandbox profile does not launch.
- Clippy: `unwrap_used = "deny"` and `expect_used = "deny"` workspace-wide. No `unwrap`/`expect`/`unsafe` in new code (the Linux sandbox syscalls go through `rustix`, which is safe).
- Serialization: canonical JSON (RFC 8785) for signed payloads.
- Commits: conventional commits.
- New crates use the workspace template: `version.workspace = true`, `edition.workspace = true`, `license.workspace = true`, `publish = false`, `[lints] workspace = true`, deps as `{ workspace = true }`.
- Threat-row framing: mechanisms that make rows closable, not closures.
- Verify each phase with: `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`.

---

## File Structure

**`crates/security/chio-keyring/` (create):**
- `Cargo.toml`, `src/lib.rs`
- `src/epoch.rs`: `KeyEpoch` (a key's lifecycle record) and `KeyOperation`.
- `src/log.rs`: the append-only transparency log with a Merkle root over key epochs.
- `src/rotation.rs`: rotate to a new active key with an overlap window.
- `src/verify.rs`: pin a log root, reject any key not proven present.

**`crates/security/chio-secret-broker/` (create):**
- `Cargo.toml`, `src/lib.rs`
- `src/lease.rs`: `Lease` (capability-bound, TTL'd credential handle).
- `src/backend.rs`: the `SecretBackend` trait and a local reference backend.
- `src/broker.rs`: mint, renew, revoke; per-subject rate limiting.
- `src/boundary.rs`: run `SecretLeakGuard` over values crossing the lease boundary.

**`crates/security/chio-cage/` (create):**
- `Cargo.toml`, `src/lib.rs`
- `src/profile.rs`: `SandboxProfile` (allowed roots, network, syscall allowlist).
- `src/compile.rs`: derive a `SandboxProfile` from `RequiredPermissions`.
- `src/sandbox.rs`: the portable `Sandbox` trait and a fail-closed default.
- `src/linux.rs`: the Linux reference impl (seccomp + Landlock), `#[cfg(target_os = "linux")]`.

**Gates, evidence, spec, workspace (create/modify):**
- `scripts/check-keyring-log-append-only.sh`, `scripts/check-broker-lease-ttl.sh`, `scripts/check-cage-fail-closed.sh`
- `crates/core/chio-adversarial-suite/cases/key_log_omission/`, `.../lease_after_revocation/`, `.../sandbox_escape_attempt/`
- Root `Cargo.toml` (modify): register three members; add `rustix` to `[workspace.dependencies]`.
- `spec/PROTOCOL.md`, `spec/SECURITY.md` (modify).

---

## Phase 1: chio-keyring

### Task 1: Crate scaffold and `KeyEpoch`

**Files:**
- Create: `crates/security/chio-keyring/Cargo.toml`, `src/lib.rs`, `src/epoch.rs`
- Modify: root `Cargo.toml` (`members`)
- Test: inline in `epoch.rs`

**Interfaces:**
- Consumes: `chio_core_types::crypto::{PublicKey, SigningAlgorithm}`.
- Produces: `KeyEpoch { seq: u64, activated_at: u64, retired_at: Option<u64>, algorithm: SigningAlgorithm, public_key: PublicKey, operation: KeyOperation }` and `KeyOperation { Issuance, Rotation, Retirement }`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::crypto::{Keypair, SigningAlgorithm};

    #[test]
    fn key_epoch_records_activation() {
        let pk = Keypair::generate().public_key();
        let epoch = KeyEpoch {
            seq: 0,
            activated_at: 1_000,
            retired_at: None,
            algorithm: SigningAlgorithm::Ed25519,
            public_key: pk,
            operation: KeyOperation::Issuance,
        };
        assert_eq!(epoch.seq, 0);
        assert!(epoch.retired_at.is_none());
        assert_eq!(epoch.operation, KeyOperation::Issuance);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-keyring epoch`
Expected: FAIL (crate/type missing).

- [ ] **Step 3: Write minimal implementation**

`Cargo.toml`:

```toml
[package]
name = "chio-keyring"
description = "Chio authority-key rotation and transparency log"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[lib]
name = "chio_keyring"

[dependencies]
chio-core-types = { workspace = true }
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }
sha2 = { workspace = true }

[lints]
workspace = true
```

`src/lib.rs`:

```rust
//! Authority-key lifecycle: rotation with overlap windows and an append-only
//! Merkle transparency log so verifiers can pin the set of keys that ever
//! signed.

pub mod epoch;
pub mod log;
pub mod rotation;
pub mod verify;
```

`src/epoch.rs`:

```rust
//! A key epoch: one authority key's lifecycle record in the transparency log.

use chio_core_types::crypto::{PublicKey, SigningAlgorithm};
use serde::{Deserialize, Serialize};

/// What lifecycle event a key epoch records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyOperation {
    Issuance,
    Rotation,
    Retirement,
}

/// One authority key's lifecycle record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyEpoch {
    pub seq: u64,
    pub activated_at: u64,
    pub retired_at: Option<u64>,
    pub algorithm: SigningAlgorithm,
    pub public_key: PublicKey,
    pub operation: KeyOperation,
}
```

Add `"crates/security/chio-keyring",` to the root `Cargo.toml` `members`. If `PublicKey` does not implement `Serialize`, serialize the hex form instead: read `crates/core/chio-core-types/src/crypto.rs:253` and use `to_hex()`/`from_hex()` with a `String` field.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-keyring epoch`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-keyring Cargo.toml
git commit -m "feat(keyring): scaffold with KeyEpoch lifecycle record"
```

### Task 2: Append-only transparency log

**Files:**
- Create: `crates/security/chio-keyring/src/log.rs`
- Test: inline

**Interfaces:**
- Consumes: `sha2::Sha256`, `crate::epoch::KeyEpoch`.
- Produces: `TransparencyLog` with `pub fn new() -> Self`, `pub fn append(&mut self, epoch: KeyEpoch) -> Result<LogRoot, LogError>`, and `pub fn root(&self) -> LogRoot`. `LogRoot { size: u64, root_hash: [u8; 32] }`; `LogError::Serialization`. `append` returns `Err` without mutating the log on serialization failure, so a caller never treats a failed append as success. Each root commits to the previous root, so the log is append-only and tamper-evident.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::crypto::{Keypair, SigningAlgorithm};
    use crate::epoch::{KeyEpoch, KeyOperation};

    fn epoch(seq: u64) -> KeyEpoch {
        KeyEpoch {
            seq,
            activated_at: seq * 100,
            retired_at: None,
            algorithm: SigningAlgorithm::Ed25519,
            public_key: Keypair::generate().public_key(),
            operation: KeyOperation::Rotation,
        }
    }

    #[test]
    fn append_grows_and_changes_root() {
        let mut log = TransparencyLog::new();
        let r0 = log.root();
        let r1 = log.append(epoch(0)).expect("append");
        assert_eq!(r1.size, 1);
        assert_ne!(r1.root_hash, r0.root_hash);
    }

    #[test]
    fn root_commits_to_previous_root() {
        let mut a = TransparencyLog::new();
        let mut b = TransparencyLog::new();
        a.append(epoch(0)).expect("append");
        let ra = a.append(epoch(1)).expect("append");
        // A log that appended the same two epochs in order has the same root.
        b.append(epoch_fixed(0)).expect("append");
        let rb = b.append(epoch_fixed(1)).expect("append");
        // Different keys -> different roots, proving order and content bind.
        assert_ne!(ra.root_hash, rb.root_hash);
    }

    fn epoch_fixed(seq: u64) -> KeyEpoch {
        KeyEpoch {
            seq,
            activated_at: seq * 100,
            retired_at: None,
            algorithm: SigningAlgorithm::Ed25519,
            public_key: Keypair::from_seed(&[7u8; 32]).public_key(),
            operation: KeyOperation::Rotation,
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-keyring log`
Expected: FAIL (`TransparencyLog` missing).

- [ ] **Step 3: Write minimal implementation**

`src/log.rs`:

```rust
//! Append-only key-transparency log. Each root hashes (previous root ||
//! canonical epoch), so the sequence is order-sensitive and tamper-evident.

use chio_core_types::canonical::to_canonical_json;
use sha2::{Digest, Sha256};

use crate::epoch::KeyEpoch;

/// A commitment to the log contents at a given size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRoot {
    pub size: u64,
    pub root_hash: [u8; 32],
}

/// A transparency-log operation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogError {
    /// The epoch could not be canonicalized for hashing; the log is unchanged.
    Serialization,
}

/// An append-only log of key epochs with a rolling Merkle-style root.
pub struct TransparencyLog {
    size: u64,
    root_hash: [u8; 32],
}

impl Default for TransparencyLog {
    fn default() -> Self {
        Self { size: 0, root_hash: [0u8; 32] }
    }
}

impl TransparencyLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an epoch, folding it into the rolling root. Returns the new root,
    /// or `Err` on serialization failure without mutating the log, so a caller
    /// (rotation) never activates a key whose append did not commit.
    pub fn append(&mut self, epoch: KeyEpoch) -> Result<LogRoot, LogError> {
        let bytes = to_canonical_json(&epoch).map_err(|_| LogError::Serialization)?;
        let mut hasher = Sha256::new();
        hasher.update(self.root_hash);
        hasher.update(bytes);
        self.root_hash = hasher.finalize().into();
        self.size += 1;
        Ok(self.root())
    }

    #[must_use]
    pub fn root(&self) -> LogRoot {
        LogRoot { size: self.size, root_hash: self.root_hash }
    }
}
```

Confirm the canonical-JSON helper name: read `crates/core/chio-core-types/src/canonical.rs` and use its public `to_canonical_json` (or equivalent) function; adjust the import if the name differs.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-keyring log`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-keyring/src/log.rs
git commit -m "feat(keyring): add append-only transparency log"
```

### Task 3: Rotation with overlap window

**Files:**
- Create: `crates/security/chio-keyring/src/rotation.rs`
- Test: inline

**Interfaces:**
- Consumes: `crate::epoch::{KeyEpoch, KeyOperation}`, `crate::log::TransparencyLog`.
- Produces: `Keyring` holding the log and epoch history, with `pub fn rotate(&mut self, new_key: KeyEpoch, now: u64) -> Result<(), LogError>` (appends a Retirement record for the previous key then the new key, activating the new key only after both appends commit) and `pub fn is_valid(&self, seq: u64, now: u64) -> bool` (a key is valid only at or after its activation time, and while active or within its overlap window).

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::crypto::{Keypair, SigningAlgorithm};
    use crate::epoch::{KeyEpoch, KeyOperation};

    fn epoch(seq: u64, now: u64) -> KeyEpoch {
        KeyEpoch {
            seq,
            activated_at: now,
            retired_at: None,
            algorithm: SigningAlgorithm::Ed25519,
            public_key: Keypair::generate().public_key(),
            operation: if seq == 0 { KeyOperation::Issuance } else { KeyOperation::Rotation },
        }
    }

    #[test]
    fn previous_key_valid_during_overlap_then_expires() {
        let mut kr = Keyring::new(60);
        kr.rotate(epoch(0, 0), 0).expect("rotate");
        kr.rotate(epoch(1, 100), 100).expect("rotate");
        // key 0 retired at 100, overlap 60 -> valid until 160.
        assert!(kr.is_valid(0, 150));
        assert!(!kr.is_valid(0, 161));
        // key 1 is active.
        assert!(kr.is_valid(1, 200));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-keyring rotation`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

`src/rotation.rs`:

```rust
//! Rotation with an overlap window: the previous key stays valid for
//! `overlap_secs` after retirement so in-flight capabilities do not break.

use crate::epoch::{KeyEpoch, KeyOperation};
use crate::log::{LogError, TransparencyLog};

/// Holds the transparency log and the current active key.
pub struct Keyring {
    log: TransparencyLog,
    epochs: Vec<KeyEpoch>,
    overlap_secs: u64,
}

impl Keyring {
    #[must_use]
    pub fn new(overlap_secs: u64) -> Self {
        Self { log: TransparencyLog::new(), epochs: Vec::new(), overlap_secs }
    }

    /// Rotate to a new key. Append a Retirement record for the current active
    /// key first, then the new key, marking state only after each append
    /// commits. If an append fails, the rotation returns `Err` and the new key
    /// is not activated, so the authority never signs with a key absent from
    /// the pinned log.
    pub fn rotate(&mut self, new_key: KeyEpoch, now: u64) -> Result<(), LogError> {
        if let Some(prev) = self.epochs.last().cloned() {
            if prev.retired_at.is_none() {
                self.log.append(KeyEpoch {
                    seq: prev.seq,
                    activated_at: prev.activated_at,
                    retired_at: Some(now),
                    algorithm: prev.algorithm,
                    public_key: prev.public_key.clone(),
                    operation: KeyOperation::Retirement,
                })?;
                if let Some(entry) = self.epochs.last_mut() {
                    entry.retired_at = Some(now);
                }
            }
        }
        self.log.append(new_key.clone())?;
        self.epochs.push(new_key);
        Ok(())
    }

    /// Whether the key at `seq` is valid at `now`: active (not retired) or
    /// within its overlap window.
    #[must_use]
    pub fn is_valid(&self, seq: u64, now: u64) -> bool {
        self.epochs.iter().any(|e| {
            // A key is never valid before its activation time, whether active or
            // retired, so a rewound clock cannot make a not-yet-activated key
            // valid just because it carries a retirement record.
            e.seq == seq
                && now >= e.activated_at
                && match e.retired_at {
                    None => true,
                    Some(retired) => now <= retired.saturating_add(self.overlap_secs),
                }
        })
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-keyring rotation`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-keyring/src/rotation.rs
git commit -m "feat(keyring): add rotation with overlap window"
```

### Task 4: Verify against a pinned log root

**Files:**
- Create: `crates/security/chio-keyring/src/verify.rs`
- Test: inline

**Interfaces:**
- Consumes: `crate::epoch::KeyEpoch`, `chio_core_types::crypto::PublicKey`.
- Produces: `pub fn key_in_log(epochs: &[KeyEpoch], pinned: LogRoot, key: &PublicKey) -> bool`. It recomputes the log root over `epochs` and rejects (returns false) unless they reproduce `pinned`, then checks membership; a key absent from the log, or present only in a slice that does not fold to the pinned root, is rejected (the caller fails closed).

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::crypto::{Keypair, SigningAlgorithm};
    use crate::epoch::{KeyEpoch, KeyOperation};
    use crate::log::TransparencyLog;

    fn epoch(seq: u64, key: chio_core_types::crypto::PublicKey) -> KeyEpoch {
        KeyEpoch {
            seq, activated_at: seq, retired_at: None,
            algorithm: SigningAlgorithm::Ed25519,
            public_key: key,
            operation: KeyOperation::Issuance,
        }
    }

    #[test]
    fn key_accepted_only_when_epochs_reproduce_the_pinned_root() {
        let kp = Keypair::generate();
        let epochs = vec![epoch(0, kp.public_key())];
        // Pin the root the honest log would produce for these epochs.
        let mut log = TransparencyLog::new();
        log.append(epochs[0].clone()).expect("append");
        let pinned = log.root();

        assert!(key_in_log(&epochs, pinned, &kp.public_key()));
        let stranger = Keypair::from_seed(&[9u8; 32]).public_key();
        assert!(!key_in_log(&epochs, pinned, &stranger));

        // A slice with an extra, unlogged key does not reproduce the pinned
        // root, so its key is rejected even though it is present in the slice.
        let mut forged = epochs.clone();
        forged.push(epoch(1, stranger.clone()));
        assert!(!key_in_log(&forged, pinned, &stranger));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-keyring verify`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

`src/verify.rs`:

```rust
//! Verification: a signing key is trusted only if it appears in the epochs
//! that reproduce the pinned transparency-log root. Recomputing the root stops
//! a caller from smuggling an unlogged key in via an arbitrary epoch slice.

use chio_core_types::crypto::PublicKey;

use crate::epoch::KeyEpoch;
use crate::log::{LogRoot, TransparencyLog};

/// Whether `key` appears in `epochs` AND those epochs fold to `pinned`. If the
/// epochs do not reproduce the pinned root (size and hash), the key is rejected
/// regardless of membership, so an injected unlogged key cannot be accepted.
#[must_use]
pub fn key_in_log(epochs: &[KeyEpoch], pinned: LogRoot, key: &PublicKey) -> bool {
    let mut log = TransparencyLog::new();
    for epoch in epochs {
        if log.append(epoch.clone()).is_err() {
            return false;
        }
    }
    let recomputed = log.root();
    if recomputed.size != pinned.size || recomputed.root_hash != pinned.root_hash {
        return false;
    }
    let target = key.to_hex();
    epochs.iter().any(|e| e.public_key.to_hex() == target)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-keyring verify`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-keyring/src/verify.rs
git commit -m "feat(keyring): reject signing keys absent from the transparency log"
```

---

## Phase 2: chio-secret-broker

### Task 5: Crate scaffold and `Lease`

**Files:**
- Create: `crates/security/chio-secret-broker/Cargo.toml`, `src/lib.rs`, `src/lease.rs`
- Modify: root `Cargo.toml` (`members`)
- Test: inline in `lease.rs`

**Interfaces:**
- Produces: `Lease { id: String, capability_id: String, subject: String, issued_at: u64, expires_at: u64 }` with `pub fn is_live(&self, now: u64) -> bool`. A lease is a handle bound to a capability; it never carries the raw secret.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_expires_at_ttl() {
        let lease = Lease {
            id: "lease-1".to_string(),
            capability_id: "cap-1".to_string(),
            subject: "did:chio:agent".to_string(),
            issued_at: 100,
            expires_at: 160,
        };
        assert!(lease.is_live(150));
        assert!(!lease.is_live(161));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-secret-broker lease`
Expected: FAIL (crate missing).

- [ ] **Step 3: Write minimal implementation**

`Cargo.toml`:

```toml
[package]
name = "chio-secret-broker"
description = "Chio ephemeral capability-bound credential leases"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[lib]
name = "chio_secret_broker"

[dependencies]
chio-core-types = { workspace = true }
chio-guards = { workspace = true }
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }

[lints]
workspace = true
```

`src/lib.rs`:

```rust
//! Ephemeral credential leases: tool servers receive a short-TTL, capability-
//! bound handle, never a long-lived secret. Leases die with their capability.

pub mod backend;
pub mod boundary;
pub mod broker;
pub mod lease;
```

`src/lease.rs`:

```rust
//! A lease: a capability-bound, TTL'd credential handle.

use serde::{Deserialize, Serialize};

/// A credential lease. Carries no raw secret; the backend resolves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lease {
    pub id: String,
    pub capability_id: String,
    pub subject: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl Lease {
    /// Whether `now` is within the lease's validity window. Requires
    /// `issued_at <= now <= expires_at`, so a rewound clock (`now < issued_at`)
    /// fails closed instead of reviving an expired lease.
    #[must_use]
    pub fn is_live(&self, now: u64) -> bool {
        self.issued_at <= now && now <= self.expires_at
    }
}
```

Add the member to the root `Cargo.toml`. Confirm `chio-guards` is the correct crate name for `SecretLeakGuard` in `[workspace.dependencies]`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-secret-broker lease`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-secret-broker Cargo.toml
git commit -m "feat(secret-broker): scaffold with capability-bound Lease"
```

### Task 6: Backend trait, local backend, and broker lifecycle

**Files:**
- Create: `crates/security/chio-secret-broker/src/backend.rs`, `src/broker.rs`
- Test: inline in `broker.rs`

**Interfaces:**
- Produces: `SecretBackend` trait (`resolve`/`store`) and `LocalBackend`; a `RevocationView` trait (`fn is_revoked(&self, capability_id: &str) -> bool`); `Broker::new(backend, default_ttl, max_leases_per_subject)` tracking issued leases, with `pub fn mint(&mut self, capability_id: &str, subject: &str, now: u64) -> Option<Lease>` (returns `None` past the per-subject live-lease limit), `revoke`, and `pub fn resolve(&self, lease: &Lease, now: u64, revocations: &dyn RevocationView) -> Option<String>`. `resolve` yields `None` unless the lease was minted by this broker and equals its stored binding, is within TTL, is not lease-revoked, and its bound capability is not revoked. The raw-secret boundary scan is wired into `resolve` in Task 7.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::LocalBackend;

    struct NoRevocations;
    impl RevocationView for NoRevocations {
        fn is_revoked(&self, _capability_id: &str) -> bool { false }
    }
    struct CapabilityRevoked;
    impl RevocationView for CapabilityRevoked {
        fn is_revoked(&self, _capability_id: &str) -> bool { true }
    }

    fn broker_with_secret() -> Broker {
        let mut backend = LocalBackend::new();
        backend.store("cap-1", "s3cr3t".to_string());
        Broker::new(Box::new(backend), 60, 8)
    }

    #[test]
    fn minted_lease_resolves_then_revokes() {
        let mut broker = broker_with_secret();
        let lease = broker.mint("cap-1", "did:chio:agent", 100).expect("under limit");
        assert_eq!(lease.expires_at, 160);
        assert_eq!(broker.resolve(&lease, 150, &NoRevocations), Some("s3cr3t".to_string()));
        broker.revoke(&lease.id);
        assert!(broker.resolve(&lease, 150, &NoRevocations).is_none());
    }

    #[test]
    fn fabricated_lease_does_not_resolve() {
        let broker = broker_with_secret();
        // Never minted by this broker: fresh id, far-future expiry, known cap.
        let forged = Lease {
            id: "lease-999".to_string(),
            capability_id: "cap-1".to_string(),
            subject: "attacker".to_string(),
            issued_at: 0,
            expires_at: u64::MAX,
        };
        assert!(broker.resolve(&forged, 150, &NoRevocations).is_none());
    }

    #[test]
    fn lease_dies_when_bound_capability_is_revoked() {
        let mut broker = broker_with_secret();
        let lease = broker.mint("cap-1", "did:chio:agent", 100).expect("under limit");
        assert!(broker.resolve(&lease, 150, &CapabilityRevoked).is_none());
    }

    #[test]
    fn mint_refuses_past_the_per_subject_limit() {
        let backend = LocalBackend::new();
        let mut broker = Broker::new(Box::new(backend), 60, 2);
        assert!(broker.mint("cap-1", "sub", 100).is_some());
        assert!(broker.mint("cap-1", "sub", 100).is_some());
        // Third live lease for the same subject is refused.
        assert!(broker.mint("cap-1", "sub", 100).is_none());
        // A different subject is unaffected.
        assert!(broker.mint("cap-1", "other", 100).is_some());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-secret-broker broker`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

`src/backend.rs`:

```rust
//! The secret backend abstraction. The local reference backend holds secrets
//! keyed by capability id; external KMS or Vault backends are a later,
//! feature-gated addition behind this trait.

use std::collections::HashMap;

use crate::lease::Lease;

/// Resolves a lease to its underlying secret. Implementations must return
/// `None` for any lease they do not recognize (fail-closed).
pub trait SecretBackend: Send + Sync {
    fn resolve(&self, lease: &Lease) -> Option<String>;
    fn store(&mut self, key: &str, secret: String);
}

/// In-process reference backend: secrets keyed by capability id.
#[derive(Default)]
pub struct LocalBackend {
    secrets: HashMap<String, String>,
}

impl LocalBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretBackend for LocalBackend {
    fn resolve(&self, lease: &Lease) -> Option<String> {
        self.secrets.get(&lease.capability_id).cloned()
    }

    fn store(&mut self, key: &str, secret: String) {
        self.secrets.insert(key.to_string(), secret);
    }
}
```

`src/broker.rs`:

```rust
//! The broker: mints, renews, and revokes leases. Only broker-minted leases
//! resolve, and a lease dies with its capability (revocation) as well as its
//! TTL.

use std::collections::{HashMap, HashSet};

use crate::backend::SecretBackend;
use crate::lease::Lease;

/// A view over capability revocation state (backed by chio-revocation-oracle in
/// production). A lease dies with its bound capability.
pub trait RevocationView {
    fn is_revoked(&self, capability_id: &str) -> bool;
}

/// Issues and tracks leases over a secret backend.
pub struct Broker {
    backend: Box<dyn SecretBackend>,
    issued: HashMap<String, Lease>,
    revoked: HashSet<String>,
    next_id: u64,
    default_ttl: u64,
    max_leases_per_subject: usize,
}

impl Broker {
    #[must_use]
    pub fn new(
        backend: Box<dyn SecretBackend>,
        default_ttl: u64,
        max_leases_per_subject: usize,
    ) -> Self {
        Self {
            backend,
            issued: HashMap::new(),
            revoked: HashSet::new(),
            next_id: 0,
            default_ttl,
            max_leases_per_subject,
        }
    }

    /// Mint a lease bound to a capability, expiring at `now + default_ttl`, and
    /// record it so only broker-minted leases can later resolve. Returns `None`
    /// when the subject already holds `max_leases_per_subject` live, unrevoked
    /// leases, so a compromised subject cannot mint unbounded live leases.
    pub fn mint(&mut self, capability_id: &str, subject: &str, now: u64) -> Option<Lease> {
        let live_for_subject = self
            .issued
            .values()
            .filter(|l| l.subject == subject && !self.revoked.contains(&l.id) && l.is_live(now))
            .count();
        if live_for_subject >= self.max_leases_per_subject {
            return None;
        }
        let id = format!("lease-{}", self.next_id);
        self.next_id += 1;
        let lease = Lease {
            id: id.clone(),
            capability_id: capability_id.to_string(),
            subject: subject.to_string(),
            issued_at: now,
            expires_at: now.saturating_add(self.default_ttl),
        };
        self.issued.insert(id, lease.clone());
        Some(lease)
    }

    /// Revoke a lease by id.
    pub fn revoke(&mut self, lease_id: &str) {
        self.revoked.insert(lease_id.to_string());
    }

    /// Resolve a lease to its secret, or `None` if the lease was not minted by
    /// this broker (unknown id, or a presented lease that does not match the
    /// stored binding), is expired or lease-revoked, or its bound capability
    /// has been revoked. A fabricated lease with a fresh id and far-future
    /// expiry cannot resolve because it is absent from `issued`.
    #[must_use]
    pub fn resolve(
        &self,
        lease: &Lease,
        now: u64,
        revocations: &dyn RevocationView,
    ) -> Option<String> {
        let issued = self.issued.get(&lease.id)?;
        if issued != lease {
            return None;
        }
        if self.revoked.contains(&lease.id) || !lease.is_live(now) {
            return None;
        }
        if revocations.is_revoked(&lease.capability_id) {
            return None;
        }
        self.backend.resolve(lease)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-secret-broker broker`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-secret-broker/src/backend.rs crates/security/chio-secret-broker/src/broker.rs
git commit -m "feat(secret-broker): add backend trait, local backend, and broker lifecycle"
```

### Task 7: Lease boundary secret scan

**Files:**
- Create: `crates/security/chio-secret-broker/src/boundary.rs`
- Modify: `crates/security/chio-secret-broker/src/broker.rs` (call the scan in `resolve`), `src/lib.rs` (`pub mod boundary;`)
- Test: inline

**Interfaces:**
- Consumes: `chio_guards::SecretLeakGuard` (confirm the exact export path; the exploration cites `crates/guards/chio-guards/src/secret_leak.rs` with `SecretLeakGuard::new()` and `SecretMatch { pattern_name, offset, length, redacted }`).
- Produces: `pub fn scan_for_raw_secret(value: &str) -> bool` returning true when the value looks like a raw long-lived secret. `Broker::resolve` calls it on the resolved value and returns `None` when it fires, so a lease never hands back a raw long-lived credential.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_style_secret() {
        // An AKIA-prefixed key is a classic long-lived secret.
        assert!(scan_for_raw_secret("AKIAIOSFODNN7EXAMPLE"));
        assert!(!scan_for_raw_secret("lease-1"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-secret-broker boundary`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

`src/boundary.rs`:

```rust
//! The lease boundary: run the existing secret detector over any value the
//! broker is about to return, so a raw long-lived secret cannot be handed
//! back where a lease handle was expected.

use chio_guards::SecretLeakGuard;

/// Whether `value` looks like a raw long-lived secret. Uses the shared
/// `SecretLeakGuard` detector so patterns stay consistent with the rest of
/// Chio.
#[must_use]
pub fn scan_for_raw_secret(value: &str) -> bool {
    let guard = SecretLeakGuard::new();
    !guard.scan(value).is_empty()
}
```

Confirm the detector method: read `crates/guards/chio-guards/src/secret_leak.rs` for the public scan method that returns `Vec<SecretMatch>` (the exploration names `SecretMatch`); if the method is named differently (for example `detect` or `find_secrets`), use that name and keep the "non-empty means secret" logic.

Then wire the scan into `Broker::resolve` so a resolved raw secret is refused, and add `pub mod boundary;` to `lib.rs`. Change the tail of `resolve`:

```rust
        let secret = self.backend.resolve(lease)?;
        // A lease must never hand back a raw long-lived secret; refuse if the
        // resolved value looks like one.
        if crate::boundary::scan_for_raw_secret(&secret) {
            return None;
        }
        Some(secret)
```

Add a broker test proving a lease over a raw AWS-style secret refuses to resolve (it reuses the `NoRevocations` fake from Task 6's test module):

```rust
    #[test]
    fn lease_refuses_to_return_a_raw_secret() {
        let mut backend = LocalBackend::new();
        backend.store("cap-raw", "AKIAIOSFODNN7EXAMPLE".to_string());
        let mut broker = Broker::new(Box::new(backend), 60, 8);
        let lease = broker.mint("cap-raw", "did:chio:agent", 100).expect("under limit");
        assert!(broker.resolve(&lease, 150, &NoRevocations).is_none());
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-secret-broker boundary && cargo test -p chio-secret-broker broker`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-secret-broker/src/boundary.rs crates/security/chio-secret-broker/src/broker.rs crates/security/chio-secret-broker/src/lib.rs
git commit -m "feat(secret-broker): scan lease boundary and refuse raw secrets in resolve"
```

---

## Phase 3: chio-cage

### Task 8: Crate scaffold and `SandboxProfile`

**Files:**
- Create: `crates/security/chio-cage/Cargo.toml`, `src/lib.rs`, `src/profile.rs`
- Modify: root `Cargo.toml` (`members`)
- Test: inline in `profile.rs`

**Interfaces:**
- Produces: `SandboxProfile { read_roots: Vec<String>, write_roots: Vec<String>, network_dests: Vec<String>, syscall_allow: Vec<String> }` with `pub fn deny_all() -> Self` (the fail-closed default: nothing allowed).

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_all_allows_nothing() {
        let p = SandboxProfile::deny_all();
        assert!(p.read_roots.is_empty());
        assert!(p.write_roots.is_empty());
        assert!(p.network_dests.is_empty());
        assert!(p.syscall_allow.is_empty());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-cage profile`
Expected: FAIL (crate missing).

- [ ] **Step 3: Write minimal implementation**

`Cargo.toml`:

```toml
[package]
name = "chio-cage"
description = "Chio OS sandbox profiles compiled from the signed manifest"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[lib]
name = "chio_cage"

[dependencies]
chio-manifest = { workspace = true }
serde = { workspace = true, features = ["derive"] }

[target.'cfg(target_os = "linux")'.dependencies]
rustix = { workspace = true, features = ["process", "thread"] }

[lints]
workspace = true
```

`src/lib.rs`:

```rust
//! OS sandbox profiles compiled from a signed manifest's RequiredPermissions.
//! Portable `Sandbox` trait with a Linux reference implementation; fail-closed
//! everywhere a profile cannot be built or enforced.

pub mod compile;
pub mod profile;
pub mod sandbox;

#[cfg(target_os = "linux")]
pub mod linux;
```

`src/profile.rs`:

```rust
//! The sandbox profile: the confinement a tool server runs under.

use serde::{Deserialize, Serialize};

/// A derived confinement profile for one tool server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxProfile {
    pub read_roots: Vec<String>,
    pub write_roots: Vec<String>,
    pub network_dests: Vec<String>,
    pub syscall_allow: Vec<String>,
}

impl SandboxProfile {
    /// The fail-closed default: allow nothing.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }
}
```

Add the member to the root `Cargo.toml`, and add `rustix = "0.38"` (or the current version) to `[workspace.dependencies]`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-cage profile`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-cage Cargo.toml
git commit -m "feat(cage): scaffold with fail-closed SandboxProfile"
```

### Task 9: Compile `RequiredPermissions` into a profile

**Files:**
- Create: `crates/security/chio-cage/src/compile.rs`
- Test: inline

**Interfaces:**
- Consumes: `chio_manifest::{ToolManifest, RequiredPermissions}`, `crate::profile::SandboxProfile`.
- Produces: `pub fn compile(manifest: &ToolManifest) -> SandboxProfile`. When `required_permissions` is `None`, returns `deny_all` (fail-closed). Otherwise maps `read_paths`/`write_paths`/`network_hosts` into the profile and sets a minimal baseline syscall allowlist.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chio_manifest::{RequiredPermissions, ToolManifest};

    fn manifest(perms: Option<RequiredPermissions>) -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "srv".into(),
            name: "s".to_string(),
            description: None,
            version: "1".to_string(),
            tools: Vec::new(),
            server_tools: Vec::new(),
            required_permissions: perms,
            public_key: String::new(),
        }
    }

    #[test]
    fn no_permissions_is_deny_all() {
        assert_eq!(compile(&manifest(None)), SandboxProfile::deny_all());
    }

    #[test]
    fn read_paths_map_into_profile() {
        let perms = RequiredPermissions {
            read_paths: Some(vec!["/data".to_string()]),
            write_paths: None,
            network_hosts: None,
            environment_variables: None,
        };
        let profile = compile(&manifest(Some(perms)));
        assert_eq!(profile.read_roots, vec!["/data".to_string()]);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-cage compile`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

`src/compile.rs`:

```rust
//! Compile a signed manifest's RequiredPermissions into a SandboxProfile.
//! No permissions block means no launch: fail-closed to deny_all.

use chio_manifest::ToolManifest;

use crate::profile::SandboxProfile;

/// Minimal syscalls every tool server needs to run at all.
const BASELINE_SYSCALLS: &[&str] = &["read", "write", "exit", "exit_group", "rt_sigreturn"];

/// Derive a sandbox profile from a manifest. A manifest with no declared
/// permissions yields `deny_all`.
#[must_use]
pub fn compile(manifest: &ToolManifest) -> SandboxProfile {
    let Some(perms) = &manifest.required_permissions else {
        return SandboxProfile::deny_all();
    };
    SandboxProfile {
        read_roots: perms.read_paths.clone().unwrap_or_default(),
        write_roots: perms.write_paths.clone().unwrap_or_default(),
        network_dests: perms.network_hosts.clone().unwrap_or_default(),
        syscall_allow: BASELINE_SYSCALLS.iter().map(|s| (*s).to_string()).collect(),
    }
}
```

Confirm the `ToolManifest` field set against `crates/platform/chio-manifest/src/lib.rs:28`; if `server_id` is a newtype, construct it with the real constructor rather than `.into()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-cage compile`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-cage/src/compile.rs
git commit -m "feat(cage): compile RequiredPermissions into a sandbox profile"
```

### Task 10: Sandbox trait, fail-closed default, Linux reference impl

**Files:**
- Create: `crates/security/chio-cage/src/sandbox.rs`, `src/linux.rs`
- Test: inline in `sandbox.rs`

**Interfaces:**
- Produces: `Sandbox` trait with `fn apply(&self, profile: &SandboxProfile) -> Result<(), SandboxError>`; `DenySandbox` (the portable fail-closed default that refuses to launch when it cannot enforce a profile); and, on Linux, `LinuxSandbox` applying seccomp and Landlock via `rustix`. Non-Linux builds use `DenySandbox`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::SandboxProfile;

    #[test]
    fn deny_sandbox_refuses_when_it_cannot_enforce() {
        let sandbox = DenySandbox;
        let err = sandbox.apply(&SandboxProfile::deny_all());
        assert!(err.is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-cage sandbox`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

`src/sandbox.rs`:

```rust
//! The portable Sandbox trait and the fail-closed default. Where no real OS
//! sandbox is available, `DenySandbox` refuses to launch rather than running
//! a tool server unconfined.

use crate::profile::SandboxProfile;

/// A failure to establish confinement. Callers must treat this as "do not
/// launch the tool server".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxError {
    pub detail: String,
}

/// Applies a sandbox profile to the current process before exec.
pub trait Sandbox {
    fn apply(&self, profile: &SandboxProfile) -> Result<(), SandboxError>;
}

/// The fail-closed default: never confirms confinement, so a caller that only
/// has this must refuse to launch.
pub struct DenySandbox;

impl Sandbox for DenySandbox {
    fn apply(&self, _profile: &SandboxProfile) -> Result<(), SandboxError> {
        Err(SandboxError {
            detail: "no OS sandbox backend available on this platform; refusing to launch".to_string(),
        })
    }
}

/// The best sandbox available on this platform. On Linux this is
/// `LinuxSandbox`; elsewhere it is `DenySandbox`.
#[must_use]
#[cfg(target_os = "linux")]
pub fn platform_sandbox() -> Box<dyn Sandbox> {
    Box::new(crate::linux::LinuxSandbox::new())
}

#[must_use]
#[cfg(not(target_os = "linux"))]
pub fn platform_sandbox() -> Box<dyn Sandbox> {
    Box::new(DenySandbox)
}
```

`src/linux.rs`:

```rust
//! Linux reference sandbox: applies Landlock filesystem rules and a seccomp
//! syscall filter derived from the profile. Uses `rustix` (safe syscall
//! bindings); no `unsafe`. Probes for support at construction and fails
//! closed when the kernel lacks Landlock or seccomp.

use crate::profile::SandboxProfile;
use crate::sandbox::{Sandbox, SandboxError};

/// Linux sandbox backend.
pub struct LinuxSandbox {
    landlock_supported: bool,
}

impl LinuxSandbox {
    #[must_use]
    pub fn new() -> Self {
        // Probe once; a full implementation queries the Landlock ABI version.
        Self { landlock_supported: probe_landlock() }
    }
}

impl Sandbox for LinuxSandbox {
    fn apply(&self, profile: &SandboxProfile) -> Result<(), SandboxError> {
        if !self.landlock_supported {
            return Err(SandboxError {
                detail: "Landlock unsupported on this kernel; refusing to launch".to_string(),
            });
        }
        if profile.read_roots.is_empty() && profile.write_roots.is_empty() {
            return Err(SandboxError {
                detail: "empty filesystem profile; refusing to launch".to_string(),
            });
        }
        if !profile.network_dests.is_empty() {
            // seccomp and Landlock filesystem rules do not constrain network
            // egress to the signed manifest hosts. Until a per-destination
            // network path exists (Landlock network port rules on newer kernels,
            // or an nftables/eBPF hook), refuse to launch a networked tool rather
            // than allow unconstrained egress.
            return Err(SandboxError {
                detail: "network destinations declared but not enforceable; refusing to launch"
                    .to_string(),
            });
        }
        // Full implementation: build a Landlock ruleset from read_roots and
        // write_roots and a seccomp filter from syscall_allow via rustix, then
        // restrict_self before exec. Kept minimal here so the crate builds and
        // tests portably; the enforcement body is the next increment.
        Ok(())
    }
}

fn probe_landlock() -> bool {
    // A full implementation calls the Landlock ABI-version syscall via rustix.
    // Default false so unsupported kernels fail closed.
    false
}
```

Read the current `rustix` Landlock and seccomp surface before fleshing out `apply`; the minimal body above compiles and preserves the fail-closed contract that the test checks. Because `probe_landlock` returns false, the Linux path also fails closed until the enforcement body lands, which is the safe default.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-cage sandbox`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-cage/src/sandbox.rs crates/security/chio-cage/src/linux.rs
git commit -m "feat(cage): add Sandbox trait, fail-closed default, and Linux backend skeleton"
```

---

## Phase 4: Gates, evidence, spec

### Task 11: Release gates and adversarial corpus

**Files:**
- Create: `scripts/check-keyring-log-append-only.sh`, `scripts/check-broker-lease-ttl.sh`, `scripts/check-cage-fail-closed.sh`
- Create: `crates/core/chio-adversarial-suite/cases/key_log_omission/key-log-omission-001.json`, `.../lease_after_revocation/lease-after-revocation-001.json`, `.../sandbox_escape_attempt/sandbox-escape-attempt-001.json`
- Test: run each script; run the suite loader

**Interfaces:**
- Produces: three fail-closed gates and three adversarial cases mirroring the existing case schema.

- [ ] **Step 1: Write the three gate scripts**

`scripts/check-keyring-log-append-only.sh`:

```bash
#!/usr/bin/env bash
# Fail-closed gate: the transparency log must fold the previous root into each
# append (append-only, tamper-evident).
set -euo pipefail
grep -q "hasher.update(self.root_hash)" crates/security/chio-keyring/src/log.rs \
  || { echo "FAIL: log append does not chain the previous root" >&2; exit 1; }
echo "OK: keyring log chains prior root"
```

`scripts/check-broker-lease-ttl.sh`:

```bash
#!/usr/bin/env bash
# Fail-closed gate: every lease must carry an expiry and resolution must honor
# revocation and TTL.
set -euo pipefail
grep -q "expires_at" crates/security/chio-secret-broker/src/lease.rs \
  || { echo "FAIL: Lease has no expires_at" >&2; exit 1; }
grep -q "self.revoked.contains" crates/security/chio-secret-broker/src/broker.rs \
  || { echo "FAIL: broker.resolve does not honor revocation" >&2; exit 1; }
echo "OK: broker leases are TTL'd and revocable"
```

`scripts/check-cage-fail-closed.sh`:

```bash
#!/usr/bin/env bash
# Fail-closed gate: no permissions block compiles to deny_all, and the default
# sandbox refuses to launch.
set -euo pipefail
grep -q "return SandboxProfile::deny_all()" crates/security/chio-cage/src/compile.rs \
  || { echo "FAIL: compile does not fail closed on missing permissions" >&2; exit 1; }
grep -q "refusing to launch" crates/security/chio-cage/src/sandbox.rs \
  || { echo "FAIL: DenySandbox does not refuse to launch" >&2; exit 1; }
echo "OK: cage fails closed"
```

- [ ] **Step 2: Run the three gates**

Run: `bash scripts/check-keyring-log-append-only.sh && bash scripts/check-broker-lease-ttl.sh && bash scripts/check-cage-fail-closed.sh`
Expected: three OK lines.

- [ ] **Step 3: Read an existing adversarial case and mirror its schema**

Run: `sed -n '1,40p' $(find crates/core/chio-adversarial-suite/cases -name '*.json' | head -1)`
Then write the three new case files with the same top-level fields (`class`, `reason`, `path`, and any manifest entry), encoding: `key_log_omission` (a signature from a key absent from the log), `lease_after_revocation` (a lease resolved after revoke), `sandbox_escape_attempt` (a syscall outside the allowlist). Register them in the suite index if one exists.

- [ ] **Step 4: Run the suite and gates**

Run: `cargo test -p chio-adversarial-suite && bash scripts/check-cage-fail-closed.sh`
Expected: PASS and OK.

- [ ] **Step 5: Commit**

```bash
chmod +x scripts/check-keyring-log-append-only.sh scripts/check-broker-lease-ttl.sh scripts/check-cage-fail-closed.sh
git add scripts/check-keyring-log-append-only.sh scripts/check-broker-lease-ttl.sh scripts/check-cage-fail-closed.sh crates/core/chio-adversarial-suite/cases/
git commit -m "feat(security): add enterprise-pack release gates and adversarial cases"
```

### Task 12: Spec deltas and workspace verification

**Files:**
- Modify: `spec/PROTOCOL.md`, `spec/SECURITY.md`
- Test: whole workspace

**Interfaces:**
- Produces: normative prose for the transparency-log semantics (append-only, key-pinning), the lease model (capability binding, TTL), and the manifest-to-sandbox compilation contract (no permissions implies no launch).

- [ ] **Step 1: Add the transparency-log and sandbox sections to `spec/SECURITY.md`**

Under the implementation-guidance section, document: keys must appear in the transparency log before use; rotation keeps the prior key valid through an overlap window; a tool server with no derivable sandbox profile does not launch. Use hyphens, not em dashes.

- [ ] **Step 2: Add the lease model to `spec/PROTOCOL.md`**

Under the capability contract, document that a lease is bound to a capability id and dies with it, and that raw long-lived secrets never cross the lease boundary.

- [ ] **Step 3: Run the full workspace one-liner**

Run: `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`
Expected: all green. On non-Linux hosts the `chio-cage` Linux path is compiled out; confirm `platform_sandbox` returns `DenySandbox` there.

- [ ] **Step 4: Run the three gates**

Run: `bash scripts/check-keyring-log-append-only.sh && bash scripts/check-broker-lease-ttl.sh && bash scripts/check-cage-fail-closed.sh`
Expected: three OK lines.

- [ ] **Step 5: Commit**

```bash
git add spec/PROTOCOL.md spec/SECURITY.md
git commit -m "docs(spec): specify transparency log, lease model, and sandbox compilation"
```

---

## Self-Review

**Spec coverage:** `chio-keyring` epoch/log/rotation/verify (Tasks 1-4); `chio-secret-broker` lease/backend/broker/boundary (Tasks 5-7); `chio-cage` profile/compile/sandbox/linux (Tasks 8-10); gates and adversarial corpus (Task 11); spec deltas and workspace registration (Task 12). The three threat rows in the spec (`tool_server_escape`, `pq_signature_downgrade`, `pii_phi_exposure`) map to cage, keyring, and secret-broker respectively, framed as mechanisms not closures.

**Deferred items made explicit (not silent gaps):** the Linux sandbox enforcement body (Task 10 ships the fail-closed skeleton and probe; the seccomp/Landlock ruleset construction via `rustix` is the next increment, and until it lands the Linux path fails closed); external KMS/Vault backends (Task 6 ships the trait and a local backend); a real Merkle inclusion proof for the transparency log (Task 2 ships a rolling chained root; per-key inclusion proofs mirror `chio-revocation-oracle` and are a follow-up).

**Placeholder scan:** no `TBD`/`TODO`/`implement later` in any step. Three tasks (1, 7, 9) instruct the implementer to confirm an exact upstream name against a cited file path, which is a verification instruction, not a placeholder.

**Type consistency:** `SandboxProfile::deny_all` is used consistently in Tasks 8-10; `Lease.expires_at` and `is_live` are consistent in Tasks 5-6; `SecretBackend::resolve`/`store` match across Tasks 6-7; `KeyEpoch` fields match across Tasks 1-4. Crypto surface verified against the exploration: `Keypair::generate()`, `Keypair::from_seed(&[u8;32])`, `Keypair::public_key()`, `PublicKey::to_hex()`, `SigningAlgorithm::Ed25519`.
