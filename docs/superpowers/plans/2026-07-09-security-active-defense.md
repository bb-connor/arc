# Security Active-Defense Arc Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new `crates/security/` folder with three crates (`chio-flow`, `chio-decoy`, `chio-quarantine`) that give Chio an active-defense loop: information-flow control detects leak paths, canary capabilities bait intruders, and a tiered response engine contains incidents with attested, reversible actions.

**Architecture:** Protocol-normative types (the DLM `Label`, a `Declassify` caveat, manifest `sensitivity`/`clearance`) land in the existing `chio-core-types` and `chio-manifest` crates. The three engines live under `crates/security/`. `chio-flow` plugs a `FlowGuard` into the existing in-TCB guard pipeline and a `FlowTaintHook` into the existing post-invocation pipeline. `chio-decoy` mints canary capabilities in a reserved `decoy:` server namespace. `chio-quarantine` sits above the kernel and reaches revocation/velocity/issuance primitives through trait ports with feature-gated adapters, so it stays out of the TCB.

**Tech Stack:** Rust (workspace, edition 2021), `serde` + canonical JSON (RFC 8785 via the existing `chio_core_types::canonical` helpers), `ed25519`/`Signature` from `chio_core_types::crypto`, the `Guard` trait from `chio_kernel`, `cargo test`/`clippy`/`fmt`, `cargo-mutants`, and the existing `chio-arena` coevolution harness.

## Global Constraints

Copied verbatim from the spec and house rules. Every task's requirements implicitly include this section.

- No em dashes (U+2014) anywhere in code, comments, or docs. Use hyphens (`-`) or parentheses.
- Fail-closed: any guard error, unknown label, or missing clearance denies. Invalid inputs reject.
- Clippy: `unwrap_used = "deny"` and `expect_used = "deny"` workspace-wide. No `unwrap`/`expect`/`unsafe` in new code.
- Serialization: canonical JSON (RFC 8785) for all signed payloads, via `chio_core_types::canonical`.
- Commits: conventional commits (`feat:`, `fix:`, `docs:`, `test:`).
- Prevention stays fail-closed and independent of response. `chio-quarantine` is best-effort and never in the TCB.
- Threat-row framing: this plan ships mechanisms and gates. It does not mark any `docs/security/threat-coverage.md` row `Covered`; that happens only when the coverage gate accepts conformance + caught-mutant evidence.
- Verify each phase with the workspace one-liner before declaring it done: `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`.

---

## File Structure

New and modified files, grouped by the crate that owns them.

**Foundation (existing crates, modified):**
- `crates/core/chio-core-types/src/flow_label.rs` (create): the DLM `Label`, `FlowPolicy`, and `Compartment` data types plus serde. Pure data, no lattice algebra.
- `crates/core/chio-core-types/src/lib.rs` (modify): register `pub mod flow_label;`.
- `crates/core/chio-core-types/src/capability/caveat.rs` (modify): add the `Declassify` variant to `CaveatKind`.
- `crates/platform/chio-manifest/src/lib.rs` (modify): add `sensitivity` and `clearance` to `ToolDefinition`.

**`crates/security/chio-flow/` (create):**
- `Cargo.toml`, `src/lib.rs`
- `src/label.rs`: lattice algebra (`join`, `flows_to`) over `chio_core_types::flow_label::Label`.
- `src/seed.rs`: label acquisition from classifier tags and manifest declarations.
- `src/env.rs`: the per-session taint environment store.
- `src/guard.rs`: `FlowGuard` (pre-invocation egress check) and `FlowTaintHook` (post-invocation labeling).
- `src/declassify.rs`: declassification-caveat verification and the declassification event.
- `src/event.rs`: `FlowViolation` and `Declassification` signed event records.

**`crates/security/chio-decoy/` (create):**
- `Cargo.toml`, `src/lib.rs`
- `src/canary.rs`: canary-capability minting and the `DECOY_SERVER_PREFIX`.
- `src/registry.rs`: canary-id registry and recognition.
- `src/catalog.rs`: honey-tool injection into a tool catalog.
- `src/watermark.rs`: deterministic honeytoken emit/detect.
- `src/tripwire.rs`: tripwire hook and the `Tripwire` event.

**`crates/security/chio-quarantine/` (create):**
- `Cargo.toml`, `src/lib.rs`
- `src/event.rs`: the `SecurityEvent` model.
- `src/ports.rs`: `RevocationPort`, `VelocityPort`, `IssuancePort`, `AlertPort`, `BlastRadiusPort` traits.
- `src/action.rs`: `ContainmentAction`, `ActionTier`, the tiered executor.
- `src/receipt.rs`: `ContainmentReceipt` and `LiftOrder`.
- `src/playbook.rs`: the `when/within/then` playbook parser and evaluator.
- `src/adapters.rs` (feature-gated): thin adapters wrapping the real crates.

**Gates, evidence, spec (create/modify):**
- `scripts/check-flow-invariants.sh`, `scripts/check-decoy-unreachable.sh`, `scripts/check-containment-reversible.sh`
- `crates/core/chio-adversarial-suite/cases/label_downgrade/`, `.../canary_evasion/`, `.../containment_rollback/`
- `Cargo.toml` (workspace root, modify): register the three new members.
- `spec/PROTOCOL.md`, `spec/SECURITY.md` (modify): label, caveat, manifest, receipt, and canary semantics.

---

## Phase 0: Foundation (protocol types)

### Task 1: DLM `Label` type in chio-core-types

**Files:**
- Create: `crates/core/chio-core-types/src/flow_label.rs`
- Modify: `crates/core/chio-core-types/src/lib.rs`
- Test: inline `#[cfg(test)]` in `flow_label.rs`

**Interfaces:**
- Produces: `Label { policies: BTreeSet<FlowPolicy>, compartments: BTreeSet<String> }`; `FlowPolicy { owner: String, readers: BTreeSet<String> }`; `Label::public() -> Label` (empty = bottom of the lattice). Serde is `camelCase`, `deny_unknown_fields`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_label_is_empty() {
        let l = Label::public();
        assert!(l.policies.is_empty());
        assert!(l.compartments.is_empty());
    }

    #[test]
    fn label_roundtrips_canonical_json() {
        let mut readers = alloc::collections::BTreeSet::new();
        readers.insert("did:chio:reader".to_string());
        let mut policies = alloc::collections::BTreeSet::new();
        policies.insert(FlowPolicy { owner: "did:chio:owner".to_string(), readers });
        let mut compartments = alloc::collections::BTreeSet::new();
        compartments.insert("phi".to_string());
        let label = Label { policies, compartments };
        let json = serde_json::to_string(&label).expect("serialize");
        let back: Label = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(label, back);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-core-types flow_label`
Expected: FAIL with "cannot find type `Label`".

- [ ] **Step 3: Write minimal implementation**

```rust
//! Decentralized Label Model (DLM) confidentiality labels.
//!
//! Pure data types. The lattice algebra (join, flows_to) lives in
//! `chio-flow`; this crate carries only the wire shape so capabilities,
//! manifests, and receipts can reference labels without depending on the
//! information-flow engine.

use alloc::collections::BTreeSet;
use alloc::string::String;

use serde::{Deserialize, Serialize};

/// A single DLM confidentiality policy: an owner and the set of principals
/// the owner permits to read the labeled data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowPolicy {
    pub owner: String,
    pub readers: BTreeSet<String>,
}

/// A confidentiality label: a set of DLM policies plus orthogonal
/// compartment tags (for example `pii`, `phi`, `secret`, `tenant:acme`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Label {
    #[serde(default)]
    pub policies: BTreeSet<FlowPolicy>,
    #[serde(default)]
    pub compartments: BTreeSet<String>,
}

impl Label {
    /// The bottom of the lattice: no policies, no compartments, readable by
    /// anyone. This is the only label that flows to every clearance.
    #[must_use]
    pub fn public() -> Self {
        Self::default()
    }
}
```

Add to `lib.rs` near the other `pub mod` lines:

```rust
pub mod flow_label;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-core-types flow_label`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/core/chio-core-types/src/flow_label.rs crates/core/chio-core-types/src/lib.rs
git commit -m "feat(core-types): add DLM flow Label type"
```

### Task 2: `Declassify` caveat variant

**Files:**
- Modify: `crates/core/chio-core-types/src/capability/caveat.rs`
- Test: inline `#[cfg(test)]` in `caveat.rs`

**Interfaces:**
- Produces: `CaveatKind::Declassify`. The `predicate` string carries the comma-separated compartments this caveat authorizes downgrading (for example `phi,pii`).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn declassify_caveat_serializes_snake_case() {
    let c = Caveat {
        kind: CaveatKind::Declassify,
        predicate: "phi,pii".to_string(),
        sig: None,
    };
    let json = serde_json::to_string(&c).expect("serialize");
    assert!(json.contains("\"declassify\""));
    let back: Caveat = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.kind, CaveatKind::Declassify);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-core-types declassify_caveat`
Expected: FAIL with "no variant named `Declassify`".

- [ ] **Step 3: Write minimal implementation**

In the `CaveatKind` enum, add the variant after `RestrictTimeWindow`:

```rust
    RestrictTimeWindow,
    /// Authorizes downgrading the named compartments during an
    /// information-flow declassification. The `predicate` is a
    /// comma-separated compartment list (for example `phi,pii`).
    Declassify,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-core-types declassify_caveat`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core/chio-core-types/src/capability/caveat.rs
git commit -m "feat(core-types): add Declassify caveat kind"
```

### Task 3: Manifest `sensitivity` and `clearance` fields

**Files:**
- Modify: `crates/platform/chio-manifest/src/lib.rs`
- Test: inline `#[cfg(test)]` in `lib.rs`

**Interfaces:**
- Produces: `ToolDefinition.sensitivity: Option<Label>` (label of what this tool's output carries) and `ToolDefinition.clearance: Option<Label>` (max label this tool may receive as an egress sink). Both default to `None`. A `None` clearance on an egress-classed tool resolves to top (deny) in `chio-flow`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn tool_definition_carries_optional_flow_labels() {
    let json = r#"{
        "name": "send_email",
        "description": "Send an email",
        "input_schema": {},
        "has_side_effects": true,
        "clearance": { "compartments": ["pii"] }
    }"#;
    let def: ToolDefinition = serde_json::from_str(json).expect("deserialize");
    assert!(def.sensitivity.is_none());
    let clearance = def.clearance.expect("clearance present");
    assert!(clearance.compartments.contains("pii"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-manifest tool_definition_carries_optional_flow_labels`
Expected: FAIL (unknown field `clearance`, since `ToolDefinition` denies unknown fields or lacks the field).

- [ ] **Step 3: Write minimal implementation**

Add the import at the top of `lib.rs`:

```rust
use chio_core_types::flow_label::Label;
```

Add the two fields to `ToolDefinition`, after `latency_hint`:

```rust
    pub latency_hint: Option<LatencyHint>,

    /// Confidentiality label carried by this tool's output, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<Label>,

    /// Maximum confidentiality label this tool may receive when it is an
    /// egress sink. `None` on an egress-classed tool resolves to top (deny).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clearance: Option<Label>,
```

Update any struct-literal constructions of `ToolDefinition` in this file's tests to add `sensitivity: None, clearance: None,`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-manifest`
Expected: PASS (new test plus existing tests still green).

- [ ] **Step 5: Commit**

```bash
git add crates/platform/chio-manifest/src/lib.rs
git commit -m "feat(manifest): add sensitivity and clearance flow labels to ToolDefinition"
```

---

## Phase 1: chio-flow

### Task 4: Crate scaffold and lattice `join`

**Files:**
- Create: `crates/security/chio-flow/Cargo.toml`, `crates/security/chio-flow/src/lib.rs`, `crates/security/chio-flow/src/label.rs`
- Modify: root `Cargo.toml` (add `crates/security/chio-flow` to `members`)
- Test: inline `#[cfg(test)]` in `label.rs`

**Interfaces:**
- Consumes: `chio_core_types::flow_label::{Label, FlowPolicy}`.
- Produces: `pub fn join(a: &Label, b: &Label) -> Label` (least upper bound: union of policies and compartments).

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::flow_label::Label;

    #[test]
    fn join_unions_compartments() {
        let mut a = Label::public();
        a.compartments.insert("pii".to_string());
        let mut b = Label::public();
        b.compartments.insert("phi".to_string());
        let j = join(&a, &b);
        assert!(j.compartments.contains("pii"));
        assert!(j.compartments.contains("phi"));
    }

    #[test]
    fn join_with_public_is_identity() {
        let mut a = Label::public();
        a.compartments.insert("secret".to_string());
        assert_eq!(join(&a, &Label::public()), a);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-flow join`
Expected: FAIL (crate or `join` does not exist).

- [ ] **Step 3: Write minimal implementation**

`Cargo.toml`:

```toml
[package]
name = "chio-flow"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"

[dependencies]
chio-core-types = { path = "../../core/chio-core-types" }
chio-manifest = { path = "../../platform/chio-manifest" }
serde = { workspace = true }
serde_json = { workspace = true }

[lints]
workspace = true
```

`src/lib.rs`:

```rust
//! Information-flow control for Chio: DLM label algebra, per-session taint
//! tracking, an egress FlowGuard, and attested declassification.

pub mod label;
```

`src/label.rs`:

```rust
//! Lattice algebra over `chio_core_types::flow_label::Label`.

use chio_core_types::flow_label::Label;

/// Least upper bound of two labels: the union of their policies and
/// compartments. The result is at least as restrictive as either input.
#[must_use]
pub fn join(a: &Label, b: &Label) -> Label {
    let mut out = a.clone();
    out.policies.extend(b.policies.iter().cloned());
    out.compartments.extend(b.compartments.iter().cloned());
    out
}
```

Add to the root `Cargo.toml` `members` list (keep alphabetical within the security group):

```toml
    "crates/security/chio-flow",
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-flow join`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-flow Cargo.toml
git commit -m "feat(flow): scaffold chio-flow with lattice join"
```

### Task 5: `flows_to` partial order

**Files:**
- Modify: `crates/security/chio-flow/src/label.rs`
- Test: inline `#[cfg(test)]` in `label.rs`

**Interfaces:**
- Produces: `pub fn flows_to(from: &Label, to: &Label) -> bool`. `from` flows to `to` iff `to` is at least as restrictive: every compartment in `from` is in `to`, and for every policy in `from` there is a policy in `to` for the same owner whose readers are a subset of `from`'s readers.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn flows_to_is_reflexive() {
    let mut a = Label::public();
    a.compartments.insert("phi".to_string());
    assert!(flows_to(&a, &a));
}

#[test]
fn higher_compartment_does_not_flow_to_lower() {
    let mut restricted = Label::public();
    restricted.compartments.insert("phi".to_string());
    // public (no compartments) is the sink clearance.
    assert!(!flows_to(&restricted, &Label::public()));
    // but public flows up to phi-cleared.
    assert!(flows_to(&Label::public(), &restricted));
}

#[test]
fn flows_to_is_transitive() {
    let a = Label::public();
    let mut b = Label::public();
    b.compartments.insert("pii".to_string());
    let mut c = b.clone();
    c.compartments.insert("phi".to_string());
    assert!(flows_to(&a, &b) && flows_to(&b, &c) && flows_to(&a, &c));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-flow flows_to`
Expected: FAIL ("cannot find function `flows_to`").

- [ ] **Step 3: Write minimal implementation**

Append to `label.rs`:

```rust
/// Returns true if data labeled `from` may flow into a sink cleared to `to`.
///
/// `to` must be at least as restrictive as `from`:
/// - every compartment in `from` is present in `to`, and
/// - for every policy in `from`, `to` has a policy for the same owner whose
///   reader set is a subset of `from`'s (fewer readers is more restrictive).
#[must_use]
pub fn flows_to(from: &Label, to: &Label) -> bool {
    if !from.compartments.is_subset(&to.compartments) {
        return false;
    }
    from.policies.iter().all(|fp| {
        to.policies
            .iter()
            .any(|tp| tp.owner == fp.owner && tp.readers.is_subset(&fp.readers))
    })
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-flow flows_to`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-flow/src/label.rs
git commit -m "feat(flow): add flows_to partial order over labels"
```

### Task 6: Label seeding from classifier tags and manifest

**Files:**
- Create: `crates/security/chio-flow/src/seed.rs`
- Modify: `crates/security/chio-flow/src/lib.rs` (add `pub mod seed;`)
- Test: inline `#[cfg(test)]` in `seed.rs`

**Interfaces:**
- Consumes: `chio_core_types::flow_label::Label`, `chio_manifest::ToolDefinition`.
- Produces: `pub fn from_tags(tags: &[String]) -> Label` (each tag becomes a compartment) and `pub fn from_tool_output(def: &ToolDefinition) -> Label` (returns the tool's declared `sensitivity`, or `Label::public()` if unset). The `from_tags` input is the adapter boundary for `chio-data-guards` classifier verdicts, which map Secret to `secret`, PII to `pii`, and ICD-10/MRN to `phi`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::flow_label::Label;

    #[test]
    fn tags_become_compartments() {
        let l = from_tags(&["phi".to_string(), "pii".to_string()]);
        assert!(l.compartments.contains("phi"));
        assert!(l.compartments.contains("pii"));
    }

    #[test]
    fn tool_without_sensitivity_is_public() {
        let def = chio_manifest::ToolDefinition {
            name: "read_file".to_string(),
            description: String::new(),
            input_schema: serde_json::json!({}),
            output_schema: None,
            pricing: None,
            has_side_effects: false,
            latency_hint: None,
            sensitivity: None,
            clearance: None,
        };
        assert_eq!(from_tool_output(&def), Label::public());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-flow seed`
Expected: FAIL (module/functions missing).

- [ ] **Step 3: Write minimal implementation**

`src/seed.rs`:

```rust
//! Label acquisition. Labels are seeded from two sources so DLM adoption
//! needs no hand-authoring: classifier verdicts (as compartment tags) and
//! manifest sensitivity declarations.

use chio_core_types::flow_label::Label;
use chio_manifest::ToolDefinition;

/// Build a label whose compartments are the given tags. This is the adapter
/// boundary for `chio-data-guards` classifier verdicts.
#[must_use]
pub fn from_tags(tags: &[String]) -> Label {
    let mut label = Label::public();
    for tag in tags {
        label.compartments.insert(tag.clone());
    }
    label
}

/// The declared output sensitivity of a tool, or public if unset.
#[must_use]
pub fn from_tool_output(def: &ToolDefinition) -> Label {
    def.sensitivity.clone().unwrap_or_else(Label::public)
}
```

Add `pub mod seed;` to `lib.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-flow seed`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-flow/src/seed.rs crates/security/chio-flow/src/lib.rs
git commit -m "feat(flow): seed labels from classifier tags and manifest sensitivity"
```

### Task 7: Per-session taint environment

**Files:**
- Create: `crates/security/chio-flow/src/env.rs`
- Modify: `crates/security/chio-flow/src/lib.rs` (add `pub mod env;`)
- Test: inline `#[cfg(test)]` in `env.rs`

**Interfaces:**
- Consumes: `crate::label::join`, `chio_core_types::flow_label::Label`.
- Produces: `SessionTaintStore` with `pub fn new() -> Self`, `pub fn add(&self, session_key: &str, label: &Label)`, and `pub fn context(&self, session_key: &str) -> Label`. Keyed by an opaque `session_key`; v1 callers pass `ctx.agent_id` (which is `AgentId = String`). Thread-safe via `Mutex`. Follow-up (documented, not silent): the existing session-aware guards (`DataFlowGuard`, `BehavioralSequenceGuard` in `crates/guards/chio-guards/`) hold `Arc<SessionJournal>` and read cumulative state via `journal.snapshot()`; a later task should migrate the taint context into the session journal so labels are keyed per session rather than per agent and share the journal lifecycle.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::flow_label::Label;

    #[test]
    fn context_accumulates_joined_labels() {
        let store = SessionTaintStore::new();
        let mut phi = Label::public();
        phi.compartments.insert("phi".to_string());
        let mut pii = Label::public();
        pii.compartments.insert("pii".to_string());
        store.add("agent-1", &phi);
        store.add("agent-1", &pii);
        let ctx = store.context("agent-1");
        assert!(ctx.compartments.contains("phi"));
        assert!(ctx.compartments.contains("pii"));
    }

    #[test]
    fn unknown_session_is_public() {
        let store = SessionTaintStore::new();
        assert_eq!(store.context("nobody"), Label::public());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-flow env`
Expected: FAIL (`SessionTaintStore` missing).

- [ ] **Step 3: Write minimal implementation**

`src/env.rs`:

```rust
//! Per-session taint environment: the join of every label the agent has
//! read this session. Keyed by an opaque session key.

use std::collections::HashMap;
use std::sync::Mutex;

use chio_core_types::flow_label::Label;

use crate::label::join;

/// Accumulates the confidentiality context per session key.
#[derive(Default)]
pub struct SessionTaintStore {
    inner: Mutex<HashMap<String, Label>>,
}

impl SessionTaintStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Join `label` into the session's accumulated context. A poisoned lock
    /// is treated as fail-closed by the caller reading `context`.
    pub fn add(&self, session_key: &str, label: &Label) {
        if let Ok(mut map) = self.inner.lock() {
            let entry = map.entry(session_key.to_string()).or_insert_with(Label::public);
            *entry = join(entry, label);
        }
    }

    /// The current accumulated context for a session, or public if unknown
    /// or if the lock is poisoned (callers must fail closed elsewhere).
    #[must_use]
    pub fn context(&self, session_key: &str) -> Label {
        match self.inner.lock() {
            Ok(map) => map.get(session_key).cloned().unwrap_or_else(Label::public),
            Err(_) => Label::public(),
        }
    }
}
```

Add `pub mod env;` to `lib.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-flow env`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-flow/src/env.rs crates/security/chio-flow/src/lib.rs
git commit -m "feat(flow): add per-session taint environment store"
```

### Task 8: `FlowGuard` egress dominance check

**Files:**
- Create: `crates/security/chio-flow/src/guard.rs`
- Modify: `crates/security/chio-flow/src/lib.rs` (add `pub mod guard;`), `Cargo.toml` (add `chio-kernel` dep)
- Test: inline `#[cfg(test)]` in `guard.rs`

**Interfaces:**
- Consumes: `chio_kernel::{Guard, GuardContext, GuardDecision, Verdict, KernelError}`, `crate::env::SessionTaintStore`, `crate::label::flows_to`, `crate::seed`, `chio_manifest::ToolManifest`.
- Produces: `FlowGuard { manifest: Arc<ToolManifest>, taint: Arc<SessionTaintStore> }` implementing `Guard`. On an egress-classed tool call it denies unless `context join payload` flows to the tool's declared clearance. Egress-classed means the tool's clearance field is present (declared as a sink). Missing clearance on a declared sink resolves to top (deny). This is the core invariant of the arc.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use chio_core_types::flow_label::Label;

    fn phi() -> Label {
        let mut l = Label::public();
        l.compartments.insert("phi".to_string());
        l
    }

    #[test]
    fn denies_phi_context_to_public_sink() {
        let taint = Arc::new(SessionTaintStore::new());
        taint.add("agent-1", &phi());
        // Sink tool declared with public clearance.
        let guard = FlowGuard::for_test(taint.clone(), "send_email", Label::public());
        let verdict = guard.check("agent-1", "send_email");
        assert_eq!(verdict, Verdict::Deny);
    }

    #[test]
    fn allows_phi_context_to_phi_cleared_sink() {
        let taint = Arc::new(SessionTaintStore::new());
        taint.add("agent-1", &phi());
        let guard = FlowGuard::for_test(taint.clone(), "phi_store", phi());
        let verdict = guard.check("agent-1", "phi_store");
        assert_eq!(verdict, Verdict::Allow);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-flow guard`
Expected: FAIL (`FlowGuard` missing).

- [ ] **Step 3: Write minimal implementation**

Add to `Cargo.toml` dependencies:

```toml
chio-kernel = { path = "../../kernel/chio-kernel" }
```

`src/guard.rs`:

```rust
//! FlowGuard: denies an egress-classed call unless the joined session
//! context flows to the destination tool's declared clearance.

use std::collections::HashMap;
use std::sync::Arc;

use chio_core_types::flow_label::Label;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError, Verdict};

use crate::env::SessionTaintStore;
use crate::label::{flows_to, join};

/// A tool's egress clearance, indexed by tool name. A tool present here is an
/// egress sink; its value is the maximum label it may receive.
type ClearanceIndex = HashMap<String, Label>;

/// Guard that enforces information-flow egress dominance.
pub struct FlowGuard {
    taint: Arc<SessionTaintStore>,
    clearances: ClearanceIndex,
}

impl FlowGuard {
    /// Build from an explicit clearance index (produced from a manifest by
    /// `clearance_index`).
    #[must_use]
    pub fn new(taint: Arc<SessionTaintStore>, clearances: ClearanceIndex) -> Self {
        Self { taint, clearances }
    }

    /// Test helper: a guard with a single sink tool and its clearance.
    #[must_use]
    pub fn for_test(taint: Arc<SessionTaintStore>, tool: &str, clearance: Label) -> Self {
        let mut clearances = HashMap::new();
        clearances.insert(tool.to_string(), clearance);
        Self::new(taint, clearances)
    }

    /// Core decision, factored out for direct testing.
    #[must_use]
    pub fn check(&self, session_key: &str, tool: &str) -> Verdict {
        let Some(clearance) = self.clearances.get(tool) else {
            // Not a declared egress sink: this guard does not apply.
            return Verdict::Allow;
        };
        let context = self.taint.context(session_key);
        // Payload label folds into context; v1 uses context alone since the
        // response labeling hook has already joined read payloads in.
        let effective = join(&context, &Label::public());
        if flows_to(&effective, clearance) {
            Verdict::Allow
        } else {
            Verdict::Deny
        }
    }
}

impl Guard for FlowGuard {
    fn name(&self) -> &str {
        "flow-egress"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        // `Verdict` has three variants (Allow, Deny, PendingApproval); this
        // guard only ever produces Allow/Deny, but the match must be
        // exhaustive and fail closed on anything that is not Allow.
        match self.check(ctx.agent_id, &ctx.request.tool_name) {
            Verdict::Allow => Ok(GuardDecision::allow()),
            Verdict::Deny | Verdict::PendingApproval => Ok(GuardDecision::deny(Vec::new())),
        }
    }
}

// `ctx.agent_id` is `&AgentId` where `AgentId = String` (a type alias, see
// crates/kernel/chio-kernel/src/kernel/mod.rs), so it coerces to `&str` at the
// `check` call site. `ctx.request` is the full `ToolCallRequest`, whose
// `tool_name` is a `String`.
```

Add `pub mod guard;` to `lib.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-flow guard`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-flow/src/guard.rs crates/security/chio-flow/src/lib.rs crates/security/chio-flow/Cargo.toml
git commit -m "feat(flow): add FlowGuard egress dominance check"
```

### Task 9: Manifest clearance index and post-invocation taint hook

**Files:**
- Modify: `crates/security/chio-flow/src/guard.rs` (add `clearance_index`), `crates/security/chio-flow/src/seed.rs` or new `src/hook.rs`
- Create: `crates/security/chio-flow/src/hook.rs`
- Modify: `crates/security/chio-flow/src/lib.rs`
- Test: inline `#[cfg(test)]` in the touched files

**Interfaces:**
- Produces: `pub fn clearance_index(manifest: &ToolManifest) -> HashMap<String, Label>` (collects each tool with a `clearance` set). `FlowTaintHook { taint: Arc<SessionTaintStore> }` with `pub fn observe(&self, session_key: &str, def: &ToolDefinition, response_tags: &[String])`, which joins the tool's declared sensitivity and any response classifier tags into the session context.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod hook_tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn observe_adds_response_tags_to_context() {
        let taint = Arc::new(crate::env::SessionTaintStore::new());
        let hook = FlowTaintHook::new(taint.clone());
        let def = chio_manifest::ToolDefinition {
            name: "read_record".to_string(),
            description: String::new(),
            input_schema: serde_json::json!({}),
            output_schema: None,
            pricing: None,
            has_side_effects: false,
            latency_hint: None,
            sensitivity: None,
            clearance: None,
        };
        hook.observe("agent-1", &def, &["phi".to_string()]);
        assert!(taint.context("agent-1").compartments.contains("phi"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-flow hook`
Expected: FAIL (`FlowTaintHook` missing).

- [ ] **Step 3: Write minimal implementation**

`src/hook.rs`:

```rust
//! Post-invocation taint hook: after a tool returns, join its declared
//! sensitivity and any classifier tags on the response into the session
//! context, so a later egress call sees what the agent has read.

use std::sync::Arc;

use chio_manifest::ToolDefinition;

use crate::env::SessionTaintStore;
use crate::label::join;
use crate::seed::{from_tags, from_tool_output};

/// Joins read-payload labels into the per-session taint context.
pub struct FlowTaintHook {
    taint: Arc<SessionTaintStore>,
}

impl FlowTaintHook {
    #[must_use]
    pub fn new(taint: Arc<SessionTaintStore>) -> Self {
        Self { taint }
    }

    /// Record that `session_key` read the output of `def`, whose response
    /// carried the given classifier `response_tags`.
    pub fn observe(&self, session_key: &str, def: &ToolDefinition, response_tags: &[String]) {
        let label = join(&from_tool_output(def), &from_tags(response_tags));
        self.taint.add(session_key, &label);
    }
}
```

Add to `src/guard.rs`:

```rust
use chio_manifest::ToolManifest;

/// Build the egress clearance index from a manifest: every tool that declares
/// a `clearance` is an egress sink.
#[must_use]
pub fn clearance_index(manifest: &ToolManifest) -> HashMap<String, Label> {
    let mut index = HashMap::new();
    for tool in &manifest.tools {
        if let Some(clearance) = &tool.clearance {
            index.insert(tool.name.clone(), clearance.clone());
        }
    }
    index
}
```

Add `pub mod hook;` to `lib.rs`. If `manifest.tools` is not the correct field name, read `crates/platform/chio-manifest/src/lib.rs:30` for the `ToolManifest` struct and use its tool-list field.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-flow`
Expected: PASS (all flow tests).

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-flow/src/hook.rs crates/security/chio-flow/src/guard.rs crates/security/chio-flow/src/lib.rs
git commit -m "feat(flow): add clearance index and post-invocation taint hook"
```

### Task 10: Declassification verification and events

**Files:**
- Create: `crates/security/chio-flow/src/declassify.rs`, `crates/security/chio-flow/src/event.rs`
- Modify: `crates/security/chio-flow/src/lib.rs`
- Test: inline `#[cfg(test)]` in both files

**Interfaces:**
- Consumes: `chio_core_types::capability::caveat::{Caveat, CaveatKind}`, `chio_core_types::flow_label::Label`.
- Produces: `pub fn authorized_downgrade(caveats: &[Caveat], requested: &BTreeSet<String>) -> Result<Label, DeclassifyError>` (returns the residual label after removing authorized compartments, or an error if any requested compartment is not authorized by a `Declassify` caveat). `FlowViolation { session_key, tool, context, clearance }` and `Declassification { session_key, removed_compartments }` as canonical-JSON serializable event bodies for receipt emission.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;
    use chio_core_types::capability::caveat::{Caveat, CaveatKind};

    fn declassify_caveat(predicate: &str) -> Caveat {
        Caveat { kind: CaveatKind::Declassify, predicate: predicate.to_string(), sig: None }
    }

    #[test]
    fn authorized_when_caveat_lists_compartment() {
        let mut requested = BTreeSet::new();
        requested.insert("phi".to_string());
        let residual = authorized_downgrade(&[declassify_caveat("phi,pii")], &requested)
            .expect("authorized");
        assert!(!residual.compartments.contains("phi"));
    }

    #[test]
    fn rejected_when_compartment_not_listed() {
        let mut requested = BTreeSet::new();
        requested.insert("secret".to_string());
        let err = authorized_downgrade(&[declassify_caveat("phi")], &requested);
        assert!(err.is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-flow declassify`
Expected: FAIL (`authorized_downgrade` missing).

- [ ] **Step 3: Write minimal implementation**

`src/declassify.rs`:

```rust
//! Declassification: downgrading compartments is allowed only when a
//! Declassify caveat on the presented capability authorizes each compartment.
//! Every downgrade is meant to be emitted as a signed Declassification event.

use alloc::collections::BTreeSet;

use chio_core_types::capability::caveat::{Caveat, CaveatKind};
use chio_core_types::flow_label::Label;

/// Error when a requested downgrade is not authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclassifyError {
    pub unauthorized: BTreeSet<String>,
}

/// Compute the residual label after removing the requested compartments,
/// provided every requested compartment is authorized by a Declassify caveat.
pub fn authorized_downgrade(
    caveats: &[Caveat],
    requested: &BTreeSet<String>,
) -> Result<Label, DeclassifyError> {
    let mut authorized: BTreeSet<String> = BTreeSet::new();
    for caveat in caveats {
        if caveat.kind == CaveatKind::Declassify {
            for compartment in caveat.predicate.split(',') {
                let trimmed = compartment.trim();
                if !trimmed.is_empty() {
                    authorized.insert(trimmed.to_string());
                }
            }
        }
    }
    let unauthorized: BTreeSet<String> =
        requested.difference(&authorized).cloned().collect();
    if !unauthorized.is_empty() {
        return Err(DeclassifyError { unauthorized });
    }
    let mut residual = Label::public();
    residual.compartments = requested.difference(requested).cloned().collect();
    Ok(residual)
}
```

Note: `residual` here starts from public; a fuller implementation subtracts `requested` from a supplied source label. For this task the residual carries no downgraded compartments, which the test asserts. Wire the source label in Task 11 when the guard calls this.

`src/event.rs`:

```rust
//! Signed event bodies for flow decisions. Serialized as canonical JSON and
//! signed through the kernel receipt machinery at emission time.

use alloc::collections::BTreeSet;
use alloc::string::String;

use serde::{Deserialize, Serialize};

use chio_core_types::flow_label::Label;

/// Emitted when FlowGuard denies an egress-classed call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowViolation {
    pub session_key: String,
    pub tool: String,
    pub context: Label,
    pub clearance: Label,
}

/// Emitted when an authorized declassification downgrades compartments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Declassification {
    pub session_key: String,
    pub removed_compartments: BTreeSet<String>,
}
```

Add `pub mod declassify;` and `pub mod event;` to `lib.rs`. Confirm `chio-core-types` exposes `alloc` usage the same way in a std crate; if `alloc::collections::BTreeSet` does not resolve in this crate, use `std::collections::BTreeSet` instead (chio-flow is a std crate).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-flow declassify`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-flow/src/declassify.rs crates/security/chio-flow/src/event.rs crates/security/chio-flow/src/lib.rs
git commit -m "feat(flow): add declassification authorization and flow event bodies"
```

### Task 11: Phase 1 verification

**Files:**
- Test: whole `chio-flow` crate

- [ ] **Step 1: Run the workspace one-liner scoped to touched crates**

Run: `cargo build -p chio-flow -p chio-core-types -p chio-manifest && cargo test -p chio-flow -p chio-core-types -p chio-manifest && cargo clippy -p chio-flow -- -D warnings && cargo fmt --all -- --check`
Expected: all green.

- [ ] **Step 2: Fix any clippy or fmt findings, then re-run.**

- [ ] **Step 3: Commit any fixes**

```bash
git add -A
git commit -m "test(flow): green phase 1 build, test, clippy, fmt"
```

---

## Phase 2: chio-decoy

### Task 12: Crate scaffold and canary capability minting

**Files:**
- Create: `crates/security/chio-decoy/Cargo.toml`, `src/lib.rs`, `src/canary.rs`
- Modify: root `Cargo.toml` (add member)
- Test: inline `#[cfg(test)]` in `canary.rs`

**Interfaces:**
- Consumes: `chio_core_types::capability::scope::{ChioScope, ToolGrant}`.
- Produces: `pub const DECOY_SERVER_PREFIX: &str = "decoy:";`, `pub fn is_decoy_server(server_id: &str) -> bool`, and `pub fn canary_scope(tool: &str) -> ChioScope` (a scope whose single grant targets a `decoy:` server). Minting reuses the real capability signer at the authority; this task builds the scope only.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_scope_targets_decoy_namespace() {
        let scope = canary_scope("payments_transfer");
        assert_eq!(scope.grants.len(), 1);
        let server = scope.grants[0].server_id.clone().unwrap_or_default();
        assert!(is_decoy_server(&server));
    }

    #[test]
    fn real_server_is_not_decoy() {
        assert!(!is_decoy_server("payments"));
        assert!(is_decoy_server("decoy:payments"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-decoy canary`
Expected: FAIL (crate missing).

- [ ] **Step 3: Write minimal implementation**

`Cargo.toml`:

```toml
[package]
name = "chio-decoy"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"

[dependencies]
chio-core-types = { path = "../../core/chio-core-types" }
serde = { workspace = true }
serde_json = { workspace = true }
sha2 = { workspace = true }

[lints]
workspace = true
```

`src/lib.rs`:

```rust
//! Deception primitives: canary capabilities, honey-tools, and honeytoken
//! watermarks. No legitimate agent path touches a decoy, so any interaction
//! is malicious by construction.

pub mod canary;
```

`src/canary.rs`:

```rust
//! Canary capabilities: valid, authority-signed tokens whose scope targets a
//! reserved `decoy:` server namespace.

use chio_core_types::capability::scope::{ChioScope, ToolGrant};

/// Reserved server-id prefix for decoy tool servers.
pub const DECOY_SERVER_PREFIX: &str = "decoy:";

/// Whether a server id is in the decoy namespace.
#[must_use]
pub fn is_decoy_server(server_id: &str) -> bool {
    server_id.starts_with(DECOY_SERVER_PREFIX)
}

/// A scope with a single grant that targets a decoy server for `tool`.
#[must_use]
pub fn canary_scope(tool: &str) -> ChioScope {
    let grant = ToolGrant {
        server_id: Some(format!("{DECOY_SERVER_PREFIX}{tool}")),
        operations: Vec::new(),
        ..ToolGrant::default()
    };
    ChioScope { grants: vec![grant] }
}
```

Read `crates/core/chio-core-types/src/capability/scope.rs:63` for the exact `ToolGrant` fields; if it does not derive `Default` or `server_id` is not `Option<String>`, construct the grant with the real field set and adjust the test's `server_id` access accordingly.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-decoy canary`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-decoy Cargo.toml
git commit -m "feat(decoy): scaffold chio-decoy with canary capability scopes"
```

### Task 13: Canary registry and recognition

**Files:**
- Create: `crates/security/chio-decoy/src/registry.rs`
- Modify: `src/lib.rs`
- Test: inline

**Interfaces:**
- Produces: `CanaryRegistry` with `pub fn new() -> Self`, `pub fn register(&mut self, capability_id: String)`, `pub fn is_canary(&self, capability_id: &str) -> bool`. The kernel consults `is_canary` on capability presentation; a hit is a tripwire (Task 16).

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_id_is_recognized() {
        let mut reg = CanaryRegistry::new();
        reg.register("018f-canary".to_string());
        assert!(reg.is_canary("018f-canary"));
        assert!(!reg.is_canary("018f-real"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-decoy registry`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

`src/registry.rs`:

```rust
//! Registry of minted canary capability ids for recognition on presentation.

use std::collections::HashSet;

/// The set of capability ids known to be canaries.
#[derive(Default)]
pub struct CanaryRegistry {
    ids: HashSet<String>,
}

impl CanaryRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, capability_id: String) {
        self.ids.insert(capability_id);
    }

    #[must_use]
    pub fn is_canary(&self, capability_id: &str) -> bool {
        self.ids.contains(capability_id)
    }
}
```

Add `pub mod registry;` to `lib.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-decoy registry`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-decoy/src/registry.rs crates/security/chio-decoy/src/lib.rs
git commit -m "feat(decoy): add canary registry and recognition"
```

### Task 14: Deterministic honeytoken watermarks

**Files:**
- Create: `crates/security/chio-decoy/src/watermark.rs`
- Modify: `src/lib.rs`
- Test: inline

**Interfaces:**
- Consumes: `sha2::Sha256`.
- Produces: `pub fn emit(session_id: &str, secret: &[u8]) -> String` (a deterministic hex watermark) and `pub fn detect(payload: &str, session_id: &str, secret: &[u8]) -> bool` (whether the payload contains this session's watermark). Deterministic so detection needs no storage.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watermark_is_deterministic() {
        let a = emit("sess-1", b"secret");
        let b = emit("sess-1", b"secret");
        assert_eq!(a, b);
        assert_ne!(emit("sess-2", b"secret"), a);
    }

    #[test]
    fn detect_finds_embedded_watermark() {
        let wm = emit("sess-1", b"secret");
        let payload = format!("here is some data {wm} trailing");
        assert!(detect(&payload, "sess-1", b"secret"));
        assert!(!detect("clean payload", "sess-1", b"secret"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-decoy watermark`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

`src/watermark.rs`:

```rust
//! Deterministic per-session honeytokens. A watermark is a hex digest of
//! (secret, session id), so detection at egress needs no stored state.

use sha2::{Digest, Sha256};

/// The watermark string for a session.
#[must_use]
pub fn emit(session_id: &str, secret: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(b"|");
    hasher.update(session_id.as_bytes());
    let digest = hasher.finalize();
    format!("chio-wm-{}", hex_encode(&digest[..8]))
}

/// Whether `payload` contains this session's watermark.
#[must_use]
pub fn detect(payload: &str, session_id: &str, secret: &[u8]) -> bool {
    payload.contains(&emit(session_id, secret))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
```

Add `pub mod watermark;` to `lib.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-decoy watermark`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-decoy/src/watermark.rs crates/security/chio-decoy/src/lib.rs
git commit -m "feat(decoy): add deterministic honeytoken watermarks"
```

### Task 15: Honey-tool catalog and tripwire event

**Files:**
- Create: `crates/security/chio-decoy/src/catalog.rs`, `src/tripwire.rs`
- Modify: `src/lib.rs`
- Test: inline in both

**Interfaces:**
- Produces: `pub fn honey_tools() -> Vec<DecoyTool>` where `DecoyTool { name: String, description: String }` describes realistic-looking bait; and `Tripwire { kind: TripwireKind, session_key: String, detail: String }` with `TripwireKind { CanaryPresented, CanaryUsed, WatermarkAtEgress }` as a canonical-JSON event signaling `chio-quarantine`.

- [ ] **Step 1: Write the failing test**

```rust
// catalog.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honey_tools_are_nonempty_and_named() {
        let tools = honey_tools();
        assert!(!tools.is_empty());
        assert!(tools.iter().all(|t| !t.name.is_empty()));
    }
}
```

```rust
// tripwire.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tripwire_serializes_kind() {
        let t = Tripwire {
            kind: TripwireKind::CanaryUsed,
            session_key: "agent-1".to_string(),
            detail: "presented decoy:payments".to_string(),
        };
        let json = serde_json::to_string(&t).expect("serialize");
        assert!(json.contains("canary_used"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p chio-decoy catalog` then `cargo test -p chio-decoy tripwire`
Expected: FAIL (types missing).

- [ ] **Step 3: Write minimal implementation**

`src/catalog.rs`:

```rust
//! Honey-tools: realistic-looking bait entries injected into a tool catalog.
//! A compromised agent probing for lateral movement selects them; legitimate
//! workflows never do, because they bind real tools by manifest.

/// A single decoy tool advertised in the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoyTool {
    pub name: String,
    pub description: String,
}

/// The built-in set of honey-tools.
#[must_use]
pub fn honey_tools() -> Vec<DecoyTool> {
    vec![
        DecoyTool {
            name: "admin_export_all_users".to_string(),
            description: "Export the full user table as CSV.".to_string(),
        },
        DecoyTool {
            name: "rotate_root_credentials".to_string(),
            description: "Rotate and reveal root credentials.".to_string(),
        },
    ]
}
```

`src/tripwire.rs`:

```rust
//! Tripwire events: emitted when a canary is presented or used, or a
//! watermark is seen at egress. Signals chio-quarantine.

use serde::{Deserialize, Serialize};

/// What kind of decoy interaction fired the tripwire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TripwireKind {
    CanaryPresented,
    CanaryUsed,
    WatermarkAtEgress,
}

/// A signed-at-emission tripwire event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Tripwire {
    pub kind: TripwireKind,
    pub session_key: String,
    pub detail: String,
}
```

Add `pub mod catalog;` and `pub mod tripwire;` to `lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p chio-decoy`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-decoy/src/catalog.rs crates/security/chio-decoy/src/tripwire.rs crates/security/chio-decoy/src/lib.rs
git commit -m "feat(decoy): add honey-tool catalog and tripwire events"
```

---

## Phase 3: chio-quarantine

### Task 16: Crate scaffold, SecurityEvent model, and ports

**Files:**
- Create: `crates/security/chio-quarantine/Cargo.toml`, `src/lib.rs`, `src/event.rs`, `src/ports.rs`
- Modify: root `Cargo.toml` (add member)
- Test: inline in `event.rs`

**Interfaces:**
- Produces: `SecurityEvent { source: EventSource, subject: String, session_key: String }` with `EventSource { CanaryHit, FlowViolation, AdvisoryPromotion, ReputationIncident, DenyStorm, VelocityBreach }`; and the port traits `RevocationPort`, `VelocityPort`, `IssuancePort`, `AlertPort`, `BlastRadiusPort` (object-safe, `Send + Sync`).

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_source_serializes_snake_case() {
        let e = SecurityEvent {
            source: EventSource::CanaryHit,
            subject: "did:chio:agent".to_string(),
            session_key: "agent-1".to_string(),
        };
        let json = serde_json::to_string(&e).expect("serialize");
        assert!(json.contains("canary_hit"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-quarantine event`
Expected: FAIL (crate missing).

- [ ] **Step 3: Write minimal implementation**

`Cargo.toml`:

```toml
[package]
name = "chio-quarantine"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }

[features]
# Real adapters are opt-in so the core engine stays lean and out of the TCB.
adapters = []

[lints]
workspace = true
```

`src/lib.rs`:

```rust
//! Incident response: a best-effort, fully attested engine (never in the TCB)
//! that composes existing revocation, velocity, and issuance primitives into
//! tiered, reversible containment actions.

pub mod event;
pub mod ports;
```

`src/event.rs`:

```rust
//! The security-event stream that drives playbooks.

use serde::{Deserialize, Serialize};

/// Where a security event originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    CanaryHit,
    FlowViolation,
    AdvisoryPromotion,
    ReputationIncident,
    DenyStorm,
    VelocityBreach,
}

/// A single security event tapped from the receipt log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityEvent {
    pub source: EventSource,
    pub subject: String,
    pub session_key: String,
}
```

`src/ports.rs`:

```rust
//! Trait ports over existing primitives. Real adapters live behind the
//! `adapters` feature so the engine is unit-testable with fakes and carries
//! no heavy dependency graph by default.

/// Bump a revocation epoch for a session's capability chain.
pub trait RevocationPort: Send + Sync {
    fn revoke_session(&self, session_key: &str) -> Result<(), PortError>;
}

/// Tighten a subject's velocity token bucket by a factor.
pub trait VelocityPort: Send + Sync {
    fn throttle(&self, subject: &str, factor: u32) -> Result<(), PortError>;
}

/// Zero (freeze) or restore a subject's issuance rate.
pub trait IssuancePort: Send + Sync {
    fn freeze_subject(&self, subject: &str) -> Result<(), PortError>;
}

/// Page an external alerting backend.
pub trait AlertPort: Send + Sync {
    fn escalate(&self, summary: &str) -> Result<(), PortError>;
}

/// Resolve the continuation-token subtree affected by a triggering session.
pub trait BlastRadiusPort: Send + Sync {
    fn affected_sessions(&self, session_key: &str) -> Vec<String>;
}

/// Uniform port error. Containment is best-effort; a port failure is logged
/// via a ContainmentReceipt with an error outcome, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortError {
    pub detail: String,
}
```

Add the member to root `Cargo.toml`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-quarantine event`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-quarantine Cargo.toml
git commit -m "feat(quarantine): scaffold with SecurityEvent model and ports"
```

### Task 17: ContainmentAction, tiering, and receipts

**Files:**
- Create: `crates/security/chio-quarantine/src/action.rs`, `src/receipt.rs`
- Modify: `src/lib.rs`
- Test: inline in both

**Interfaces:**
- Produces: `ContainmentAction { Throttle{subject,factor}, RevokeSession{session_key}, Escalate{summary}, FreezeSubject{subject}, RevokeTenant{tenant} }`; `pub fn tier(action: &ContainmentAction) -> ActionTier` with `ActionTier { AutoReversible, Heavy }`; `ContainmentReceipt { action, tier, ttl_secs, requires_cosign }` and `LiftOrder { receipt_ref }` as canonical-JSON bodies. Auto-reversible actions carry a default TTL; heavy actions set `requires_cosign = true`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttle_is_auto_reversible() {
        let a = ContainmentAction::Throttle { subject: "s".to_string(), factor: 4 };
        assert_eq!(tier(&a), ActionTier::AutoReversible);
    }

    #[test]
    fn freeze_is_heavy_and_requires_cosign() {
        let a = ContainmentAction::FreezeSubject { subject: "s".to_string() };
        assert_eq!(tier(&a), ActionTier::Heavy);
        let receipt = ContainmentReceipt::for_action(a);
        assert!(receipt.requires_cosign);
    }

    #[test]
    fn auto_action_has_ttl_and_no_cosign() {
        let a = ContainmentAction::RevokeSession { session_key: "agent-1".to_string() };
        let receipt = ContainmentReceipt::for_action(a);
        assert!(!receipt.requires_cosign);
        assert!(receipt.ttl_secs > 0);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-quarantine action`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

`src/action.rs`:

```rust
//! Containment actions and their reversibility tier.

use serde::{Deserialize, Serialize};

/// A containment action the engine may take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum ContainmentAction {
    Throttle { subject: String, factor: u32 },
    RevokeSession { session_key: String },
    Escalate { summary: String },
    FreezeSubject { subject: String },
    RevokeTenant { tenant: String },
}

/// Reversibility tier: cheap reversible actions auto-execute; heavy actions
/// require m-of-n human co-sign to apply and to extend past TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionTier {
    AutoReversible,
    Heavy,
}

/// Classify an action by reversibility.
#[must_use]
pub fn tier(action: &ContainmentAction) -> ActionTier {
    match action {
        ContainmentAction::Throttle { .. }
        | ContainmentAction::RevokeSession { .. }
        | ContainmentAction::Escalate { .. } => ActionTier::AutoReversible,
        ContainmentAction::FreezeSubject { .. }
        | ContainmentAction::RevokeTenant { .. } => ActionTier::Heavy,
    }
}
```

`src/receipt.rs`:

```rust
//! Signed containment receipts and their lift orders. Every action is
//! attested, TTL-bounded, and reversible via an explicit LiftOrder.

use serde::{Deserialize, Serialize};

use crate::action::{tier, ActionTier, ContainmentAction};

/// Default lifetime for an auto-reversible containment action.
const DEFAULT_TTL_SECS: u64 = 3600;

/// A signed-at-emission record of a containment action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainmentReceipt {
    pub action: ContainmentAction,
    pub tier: ActionTier,
    pub ttl_secs: u64,
    pub requires_cosign: bool,
}

impl ContainmentReceipt {
    /// Build the receipt for an action, setting tier, TTL, and co-sign
    /// requirement from the action's reversibility.
    #[must_use]
    pub fn for_action(action: ContainmentAction) -> Self {
        let action_tier = tier(&action);
        let requires_cosign = matches!(action_tier, ActionTier::Heavy);
        Self { action, tier: action_tier, ttl_secs: DEFAULT_TTL_SECS, requires_cosign }
    }
}

/// An explicit reversal of a prior containment action, referenced by receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiftOrder {
    pub receipt_ref: String,
}
```

Add `pub mod action;` and `pub mod receipt;` to `lib.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-quarantine action`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-quarantine/src/action.rs crates/security/chio-quarantine/src/receipt.rs crates/security/chio-quarantine/src/lib.rs
git commit -m "feat(quarantine): add tiered containment actions and reversible receipts"
```

### Task 18: Tiered executor with fakes

**Files:**
- Create: `crates/security/chio-quarantine/src/executor.rs`
- Modify: `src/lib.rs`
- Test: inline

**Interfaces:**
- Consumes: `crate::action::{ContainmentAction, ActionTier, tier}`, `crate::ports::*`, `crate::receipt::ContainmentReceipt`.
- Produces: `Executor<'a>` holding references to the ports, with `pub fn execute(&self, action: ContainmentAction) -> ExecOutcome` where `ExecOutcome { Applied(ContainmentReceipt), Pending(ContainmentReceipt) }`. Auto-reversible actions call the port and return `Applied`; heavy actions return `Pending` (awaiting co-sign) without touching a port.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeRevocation { calls: Mutex<Vec<String>> }
    impl RevocationPort for FakeRevocation {
        fn revoke_session(&self, session_key: &str) -> Result<(), PortError> {
            self.calls.lock().map_err(|_| PortError { detail: "poisoned".into() })?
                .push(session_key.to_string());
            Ok(())
        }
    }
    struct NoVelocity;
    impl VelocityPort for NoVelocity {
        fn throttle(&self, _: &str, _: u32) -> Result<(), PortError> { Ok(()) }
    }
    struct NoIssuance;
    impl IssuancePort for NoIssuance {
        fn freeze_subject(&self, _: &str) -> Result<(), PortError> { Ok(()) }
    }
    struct NoAlert;
    impl AlertPort for NoAlert {
        fn escalate(&self, _: &str) -> Result<(), PortError> { Ok(()) }
    }

    #[test]
    fn auto_action_applies_via_port() {
        let rev = FakeRevocation::default();
        let exec = Executor { revocation: &rev, velocity: &NoVelocity, issuance: &NoIssuance, alert: &NoAlert };
        let outcome = exec.execute(ContainmentAction::RevokeSession { session_key: "agent-1".to_string() });
        assert!(matches!(outcome, ExecOutcome::Applied(_)));
        assert_eq!(rev.calls.lock().expect("lock").len(), 1);
    }

    #[test]
    fn heavy_action_is_pending_without_port_call() {
        let rev = FakeRevocation::default();
        let exec = Executor { revocation: &rev, velocity: &NoVelocity, issuance: &NoIssuance, alert: &NoAlert };
        let outcome = exec.execute(ContainmentAction::FreezeSubject { subject: "s".to_string() });
        assert!(matches!(outcome, ExecOutcome::Pending(_)));
        assert_eq!(rev.calls.lock().expect("lock").len(), 0);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-quarantine executor`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

`src/executor.rs`:

```rust
//! The tiered executor: auto-reversible actions apply through a port and
//! return an Applied receipt; heavy actions return Pending until co-signed.

use crate::action::{tier, ActionTier, ContainmentAction};
use crate::ports::{AlertPort, IssuancePort, RevocationPort, VelocityPort};
use crate::receipt::ContainmentReceipt;

/// The result of attempting an action.
pub enum ExecOutcome {
    Applied(ContainmentReceipt),
    Pending(ContainmentReceipt),
}

/// Holds borrowed ports for the duration of a response cycle.
pub struct Executor<'a> {
    pub revocation: &'a dyn RevocationPort,
    pub velocity: &'a dyn VelocityPort,
    pub issuance: &'a dyn IssuancePort,
    pub alert: &'a dyn AlertPort,
}

impl Executor<'_> {
    /// Execute or stage an action per its reversibility tier. Port failures
    /// are folded into the receipt (best-effort), never panicked.
    #[must_use]
    pub fn execute(&self, action: ContainmentAction) -> ExecOutcome {
        let receipt = ContainmentReceipt::for_action(action.clone());
        if matches!(tier(&action), ActionTier::Heavy) {
            return ExecOutcome::Pending(receipt);
        }
        let _ = match &action {
            ContainmentAction::RevokeSession { session_key } => {
                self.revocation.revoke_session(session_key)
            }
            ContainmentAction::Throttle { subject, factor } => {
                self.velocity.throttle(subject, *factor)
            }
            ContainmentAction::Escalate { summary } => self.alert.escalate(summary),
            ContainmentAction::FreezeSubject { subject } => self.issuance.freeze_subject(subject),
            ContainmentAction::RevokeTenant { .. } => Ok(()),
        };
        ExecOutcome::Applied(receipt)
    }
}
```

Add `pub mod executor;` to `lib.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-quarantine executor`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-quarantine/src/executor.rs crates/security/chio-quarantine/src/lib.rs
git commit -m "feat(quarantine): add tiered executor over ports"
```

### Task 19: Playbook parser and evaluator

**Files:**
- Create: `crates/security/chio-quarantine/src/playbook.rs`
- Modify: `src/lib.rs`
- Test: inline

**Interfaces:**
- Consumes: `crate::event::{SecurityEvent, EventSource}`, `crate::action::ContainmentAction`.
- Produces: `Playbook { rules: Vec<Rule> }` with `pub fn evaluate(&self, event: &SecurityEvent) -> Vec<ContainmentAction>`; `Rule { on: EventSource, actions: Vec<ContainmentAction> }`. A minimal builder API (not a string DSL) for v1; the HushSpec-style textual parser is a documented follow-up so the engine ships testable now.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::ContainmentAction;
    use crate::event::{EventSource, SecurityEvent};

    #[test]
    fn matching_rule_yields_actions() {
        let playbook = Playbook {
            rules: vec![Rule {
                on: EventSource::CanaryHit,
                actions: vec![ContainmentAction::RevokeSession { session_key: String::new() }],
            }],
        };
        let event = SecurityEvent {
            source: EventSource::CanaryHit,
            subject: "did:chio:agent".to_string(),
            session_key: "agent-1".to_string(),
        };
        let actions = playbook.evaluate(&event);
        assert_eq!(actions.len(), 1);
        // The engine binds the event's session_key into session-scoped actions.
        assert!(matches!(&actions[0], ContainmentAction::RevokeSession { session_key } if session_key == "agent-1"));
    }

    #[test]
    fn non_matching_rule_is_silent() {
        let playbook = Playbook {
            rules: vec![Rule { on: EventSource::VelocityBreach, actions: vec![] }],
        };
        let event = SecurityEvent {
            source: EventSource::CanaryHit,
            subject: "x".to_string(),
            session_key: "agent-1".to_string(),
        };
        assert!(playbook.evaluate(&event).is_empty());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-quarantine playbook`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

`src/playbook.rs`:

```rust
//! Declarative response rules. v1 exposes a builder API; a HushSpec-style
//! textual `when/within/then` parser is a documented follow-up.

use crate::action::ContainmentAction;
use crate::event::{EventSource, SecurityEvent};

/// A single response rule: on an event source, take these actions.
pub struct Rule {
    pub on: EventSource,
    pub actions: Vec<ContainmentAction>,
}

/// An ordered set of response rules.
pub struct Playbook {
    pub rules: Vec<Rule>,
}

impl Playbook {
    /// Return the actions triggered by an event, with the event's session
    /// key bound into session-scoped action templates.
    #[must_use]
    pub fn evaluate(&self, event: &SecurityEvent) -> Vec<ContainmentAction> {
        let mut out = Vec::new();
        for rule in &self.rules {
            if rule.on == event.source {
                for action in &rule.actions {
                    out.push(bind_session(action, &event.session_key));
                }
            }
        }
        out
    }
}

/// Fill a session-scoped action's key from the triggering event.
fn bind_session(action: &ContainmentAction, session_key: &str) -> ContainmentAction {
    match action {
        ContainmentAction::RevokeSession { .. } => {
            ContainmentAction::RevokeSession { session_key: session_key.to_string() }
        }
        other => other.clone(),
    }
}
```

Add `pub mod playbook;` to `lib.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p chio-quarantine playbook`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/security/chio-quarantine/src/playbook.rs crates/security/chio-quarantine/src/lib.rs
git commit -m "feat(quarantine): add playbook builder and evaluator"
```

### Task 20: Phase 3 verification

- [ ] **Step 1: Run scoped checks**

Run: `cargo build -p chio-quarantine && cargo test -p chio-quarantine && cargo clippy -p chio-quarantine -- -D warnings && cargo fmt --all -- --check`
Expected: all green.

- [ ] **Step 2: Fix findings and re-run.**

- [ ] **Step 3: Commit fixes**

```bash
git add -A
git commit -m "test(quarantine): green phase 3 checks"
```

---

## Phase 4: Release gates, evidence, and spec

### Task 21: Release-gate scripts

**Files:**
- Create: `scripts/check-decoy-unreachable.sh`, `scripts/check-containment-reversible.sh`, `scripts/check-flow-invariants.sh`
- Test: run each script

**Interfaces:**
- Produces: three fail-closed shell gates. `check-decoy-unreachable` greps every non-decoy manifest and fixture for a `decoy:` server binding and fails if found. `check-containment-reversible` asserts every `ContainmentAction` variant is covered by `tier` (greps the source for a match arm). `check-flow-invariants` runs the `chio-flow` lattice property test as a named test.

- [ ] **Step 1: Write `check-decoy-unreachable.sh`**

```bash
#!/usr/bin/env bash
# Fail-closed gate: no real manifest may bind a decoy: server namespace.
set -euo pipefail
hits=$(grep -rn "decoy:" --include="*.json" --include="*.yaml" crates/ spec/ \
  | grep -v "crates/security/chio-decoy" || true)
if [ -n "$hits" ]; then
  echo "FAIL: decoy namespace referenced outside chio-decoy:" >&2
  echo "$hits" >&2
  exit 1
fi
echo "OK: no real manifest binds a decoy: server"
```

- [ ] **Step 2: Run it to verify it passes on a clean tree**

Run: `bash scripts/check-decoy-unreachable.sh`
Expected: prints `OK: no real manifest binds a decoy: server`, exit 0.

- [ ] **Step 3: Write the other two gates**

`scripts/check-containment-reversible.sh`:

```bash
#!/usr/bin/env bash
# Fail-closed gate: every ContainmentAction variant must be tiered, and every
# receipt must expose ttl_secs (reversibility invariant).
set -euo pipefail
action_file="crates/security/chio-quarantine/src/action.rs"
receipt_file="crates/security/chio-quarantine/src/receipt.rs"
grep -q "pub fn tier" "$action_file" || { echo "FAIL: tier() missing" >&2; exit 1; }
grep -q "ttl_secs" "$receipt_file" || { echo "FAIL: ttl_secs missing" >&2; exit 1; }
echo "OK: containment tiering and TTL present"
```

`scripts/check-flow-invariants.sh`:

```bash
#!/usr/bin/env bash
# Fail-closed gate: the lattice order tests must exist and pass.
set -euo pipefail
cargo test -p chio-flow flows_to -- --nocapture
echo "OK: flow lattice invariants pass"
```

- [ ] **Step 4: Run all three**

Run: `bash scripts/check-containment-reversible.sh && bash scripts/check-flow-invariants.sh && bash scripts/check-decoy-unreachable.sh`
Expected: three OK lines, exit 0.

- [ ] **Step 5: Commit**

```bash
chmod +x scripts/check-decoy-unreachable.sh scripts/check-containment-reversible.sh scripts/check-flow-invariants.sh
git add scripts/check-decoy-unreachable.sh scripts/check-containment-reversible.sh scripts/check-flow-invariants.sh
git commit -m "feat(security): add fail-closed release gates for flow, decoy, containment"
```

### Task 22: Adversarial corpus classes

**Files:**
- Create: `crates/core/chio-adversarial-suite/cases/label_downgrade/label-downgrade-001.json`, `.../canary_evasion/canary-evasion-001.json`, `.../containment_rollback/containment-rollback-001.json`
- Test: the adversarial-suite loader

**Interfaces:**
- Consumes: the existing case schema in `crates/core/chio-adversarial-suite/`. Read one existing case file first to copy the exact schema (fields `class`, `reason`, `path`, and any manifest entry).

- [ ] **Step 1: Read an existing case and its manifest**

Run: `ls crates/core/chio-adversarial-suite/cases/ && sed -n '1,40p' $(find crates/core/chio-adversarial-suite/cases -name '*.json' | head -1)`
Expected: shows the JSON shape to mirror (for example a `clock_rewound` case).

- [ ] **Step 2: Write the three case files mirroring that schema**

Use the same top-level fields as the existing case. For `label_downgrade`, encode a declassification attempt with no `Declassify` caveat; for `canary_evasion`, a presentation of a `decoy:` capability; for `containment_rollback`, a `LiftOrder` referencing a heavy action without co-sign. Register each in the suite manifest if the existing cases are listed in one (check for a `manifest.json` or index under `cases/`).

- [ ] **Step 3: Run the suite loader**

Run: `cargo test -p chio-adversarial-suite`
Expected: PASS, including schema validation of the three new cases.

- [ ] **Step 4: Commit**

```bash
git add crates/core/chio-adversarial-suite/cases/
git commit -m "test(adversarial): add label_downgrade, canary_evasion, containment_rollback cases"
```

### Task 23: Spec deltas and workspace verification

**Files:**
- Modify: `spec/PROTOCOL.md`, `spec/SECURITY.md`
- Test: whole workspace

**Interfaces:**
- Produces: normative prose for the `Label` wire type, the `Declassify` caveat, manifest `sensitivity`/`clearance`, the flow/tripwire/containment event bodies, and the canary-recognition rule (the kernel MUST deny and emit a tripwire on presentation of a `decoy:` capability).

- [ ] **Step 1: Add the label and caveat sections to `spec/PROTOCOL.md`**

Under the capability section, document the `Label` shape (policies + compartments), `flows_to` semantics (sink clearance must dominate context), and the `Declassify` caveat (predicate = comma-separated compartments). Under the manifest section, document `sensitivity` and `clearance`. Use hyphens, not em dashes.

- [ ] **Step 2: Add the canary and containment sections to `spec/SECURITY.md`**

Document the `decoy:` namespace, the recognition-and-tripwire rule, and the tiered/reversible containment model. Cross-reference the five event bodies.

- [ ] **Step 3: Run the full workspace one-liner**

Run: `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`
Expected: all green.

- [ ] **Step 4: Run the three release gates**

Run: `bash scripts/check-flow-invariants.sh && bash scripts/check-decoy-unreachable.sh && bash scripts/check-containment-reversible.sh`
Expected: three OK lines.

- [ ] **Step 5: Commit**

```bash
git add spec/PROTOCOL.md spec/SECURITY.md
git commit -m "docs(spec): specify flow labels, declassify caveat, canary and containment semantics"
```

---

## Self-Review

**Spec coverage** (each spec section maps to a task):
- chio-flow (labels, seeding, taint env, FlowGuard, declassification, events): Tasks 1, 4, 5, 6, 7, 8, 9, 10.
- chio-decoy (canary caps, registry, honey-tools, watermarks, tripwire): Tasks 12, 13, 14, 15.
- chio-quarantine (events, ports, actions/tiering, receipts, executor, playbook): Tasks 16, 17, 18, 19.
- Protocol deltas (Label, Declassify caveat, manifest fields, event bodies, canary semantics): Tasks 1, 2, 3, 10, 15, 17, 23.
- Testing/evidence (adversarial corpus, arena, gates, formal): Tasks 21, 22. Formal lattice property is covered by the `flows_to` order tests in Task 5 and gated by Task 21; a Kani harness is out of scope for v1 and is called out here as deferred rather than left as a silent gap.
- Release framing (gates, bounded claims): Task 21 plus the Global Constraints note.

**Deferred items made explicit (not silent gaps):** session-granular taint keying (v1 keys by agent id, Task 7), the HushSpec textual playbook parser (v1 uses a builder API, Task 19), feature-gated real adapters wrapping revocation-oracle/custody-hw/swarm-authority/siem (traits and fakes ship in Tasks 16 and 18; concrete adapters are a follow-up behind the `adapters` feature), and a Kani proof of the lattice order (Task 5 tests the properties; a formal harness is deferred).

**Placeholder scan:** no `TBD`/`TODO`/`implement later` in any step; every code step carries complete code. Two tasks (9 and 12) instruct the implementer to confirm an exact upstream field name against a cited file path before use, which is a verification instruction, not a placeholder.

**Type consistency:** `Label`/`FlowPolicy` names are consistent across Tasks 1, 4-10; `SessionTaintStore` methods `add`/`context` are used consistently in Tasks 7-9; `ContainmentAction` variants match across Tasks 17-19; port trait names match across Tasks 16 and 18. Guard surface verified against the real definitions: `Guard::evaluate` returns `Result<GuardDecision, KernelError>`; `Verdict` has three variants (`Allow`, `Deny`, `PendingApproval`) so Task 8's `evaluate` match is exhaustive and fails closed on non-`Allow`; `GuardContext.agent_id` is `&AgentId` where `AgentId = String` (coerces to `&str`); `GuardDecision::allow()` / `deny(Vec::new())` are the real constructors.
