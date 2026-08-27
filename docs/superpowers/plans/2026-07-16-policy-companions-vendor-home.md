# Policy Companions and Vendor Home Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement design v2 item 5.3 end to end: the `hushspec.velocity` and `hushspec.approval` incubating companion modules (full state contracts, draft-0.2 schema acceptance, stateful conformance vectors, testkit sequence evaluators) and the `vendor.chio` conformant home for `reputation`, `runtime_assurance`, and the former `extensions.chio` blocks, wired through arc with enforcement negotiation.

**Architecture:** hush is schema-first: JSON Schema is the source, `scripts/generate_sdk_models.py` emits Rust/Python/Go models (never hand-edit `generated_models.*`). All 0.2 constructs live in a separate draft schema and are reachable only through an explicit draft entry point behind the `unstable-v0-2` cargo feature, so released 0.1 behavior never changes (review finding 3). arc's `chio-policy` gains the canonical `extensions.vendor.chio` location with migration-mode aliases, `requires` negotiation (approval module: recognized but **rejected** when required, until the protocol-primitives threshold verifier lands), and velocity state-contract conformance driven by the vendored hush sequence vectors.

**Tech Stack:** Rust (hush `hushspec`, `hushspec-testkit`; arc `chio-policy`, `chio-guards`, `chio-control-plane`), JSON Schema draft 2020-12, Python 3 generator scripts, ed25519-dalek (already a hush dependency via `signing.rs`).

## Global Constraints

- Normative sources, copied verbatim where cited: `hush:spec/hushspec-velocity.md`, `hush:spec/hushspec-approval.md`, `hush:spec/vendor-registry.md`, `arc:spec/CHIO_VENDOR_EXTENSIONS.md`.
- Module identities: `hushspec.velocity` version `"0.1"`, `hushspec.approval` version `"0.1"`, `vendor.chio` version `"0.1"`.
- Currency codes match `^[A-Z]{3}$`. Amounts are integer minor units; no floating point in accumulation.
- Approval defaults: `DEFAULT_THRESHOLD_APPROVAL_TIMEOUT_SECONDS = 900`, hard maximum `3600` (protocol-primitives values; documents exceeding the max reject at load).
- Fail-closed everywhere: validation problems are errors (document rejection), never warnings; missing state denies.
- No em dashes (U+2014) in any file. Conventional commits. arc and hush both enforce `cargo clippy --workspace -- -D warnings`; arc additionally denies `unwrap_used`/`expect_used`.
- Never hand-edit `generated_models.rs` / `generated_models.py` / `generated_models.go`; change the schema and rerun `python3 scripts/generate_sdk_models.py`.
- Default parse behavior in hush (0.1) MUST NOT change; every 0.2 construct is reachable only via `parse_draft02` under the `unstable-v0-2` feature.
- arc branch: `docs/policy-expansion-design` (do not `git add -A`; the branch carries an unrelated uncommitted design doc). hush branch: `spec/incubating-companions`.

---

### Task 1: Stateful sequence fixture schema (hush)

**Files:**
- Create: `schemas/hushspec-sequence-test.v0.schema.json`
- Create: `fixtures/sequence/velocity/window-exhaustion.yaml`
- Test: `crates/hushspec-testkit/tests/sequence_schema.rs`

**Interfaces:**
- Produces: the fixture format every later task consumes. Top-level fields: `description` (string), `modules` (array of `{module, version}`), `policy` (inline HushSpec YAML as a string), `clock` (object: `start` RFC3339 string), `steps` (array). Each step is exactly one of: `{advance_secs: <int>}`, `{action: {...core action fields plus cost{amount,currency}, subjects{capability_id,grant_index,agent_id,session_id}, request_id}, expect: {decision, reason_contains?, remaining?{limit_key: int}}}`, `{present_artifact: {approver, decision, binding_ref, issued_at_offset_secs, expires_in_secs, tamper?}, expect: {...}}`, `{restart: {class: ephemeral|durable}, expect_marker?: state_reset}`, `{expect_session: {state: requested|approved|denied|expired, generation?: int}}`.
- Produces: `fixtures/sequence/` directory convention: `velocity/*.yaml`, `approval/*.yaml`.

- [ ] **Step 1: Write the failing test**

```rust
// crates/hushspec-testkit/tests/sequence_schema.rs
use std::path::Path;

#[test]
fn sequence_schema_validates_velocity_example() {
    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/hushspec-sequence-test.v0.schema.json");
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/sequence/velocity/window-exhaustion.yaml");

    let schema: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(schema_path).unwrap()).unwrap();
    let fixture_yaml = std::fs::read_to_string(fixture_path).unwrap();
    let fixture: serde_json::Value = serde_yml::from_str(&fixture_yaml).unwrap();

    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(&fixture)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}
```

If `jsonschema` is not already a testkit dev-dependency, add to `crates/hushspec-testkit/Cargo.toml` `[dev-dependencies]`: `jsonschema = "0.26"`, `serde_json = "1"`, `serde_yml = "0.0.12"` (match workspace versions already used by `hushspec`).

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p hushspec-testkit --test sequence_schema -- --nocapture`
Expected: FAIL (schema file not found).

- [ ] **Step 3: Write the schema and the first fixture**

`schemas/hushspec-sequence-test.v0.schema.json`: JSON Schema draft 2020-12, `"additionalProperties": false` at every level, `$defs` for `Action`, `Cost` (`amount`: integer >= 0, `currency`: `"pattern": "^[A-Z]{3}$"`), `Subjects`, `ArtifactPresentation`, `Expect` (`decision` enum `allow|deny|warn`), `steps` as an array of `oneOf` the five step shapes from the Interfaces block. Root requires `["description", "modules", "policy", "clock", "steps"]`.

`fixtures/sequence/velocity/window-exhaustion.yaml`:

```yaml
description: two invocations admit, third denies, refill after window
modules: [{module: hushspec.velocity, version: "0.1"}]
policy: |
  hushspec: "0.2.0"
  name: vel-window
  requires:
    - module: hushspec.velocity
      version: "0.1"
      enforcement: required
  rules:
    velocity:
      window_secs: 60
      limits:
        - subject: agent
          max_invocations: 2
clock: {start: "2026-07-16T00:00:00Z"}
steps:
  - action: {type: tool_call, target: mail.send, subjects: {agent_id: agent-a}, request_id: r1}
    expect: {decision: allow, remaining: {"agent/max_invocations": 1}}
  - action: {type: tool_call, target: mail.send, subjects: {agent_id: agent-a}, request_id: r2}
    expect: {decision: allow, remaining: {"agent/max_invocations": 0}}
  - action: {type: tool_call, target: mail.send, subjects: {agent_id: agent-a}, request_id: r3}
    expect: {decision: deny, reason_contains: "agent"}
  - advance_secs: 61
  - action: {type: tool_call, target: mail.send, subjects: {agent_id: agent-a}, request_id: r4}
    expect: {decision: allow}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p hushspec-testkit --test sequence_schema -- --nocapture`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add schemas/hushspec-sequence-test.v0.schema.json fixtures/sequence/velocity/window-exhaustion.yaml crates/hushspec-testkit/tests/sequence_schema.rs crates/hushspec-testkit/Cargo.toml
git commit -m "feat(testkit): add stateful sequence fixture schema and first velocity fixture"
```

---

### Task 2: Draft-0.2 parse mode with `requires` and vendor namespace (hush)

**Files:**
- Create: `schemas/hushspec-core.v0.2-draft.schema.json` (copy of `hushspec-core.v0.schema.json` plus: top-level `requires` array of `{module: string, version: string, enforcement: "required"|"optional"}`; `extensions.vendor` object with `"chio"` property as free-form object and `"additionalProperties": false`)
- Create: `crates/hushspec/src/draft02.rs`
- Modify: `crates/hushspec/src/lib.rs` (add `#[cfg(feature = "unstable-v0-2")] pub mod draft02;`)
- Modify: `crates/hushspec/Cargo.toml` (add `[features] unstable-v0-2 = []`)
- Test: `crates/hushspec/tests/draft02_requires.rs`

**Interfaces:**
- Produces: `draft02::parse_draft02(yaml: &str) -> Result<Draft02Document, Draft02Error>`; `Draft02Document { spec: HushSpec-equivalent fields, requires: Vec<RequiresEntry>, vendor: BTreeMap<String, serde_yml::Value> }`; `RequiresEntry { module: String, version: String, enforcement: EnforcementLevel }`; `EnforcementLevel::{Required, Optional}`; `draft02::KNOWN_MODULES: &[&str] = &["vendor.chio", "hushspec.velocity", "hushspec.approval"]`; `draft02::REGISTERED_VENDORS: &[&str] = &["chio"]`.
- Consumes: nothing from other tasks. Draft models are hand-written in `draft02.rs` for the delta only (requires + vendor); the base document reuses the released parser on the remainder. Do NOT touch `generated_models.rs`; the draft schema feeds the generator only when 0.2 stabilizes (out of scope here).

- [ ] **Step 1: Write the failing tests**

```rust
// crates/hushspec/tests/draft02_requires.rs
#![cfg(feature = "unstable-v0-2")]
use hushspec::draft02::{parse_draft02, Draft02Error, EnforcementLevel};

const VENDOR_DOC: &str = r#"
hushspec: "0.2.0"
name: vendor-home
requires:
  - module: vendor.chio
    version: "0.1"
    enforcement: required
extensions:
  vendor:
    chio:
      market_hours: {tz: America/New_York, open: "09:30", close: "16:00"}
"#;

#[test]
fn vendor_block_with_requires_parses() {
    let doc = parse_draft02(VENDOR_DOC).unwrap();
    assert_eq!(doc.requires.len(), 1);
    assert_eq!(doc.requires[0].module, "vendor.chio");
    assert_eq!(doc.requires[0].enforcement, EnforcementLevel::Required);
    assert!(doc.vendor.contains_key("chio"));
}

#[test]
fn vendor_block_without_requires_rejects() {
    let doc = VENDOR_DOC.replace(
        "requires:\n  - module: vendor.chio\n    version: \"0.1\"\n    enforcement: required\n",
        "",
    );
    let err = parse_draft02(&doc).unwrap_err();
    assert!(matches!(err, Draft02Error::UndeclaredModule(m) if m == "vendor.chio"));
}

#[test]
fn unregistered_vendor_rejects() {
    let doc = VENDOR_DOC.replace("chio:", "acme:").replace("vendor.chio", "vendor.acme");
    let err = parse_draft02(&doc).unwrap_err();
    assert!(matches!(err, Draft02Error::UnregisteredVendor(v) if v == "acme"));
}

#[test]
fn unknown_required_module_rejects() {
    let doc = VENDOR_DOC.replace("vendor.chio", "hushspec.nonexistent");
    let err = parse_draft02(&doc).unwrap_err();
    assert!(matches!(err, Draft02Error::UnknownModule(m) if m == "hushspec.nonexistent"));
}

#[test]
fn vendor_block_round_trips() {
    let doc = parse_draft02(VENDOR_DOC).unwrap();
    let emitted = doc.to_yaml().unwrap();
    let reparsed = parse_draft02(&emitted).unwrap();
    assert_eq!(doc.vendor, reparsed.vendor);
}

#[test]
fn released_parser_still_rejects_draft_fields() {
    // Guard against finding 3: default 0.1 behavior unchanged.
    assert!(hushspec::schema::HushSpec::parse(VENDOR_DOC).is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p hushspec --features unstable-v0-2 --test draft02_requires`
Expected: FAIL (module `draft02` not found).

- [ ] **Step 3: Implement `draft02.rs`**

Implementation shape (hand-written delta parser; ~120 lines):

```rust
// crates/hushspec/src/draft02.rs
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const KNOWN_MODULES: &[&str] = &["vendor.chio", "hushspec.velocity", "hushspec.approval"];
pub const REGISTERED_VENDORS: &[&str] = &["chio"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementLevel { Required, Optional }

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiresEntry {
    pub module: String,
    pub version: String,
    pub enforcement: EnforcementLevel,
}

#[derive(Debug, thiserror::Error)]
pub enum Draft02Error {
    #[error("parse error: {0}")] Parse(String),
    #[error("module used in body but not declared in requires: {0}")] UndeclaredModule(String),
    #[error("unregistered vendor namespace: {0}")] UnregisteredVendor(String),
    #[error("requires names unknown module: {0}")] UnknownModule(String),
}
```

`parse_draft02` algorithm: parse the YAML to `serde_yml::Value` (reuse the hardening pre-checks by calling the same private helpers via a crate-internal re-export, or duplicate the three checks verbatim); extract and remove `requires` and `extensions.vendor`; validate every `requires.module` against `KNOWN_MODULES` (else `UnknownModule`); validate every `extensions.vendor.<name>` key against `REGISTERED_VENDORS` (else `UnregisteredVendor`); require a `requires` entry `vendor.<name>` for each vendor key present, and entries `hushspec.velocity` / `hushspec.approval` when `rules.velocity` / `rules.human_in_loop` are present (else `UndeclaredModule`); strip the draft-only keys (`requires`, `extensions.vendor`, `rules.velocity`, `rules.human_in_loop`) from the remainder and hand it to the released `HushSpec::parse` for base validation; store the stripped subtrees verbatim (`vendor: BTreeMap<String, serde_yml::Value>`, `velocity_raw` / `human_in_loop_raw: Option<serde_yml::Value>` for Tasks 3 and 4). `Draft02Document::to_yaml` re-inserts the subtrees.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p hushspec --features unstable-v0-2 --test draft02_requires`
Expected: PASS (6 tests). Also run `cargo test -p hushspec` (default features) - expected: full existing suite PASS, proving no released-behavior change.

- [ ] **Step 5: Commit**

```bash
git add schemas/hushspec-core.v0.2-draft.schema.json crates/hushspec/src/draft02.rs crates/hushspec/src/lib.rs crates/hushspec/Cargo.toml crates/hushspec/tests/draft02_requires.rs
git commit -m "feat(draft02): requires contract and registered vendor namespace behind unstable-v0-2"
```

---

### Task 3: Velocity module validation in draft mode (hush)

**Files:**
- Create: `crates/hushspec/src/draft02/velocity.rs`
- Modify: `crates/hushspec/src/draft02.rs` (add `pub mod velocity;` and call it from `parse_draft02` when `velocity_raw` is present)
- Test: `crates/hushspec/tests/draft02_velocity.rs`

**Interfaces:**
- Consumes: `Draft02Document.velocity_raw` from Task 2.
- Produces: `draft02::velocity::{VelocityModule, VelocityLimit, LimitSubject, Money}` with `VelocityModule::from_value(&serde_yml::Value) -> Result<VelocityModule, VelocityError>`. `LimitSubject::{Grant, Capability, Agent, Session, OriginProfile}`; `Money { amount: u64, currency: String }`; `VelocityLimit { subject, max_invocations: Option<u32>, max_spend: Option<Money>, window_secs: Option<u64>, burst_factor: Option<f64> }`; `VelocityModule { enabled: bool, window_secs: u64, burst_factor: f64, limits: Vec<VelocityLimit> }`.

- [ ] **Step 1: Write the failing tests** covering spec `hushspec-velocity.md` Section 2 exactly:

```rust
// crates/hushspec/tests/draft02_velocity.rs  (#![cfg(feature = "unstable-v0-2")])
// One test per constraint, each parsing a full document via parse_draft02:
// - valid limits list parses with defaults (window 60, burst 1.0, enabled true)
// - empty limits rejects
// - limit with neither max_invocations nor max_spend rejects
// - max_spend without currency rejects; currency "usd" (lowercase) rejects; "USD" passes
// - max_invocations: 0 rejects; window_secs: 0 rejects; burst_factor: 0.5 rejects
// - duplicate (subject, kind) pair rejects: two {subject: grant, max_invocations} entries
// - non-duplicate: {grant, max_invocations} + {grant, max_spend} passes
// - unknown field inside a limit rejects
```

Write each as a real `#[test]` with an inline YAML document and an `assert!(matches!(err, VelocityError::...))`; the error enum variants are `Empty`, `NoLimitKind`, `MissingCurrency`, `BadCurrency(String)`, `ZeroValue(&'static str)`, `DuplicateLimit(String)`, `UnknownField(String)`.

- [ ] **Step 2: Run to verify FAIL** - `cargo test -p hushspec --features unstable-v0-2 --test draft02_velocity` (module not found).

- [ ] **Step 3: Implement `velocity.rs`** - serde structs with `deny_unknown_fields`, then a `validate()` pass implementing the eight constraints; `from_value` = deserialize + validate. Currency check: `currency.len() == 3 && currency.bytes().all(|b| b.is_ascii_uppercase())`.

- [ ] **Step 4: Run to verify PASS**, then `cargo clippy -p hushspec --features unstable-v0-2 -- -D warnings`.

- [ ] **Step 5: Commit** - `git commit -m "feat(draft02): velocity module schema validation"` (add `crates/hushspec/src/draft02/velocity.rs crates/hushspec/src/draft02.rs crates/hushspec/tests/draft02_velocity.rs`).

---

### Task 4: Approval module validation in draft mode (hush)

**Files:**
- Create: `crates/hushspec/src/draft02/approval.rs`
- Modify: `crates/hushspec/src/draft02.rs` (wire `human_in_loop_raw`)
- Test: `crates/hushspec/tests/draft02_approval.rs`

**Interfaces:**
- Consumes: `Draft02Document.human_in_loop_raw` from Task 2.
- Produces: `draft02::approval::{ApprovalModule, ApproverSet}` with `ApprovalModule::from_value(...) -> Result<ApprovalModule, ApprovalError>`. `ApprovalModule { enabled: bool, require_confirmation: Vec<String>, approve_above: Option<Money>, timeout_seconds: Option<u64>, on_timeout: OnTimeout, approvers: Option<ApproverSet> }`; `ApproverSet { n: u32, of: Vec<String>, timeout_seconds: Option<u64> }`; `OnTimeout::{Deny, Defer}`; reuse `Money` from Task 3. `pub const APPROVAL_HARD_MAX_TIMEOUT_SECS: u64 = 3600;`

- [ ] **Step 1: Write the failing tests** per `hushspec-approval.md` Section 2:

```rust
// crates/hushspec/tests/draft02_approval.rs  (#![cfg(feature = "unstable-v0-2")])
// - enabled block with neither require_confirmation nor approve_above rejects
// - approve_above without currency rejects
// - approvers: n=0 rejects; n=4 with of.len()=3 rejects; duplicate of entries reject; empty-string id rejects
// - timeout_seconds: 3601 rejects (load-time, not clamped); 3600 passes
// - keys embedded in document: an `of` entry object form {id: ..., key: ...} rejects (of entries are strings only)
// - valid 2-of-3 with defer parses; on_timeout defaults to deny
```

- [ ] **Step 2: Run to verify FAIL.** `cargo test -p hushspec --features unstable-v0-2 --test draft02_approval`

- [ ] **Step 3: Implement `approval.rs`** with `deny_unknown_fields` structs and a `validate()` implementing every constraint above; error enum `ApprovalError::{NoGate, MissingCurrency, BadThreshold(String), DuplicateApprover(String), EmptyApprover, TimeoutAboveMax(u64), KeysInDocument}`.

- [ ] **Step 4: Run to verify PASS** plus clippy as in Task 3.

- [ ] **Step 5: Commit** - `git commit -m "feat(draft02): approval module schema validation"`.

---

### Task 5: Testkit velocity sequence evaluator plus vector families (hush)

**Files:**
- Create: `crates/hushspec-testkit/src/sequence.rs` (runner: fixture loading, injected clock, step dispatch)
- Create: `crates/hushspec-testkit/src/sequence/velocity_state.rs` (reference state machine)
- Modify: `crates/hushspec-testkit/src/lib.rs` (export `sequence`)
- Create fixtures under `fixtures/sequence/velocity/`: `burst-headroom.yaml`, `subject-isolation.yaml`, `missing-subject-denies.yaml`, `currency-mismatch-denies.yaml`, `absent-cost-denies.yaml`, `atomic-multi-limit.yaml`, `idempotent-request-id.yaml`, `saturation-denies.yaml`, `ephemeral-restart-reset.yaml`, `store-unavailable-denies.yaml` (plus Task 1's `window-exhaustion.yaml` = families 1-10 from spec Section 9)
- Test: `crates/hushspec-testkit/tests/sequence_velocity.rs`

**Interfaces:**
- Consumes: Task 1 fixture format; Task 3 `VelocityModule` (feature `unstable-v0-2` becomes a testkit dependency feature: `hushspec = { path = "../hushspec", features = ["unstable-v0-2"] }` in testkit's Cargo.toml).
- Produces: `sequence::SequenceRunner::new(fixture_yaml: &str) -> Result<SequenceRunner, SequenceError>`; `runner.run() -> SequenceReport`; `SequenceReport { steps: Vec<StepOutcome>, pass: bool }`; `StepOutcome { index: usize, expected: String, actual: String, pass: bool }`. `velocity_state::VelocityState::admit(&mut self, key: StateKey, kind: LimitKind, units: u64, now_ms: u64, cfg: &VelocityLimit) -> Admit` where `Admit::{Allow { remaining: u64 }, Deny { reason: String } }`; `StateKey` is `(LimitSubject, String)` and `String` is the resolved subject id; `store_unavailable: bool` toggle on `VelocityState` for family 10; `saturation_cap: usize` for family 8.

- [ ] **Step 1: Write the failing test** - a discovery test that runs every fixture in `fixtures/sequence/velocity/` through `SequenceRunner` and asserts `report.pass`, printing per-step diffs on failure:

```rust
// crates/hushspec-testkit/tests/sequence_velocity.rs
#[test]
fn all_velocity_sequence_fixtures_pass() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/sequence/velocity");
    let mut ran = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") { continue; }
        let yaml = std::fs::read_to_string(&path).unwrap();
        let report = hushspec_testkit::sequence::SequenceRunner::new(&yaml).unwrap().run();
        assert!(report.pass, "{}: {:#?}", path.display(), report.steps);
        ran += 1;
    }
    assert!(ran >= 11, "expected all velocity families present, ran {ran}");
}
```

- [ ] **Step 2: Run to verify FAIL** - `cargo test -p hushspec-testkit --test sequence_velocity` (module not found).

- [ ] **Step 3: Implement the runner and state machine.** The state machine implements spec Sections 4-6 exactly: integer milli-unit token buckets, capacity `ceil(max * burst_factor)`, refill `max / window_secs` per elapsed injected-clock ms, admission all-or-nothing across the document's applicable limits, request-id dedupe map with horizon `window_secs`, missing-subject deny, currency equality check before spend admission, `restart {class: ephemeral}` step clears state and stamps the next `StepOutcome` with the `state_reset` marker, `store_unavailable` denies everything. Write each fixture as you implement its family; keep each fixture under 40 lines in the Task 1 format.

- [ ] **Step 4: Run to verify PASS** - the discovery test with all 11 fixtures; then `cargo clippy -p hushspec-testkit -- -D warnings`.

- [ ] **Step 5: Commit** - `git add crates/hushspec-testkit fixtures/sequence/velocity && git commit -m "feat(testkit): velocity sequence evaluator and conformance vector families 1-10"`.

---

### Task 6: Testkit approval sequence evaluator plus vector families (hush)

**Files:**
- Create: `crates/hushspec-testkit/src/sequence/approval_state.rs`
- Modify: `crates/hushspec-testkit/src/sequence.rs` (dispatch `present_artifact`, `expect_session` steps)
- Create fixtures under `fixtures/sequence/approval/`: `n-of-m-happy.yaml`, `duplicate-approver-once.yaml`, `invalid-artifacts.yaml` (unknown approver, wrong key, tampered payload, expired artifact), `binding-mismatch.yaml`, `replay-consumed.yaml`, `reorder-same-set.yaml`, `expiry-precedence.yaml`, `signed-denial-terminal.yaml`, `defer-once.yaml`, `ephemeral-restart.yaml`, `store-unavailable.yaml`, `document-rejections.yaml` (families 1-12 from spec Section 11)
- Test: `crates/hushspec-testkit/tests/sequence_approval.rs`

**Interfaces:**
- Consumes: Task 1 format, Task 4 `ApprovalModule`, hush `signing.rs` ed25519 primitives (`SigningKey`, `VerifyingKey`, `generate_keypair`).
- Produces: `approval_state::ApprovalSession` implementing the spec Section 3 state machine; fixtures carry deterministic test keypairs as hex seeds under a fixture-level `approver_keys: {id: seed_hex}` map (extend the Task 1 schema with this optional field in the same commit; regenerate nothing, the schema is hand-maintained). Artifact binding hash: `SHA256(canonical_json({request_id, action_type, target, policy_digest, generation}))`; eligible-set digest: `SHA256("chio.approver-set.v1\0" || canonical_json(sorted [id, verifying_key_hex] pairs))` (the Chio reference profile from the spec).

- [ ] **Step 1: Write the failing discovery test** (same shape as Task 5, directory `fixtures/sequence/approval`, `ran >= 12`).

- [ ] **Step 2: Run to verify FAIL.** `cargo test -p hushspec-testkit --test sequence_approval`

- [ ] **Step 3: Implement.** Session per binding hash; `present_artifact` steps sign inside the runner using the fixture's seed for `approver` (a `tamper: payload|signature|expired` field corrupts the artifact deliberately); distinct-approver counting; single-use consumption registry; expiry precedence at verification time (injected clock); `defer-once` re-request bumps `generation` so pre-defer artifacts fail binding verification; signed denial terminal including same-step-as-nth-approval; restart per class; store-unavailable denies; `document-rejections.yaml` exercises the Task 4 validation errors through the runner's policy-load step (`expect: {decision: deny, reason_contains: ...}` at load is expressed as a fixture-level `expect_load_error: <substring>` field, added to the Task 1 schema alongside `approver_keys`).

- [ ] **Step 4: Run to verify PASS** plus clippy.

- [ ] **Step 5: Commit** - `git commit -m "feat(testkit): approval sequence evaluator and conformance vector families 1-12"`.

---

### Task 7: Corpus manifest, registry lint, docs index (hush)

**Files:**
- Create: `scripts/check_sequence_corpus.py` (recompute SHA-256 over every file under `fixtures/sequence/` in sorted path order, compare to `fixtures/sequence/MANIFEST.sha256`, nonzero exit on mismatch; `--write` regenerates)
- Create: `fixtures/sequence/MANIFEST.sha256`
- Create: `scripts/check_vendor_registry.py` (parse `spec/vendor-registry.md` Section 5 table; verify every `extensions.vendor.<name>` key used in any fixture under `fixtures/` appears in the registry; verify `crates/hushspec/src/draft02.rs` `REGISTERED_VENDORS` matches the table exactly)
- Modify: `spec/hushspec-core.md` Section 9 cross-reference list and the repo `README.md` spec links (add velocity, approval, vendor-registry rows marked Incubating/Draft)
- Modify: `.github/workflows/ci.yml` (add both scripts as a lint step; follow the existing job layout)

**Interfaces:**
- Consumes: Tasks 1-6 outputs.
- Produces: the pinned corpus hash arc's Task 12 vendoring check consumes.

- [ ] **Step 1: Write the scripts and manifest** (scripts are their own tests here: run them).
- [ ] **Step 2: Run** `python3 scripts/check_sequence_corpus.py` - expected `OK <hash>`; corrupt one fixture byte locally, rerun, expected nonzero exit and a diff line; restore.
- [ ] **Step 3: Run** `python3 scripts/check_vendor_registry.py` - expected `OK (1 vendor: chio)`.
- [ ] **Step 4: Docs edits and CI wiring; run** `python3 scripts/check_cross_sdk_roundtrip.py` (existing) to confirm nothing regressed.
- [ ] **Step 5: Commit** - `git commit -m "chore: sequence corpus manifest, vendor registry lint, spec index updates"`.

---

### Task 8: arc canonical `vendor.chio` location with migration aliases

**Files:**
- Modify: `crates/guards/chio-policy/src/models/extensions.rs` (add `vendor: Option<VendorExtensions>` to `Extensions`; `VendorExtensions { chio: Option<ChioVendorBlock> }` with `deny_unknown_fields`; `ChioVendorBlock` = `reputation: Option<ReputationExtension>`, `runtime_assurance: Option<RuntimeAssuranceExtension>`, `market_hours/signing/k8s_namespaces/rollback` (moved types), `security: Option<ChioSecurityBlock>` where `ChioSecurityBlock { crypto_floor: Option<CryptoFloor> }`, `human_in_loop: Option<ChioVendorHumanInLoop>` with `approve_when` only)
- Modify: `crates/guards/chio-policy/src/validate.rs` (ambiguity rule; alias deprecation warnings; `security` present under `enforcement: optional` is an error per `CHIO_VENDOR_EXTENSIONS.md` 3.9)
- Modify: `crates/platform/chio-control-plane/src/policy/issuance.rs` (`materialize_reputation_issuance_policy` and `materialize_runtime_assurance_policy` read canonical location first, then legacy)
- Test: `crates/guards/chio-policy/tests/vendor_chio.rs`

**Interfaces:**
- Consumes: existing `ReputationExtension`, `RuntimeAssuranceExtension`, `CryptoFloor` types (unchanged shapes).
- Produces: `Extensions::vendor_chio(&self) -> Option<&ChioVendorBlock>` resolution helper that all downstream readers (compiler, issuance, Task 10) use; it returns the canonical block, falls back to a legacy-synthesized view, and the validator has already rejected both-present.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/guards/chio-policy/tests/vendor_chio.rs
// - canonical location parses: extensions.vendor.chio.reputation with one tier round-trips
// - legacy extensions.reputation still parses and resolves through vendor_chio() with a warning
// - both canonical and legacy reputation present: validation error containing "ambiguous"
// - extensions.vendor.chio.security.crypto_floor: pq_required parses to CryptoFloor::PqRequired
// - extends merge of security.crypto_floor is strictest-wins under every merge_strategy:
//   parent pq_required + child allow_classical resolves pq_required (CHIO_VENDOR_EXTENSIONS.md section 4)
// - unknown key under extensions.vendor.chio rejects (serde deny_unknown_fields)
// - unknown vendor name under extensions.vendor rejects
```

Each as a full `#[test]` with inline YAML and assertions on `validate(&spec)` results and `spec.extensions.unwrap().vendor_chio()`.

- [ ] **Step 2: Run to verify FAIL** - `cargo test -p chio-policy --test vendor_chio`.
- [ ] **Step 3: Implement** the structs, the resolution helper, the ambiguity validation, and the issuance fallback order.
- [ ] **Step 4: Run to verify PASS**, then the crate suite: `cargo test -p chio-policy` and `cargo test -p chio-control-plane policy` - all green (legacy fixtures must keep passing).
- [ ] **Step 5: Commit** - `git commit -m "feat(chio-policy): canonical extensions.vendor.chio home with legacy aliases and ambiguity rejection"`.

---

### Task 9: arc `requires` negotiation

**Files:**
- Modify: `crates/guards/chio-policy/src/models.rs` (add `requires: Option<Vec<RequiresEntry>>` to `HushSpec`; `RequiresEntry`/`EnforcementLevel` mirroring the hush draft02 shapes verbatim)
- Create: `crates/guards/chio-policy/src/requires.rs` (`pub fn negotiate(spec: &HushSpec) -> Result<ModuleSupport, ValidationError>`)
- Modify: `crates/guards/chio-policy/src/compiler.rs` (`ensure_compilable_policy` calls `negotiate`)
- Test: `crates/guards/chio-policy/tests/requires_negotiation.rs`

**Interfaces:**
- Consumes: Task 8's `vendor_chio()` helper.
- Produces: `ModuleSupport { enforced: Vec<String>, inert: Vec<String> }` (inert list flows into `CompiledPolicy.guard_names` metadata and receipts). arc's support table, hardcoded in `requires.rs`: `vendor.chio "0.1"` = enforced; `hushspec.velocity "0.1"` = enforced; `hushspec.approval "0.1"` = **recognized, not enforced** (the threshold verifier is the protocol-primitives workstream). Semantics per the module contract: required+unsupported = `CompileError::Invalid`; optional+unsupported = inert and recorded; body-block-without-requires = validation error; unknown module in requires = validation error.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/guards/chio-policy/tests/requires_negotiation.rs
// - doc with rules.velocity + requires{hushspec.velocity, required} compiles; ModuleSupport.enforced contains it
// - doc with rules.human_in_loop.approvers + requires{hushspec.approval, required} REJECTS at compile
//   with an error naming "hushspec.approval" (the inert-ChioApproverSet fix: never load n-of-m silently)
// - same doc with enforcement: optional compiles; approvers block is inert; ModuleSupport.inert lists it;
//   single-gate require_confirmation in the same block STILL compiles to RequireApprovalAbove
// - doc with extensions.vendor.chio but no requires entry rejects
// - requires naming vendor.chio version "9.9" rejects (unsupported version)
// - legacy doc with no requires and no module blocks compiles exactly as today (back-compat)
```

- [ ] **Step 2: Run to verify FAIL** - `cargo test -p chio-policy --test requires_negotiation`.
- [ ] **Step 3: Implement** `requires.rs` and the compiler hook.
- [ ] **Step 4: Run to verify PASS** plus `cargo test -p chio-policy` full suite.
- [ ] **Step 5: Commit** - `git commit -m "feat(chio-policy): requires-based module negotiation; approval module rejects when required"`.

---

### Task 10: arc velocity module form (parse and compile)

**Files:**
- Modify: `crates/guards/chio-policy/src/models/rules.rs` (add `limits: Option<Vec<VelocityLimit>>` plus `VelocityLimit`/`LimitSubject`/`Money` types mirroring hush draft02 exactly; flat fields stay for legacy)
- Modify: `crates/guards/chio-policy/src/validate.rs` (module-form constraints identical to hush Task 3's eight rules; flat-and-limits both present = ambiguity error; module form without `requires{hushspec.velocity}` = error, via Task 9)
- Modify: `crates/guards/chio-policy/src/compiler/rules.rs` (compile `limits` to the existing guards: `grant`/`capability` subjects to `VelocityGuard` config, `agent`/`session` to `AgentVelocityGuard`, `origin_profile` folds through the existing tightest-budget path in `compiler/budgets.rs`)
- Test: `crates/guards/chio-policy/tests/velocity_module_form.rs`

**Interfaces:**
- Consumes: Task 9 negotiation.
- Produces: `VelocityConfig` gains `spend_currency: Option<String>` (consumed by Task 11); compile mapping documented in the test names.

- [ ] **Step 1: Write the failing tests** - module-form doc compiles to the same guard set as the equivalent flat doc (assert via `CompiledPolicy.guard_names`); each of the eight validation constraints rejects; ambiguity (flat+limits) rejects; spend limit threads currency into `VelocityConfig.spend_currency`.
- [ ] **Step 2: Run to verify FAIL.** `cargo test -p chio-policy --test velocity_module_form`
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run to verify PASS** plus full crate suite (the stale "twelve guard types" test name in `tests/compile_policy.rs:2` gets corrected to the real count in this commit, closing that drift item for this file).
- [ ] **Step 5: Commit** - `git commit -m "feat(chio-policy): velocity module form with subject-scoped limits and currency"`.

---

### Task 11: arc velocity guard state contract (currency, idempotency, clock seam)

**Files:**
- Modify: `crates/guards/chio-guards/src/velocity.rs`:
  - `VelocityConfig` gains `spend_currency: Option<String>`; `planned_spend_units(ctx)` extends to `planned_spend(ctx) -> Result<(u64, Option<String>), KernelError>` returning the grant's cost currency; mismatch with `spend_currency` = fail-closed deny (`GuardDecision` deny with reason naming both currencies), absent grant currency under a currency-bearing limit = deny.
  - request-id idempotency: `admitted: HashMap<(String, usize), BoundedRequestIdSet>` inside the same mutex; re-admission of a seen `(key, request_id)` returns the original Allow without consuming tokens; horizon = one window (entries carry admit timestamp, pruned on access).
  - clock seam: `trait TimeSource { fn now(&self) -> std::time::Instant; }` with a default `MonotonicTime` and a `#[doc(hidden)] pub fn with_time_source(...)` constructor for the Task 12 harness (production paths unchanged).
- Test: extend `crates/guards/chio-guards/src/velocity.rs` `#[cfg(test)]` module (existing pattern) with: currency mismatch denies; same-currency admits and decrements; duplicate request id does not double-count; injected time source refills deterministically.

**Interfaces:**
- Consumes: Task 10's `spend_currency`.
- Produces: `with_time_source` and deterministic refill for Task 12; deny-reason strings stable (`"velocity: currency mismatch"`, `"velocity: missing cost currency"`) because Task 12 fixtures match on them.

- [ ] **Step 1: Write the four failing tests** in the existing in-file test module style.
- [ ] **Step 2: Run to verify FAIL.** `cargo test -p chio-guards velocity`
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run to verify PASS**, then `cargo test -p chio-guards` and `cargo clippy -p chio-guards -- -D warnings`.
- [ ] **Step 5: Commit** - `git commit -m "feat(chio-guards): velocity currency check, request-id idempotency, injectable time source"`.

---

### Task 12: arc runs the hush velocity sequence vectors end to end

**Files:**
- Create: `crates/guards/chio-policy/tests/vectors/` (vendored copy of hush `fixtures/sequence/velocity/` plus `MANIFEST.sha256`)
- Create: `scripts/sync-hush-vectors.sh` (copies from a hush checkout path argument, verifies against the manifest, refuses on hash mismatch)
- Create: `crates/guards/chio-policy/tests/sequence_vectors.rs` (harness: parse fixture, compile policy through `compile_policy`, drive the compiled `VelocityGuard`/`AgentVelocityGuard` with a scripted `GuardContext` per action step and the Task 11 time source per `advance_secs` step, assert expected decisions)
- Modify: `.github/workflows` arc CI (add the vector test to the existing test job; add a manifest-verify step)

**Interfaces:**
- Consumes: Task 5 fixtures and manifest, Task 10 compile path, Task 11 time source and stable deny reasons.
- Produces: the end-to-end conformance signal (design section 7); an `EXPLAINED_DELTAS.md` next to the vectors listing every intentional divergence (initially: the `remaining` expectations are asserted only where the guard exposes counts; steps asserting internal remaining state that the compiled plane does not expose are checked as decision-only, listed one per line).

- [ ] **Step 1: Write the failing harness test** (discovery loop over the vendored fixtures, same shape as Task 5's, `ran >= 11`).
- [ ] **Step 2: Run to verify FAIL.** `cargo test -p chio-policy --test sequence_vectors`
- [ ] **Step 3: Implement the harness and vendor the vectors** (`./scripts/sync-hush-vectors.sh ../hush`).
- [ ] **Step 4: Run to verify PASS**; every skipped assertion appears in `EXPLAINED_DELTAS.md`; zero unexplained differential decisions (exit-gate wording from the design, section 12).
- [ ] **Step 5: Commit** - `git commit -m "test(chio-policy): run hush velocity sequence vectors against the compiled guard plane"`.

---

### Task 13: `chio policy migrate` slice for the vendor home and module forms

**Files:**
- Modify: `crates/products/chio-cli/src/cli/types.rs` and the policy subcommand module (locate with `rg "policy" crates/products/chio-cli/src/cli --files-with-matches`; add `chio policy migrate <in> [--out <path>]`)
- Create: `crates/guards/chio-policy/src/migrate.rs` (`pub fn migrate(yaml: &str) -> Result<MigrationOutput, MigrateError>`; `MigrationOutput { yaml: String, notes: Vec<String> }`)
- Test: `crates/guards/chio-policy/tests/migrate.rs` and one CLI integration test alongside the existing `chio-cli` test layout

**Interfaces:**
- Consumes: Tasks 8-10 canonical shapes.
- Produces: rewrites, exactly per `CHIO_VENDOR_EXTENSIONS.md` Section 5 and the two companion compatibility appendices: legacy extension keys to `extensions.vendor.chio.*`; `extensions.chio.human_in_loop.approvers` to `rules.human_in_loop.approvers`; flat velocity fields to `limits[]`; `approve_above` integer plus `approve_above_currency` to `approve_above: {amount, currency}`; synthesized `requires` entries for every module the output uses. Errors (never silent): flat `max_spend_per_window` with no operator-supplied `--spend-currency` flag; unknown legacy field.

- [ ] **Step 1: Write the failing tests** - full-document golden pairs (input YAML, expected output YAML) for: vendor keys move; approvers move plus requires synthesis; velocity flat-to-limits with `--spend-currency USD`; spend without the flag errors; both-locations input errors.
- [ ] **Step 2: Run to verify FAIL.** `cargo test -p chio-policy --test migrate`
- [ ] **Step 3: Implement `migrate.rs` and the CLI wiring.**
- [ ] **Step 4: Run to verify PASS**; run the migrator over every YAML under `examples/policies/` and assert each output re-validates (`validate` plus `negotiate`) - add this as a test loop in the same file.
- [ ] **Step 5: Commit** - `git commit -m "feat(chio-cli): chio policy migrate for vendor home, approvers move, and velocity module form"`.

---

### Task 14: Profile document, design pointers, changelog

**Files:**
- Create: `spec/HUSHSPEC_PROFILE.md` (arc's conformance declaration: supported spec versions; module support table exactly matching Task 9's `requires.rs` - `vendor.chio 0.1` enforced, `hushspec.velocity 0.1` enforced with persistence class `ephemeral` and consistency class `strict (single-process)` plus the state-capacity saturation note, `hushspec.approval 0.1` recognized-not-enforced pending protocol-primitives; velocity clock = monotonic; every explained delta from Task 12 linked)
- Modify: `docs/superpowers/specs/2026-07-15-policy-expansion-design.md` section 5.3 (replace the prose promise with pointers to the four shipped spec files and this plan)
- Modify: `CHANGELOG.md` (entries for the vendor home, requires negotiation, velocity module form, migrate subcommand, profile doc)
- Test: none (docs); verification is the repo gate

**Interfaces:**
- Consumes: everything above.
- Produces: the single "what is real" declaration the design's claim-discipline gate requires.

- [ ] **Step 1: Write the three documents.**
- [ ] **Step 2: Run the full arc gate:** `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check` - all green (cold cache: several minutes).
- [ ] **Step 3: Run the hush gate in the hush repo:** `cargo build --workspace && cargo test --workspace && cargo test -p hushspec --features unstable-v0-2 && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check && python3 scripts/check_sequence_corpus.py && python3 scripts/check_vendor_registry.py`.
- [ ] **Step 4: Commit** - `git commit -m "docs(policy): HUSHSPEC_PROFILE, design pointers, changelog for companions and vendor home"`.

---

## Exit gates (from design v2 section 12, scoped to this plan)

- hush: draft02 suite green under `unstable-v0-2` AND the default-feature suite green unchanged; corpus manifest pinned; registry lint green.
- arc: sequence-vector harness green with zero unexplained differential decisions; `EXPLAINED_DELTAS.md` reviewed; migrator round-trips `examples/policies/` losslessly; full workspace gate green.
- Claim discipline: `HUSHSPEC_PROFILE.md` lists approval as recognized-not-enforced until the protocol-primitives threshold verifier lands; nothing else claims n-of-m enforcement.

## Explicitly out of scope (tracked elsewhere)

- Threshold approval enforcement in arc (protocol-primitives plan owns `ThresholdApprovalRequirement`, `AdmissionOperation`, wire and storage).
- hush core 0.2 release mechanics: full version-gated schema dispatch (design 5.1), evaluator unknown-action deny fix and browser/code routing (design 5.4), receipt/signing adoption (design 6). Each is its own plan.
- Approval sequence vectors running against arc (blocked on protocol-primitives; the vectors exist from Task 6 and wait).
- Durable-class velocity state store (arc declares `ephemeral`; durable is a promotion-criteria workstream).
- Kernel crypto-floor wiring (`set_capability_crypto_floor` from the loader, operator-vs-policy strictest-wins at construction): design section 8. This plan parses and merges the vendor `security.crypto_floor` field; the loader translation is the design's arc-corrections workstream.
