---
phase: 14
slug: portable-verifier-distribution-and-replay-safety
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-24
---

# Phase 14 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (Rust integration + unit tests) |
| **Config file** | `Cargo.toml` / crate-local `Cargo.toml` files |
| **Quick run command** | `cargo test -p arc-cli --test passport -- --nocapture` |
| **Full suite command** | `cargo test --workspace` |
| **Targeted feedback loop** | 10-30 seconds after build warmup |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 14-01 | VER-01 | `cargo test -p arc-cli --test passport -- --nocapture` |
| 14-02 | VER-02 | `cargo test -p arc-cli --test passport -- --nocapture` |
| 14-03 | VER-03 | `cargo test -p arc-cli --test federated_issue -- --nocapture` |
| 14-04 | VER-01, VER-02, VER-03 | `cargo test -p arc-cli --test provider_admin -- --nocapture` and doc assertions |

## Wave 0 Requirements

- [x] Signed verifier policy artifact type and signature validation
- [x] Durable verifier policy registry with load/save/upsert/delete helpers
- [x] Durable replay-safe challenge state with explicit `issued`, `consumed`,
  and `expired` transitions
- [x] Local CLI support for `policyRef`, replay-safe challenge verification,
  and verifier policy admin commands
- [x] Remote trust-control support for verifier policy CRUD and challenge
  create/verify flows
- [x] End-to-end federated issue coverage for stored verifier policy references
  plus replay-safe challenge consumption
- [x] Operator docs updated to explain policy references and replay semantics

## Manual-Only Verifications

| Behavior | Why Manual | Check |
|----------|------------|-------|
| Verifier output is operator-comprehensible | Human judgment on reporting quality | Inspect `policyId`, `policySource`, `policyEvaluated`, and `replayState` in JSON and human-readable outputs |
| Docs explain local vs remote verifier storage clearly | Human judgment on guidance quality | Read the updated passport guide and confirm the difference between `--verifier-policies-file`, `--verifier-challenge-db`, and `--control-url` is explicit |

## Sign-Off

- [x] All plans have automated verification
- [x] No three-plan gap without test coverage
- [x] Phase coverage includes both local and remote verifier surfaces
- [x] `nyquist_compliant: true` is set

**Approval:** completed
