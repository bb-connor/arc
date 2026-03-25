# Testing Patterns

**Analysis Date:** 2026-03-19

## Test Framework

**Runner:**
- Rust built-in test runner via `cargo test`
- CI config in `.github/workflows/ci.yml`

**Assertion Library:**
- Standard Rust `assert!`, `assert_eq!`, `assert_ne!`
- Panic-oriented setup assertions with `expect` are common in tests

**Run Commands:**
```bash
cargo test --workspace                         # Run the full workspace suite
cargo test -p pact-cli --test trust_cluster    # Run targeted HA trust-control integration coverage
cargo test -p pact-conformance                 # Run conformance harness tests
cargo fmt --all -- --check                     # Format gate
cargo clippy --workspace -- -D warnings        # Lint gate
```

## Test File Organization

**Location:**
- Integration tests live in `tests/*.rs` within crates
- Workspace-level e2e coverage lives in `tests/e2e/`
- Formal/differential coverage lives in `formal/diff-tests/`

**Naming:**
- Feature-oriented names such as `trust_cluster.rs`, `mcp_serve_http.rs`, `wave1_live.rs`
- Live conformance waves are grouped by protocol area (`wave1` through `wave5`)

**Structure:**
```text
crates/pact-cli/tests/
  mcp_auth_server.rs
  mcp_serve.rs
  mcp_serve_http.rs
  receipt_db.rs
  trust_cluster.rs
  trust_revocation.rs

crates/pact-conformance/tests/
  wave1_live.rs
  wave2_tasks_live.rs
  wave3_auth_live.rs
  wave4_notifications_live.rs
  wave5_nested_flows_live.rs
```

## Test Structure

**Suite Organization:**
```rust
#[test]
fn trust_control_cluster_replicates_state_and_survives_leader_failover() {
    // setup helpers
    // execute real system behavior
    // assert observable state or outputs
}
```

**Patterns:**
- Helper functions live near the tests for process spawning, temp dirs, HTTP requests, and polling
- Real subprocesses and HTTP clients are used for integration coverage instead of heavy mocking
- `thread::sleep`, polling loops, and timeout helpers appear in cluster/runtime tests where convergence matters

## Mocking

**Framework:**
- Minimal mocking culture; many tests prefer real subprocesses, temporary files, and local HTTP calls

**Patterns:**
- Build or spawn the actual `pact` binary where practical
- Use temporary directories, random local ports, and local SQLite files for isolation
- Skip live conformance tests gracefully when required external runtimes are unavailable

**What to Mock:**
- External runtimes or peers only when the test target is internal logic rather than end-to-end behavior

**What NOT to Mock:**
- Core kernel/session/policy behavior when integration semantics are the point of the test

## Fixtures and Factories

**Test Data:**
- Ad hoc helper constructors are common, such as sample receipts, temp dirs, and reserved listen addresses
- JSON payloads are often built inline with `serde_json::json!`

**Location:**
- Most fixtures are local to the test file rather than maintained in a separate shared fixture tree

## Coverage

**Requirements:**
- No explicit percentage target is documented
- The practical standard is strong coverage at the integration/conformance boundary for supported behavior

**Configuration:**
- CI blocks on `cargo fmt`, `cargo clippy`, `cargo build`, and `cargo test --workspace`
- Live conformance waves add cross-language evidence beyond unit tests

## Test Types

**Unit Tests:**
- Focused crate/module checks inside the source crates
- Use direct assertions and lightweight helpers

**Integration Tests:**
- Heavy use in `pact-cli/tests/` and related crates
- Exercise subprocesses, HTTP endpoints, SQLite state, and protocol flows

**E2E Tests:**
- `tests/e2e/tests/full_flow.rs` covers end-to-end user/system flows

**Conformance Tests:**
- `pact-conformance/tests/` runs live wave suites against JS and Python peers when runtimes are available

## Common Patterns

**Async and concurrency testing:**
```rust
fn wait_until<F>(label: &str, timeout: Duration, mut condition: F)
where
    F: FnMut() -> bool,
{
    // poll until the observed system state converges or time out
}
```

**Error testing:**
```rust
let status = Command::new("cargo").arg("build").status().expect("build pact-cli");
assert!(status.success(), "cargo build -p pact-cli must succeed");
```

**Snapshot Testing:**
- Not a major pattern in this repo
- Behavioral assertions dominate over snapshot assertions

---
*Testing analysis: 2026-03-19*
*Update when test patterns change*
