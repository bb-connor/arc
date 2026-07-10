# WS1 First Light Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the WS1 Phase 1 seams and fail-closed corrections (the `economy` config block, the three control-plane `configure_*` seams and their CLI-runtime chaining, the F72 BudgetTree currency-mismatch deny, and the F68 settlement-outcome routing consumer with a `settle_attempts` table and a `CHIO_SETTLEMENT_UNRESOLVED_TOTAL` metric) with byte-identical behavior whenever the `economy` block is absent.

**Architecture:** A new defaulted `EconomyConfig` under `ChioConfig.economy` (`chio-config`) carries `settlement`/`payment`/`oracle`/`credit` sections; three `configure_*` seams in `chio-control-plane` validate those sections fail-closed and install nothing in Phase 1 (the production drivers land in later phases), chained into the CLI runtime after `configure_budget_store`. `BudgetTree::evaluate` gains a `Deny(CurrencyMismatch)` in place of the silent skip (F72). The kernel replaces the discarded settlement-observer status at `receipt_persistence.rs:185` with `route_settlement_observer_status`, which warns, increments a process-global `CHIO_SETTLEMENT_UNRESOLVED_TOTAL` counter, and persists a `settle_attempts` or `settle_dead_letters` row through a new kernel-defined `SettlementAttemptStore` trait implemented in `chio-store-sqlite` (F68).

**Tech Stack:** Rust workspace crates `chio-config` (serde schema), `chio-control-plane` (CLI wiring), `chio-cli` (runtime chaining), `chio-metering` (BudgetTree), `chio-kernel` (routing consumer, store trait, metric), `chio-store-sqlite` (`settle_attempts` table via `rusqlite`/`r2d2`), `chio-settle` (`classify_attempt`, `RetryPolicy`, `DeadLetterRecord`), `chio-metrics-spec` (metric descriptor); `serde`/`serde_yml`, `tracing`, `thiserror`.

## Global Constraints

- Workspace gate before declaring done: `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check` (a cold `cargo build --workspace` takes several minutes; capture a `main` baseline of `cargo test --workspace` first, since the workspace carries a small set of pre-existing environmental test failures such as the wasm toolchain, and compare against it rather than assuming green).
- No `.unwrap()` / `.expect()` in any new non-test code (workspace clippy sets `unwrap_used = "deny"` and `expect_used = "deny"`). In tests, copy the local idiom of the module you are editing: `chio-config`'s `schema.rs` test module uses `serde_yml::from_str(yaml).unwrap_or_else(|e| panic!("deser failed: {e}"))` and binds error cases to a `Result` then asserts `is_err()`; `chio-control-plane`'s test module opens with `#[allow(clippy::unwrap_used, clippy::expect_used)]` so `.unwrap()`/`.unwrap_err()` are permitted there; `chio-metering`'s `budget_hierarchy.rs` test module uses `.expect(...)`/`.unwrap_err()`; `chio-store-sqlite` tests use `chio_test_support::prelude::*` and `.test_expect(...)`/`.test_expect_err(...)`; `chio-kernel` internal tests return `Result<(), Box<dyn std::error::Error>>` and use `?` / `ok_or_else` / `let ... else` / `unwrap_or_else(|e| panic!(...))`.
- No em dashes (U+2014) anywhere; hyphens or parentheses only. No process-narration comments (state invariants and contracts, never dev history).
- Conventional commits; the six commit messages are fixed verbatim (see Tasks 1, 2, 3, 4, 5, 6).
- Fail-closed everywhere: an absent/invalid config section rejects at load or installs nothing; a currency the cap cannot be compared against denies; an unresolved settlement outcome is loud (warn plus metric) and, when a store is installed, durable (attempt or dead-letter row); it is never silently dropped.
- All monetary values are `chio_core::capability::scope::MonetaryAmount` (u64 minor units, ISO-4217); no floats in money math.
- Default-closed invariant (the hard Phase 1 gate): with no `economy` block, the config parses to all-`None` sections, the `configure_*` seams install nothing, and every kernel receipt is byte-identical to the pre-economy baseline. The existing observer byte-identity oracle (`crates/kernel/chio-kernel/tests/settlement_observer_byte_identity.rs`, using `chio_core::canonical::canonical_json_bytes`) is the byte oracle; Task 6 reuses it to prove the F68 change preserves it.
- All work happens on branch `chio/ws1-first-light` off `main`, one PR.
- All line anchors below were re-verified against the working tree on 2026-07-10.

---

### Task 1: `EconomyConfig` block in `chio-config` (serde defaults) + parse tests

**Files:**
- Modify: `crates/platform/chio-config/src/schema.rs` (add the `economy` field to `ChioConfig` after `wasm_guards` at line 41; add the new section structs after `default_wasm_priority` at line 257; add tests to the existing `mod tests` at line 281)

**Interfaces:**
- Consumes (verified): `ChioConfig` (`schema.rs:11`, `#[derive(Debug, Clone, Deserialize)]` + `#[serde(deny_unknown_fields)]`, fields `kernel`, `adapters`, `edges`, `receipts`, `logging`, `telemetry`, `guards`, `wasm_guards` each `#[serde(default)]` except `kernel`); the crate imports only `use serde::Deserialize;`.
- Produces: `ChioConfig.economy: EconomyConfig` (`#[serde(default)]`); `EconomyConfig { settlement: Option<SettlementConfig>, payment: Option<PaymentConfig>, oracle: Option<OracleConfig>, credit: Option<CreditConfig> }`; `SettlementConfig { driver: SettlementDriver, store: Option<String>, control_url: Option<String>, control_token: Option<String> }`; `enum SettlementDriver { None, Ops }` (default `None`); `PaymentConfig { rail: String, endpoint: String, timeout_ms: u64, auth: Option<String> }`; `OracleConfig { endpoint: String, auth: Option<String> }`; `CreditConfig { store: Option<String>, issuer: Option<String> }`. Tasks 2 and 3 consume these types.

- [ ] Create the working branch and capture the test baseline:
  ```bash
  set -o pipefail
  cd "$(git rev-parse --show-toplevel)"
  git checkout main && git pull
  git checkout -b chio/ws1-first-light
  cargo test -p chio-config 2>&1 | tail -5
  ```
  Expected: the `chio-config` suite is green on `main` (record the totals; any failure here is pre-existing and must be reported before continuing).

- [ ] Write the failing tests. Append these to the `mod tests` block in `crates/platform/chio-config/src/schema.rs` (after the existing `deserialize_adapter_with_auth` test, before the closing `}` at line 343). They will not compile until `EconomyConfig` exists:
  ```rust
  #[test]
  fn economy_block_absent_installs_no_sections() {
      let yaml = r#"
          kernel:
            signing_key: "generate"
      "#;
      let config: ChioConfig =
          serde_yml::from_str(yaml).unwrap_or_else(|e| panic!("deser failed: {e}"));
      assert!(config.economy.settlement.is_none());
      assert!(config.economy.payment.is_none());
      assert!(config.economy.oracle.is_none());
      assert!(config.economy.credit.is_none());
  }

  #[test]
  fn economy_block_parses_all_sections() {
      let yaml = r#"
          kernel:
            signing_key: "generate"
          economy:
            settlement:
              driver: ops
              store: "/var/chio/settle.db"
            payment:
              rail: "x402"
              endpoint: "https://rail.example/x402"
            oracle:
              endpoint: "https://oracle.example"
            credit:
              store: "/var/chio/iou.db"
      "#;
      let config: ChioConfig =
          serde_yml::from_str(yaml).unwrap_or_else(|e| panic!("deser failed: {e}"));
      let settlement = config
          .economy
          .settlement
          .unwrap_or_else(|| panic!("settlement section present"));
      assert_eq!(settlement.driver, SettlementDriver::Ops);
      assert_eq!(settlement.store.as_deref(), Some("/var/chio/settle.db"));
      assert!(settlement.control_url.is_none());
      let payment = config
          .economy
          .payment
          .unwrap_or_else(|| panic!("payment section present"));
      assert_eq!(payment.rail, "x402");
      assert_eq!(payment.endpoint, "https://rail.example/x402");
      assert_eq!(payment.timeout_ms, 30_000);
  }

  #[test]
  fn economy_settlement_driver_defaults_to_none() {
      let yaml = r#"
          kernel:
            signing_key: "generate"
          economy:
            settlement:
              store: "/var/chio/settle.db"
      "#;
      let config: ChioConfig =
          serde_yml::from_str(yaml).unwrap_or_else(|e| panic!("deser failed: {e}"));
      let settlement = config
          .economy
          .settlement
          .unwrap_or_else(|| panic!("settlement section present"));
      assert_eq!(settlement.driver, SettlementDriver::None);
  }

  #[test]
  fn economy_rejects_unknown_field() {
      let yaml = r#"
          kernel:
            signing_key: "generate"
          economy:
            not_a_section: true
      "#;
      let result: Result<ChioConfig, _> = serde_yml::from_str(yaml);
      assert!(result.is_err());
  }
  ```

- [ ] Run the tests to verify they fail:
  ```bash
  set -o pipefail
  cargo test -p chio-config economy_ 2>&1 | tail -20
  ```
  Expected failure: compile error `error[E0609]: no field 'economy' on type 'ChioConfig'` (and `error[E0433]` for the unresolved `SettlementDriver`); the whole `chio-config` test target fails to compile, which is the expected red state.

- [ ] Write the implementation. First, add the `economy` field to `ChioConfig` immediately after the `wasm_guards` field (after line 41, before the struct's closing `}` at line 42):
  ```rust
      /// Economic subsystem configuration (settlement, payment, oracle,
      /// credit). Every section is optional; an omitted `economy` block
      /// installs no settlement observer, payment adapter, price oracle, or
      /// credit driver and reproduces the pre-economy behavior byte-for-byte.
      #[serde(default)]
      pub economy: EconomyConfig,
  ```
  Then add the section types immediately after `default_wasm_priority` (after line 257, before the `// -- Default value functions --` comment at line 259):
  ```rust
  /// Economic subsystem configuration. Each section is optional; an absent
  /// section installs nothing through the control-plane `configure_*` seams.
  #[derive(Debug, Clone, Default, Deserialize)]
  #[serde(deny_unknown_fields)]
  pub struct EconomyConfig {
      /// Settlement observer and driver wiring.
      #[serde(default)]
      pub settlement: Option<SettlementConfig>,

      /// Payment rail adapter wiring.
      #[serde(default)]
      pub payment: Option<PaymentConfig>,

      /// Cross-currency price oracle wiring.
      #[serde(default)]
      pub oracle: Option<OracleConfig>,

      /// Credit IOU driver wiring.
      #[serde(default)]
      pub credit: Option<CreditConfig>,
  }

  /// Settlement section. `store` (local) and `control_url` (remote) are
  /// mutually exclusive reconciliation destinations; `control_url` requires
  /// `control_token`.
  #[derive(Debug, Clone, Deserialize)]
  #[serde(deny_unknown_fields)]
  pub struct SettlementConfig {
      /// Settlement driver. `none` installs no runtime (default-closed).
      #[serde(default)]
      pub driver: SettlementDriver,

      /// Local reconciliation store path. Mutually exclusive with `control_url`.
      #[serde(default)]
      pub store: Option<String>,

      /// Remote trust-control reconcile URL. Mutually exclusive with `store`.
      #[serde(default)]
      pub control_url: Option<String>,

      /// Bearer token required when `control_url` is set.
      #[serde(default)]
      pub control_token: Option<String>,
  }

  /// Settlement driver selector.
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
  #[serde(rename_all = "snake_case")]
  pub enum SettlementDriver {
      /// No settlement runtime (default-closed).
      #[default]
      None,
      /// Reconciling ops runtime, installed in a later phase.
      Ops,
  }

  /// Payment rail section.
  #[derive(Debug, Clone, Deserialize)]
  #[serde(deny_unknown_fields)]
  pub struct PaymentConfig {
      /// Rail identifier (e.g. "x402", "acp").
      pub rail: String,

      /// Rail endpoint base URL.
      pub endpoint: String,

      /// Per-call rail timeout in milliseconds.
      #[serde(default = "default_payment_timeout_ms")]
      pub timeout_ms: u64,

      /// Optional rail auth token.
      #[serde(default)]
      pub auth: Option<String>,
  }

  /// Price oracle section (a minimal shape for Phase 1; the production
  /// `ChioLinkOracle` is installed from this section in a later phase).
  #[derive(Debug, Clone, Deserialize)]
  #[serde(deny_unknown_fields)]
  pub struct OracleConfig {
      /// Oracle endpoint base URL.
      pub endpoint: String,

      /// Optional oracle auth token.
      #[serde(default)]
      pub auth: Option<String>,
  }

  /// Credit IOU driver section.
  #[derive(Debug, Clone, Deserialize)]
  #[serde(deny_unknown_fields)]
  pub struct CreditConfig {
      /// Local IOU store path.
      #[serde(default)]
      pub store: Option<String>,

      /// Credit issuer identity (hex public key); defaults to the kernel key.
      #[serde(default)]
      pub issuer: Option<String>,
  }

  fn default_payment_timeout_ms() -> u64 {
      30_000
  }
  ```

- [ ] Run the tests to verify they pass:
  ```bash
  set -o pipefail
  cargo test -p chio-config economy_ 2>&1 | tail -8
  cargo test -p chio-config 2>&1 | tail -5
  ```
  Expected: the four `economy_*` tests PASS; the whole `chio-config` suite matches the baseline plus the four new tests.

- [ ] Pre-commit check and commit (exact commands):
  ```bash
  set -o pipefail
  cargo clippy -p chio-config -- -D warnings 2>&1 | tail -3
  cargo fmt --all
  cd "$(git rev-parse --show-toplevel)"
  git add crates/platform/chio-config/src/schema.rs
  git commit -m "feat(config): add economy configuration block to ChioConfig"
  ```
  Expected: clippy clean, fmt applies, one commit.

---

### Task 2: Three `configure_*` economy seams in `chio-control-plane` + unit tests

**Files:**
- Modify: `crates/platform/chio-control-plane/Cargo.toml` (add the `chio-config` dependency; the crate already depends on `chio-store-sqlite`, `chio-link`, `chio-settle`, `chio-kernel`)
- Modify: `crates/platform/chio-control-plane/src/lib.rs` (add the three functions after `configure_budget_store`, which ends at line 551, before `require_control_token` at line 553; add tests to the existing `mod tests` at line 635)

**Interfaces:**
- Consumes (verified): `configure_budget_store(kernel: &mut ChioKernel, budget_db_path: Option<&Path>, control_url: Option<&str>, control_token: Option<&str>) -> Result<(), CliError>` (`lib.rs:527`, the `match (path, control_url)` four-arm mutual-exclusion pattern to mirror); `require_control_token(control_token: Option<&str>) -> Result<&str, CliError>` (`lib.rs:553`); `CliError::cli_other_error(impl Into<String>) -> Self` (`lib.rs:191`); `chio_config::{SettlementConfig, PaymentConfig, OracleConfig, SettlementDriver}` (Task 1); the crate's `#![allow(clippy::result_large_err, clippy::too_many_arguments)]` header (`lib.rs:1`).
- Produces: `configure_settlement(settlement: Option<&chio_config::SettlementConfig>) -> Result<(), CliError>`; `configure_payment_rail(payment: Option<&chio_config::PaymentConfig>) -> Result<(), CliError>`; `configure_price_oracle(oracle: Option<&chio_config::OracleConfig>) -> Result<(), CliError>`. Task 3 chains all three.

Design note (a decision the spec leaves open; resolved here): the spec's Phase 3 explicitly owns "the payment adapter and price oracle installed from config" and "the observer-slot `SettlementHook`", while the Phase 1 line calls these functions "seams ... installing nothing when the block is absent". These three functions are therefore Phase-1 **validated seams**: they enforce the fail-closed config validation and install nothing (so both the absent-section and present-section cases keep byte-identical behavior in Phase 1). Because Phase 1 installs nothing, they take no `&mut ChioKernel` (no unused parameter under `-D warnings`); Phase 3 extends the signatures to take the kernel and fill in the `set_*` installs. This is the only reading consistent with (a) Phase 3 owning the adapter/oracle/hook installs, (b) the byte-identical Phase-1 invariant, and (c) the "seams and fail-closed corrections" phase title.

- [ ] Add the `chio-config` dependency. In `crates/platform/chio-control-plane/Cargo.toml`, under `[dependencies]`, add (alphabetically, beside the other `chio-*` workspace deps):
  ```toml
  chio-config = { workspace = true }
  ```

- [ ] Write the failing tests. Append to the `mod tests` block in `crates/platform/chio-control-plane/src/lib.rs` (after the last test, before the closing `}` at line 876; the module already carries `#[allow(clippy::unwrap_used, clippy::expect_used)]` at line 636 so `.unwrap_err()` is permitted):
  ```rust
  #[test]
  fn configure_settlement_absent_is_ok() {
      assert!(configure_settlement(None).is_ok());
  }

  #[test]
  fn configure_settlement_rejects_store_and_control_url_together() {
      let cfg = chio_config::SettlementConfig {
          driver: chio_config::SettlementDriver::None,
          store: Some("/tmp/settle.db".to_string()),
          control_url: Some("https://control.example".to_string()),
          control_token: Some("token".to_string()),
      };
      let error = configure_settlement(Some(&cfg)).unwrap_err();
      assert!(error.to_string().contains("either"));
  }

  #[test]
  fn configure_settlement_requires_token_with_control_url() {
      let cfg = chio_config::SettlementConfig {
          driver: chio_config::SettlementDriver::None,
          store: None,
          control_url: Some("https://control.example".to_string()),
          control_token: None,
      };
      let error = configure_settlement(Some(&cfg)).unwrap_err();
      assert!(error.to_string().contains("control_token"));
  }

  #[test]
  fn configure_settlement_accepts_local_store() {
      let cfg = chio_config::SettlementConfig {
          driver: chio_config::SettlementDriver::Ops,
          store: Some("/tmp/settle.db".to_string()),
          control_url: None,
          control_token: None,
      };
      assert!(configure_settlement(Some(&cfg)).is_ok());
  }

  #[test]
  fn configure_payment_rail_validates_rail_and_endpoint() {
      assert!(configure_payment_rail(None).is_ok());
      let ok = chio_config::PaymentConfig {
          rail: "x402".to_string(),
          endpoint: "https://rail.example".to_string(),
          timeout_ms: 30_000,
          auth: None,
      };
      assert!(configure_payment_rail(Some(&ok)).is_ok());
      let unknown = chio_config::PaymentConfig {
          rail: "wire-transfer".to_string(),
          endpoint: "https://rail.example".to_string(),
          timeout_ms: 30_000,
          auth: None,
      };
      let error = configure_payment_rail(Some(&unknown)).unwrap_err();
      assert!(error.to_string().contains("wire-transfer"));
  }

  #[test]
  fn configure_price_oracle_validates_endpoint() {
      assert!(configure_price_oracle(None).is_ok());
      let ok = chio_config::OracleConfig {
          endpoint: "https://oracle.example".to_string(),
          auth: None,
      };
      assert!(configure_price_oracle(Some(&ok)).is_ok());
      let blank = chio_config::OracleConfig {
          endpoint: "   ".to_string(),
          auth: None,
      };
      let error = configure_price_oracle(Some(&blank)).unwrap_err();
      assert!(error.to_string().contains("endpoint"));
  }
  ```

- [ ] Run the tests to verify they fail:
  ```bash
  set -o pipefail
  cargo test -p chio-control-plane configure_settlement configure_payment_rail configure_price_oracle 2>&1 | tail -15
  ```
  Expected failure: compile error `error[E0425]: cannot find function 'configure_settlement' in this scope` (and the same for `configure_payment_rail` / `configure_price_oracle`); the test target fails to compile, which is the expected red state.

- [ ] Write the implementation. Insert the three functions in `crates/platform/chio-control-plane/src/lib.rs` immediately after the closing `}` of `configure_budget_store` (after line 551) and before `pub fn require_control_token` (line 553):
  ```rust
  /// Phase 1 settlement seam. Validates the settlement section fail-closed
  /// (`store` and `control_url` are mutually exclusive; `control_url`
  /// requires a non-empty `control_token`) and installs nothing: the
  /// production observer hook and settlement runtime install from this
  /// section in a later phase. An absent section is a no-op, preserving
  /// today's no-settlement path.
  pub fn configure_settlement(
      settlement: Option<&chio_config::SettlementConfig>,
  ) -> Result<(), CliError> {
      let Some(settlement) = settlement else {
          return Ok(());
      };
      match (settlement.store.as_deref(), settlement.control_url.as_deref()) {
          (Some(_), Some(_)) => Err(CliError::cli_other_error(
              "economy.settlement: set either `store` or `control_url`, not both".to_string(),
          )),
          (None, Some(_)) => match settlement.control_token.as_deref() {
              Some(token) if !token.trim().is_empty() => Ok(()),
              _ => Err(CliError::cli_other_error(
                  "economy.settlement.control_url requires a non-empty control_token".to_string(),
              )),
          },
          (Some(_), None) | (None, None) => Ok(()),
      }
  }

  /// Phase 1 payment-rail seam. Validates the payment section fail-closed
  /// (known rail id, non-empty endpoint) and installs nothing: the
  /// production `PaymentAdapter` installs from this section in a later
  /// phase. An absent section is a no-op.
  pub fn configure_payment_rail(
      payment: Option<&chio_config::PaymentConfig>,
  ) -> Result<(), CliError> {
      let Some(payment) = payment else {
          return Ok(());
      };
      match payment.rail.as_str() {
          "x402" | "acp" => {}
          other => {
              return Err(CliError::cli_other_error(format!(
                  "unknown economy.payment.rail {other:?} (known: x402, acp)"
              )));
          }
      }
      if payment.endpoint.trim().is_empty() {
          return Err(CliError::cli_other_error(
              "economy.payment.endpoint must be non-empty".to_string(),
          ));
      }
      Ok(())
  }

  /// Phase 1 price-oracle seam. Validates the oracle section fail-closed
  /// (non-empty endpoint) and installs nothing: the production
  /// `ChioLinkOracle` installs from this section in a later phase. An
  /// absent section is a no-op, keeping cross-currency resolution on the
  /// no-oracle path.
  pub fn configure_price_oracle(
      oracle: Option<&chio_config::OracleConfig>,
  ) -> Result<(), CliError> {
      let Some(oracle) = oracle else {
          return Ok(());
      };
      if oracle.endpoint.trim().is_empty() {
          return Err(CliError::cli_other_error(
              "economy.oracle.endpoint must be non-empty".to_string(),
          ));
      }
      Ok(())
  }
  ```

- [ ] Run the tests to verify they pass:
  ```bash
  set -o pipefail
  cargo test -p chio-control-plane configure_settlement configure_payment_rail configure_price_oracle 2>&1 | tail -8
  ```
  Expected: all six new tests PASS.

- [ ] Pre-commit check and commit (exact commands):
  ```bash
  set -o pipefail
  cargo clippy -p chio-control-plane -- -D warnings 2>&1 | tail -3
  cargo fmt --all
  cd "$(git rev-parse --show-toplevel)"
  git add crates/platform/chio-control-plane/Cargo.toml crates/platform/chio-control-plane/src/lib.rs
  git commit -m "feat(control-plane): add economy settlement, payment, and oracle configure seams"
  ```

---

### Task 3: CLI runtime chaining + default-closed "installs nothing" test

**Files:**
- Modify: `crates/products/chio-cli/src/main.rs` (add the three function names to the `pub use chio_control_plane::{...}` re-export at lines 41-48)
- Modify: `crates/products/chio-cli/src/cli/runtime.rs` (chain the three calls after `configure_budget_store` in `cmd_run` at line 46, `cmd_check` at line 346, and `cmd_mcp_serve` at line 622)
- Modify: `crates/platform/chio-control-plane/src/lib.rs` (add one integration test proving a kernel built through the seams installs no settlement observer)

**Interfaces:**
- Consumes (verified): the re-export `pub use chio_control_plane::{... configure_budget_store, ...}` (`main.rs:41-48`) that the `cli/*` submodules inherit via `use super::*;`; the chaining sites where `configure_budget_store(&mut kernel, budget_db_path, control_url, control_token)?;` is called (`runtime.rs:46`, `:346`, `:622`); `ChioKernel::settlement_observer(&self) -> Option<Arc<dyn SettlementHook>>` (`construction.rs:496`); `configure_settlement`/`configure_payment_rail`/`configure_price_oracle` (Task 2).
- Produces: the three seams chained into all three kernel-constructing CLI commands; test `seams_install_no_settlement_observer_when_absent`.

Design note: the CLI `run`/`check`/`mcp serve` commands load a policy, not a `chio.yaml` `ChioConfig` (a repo-wide grep confirms `ChioConfig` is referenced only by the `doctor` probes, never on the run path). Phase 1 therefore chains the seams with an absent economy section (`None`), which installs nothing and keeps the run path byte-identical; wiring a `ChioConfig` loader into the run path lands with the component installs in a later phase. The seams' own coverage is the `chio-control-plane` unit tests from Task 2 plus the integration test below.

- [ ] Write the failing test. Append to the `mod tests` block in `crates/platform/chio-control-plane/src/lib.rs` (the module already provides `make_kernel(require_web3_evidence: bool) -> ChioKernel` at line 643):
  ```rust
  #[test]
  fn seams_install_no_settlement_observer_when_absent() {
      let mut kernel = make_kernel(false);
      configure_settlement(None).unwrap();
      configure_payment_rail(None).unwrap();
      configure_price_oracle(None).unwrap();
      assert!(
          kernel.settlement_observer().is_none(),
          "the default-closed economy seams must install no settlement observer"
      );
      // Touch the kernel so the assertion above is not dead: a kernel that
      // never had an observer installed reports None here and after the
      // no-op seams, proving the seams do not install one.
      let _ = &mut kernel;
  }
  ```

- [ ] Run the test to verify it fails:
  ```bash
  set -o pipefail
  cargo test -p chio-control-plane seams_install_no_settlement_observer_when_absent 2>&1 | tail -10
  ```
  Expected failure: compile error `error[E0425]: cannot find function 'configure_settlement' in this scope` only if Task 2 was skipped; if Task 2 is committed, this test COMPILES and PASSES immediately (it is a regression guard for the default-closed invariant, so a green first run is correct here - the red state for this task is the CLI chaining not compiling until the re-export is added, verified in the next steps).

- [ ] Add the re-export. In `crates/products/chio-cli/src/main.rs`, extend the `pub use chio_control_plane::{...}` list (lines 41-48) to include the three functions in alphabetical order among the existing `configure_*` names:
  ```rust
  pub use chio_control_plane::{
      authority_public_key_from_seed_file, build_kernel, certify, configure_budget_store,
      configure_capability_authority, configure_payment_rail, configure_price_oracle,
      configure_receipt_store, configure_revocation_store, configure_settlement,
      enterprise_federation, evidence_export, federation_policy, issuance,
      issue_default_capabilities, load_or_create_authority_keypair, passport_verifier, policy,
      reputation, require_control_token, rotate_authority_keypair, scim_lifecycle, trust_control,
      CliError,
  };
  ```

- [ ] Chain the seams in `crates/products/chio-cli/src/cli/runtime.rs`. After each `configure_budget_store(&mut kernel, budget_db_path, control_url, control_token)?;` line (at `cmd_run` line 46, `cmd_check` line 346, and `cmd_mcp_serve` line 622), insert the identical three lines:
  ```rust
      configure_price_oracle(None)?;
      configure_payment_rail(None)?;
      configure_settlement(None)?;
  ```
  (Phase 1 passes `None` because the run path has no `ChioConfig` loader; the seams install nothing, so the runtime stays byte-identical. Apply the insertion at all three sites.)

- [ ] Run the tests to verify they pass and the CLI compiles:
  ```bash
  set -o pipefail
  cargo test -p chio-control-plane seams_install_no_settlement_observer_when_absent 2>&1 | tail -5
  cargo build -p chio-cli 2>&1 | tail -5
  ```
  Expected: the integration test PASSES; `chio-cli` builds clean (the three seams are in scope via the re-export and chained at all three sites).

- [ ] Pre-commit check and commit (exact commands):
  ```bash
  set -o pipefail
  cargo clippy -p chio-cli -p chio-control-plane -- -D warnings 2>&1 | tail -3
  cargo fmt --all
  cd "$(git rev-parse --show-toplevel)"
  git add crates/products/chio-cli/src/main.rs \
          crates/products/chio-cli/src/cli/runtime.rs \
          crates/platform/chio-control-plane/src/lib.rs
  git commit -m "feat(cli): chain economy configure seams into the kernel runtime"
  ```

---

### Task 4: F72 BudgetTree currency-mismatch deny (`chio-metering`)

**Files:**
- Modify: `crates/economy/chio-metering/src/budget_hierarchy.rs` (add the `CurrencyMismatch` variant to `BudgetDenyReason` after `UnknownNode` at line 363; replace the spend-cap skip in `BudgetTree::evaluate` at lines 613-637; add tests to the existing `mod tests` at line 767)

**Interfaces:**
- Consumes (verified): `BudgetDenyReason` (`budget_hierarchy.rs:334`, `#[serde(tag = "reason", rename_all = "snake_case")]`, variants `NodeDisabled`/`DimensionExceeded`/`WindowExpired`/`UnknownNode`); `BudgetTree::evaluate(&self, id: &BudgetNodeId, draft: AggregateSpend, current: &SpendSnapshot) -> BudgetDecision` (`:583`); the current spend-cap block at `:613-637` (`if let Some(cap) = limits.max_spend_units { let currency_matches = match (&limits.currency, &draft.currency) { (Some(a), Some(b)) => a == b, _ => false }; if currency_matches && projected.spend_units > cap { ... DimensionExceeded ... } }`); `BudgetLimits { max_spend_units, currency, ... }` (`:120`); `AggregateSpend::with_spend(units, currency)` (`:237`) and `AggregateSpend::default()`; `SpendSnapshot::new()` (`:315`); `BudgetNodeId::new(&str)` (used at `:734`); test helper `leaf(id, parent, limits, window) -> BudgetNode` (`:771`); `BudgetWindow::Daily` (`:791`); `BudgetTree::new()` and `tree.insert(node) -> Result<(), BudgetError>` (`:721`, `:787`). `validate_limits` (`:750`) already rejects a spend cap without a node currency, so a spend-capped node always has a currency.
- Produces: `BudgetDenyReason::CurrencyMismatch { node: BudgetNodeId, node_currency: Option<String>, draft_currency: Option<String> }`; the fail-closed deny in `evaluate`. Later WS1 phases and the money loop rely on this deny.

- [ ] Write the failing tests. Append to the `mod tests` block in `crates/economy/chio-metering/src/budget_hierarchy.rs` (the module uses `.expect(...)`/`.unwrap_err()`):
  ```rust
  #[test]
  fn currency_mismatch_denies_instead_of_skipping() {
      let mut tree = BudgetTree::new();
      tree.insert(leaf(
          "org",
          None,
          BudgetLimits {
              max_spend_units: Some(100),
              currency: Some("USD".to_string()),
              ..BudgetLimits::default()
          },
          BudgetWindow::Daily,
      ))
      .expect("insert usd-capped node");

      let decision = tree.evaluate(
          &BudgetNodeId::new("org"),
          AggregateSpend::with_spend(50, "EUR"),
          &SpendSnapshot::new(),
      );
      match decision {
          BudgetDecision::Deny {
              reason:
                  BudgetDenyReason::CurrencyMismatch {
                      node,
                      node_currency,
                      draft_currency,
                  },
          } => {
              assert_eq!(node, BudgetNodeId::new("org"));
              assert_eq!(node_currency.as_deref(), Some("USD"));
              assert_eq!(draft_currency.as_deref(), Some("EUR"));
          }
          other => panic!("expected CurrencyMismatch deny, got {other:?}"),
      }
  }

  #[test]
  fn absent_draft_currency_denies_against_spend_cap() {
      let mut tree = BudgetTree::new();
      tree.insert(leaf(
          "org",
          None,
          BudgetLimits {
              max_spend_units: Some(100),
              currency: Some("USD".to_string()),
              ..BudgetLimits::default()
          },
          BudgetWindow::Daily,
      ))
      .expect("insert");
      let decision = tree.evaluate(
          &BudgetNodeId::new("org"),
          AggregateSpend {
              spend_units: 50,
              currency: None,
              ..AggregateSpend::default()
          },
          &SpendSnapshot::new(),
      );
      assert!(matches!(
          decision,
          BudgetDecision::Deny {
              reason: BudgetDenyReason::CurrencyMismatch { .. }
          }
      ));
  }

  #[test]
  fn matching_currency_still_allows_within_cap() {
      let mut tree = BudgetTree::new();
      tree.insert(leaf(
          "org",
          None,
          BudgetLimits {
              max_spend_units: Some(100),
              currency: Some("USD".to_string()),
              ..BudgetLimits::default()
          },
          BudgetWindow::Daily,
      ))
      .expect("insert");
      let decision = tree.evaluate(
          &BudgetNodeId::new("org"),
          AggregateSpend::with_spend(50, "USD"),
          &SpendSnapshot::new(),
      );
      assert!(matches!(decision, BudgetDecision::Allow));
  }

  #[test]
  fn spend_capped_node_never_allows_on_currency_mismatch() {
      for (node_currency, draft_currency) in [
          ("USD", Some("EUR")),
          ("USD", None),
          ("EUR", Some("USD")),
          ("JPY", Some("EUR")),
      ] {
          let mut tree = BudgetTree::new();
          tree.insert(leaf(
              "org",
              None,
              BudgetLimits {
                  max_spend_units: Some(100),
                  currency: Some(node_currency.to_string()),
                  ..BudgetLimits::default()
              },
              BudgetWindow::Daily,
          ))
          .expect("insert");
          let draft = AggregateSpend {
              spend_units: 1,
              currency: draft_currency.map(str::to_string),
              ..AggregateSpend::default()
          };
          let decision = tree.evaluate(&BudgetNodeId::new("org"), draft, &SpendSnapshot::new());
          assert!(
              !matches!(decision, BudgetDecision::Allow),
              "spend-capped node allowed a mismatched-currency draft: node={node_currency} draft={draft_currency:?}"
          );
      }
  }
  ```

- [ ] Run the tests to verify they fail:
  ```bash
  set -o pipefail
  cargo test -p chio-metering currency_mismatch absent_draft_currency matching_currency spend_capped_node_never 2>&1 | tail -15
  ```
  Expected failure: compile error `error[E0599]: no variant or associated item named 'CurrencyMismatch' found for enum 'BudgetDenyReason'` (the test target fails to compile because the variant does not exist yet).

- [ ] Write the implementation. First add the variant to `BudgetDenyReason` immediately after the `UnknownNode { ... }` variant (after line 363, before the enum's closing `}` at line 364):
  ```rust
      /// A spend cap exists but the draft currency is absent or differs from
      /// the node's, so the cap is uncomparable. Fail-closed (F72): deny
      /// rather than skipping the cap.
      CurrencyMismatch {
          /// The node whose spend cap could not be compared.
          node: BudgetNodeId,
          /// The node's declared currency, if any.
          node_currency: Option<String>,
          /// The draft's currency, if any.
          draft_currency: Option<String>,
      },
  ```
  Then replace the entire spend-cap block at lines 613-637:
  ```rust
              if let Some(cap) = limits.max_spend_units {
                  let currency_matches = match (&limits.currency, &draft.currency) {
                      (Some(a), Some(b)) => a == b,
                      // If the node has no currency or the draft has no
                      // currency, the spend cap only activates on matched
                      // currency; mismatched currency means we skip.
                      _ => false,
                  };
                  if currency_matches && projected.spend_units > cap {
                      let cap_str =
                          format!("{} {}", cap, limits.currency.clone().unwrap_or_default());
                      let reach_str = format!(
                          "{} {}",
                          projected.spend_units,
                          projected.currency.clone().unwrap_or_default()
                      );
                      let candidate = BudgetDenyReason::DimensionExceeded {
                          node: node_id.clone(),
                          dimension: "spend".to_string(),
                          cap: cap_str,
                          would_reach: reach_str,
                      };
                      offender = Some((idx, candidate));
                  }
              }
  ```
  with:
  ```rust
              if let Some(cap) = limits.max_spend_units {
                  match (&limits.currency, &draft.currency) {
                      (Some(node_currency), Some(draft_currency))
                          if node_currency == draft_currency =>
                      {
                          if projected.spend_units > cap {
                              let cap_str = format!("{cap} {node_currency}");
                              let reach_str = format!(
                                  "{} {}",
                                  projected.spend_units,
                                  projected.currency.clone().unwrap_or_default()
                              );
                              let candidate = BudgetDenyReason::DimensionExceeded {
                                  node: node_id.clone(),
                                  dimension: "spend".to_string(),
                                  cap: cap_str,
                                  would_reach: reach_str,
                              };
                              offender = Some((idx, candidate));
                          }
                      }
                      _ => {
                          // Fail-closed (F72): a spend cap the draft currency
                          // cannot be compared against denies rather than being
                          // silently skipped.
                          let candidate = BudgetDenyReason::CurrencyMismatch {
                              node: node_id.clone(),
                              node_currency: limits.currency.clone(),
                              draft_currency: draft.currency.clone(),
                          };
                          offender = Some((idx, candidate));
                      }
                  }
              }
  ```

- [ ] Run the tests to verify they pass:
  ```bash
  set -o pipefail
  cargo test -p chio-metering currency_mismatch absent_draft_currency matching_currency spend_capped_node_never 2>&1 | tail -8
  cargo test -p chio-metering 2>&1 | tail -5
  ```
  Expected: the four new tests PASS; the whole `chio-metering` suite matches the baseline plus the four new tests. If any pre-existing `budget_hierarchy` test asserted the old skip-on-mismatch behavior it will now fail; inspect and update it to the fail-closed deny (grep first: `grep -n "currency" crates/economy/chio-metering/src/budget_hierarchy.rs` in the test module) - the only pre-existing currency tests are the insert-time `validate_limits` tests at lines 819-876, which are unaffected.

- [ ] Pre-commit check and commit (exact commands):
  ```bash
  set -o pipefail
  cargo clippy -p chio-metering -- -D warnings 2>&1 | tail -3
  cargo fmt --all
  cd "$(git rev-parse --show-toplevel)"
  git add crates/economy/chio-metering/src/budget_hierarchy.rs
  git commit -m "fix(metering): deny on BudgetTree currency mismatch (F72)"
  ```

---

### Task 5: F68 persistence and metric primitives (`settle_attempts` store, `SettlementAttemptStore` trait, `CHIO_SETTLEMENT_UNRESOLVED_TOTAL`)

**Files:**
- Create: `crates/kernel/chio-kernel/src/settlement_attempt_store.rs` (the kernel-defined trait, entry type, error, and the process-global metric counter)
- Modify: `crates/kernel/chio-kernel/src/lib.rs` (declare `mod settlement_attempt_store;` and re-export its public types)
- Create: `crates/platform/chio-store-sqlite/src/settle_attempts.rs` (the SQLite implementation, following the `dead_letters.rs` pattern)
- Modify: `crates/platform/chio-store-sqlite/src/lib.rs` (declare `pub mod settle_attempts;` and re-export `SqliteSettleAttemptStore`)
- Modify: `crates/observability/chio-metrics-spec/src/lib.rs` (declare the metric const and add its `describe!` registry entry)
- Modify: `crates/observability/chio-metrics-spec/metrics.snapshot` (add the metric line so the golden snapshot test passes)
- Modify: `crates/kernel/chio-kernel/src/observability/metrics.rs` (add the runtime metric family and its `scalar_metric_value` arm)

**Interfaces:**
- Consumes (verified): the dependency direction `chio-store-sqlite -> chio-kernel` (`chio-store-sqlite/src/lib.rs` implements kernel-defined store traits), so the kernel defines the trait and the SQLite crate implements it, mirroring `BudgetStore`; the `dead_letters.rs` store pattern (`SqliteDeadLetterStore::open_with_pool(pool) -> Result<Self, DeadLetterStoreError>`, `open_alongside(&SqliteReceiptStore)`, `insert(&DeadLetterRecord) -> Result<bool, DeadLetterStoreError>` idempotent-on-byte-identical, `DeadLetterStoreError::{Backend, Conflict}`, `SETTLE_DEAD_LETTERS_MIGRATION`); `chio_settle::DeadLetterRecord` (`retry.rs:164`); the signing-counter metric pattern (`static SIGNING_QUEUE_BLOCK_TOTAL: AtomicU64` + `pub(crate) fn signing_queue_block_total() -> u64` + `fn record_signing_queue_block()`, `signing_task.rs:164-172`); the metrics exposition (`RUNTIME_METRIC_FAMILIES` at `observability/metrics.rs:88`, `scalar_metric_value` match at `:166`, both keyed on the metric-name const); the metrics-spec const/`describe!` pattern (`lib.rs:175`, `:513`) and the golden test `golden_snapshot_matches_registry` (`lib.rs:705`) comparing `registry_snapshot()` to `include_str!("../metrics.snapshot")`; `r2d2::Pool<SqliteConnectionManager>` and `rusqlite::{params, OptionalExtension}`; `chio_test_support::prelude::*` (`.test_expect`).
- Produces: `pub trait SettlementAttemptStore: Send + Sync` with `load_attempt`, `upsert_attempt`, `clear_attempt`, `record_dead_letter`; `pub struct SettlementAttemptEntry`; `pub enum SettlementStoreError`; `pub(crate) fn settlement_unresolved_total() -> u64` and `pub(crate) fn record_settlement_unresolved()`; `SqliteSettleAttemptStore` (implements the trait); `chio_metrics_spec::CHIO_SETTLEMENT_UNRESOLVED_TOTAL`. Task 6 consumes all of these.

- [ ] Write the failing store tests. Create `crates/platform/chio-store-sqlite/src/settle_attempts.rs` with only the test module first (so the target fails to compile against the not-yet-written store), then fill in the implementation in the next step. Write the full file now (tests plus a placeholder-free implementation) as follows:
  ```rust
  //! SQLite-backed persistence for the F68 `settle_attempts` retry ledger.
  //!
  //! Keyed by `receipt_id` so a finalized receipt has at most one open
  //! attempt row. The store implements the kernel-defined
  //! [`chio_kernel::SettlementAttemptStore`] trait (like the budget and
  //! receipt stores), so the kernel routing consumer persists retry
  //! attempts and dead letters without depending on this crate.
  //!
  //! The migration is `CREATE TABLE IF NOT EXISTS` plus
  //! `CREATE INDEX IF NOT EXISTS`, so it runs repeatedly against a database
  //! that already holds other tables.

  use chio_kernel::{SettlementAttemptEntry, SettlementAttemptStore, SettlementStoreError};
  use chio_settle::DeadLetterRecord;
  use r2d2::Pool;
  use r2d2_sqlite::SqliteConnectionManager;
  use rusqlite::{params, OptionalExtension};

  /// SQL migration creating the `settle_attempts` table.
  pub const SETTLE_ATTEMPTS_MIGRATION: &str = r#"
  CREATE TABLE IF NOT EXISTS settle_attempts (
      receipt_id      TEXT PRIMARY KEY,
      finalized_at    INTEGER NOT NULL,
      attempts        INTEGER NOT NULL,
      next_visible_at INTEGER NOT NULL,
      last_reason     TEXT,
      updated_at      INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  );
  CREATE INDEX IF NOT EXISTS idx_settle_attempts_next_visible_at
      ON settle_attempts(next_visible_at);
  "#;

  /// SQLite-backed settlement-attempt store. Shares a connection pool with a
  /// sibling receipt store so attempts, dead letters, and receipts sit in
  /// one database and journal mode.
  pub struct SqliteSettleAttemptStore {
      pool: Pool<SqliteConnectionManager>,
  }

  impl SqliteSettleAttemptStore {
      /// Open a store on an existing pool, running the additive migration.
      pub fn open_with_pool(
          pool: Pool<SqliteConnectionManager>,
      ) -> Result<Self, SettlementStoreError> {
          let connection = pool
              .get()
              .map_err(|err| SettlementStoreError::Backend(err.to_string()))?;
          connection
              .execute_batch(SETTLE_ATTEMPTS_MIGRATION)
              .map_err(|err| SettlementStoreError::Backend(err.to_string()))?;
          Ok(Self { pool })
      }

      /// Construct the store sharing the pool of an existing receipt store.
      pub fn open_alongside(
          store: &crate::SqliteReceiptStore,
      ) -> Result<Self, SettlementStoreError> {
          Self::open_with_pool(store.pool.clone())
      }
  }

  impl SettlementAttemptStore for SqliteSettleAttemptStore {
      fn load_attempt(&self, receipt_id: &str) -> Result<Option<u32>, SettlementStoreError> {
          let connection = self
              .pool
              .get()
              .map_err(|err| SettlementStoreError::Backend(err.to_string()))?;
          let attempts = connection
              .query_row(
                  "SELECT attempts FROM settle_attempts WHERE receipt_id = ?1",
                  params![receipt_id],
                  |row| row.get::<_, i64>(0),
              )
              .optional()
              .map_err(|err| SettlementStoreError::Backend(err.to_string()))?;
          match attempts {
              Some(value) => {
                  let value = u32::try_from(value).map_err(|err| {
                      SettlementStoreError::Backend(format!("attempts out of range: {err}"))
                  })?;
                  Ok(Some(value))
              }
              None => Ok(None),
          }
      }

      fn upsert_attempt(
          &self,
          entry: &SettlementAttemptEntry,
      ) -> Result<(), SettlementStoreError> {
          let connection = self
              .pool
              .get()
              .map_err(|err| SettlementStoreError::Backend(err.to_string()))?;
          let finalized_at = i64::try_from(entry.finalized_at)
              .map_err(|err| SettlementStoreError::Backend(err.to_string()))?;
          let next_visible_at = i64::try_from(entry.next_visible_at)
              .map_err(|err| SettlementStoreError::Backend(err.to_string()))?;
          connection
              .execute(
                  "INSERT INTO settle_attempts \
                      (receipt_id, finalized_at, attempts, next_visible_at, last_reason, updated_at) \
                   VALUES (?1, ?2, ?3, ?4, ?5, strftime('%s','now')) \
                   ON CONFLICT(receipt_id) DO UPDATE SET \
                      attempts = excluded.attempts, \
                      next_visible_at = excluded.next_visible_at, \
                      last_reason = excluded.last_reason, \
                      updated_at = excluded.updated_at",
                  params![
                      entry.receipt_id.as_str(),
                      finalized_at,
                      i64::from(entry.attempts),
                      next_visible_at,
                      entry.last_reason.as_deref(),
                  ],
              )
              .map_err(|err| SettlementStoreError::Backend(err.to_string()))?;
          Ok(())
      }

      fn clear_attempt(&self, receipt_id: &str) -> Result<bool, SettlementStoreError> {
          let connection = self
              .pool
              .get()
              .map_err(|err| SettlementStoreError::Backend(err.to_string()))?;
          let affected = connection
              .execute(
                  "DELETE FROM settle_attempts WHERE receipt_id = ?1",
                  params![receipt_id],
              )
              .map_err(|err| SettlementStoreError::Backend(err.to_string()))?;
          Ok(affected > 0)
      }

      fn record_dead_letter(
          &self,
          record: &DeadLetterRecord,
      ) -> Result<bool, SettlementStoreError> {
          let store = crate::dead_letters::SqliteDeadLetterStore::open_with_pool(self.pool.clone())
              .map_err(|err| SettlementStoreError::Backend(err.to_string()))?;
          store.insert(record).map_err(|err| match err {
              crate::dead_letters::DeadLetterStoreError::Conflict(message) => {
                  SettlementStoreError::Conflict(message)
              }
              crate::dead_letters::DeadLetterStoreError::Backend(message) => {
                  SettlementStoreError::Backend(message)
              }
          })
      }
  }

  #[cfg(test)]
  mod tests {
      use super::*;

      use chio_kernel::SettlementAttemptEntry;
      use chio_test_support::prelude::*;

      fn pool() -> Pool<SqliteConnectionManager> {
          let manager = SqliteConnectionManager::memory();
          Pool::builder()
              .max_size(2)
              .build(manager)
              .test_expect("test pool builds")
      }

      fn entry(receipt_id: &str, attempts: u32) -> SettlementAttemptEntry {
          SettlementAttemptEntry {
              receipt_id: receipt_id.to_string(),
              finalized_at: 100,
              attempts,
              next_visible_at: 250,
              last_reason: Some("rpc lag".to_string()),
          }
      }

      #[test]
      fn migration_is_idempotent() {
          let pool = pool();
          SqliteSettleAttemptStore::open_with_pool(pool.clone()).test_expect("first open");
          SqliteSettleAttemptStore::open_with_pool(pool).test_expect("second open");
      }

      #[test]
      fn upsert_then_load_round_trips_and_overwrites() {
          let store = SqliteSettleAttemptStore::open_with_pool(pool()).test_expect("store opens");
          store.upsert_attempt(&entry("rcpt-1", 1)).test_expect("first upsert");
          assert_eq!(
              store.load_attempt("rcpt-1").test_expect("load"),
              Some(1)
          );
          store.upsert_attempt(&entry("rcpt-1", 2)).test_expect("second upsert");
          assert_eq!(
              store.load_attempt("rcpt-1").test_expect("load"),
              Some(2)
          );
      }

      #[test]
      fn load_absent_receipt_is_none() {
          let store = SqliteSettleAttemptStore::open_with_pool(pool()).test_expect("store opens");
          assert_eq!(store.load_attempt("rcpt-missing").test_expect("load"), None);
      }

      #[test]
      fn clear_removes_row() {
          let store = SqliteSettleAttemptStore::open_with_pool(pool()).test_expect("store opens");
          store.upsert_attempt(&entry("rcpt-2", 3)).test_expect("upsert");
          assert!(store.clear_attempt("rcpt-2").test_expect("clear"));
          assert_eq!(store.load_attempt("rcpt-2").test_expect("load"), None);
          assert!(!store.clear_attempt("rcpt-2").test_expect("idempotent clear"));
      }

      #[test]
      fn record_dead_letter_persists_through_shared_pool() {
          let store = SqliteSettleAttemptStore::open_with_pool(pool()).test_expect("store opens");
          let record = chio_settle::DeadLetterRecord::new("rcpt-3", 100, 6, "permanent failure");
          assert!(store.record_dead_letter(&record).test_expect("dead letter insert"));
          assert!(!store.record_dead_letter(&record).test_expect("idempotent replay"));
      }
  }
  ```
  Note: `SqliteReceiptStore.pool` is `pub(crate)` within `chio-store-sqlite` (the `dead_letters.rs` `open_alongside` reads `store.pool.clone()` at `dead_letters.rs:77`), so `open_alongside` here compiles inside the same crate.

- [ ] Add the kernel trait and metric counter. Create `crates/kernel/chio-kernel/src/settlement_attempt_store.rs`:
  ```rust
  //! F68 settlement-attempt persistence seam and the unresolved-outcome
  //! metric counter.
  //!
  //! The trait is defined in the kernel and implemented in
  //! `chio-store-sqlite` (like `BudgetStore`/`ReceiptStore`), so the F68
  //! routing consumer persists retry attempts and dead letters without the
  //! kernel depending on the SQLite crate.

  use std::sync::atomic::{AtomicU64, Ordering};

  /// One row of the settlement retry ledger.
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub struct SettlementAttemptEntry {
      /// `id` of the finalized receipt whose settlement is being retried.
      pub receipt_id: String,
      /// Receipt finalization timestamp.
      pub finalized_at: u64,
      /// Number of attempts recorded so far.
      pub attempts: u32,
      /// Earliest unix time (seconds) a driver may re-attempt the outcome.
      pub next_visible_at: u64,
      /// Most recent failure reason, for operator visibility.
      pub last_reason: Option<String>,
  }

  /// Fail-closed errors from the settlement-attempt persistence seam.
  #[derive(Debug, thiserror::Error)]
  pub enum SettlementStoreError {
      /// Backend (connection pool, SQLite, encoding) error.
      #[error("settlement attempt store backend error: {0}")]
      Backend(String),
      /// A different dead-letter row already exists for this receipt.
      #[error("settlement dead-letter conflict: {0}")]
      Conflict(String),
  }

  /// Persistence seam for the F68 routing consumer. Implemented by
  /// `chio-store-sqlite`.
  pub trait SettlementAttemptStore: Send + Sync {
      /// Current attempt count for a receipt, or `None` if no row exists.
      fn load_attempt(&self, receipt_id: &str) -> Result<Option<u32>, SettlementStoreError>;

      /// Insert or overwrite the attempt row for a receipt.
      fn upsert_attempt(&self, entry: &SettlementAttemptEntry)
          -> Result<(), SettlementStoreError>;

      /// Delete any attempt row for a receipt. Returns `true` if one was removed.
      fn clear_attempt(&self, receipt_id: &str) -> Result<bool, SettlementStoreError>;

      /// Persist a dead-letter record. Idempotent on byte-identical replays;
      /// a byte-different row for the same receipt is a `Conflict`.
      fn record_dead_letter(
          &self,
          record: &chio_settle::DeadLetterRecord,
      ) -> Result<bool, SettlementStoreError>;
  }

  static SETTLEMENT_UNRESOLVED_TOTAL: AtomicU64 = AtomicU64::new(0);

  /// Process-global count of settlement outcomes left unresolved (retryable,
  /// permanent, or hook failure). Exported through the `/metrics` exposition
  /// under `chio_settlement_unresolved_total`.
  #[must_use]
  pub(crate) fn settlement_unresolved_total() -> u64 {
      SETTLEMENT_UNRESOLVED_TOTAL.load(Ordering::Relaxed)
  }

  /// Increment the unresolved-settlement counter (called by the F68 routing
  /// consumer whenever an outcome is not `Accepted`/`Skipped`).
  pub(crate) fn record_settlement_unresolved() {
      SETTLEMENT_UNRESOLVED_TOTAL.fetch_add(1, Ordering::Relaxed);
  }
  ```

- [ ] Wire the kernel module and re-exports. In `crates/kernel/chio-kernel/src/lib.rs`, declare the module beside the other crate-root modules and re-export its public types. Add (alphabetically among the crate's `mod` declarations near the top of the file):
  ```rust
  mod settlement_attempt_store;
  ```
  and add to the crate's public re-export surface (beside where sibling store traits like `BudgetStore` are re-exported; locate with `grep -n "pub use.*BudgetStore" crates/kernel/chio-kernel/src/lib.rs` and place adjacent):
  ```rust
  pub use settlement_attempt_store::{
      SettlementAttemptEntry, SettlementAttemptStore, SettlementStoreError,
  };
  ```

- [ ] Wire the SQLite module and re-export. In `crates/platform/chio-store-sqlite/src/lib.rs`, add the module declaration (alphabetically among the `pub mod` list; it currently runs `... receipt_query; receipt_store; revocation_store;`, so insert after `revocation_store`):
  ```rust
  pub mod settle_attempts;
  ```
  and add the type re-export beside the other `pub use ...::Sqlite*` re-exports:
  ```rust
  pub use settle_attempts::SqliteSettleAttemptStore;
  ```

- [ ] Declare the metric. In `crates/observability/chio-metrics-spec/src/lib.rs`, add the name const in alphabetical position (immediately before `pub const CHIO_SIDECAR_REQUESTS_TOTAL` at line 174):
  ```rust
  pub const CHIO_SETTLEMENT_UNRESOLVED_TOTAL: &str = "chio_settlement_unresolved_total";
  ```
  and add its registry entry to the `REGISTRY` array in alphabetical position (immediately before the `CHIO_SIDECAR_REQUESTS_TOTAL` `describe!` at line 507):
  ```rust
      describe!(
          name = CHIO_SETTLEMENT_UNRESOLVED_TOTAL,
          help = "Total settlement observer outcomes left unresolved (retryable, permanent, or hook failure).",
          kind = Counter,
          labels = []
      ),
  ```

- [ ] Update the golden snapshot. Run the golden test to get the exact expected line, then add it:
  ```bash
  set -o pipefail
  cargo test -p chio-metrics-spec golden_snapshot_matches_registry 2>&1 | tail -30
  ```
  Expected: the test FAILS with an assertion diff showing the registry now contains a `chio_settlement_unresolved_total` line absent from `metrics.snapshot`. Add that exact line (a single row in the `name|kind|...|help` format the diff prints, e.g. `chio_settlement_unresolved_total|counter|||Total settlement observer outcomes left unresolved (retryable, permanent, or hook failure).`) to `crates/observability/chio-metrics-spec/metrics.snapshot` in the same sorted position the diff shows (immediately before the `chio_sidecar_requests_total` line). Re-run:
  ```bash
  set -o pipefail
  cargo test -p chio-metrics-spec 2>&1 | tail -5
  ```
  Expected: green (the golden snapshot now matches the registry).

- [ ] Export the metric through the kernel exposition. In `crates/kernel/chio-kernel/src/observability/metrics.rs`, add the import beside the existing `use crate::kernel::signing_task::signing_queue_block_total;` (line 10):
  ```rust
  use crate::settlement_attempt_store::settlement_unresolved_total;
  ```
  add the metric name to the metrics-spec import list (lines 3-8), then append a family to `RUNTIME_METRIC_FAMILIES` (after the `METRIC_CHIO_OTEL_SINK_DROP_TOTAL` entry that ends at line 109, before the closing `];` at line 110):
  ```rust
      GuardMetricFamily {
          name: CHIO_SETTLEMENT_UNRESOLVED_TOTAL,
          help: "Total settlement observer outcomes left unresolved (retryable, permanent, or hook failure).",
          kind: PrometheusMetricKind::Counter,
          labels: &[],
          buckets: &[],
      },
  ```
  and add the value arm to `scalar_metric_value` (the match at lines 166-170), before the `_ => 0,` arm:
  ```rust
          CHIO_SETTLEMENT_UNRESOLVED_TOTAL => settlement_unresolved_total(),
  ```
  (The metrics-spec import block at lines 3-8 must now include `CHIO_SETTLEMENT_UNRESOLVED_TOTAL`; add it to that `use chio_metrics_spec::{...};` list.)

- [ ] Write a failing metric-exposition test. Append to `crates/kernel/chio-kernel/tests/metrics_endpoint.rs` (which already calls `render_guard_metrics_prometheus()`):
  ```rust
  #[test]
  fn scrape_renders_settlement_unresolved_total() {
      let body = chio_kernel::observability::metrics::render_guard_metrics_prometheus();
      assert!(
          body.contains("chio_settlement_unresolved_total 0"),
          "settlement unresolved counter must render without labels"
      );
      assert!(body.contains(
          "# HELP chio_settlement_unresolved_total Total settlement observer outcomes left unresolved (retryable, permanent, or hook failure)."
      ));
  }
  ```
  Confirm the import path for `render_guard_metrics_prometheus` against the existing tests in that file (they call it directly; match the existing `use` line at the top of `metrics_endpoint.rs`, adjusting the path if the test module imports it unqualified).

- [ ] Run the store, kernel, and metric tests:
  ```bash
  set -o pipefail
  cargo test -p chio-store-sqlite settle_attempts 2>&1 | tail -8
  cargo test -p chio-kernel --test metrics_endpoint scrape_renders_settlement_unresolved_total 2>&1 | tail -8
  ```
  Expected: the five `settle_attempts` store tests PASS; `scrape_renders_settlement_unresolved_total` PASSES.

- [ ] Pre-commit check and commit (exact commands):
  ```bash
  set -o pipefail
  cargo clippy -p chio-kernel -p chio-store-sqlite -p chio-metrics-spec -- -D warnings 2>&1 | tail -3
  cargo fmt --all
  cd "$(git rev-parse --show-toplevel)"
  git add crates/kernel/chio-kernel/src/settlement_attempt_store.rs \
          crates/kernel/chio-kernel/src/lib.rs \
          crates/kernel/chio-kernel/src/observability/metrics.rs \
          crates/kernel/chio-kernel/tests/metrics_endpoint.rs \
          crates/platform/chio-store-sqlite/src/settle_attempts.rs \
          crates/platform/chio-store-sqlite/src/lib.rs \
          crates/observability/chio-metrics-spec/src/lib.rs \
          crates/observability/chio-metrics-spec/metrics.snapshot
  git commit -m "feat(kernel): add settlement-attempt store seam and unresolved-total metric"
  ```

---

### Task 6: F68 routing consumer replacing the drop at `receipt_persistence.rs:185`

**Files:**
- Modify: `crates/kernel/chio-kernel/src/kernel/kernel_struct.rs` (two new fields after `settlement_observer` at line 258)
- Modify: `crates/kernel/chio-kernel/src/kernel/construction.rs` (initialize the two fields in `ChioKernel::new` after `settlement_observer: None` at line 222; add `set_settlement_attempt_store` beside `set_settlement_observer` at line 485)
- Modify: `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs` (replace the drop at line 185; add `route_settlement_observer_status` and `persist_settlement_outcome`)
- Create: `crates/kernel/chio-kernel/tests/settlement_routing.rs` (routing behavior and byte-identity tests)

**Interfaces:**
- Consumes (verified): `record_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), KernelError>` (`receipt_persistence.rs:164`, the observer runs outside the write lock; the drop is `let _settlement_status = self.run_settlement_observer(receipt);` at `:185`); `run_settlement_observer(&self, receipt: &ChioReceipt) -> SettlementObserverStatus` (`construction.rs:506`); `SettlementObserverStatus::{NotRegistered, Skipped { reason }, Observed { outcome }, HookFailed { error }}` (`settlement_observer.rs:33`); `SettlementOutcome::{Accepted, Skipped, Retryable { reason, .. }, Permanent { reason, .. }}` (`chio-settle/src/hook.rs:122`); `chio_settle::classify_attempt(policy: &RetryPolicy, attempt: u32, outcome: &SettlementOutcome) -> RetryDecision` (`retry.rs:123`); `RetryDecision::{Retry { attempt, backoff }, DeadLetter { reason }, Skip { reason }}` (`retry.rs:106`); `chio_settle::RetryPolicy` (`retry.rs:49`, `Default`); `chio_settle::DeadLetterRecord::new(receipt_id, finalized_at, attempts, reason)` (`retry.rs:186`); `current_unix_timestamp() -> u64` (`kernel/mod.rs:998`, `pub(crate)`, in scope via `use super::*;`); `SettlementAttemptStore`/`SettlementAttemptEntry`/`SettlementStoreError`, `record_settlement_unresolved` (Task 5); `set_settlement_observer` pattern (`construction.rs:485`); `ChioKernel::new` struct literal (`construction.rs:133`, last fields `settlement_observer: None` at `:222`, `budget_registry: ...` at `:224`); `warn!` (`tracing`, already imported in `receipt_persistence.rs` via `use super::*;`); `chio_core::receipt::body::ChioReceipt` fields `id: String`, `timestamp: u64`.
- Produces: kernel fields `settlement_attempt_store: Option<Arc<dyn SettlementAttemptStore>>` and `settlement_retry_policy: chio_settle::RetryPolicy`; `set_settlement_attempt_store(&mut self, store: Arc<dyn SettlementAttemptStore>)`; `route_settlement_observer_status(&self, &ChioReceipt, &SettlementObserverStatus)`; `persist_settlement_outcome(&self, &ChioReceipt, &SettlementObserverStatus) -> Result<(), SettlementStoreError>`.

- [ ] Write the failing tests. Create `crates/kernel/chio-kernel/tests/settlement_routing.rs`. These drive `route_settlement_observer_status` indirectly through `record_chio_receipt` by installing a test settlement hook plus the attempt store, then persisting a priced receipt; the byte-identity test reuses the `canonical_json_bytes` oracle:
  ```rust
  //! F68 settlement-routing integration tests.
  //!
  //! Proves that the settlement-observer outcome is routed (warned, metered,
  //! and persisted) instead of dropped, and that with no hook registered the
  //! routing consumer changes no receipt bytes (default-closed invariant).

  #![allow(clippy::expect_used, clippy::unwrap_used)]

  use std::sync::Arc;

  use chio_core::canonical::canonical_json_bytes;
  use chio_core::crypto::Keypair;
  use chio_core::receipt::{
      body::chio_receipt_id, body::ChioReceipt, body::ChioReceiptBody, decision::Decision,
      decision::ToolCallAction, kinds::TrustLevel, metadata::GuardEvidence,
  };
  use chio_kernel::{
      ChioKernel, KernelConfig, SettlementAttemptEntry, SettlementAttemptStore,
      SettlementStoreError,
  };
  use chio_settle::{
      DeadLetterRecord, SettlementHook, SettlementHookError, SettlementObservation,
      SettlementOutcome,
  };

  /// A test hook that always returns a retryable failure.
  struct RetryableHook;
  impl SettlementHook for RetryableHook {
      fn observe(
          &self,
          _observation: &SettlementObservation,
      ) -> Result<SettlementOutcome, SettlementHookError> {
          Ok(SettlementOutcome::retryable("rail unreachable"))
      }
  }

  /// An in-memory `SettlementAttemptStore` recording every write.
  #[derive(Default)]
  struct RecordingAttemptStore {
      attempts: std::sync::Mutex<std::collections::HashMap<String, u32>>,
      dead_letters: std::sync::Mutex<Vec<String>>,
  }

  impl SettlementAttemptStore for RecordingAttemptStore {
      fn load_attempt(&self, receipt_id: &str) -> Result<Option<u32>, SettlementStoreError> {
          Ok(self
              .attempts
              .lock()
              .map_err(|_| SettlementStoreError::Backend("poisoned".to_string()))?
              .get(receipt_id)
              .copied())
      }

      fn upsert_attempt(
          &self,
          entry: &SettlementAttemptEntry,
      ) -> Result<(), SettlementStoreError> {
          self.attempts
              .lock()
              .map_err(|_| SettlementStoreError::Backend("poisoned".to_string()))?
              .insert(entry.receipt_id.clone(), entry.attempts);
          Ok(())
      }

      fn clear_attempt(&self, receipt_id: &str) -> Result<bool, SettlementStoreError> {
          Ok(self
              .attempts
              .lock()
              .map_err(|_| SettlementStoreError::Backend("poisoned".to_string()))?
              .remove(receipt_id)
              .is_some())
      }

      fn record_dead_letter(
          &self,
          record: &DeadLetterRecord,
      ) -> Result<bool, SettlementStoreError> {
          self.dead_letters
              .lock()
              .map_err(|_| SettlementStoreError::Backend("poisoned".to_string()))?
              .push(record.receipt_id.clone());
          Ok(true)
      }
  }

  fn test_kernel() -> ChioKernel {
      ChioKernel::new(KernelConfig {
          keypair: Keypair::generate(),
          ca_public_keys: vec![],
          max_delegation_depth: 5,
          policy_hash: "settlement-routing-test".to_string(),
          allow_sampling: false,
          allow_sampling_tool_use: false,
          allow_elicitation: false,
          max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
          max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
          require_web3_evidence: false,
          checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
          retention_config: None,
          allow_ephemeral_receipt_log: true,
      })
  }

  fn priced_receipt(kernel: &ChioKernel) -> ChioReceipt {
      let metadata = serde_json::json!({
          "financial": { "cost_charged": 250, "currency": "USD" }
      });
      let action = ToolCallAction::from_parameters(serde_json::json!({"k": "v"}))
          .expect("test action constructs");
      let mut body = ChioReceiptBody {
          id: "rcpt-settle".to_string(),
          timestamp: 1_000,
          capability_id: "cap-1".to_string(),
          tool_server: "srv".to_string(),
          tool_name: "tool".to_string(),
          action,
          decision: Some(Decision::Allow),
          receipt_kind: Default::default(),
          boundary_class: Default::default(),
          observation_outcome: None,
          tool_origin: Default::default(),
          redaction_mode: Default::default(),
          actor_chain: Vec::new(),
          content_hash: "ch-1".to_string(),
          policy_hash: "settlement-routing-test".to_string(),
          evidence: vec![GuardEvidence {
              guard_name: "G".to_string(),
              verdict: true,
              details: None,
          }],
          metadata: Some(metadata),
          trust_level: TrustLevel::default(),
          tenant_id: None,
          kernel_key: kernel.public_key(),
          bbs_projection_version: None,
      };
      body.id = chio_receipt_id(&body).expect("canonical receipt id");
      ChioReceipt::sign(body, kernel.signing_keypair()).expect("test receipt signs")
  }

  #[test]
  fn retryable_outcome_records_attempt_and_increments_metric() {
      let mut kernel = test_kernel();
      kernel.set_settlement_observer(Arc::new(RetryableHook));
      let store = Arc::new(RecordingAttemptStore::default());
      kernel.set_settlement_attempt_store(store.clone());

      let receipt = priced_receipt(&kernel);
      let before = chio_kernel::observability::metrics::render_guard_metrics_prometheus();
      let before_value = counter_value(&before);

      kernel
          .record_chio_receipt_for_test(&receipt)
          .expect("record persists");

      let after = chio_kernel::observability::metrics::render_guard_metrics_prometheus();
      assert_eq!(
          counter_value(&after),
          before_value + 1,
          "a retryable outcome must increment the unresolved counter"
      );
      assert_eq!(
          store
              .attempts
              .lock()
              .expect("lock")
              .get(&receipt.id)
              .copied(),
          Some(1),
          "a retryable outcome must persist an attempt row"
      );
  }

  #[test]
  fn no_hook_leaves_receipt_bytes_identical() {
      let kernel_no_hook = test_kernel();
      let receipt = priced_receipt(&kernel_no_hook);
      let baseline = canonical_json_bytes(&receipt).expect("baseline bytes");

      // Routing with no hook registered returns NotRegistered and does
      // nothing; the persisted receipt bytes are unchanged.
      kernel_no_hook
          .record_chio_receipt_for_test(&receipt)
          .expect("record persists");
      let after = canonical_json_bytes(&receipt).expect("post-routing bytes");
      assert_eq!(
          baseline, after,
          "the F68 routing consumer must not mutate receipt bytes"
      );
  }

  fn counter_value(rendered: &str) -> u64 {
      rendered
          .lines()
          .find_map(|line| line.strip_prefix("chio_settlement_unresolved_total "))
          .and_then(|value| value.trim().parse().ok())
          .unwrap_or(0)
  }
  ```
  This test needs three small public test seams on the kernel that do not exist yet: `public_key()` (verify it exists with `grep -n "pub fn public_key" crates/kernel/chio-kernel/src/kernel/construction.rs`; it is used at `construction.rs:513` as `self.public_key()`, so expose it publicly if it is only `pub(crate)`), `signing_keypair()` (a `&Keypair` accessor; if absent, add `#[must_use] pub fn signing_keypair(&self) -> &Keypair { &self.config.keypair }` in `construction.rs`), and `record_chio_receipt_for_test(&self, &ChioReceipt) -> Result<(), KernelError>` (a `#[doc(hidden)] pub` wrapper around the `pub(crate)` `record_chio_receipt`, needed because this is an integration test outside the crate). Add these thin accessors in the implementation step below.

- [ ] Run the tests to verify they fail:
  ```bash
  set -o pipefail
  cargo test -p chio-kernel --test settlement_routing 2>&1 | tail -20
  ```
  Expected failure: compile errors `error[E0599]: no method named 'set_settlement_attempt_store'` and `no method named 'record_chio_receipt_for_test'` on `ChioKernel` (the routing wiring and the test seams do not exist yet).

- [ ] Add the kernel fields. In `crates/kernel/chio-kernel/src/kernel/kernel_struct.rs`, immediately after the `settlement_observer` field (line 258):
  ```rust
      /// F68 settlement retry ledger. When `Some`, the routing consumer
      /// persists unresolved settlement outcomes as retry attempts or dead
      /// letters. `None` keeps the routing consumer to warn-and-meter only.
      pub(super) settlement_attempt_store:
          Option<std::sync::Arc<dyn crate::SettlementAttemptStore>>,
      /// Retry envelope applied to unresolved settlement outcomes.
      pub(super) settlement_retry_policy: chio_settle::RetryPolicy,
  ```

- [ ] Initialize the fields in `ChioKernel::new`. In `crates/kernel/chio-kernel/src/kernel/construction.rs`, immediately after `settlement_observer: None,` (line 222):
  ```rust
              settlement_attempt_store: None,
              settlement_retry_policy: chio_settle::RetryPolicy::default(),
  ```

- [ ] Add the setter and test seams. In `crates/kernel/chio-kernel/src/kernel/construction.rs`, immediately after `set_settlement_observer` (ends at line 490):
  ```rust
      /// Install the F68 settlement retry ledger. When set, the routing
      /// consumer persists unresolved outcomes as attempt or dead-letter
      /// rows; when unset, it warns and increments the metric only.
      pub fn set_settlement_attempt_store(
          &mut self,
          store: std::sync::Arc<dyn crate::SettlementAttemptStore>,
      ) {
          self.settlement_attempt_store = Some(store);
      }

      /// Kernel signing keypair accessor, for tests that mint receipts under
      /// the kernel identity.
      #[doc(hidden)]
      #[must_use]
      pub fn signing_keypair(&self) -> &chio_core::crypto::Keypair {
          &self.config.keypair
      }

      /// Test-only wrapper around the crate-internal receipt persistence path,
      /// so integration tests outside the crate can exercise the F68 routing
      /// consumer end to end.
      #[doc(hidden)]
      pub fn record_chio_receipt_for_test(
          &self,
          receipt: &chio_core::receipt::body::ChioReceipt,
      ) -> Result<(), KernelError> {
          self.record_chio_receipt(receipt)
      }
  ```
  If `grep -n "pub fn public_key" crates/kernel/chio-kernel/src/kernel/construction.rs` shows `public_key` is only `pub(crate)` or `pub(super)`, widen it to `pub` (it returns the kernel public key and is already called internally at `construction.rs:513`).

- [ ] Replace the drop with the routing consumer. In `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs`, replace line 185:
  ```rust
          let _settlement_status = self.run_settlement_observer(receipt);
  ```
  with:
  ```rust
          let status = self.run_settlement_observer(receipt);
          self.route_settlement_observer_status(receipt, &status);
  ```
  Then add the two methods inside the same `impl ChioKernel` block (after `record_chio_receipt`, before `should_checkpoint_after_seq` at line 189):
  ```rust
      /// Route the settlement-observer status instead of dropping it (F68).
      /// Steady-state statuses (`NotRegistered`, `Skipped`, `Accepted`) return
      /// early. Any unresolved outcome (retryable, permanent, or hook failure)
      /// is persisted when a settlement-attempt store is installed, then
      /// always warned and counted so the money owed is never silently lost.
      pub(crate) fn route_settlement_observer_status(
          &self,
          receipt: &ChioReceipt,
          status: &settlement_observer::SettlementObserverStatus,
      ) {
          use settlement_observer::SettlementObserverStatus as S;
          let (reason, retryable) = match status {
              S::NotRegistered | S::Skipped { .. } => return,
              S::Observed { outcome } => match outcome {
                  chio_settle::SettlementOutcome::Accepted { .. }
                  | chio_settle::SettlementOutcome::Skipped { .. } => {
                      // Resolved (or not owed): clear any stale attempt row.
                      if let Some(store) = self.settlement_attempt_store.as_ref() {
                          if let Err(error) = store.clear_attempt(&receipt.id) {
                              warn!(
                                  receipt_id = %receipt.id,
                                  reason = %error,
                                  "failed to clear settlement attempt row"
                              );
                          }
                      }
                      return;
                  }
                  chio_settle::SettlementOutcome::Retryable { reason, .. } => {
                      (reason.clone(), true)
                  }
                  chio_settle::SettlementOutcome::Permanent { reason, .. } => {
                      (reason.clone(), false)
                  }
              },
              S::HookFailed { error } => (error.clone(), true),
          };

          if let Err(error) = self.persist_settlement_outcome(receipt, status) {
              warn!(
                  receipt_id = %receipt.id,
                  reason = %error,
                  "failed to persist settlement outcome"
              );
          }
          warn!(
              receipt_id = %receipt.id,
              retryable,
              reason = %reason,
              "settlement outcome unresolved"
          );
          crate::settlement_attempt_store::record_settlement_unresolved();
      }

      /// Persist an unresolved settlement outcome as a retry attempt or a
      /// dead-letter row via the installed store. A no-op when no store is
      /// installed (the caller still warns and increments the metric). A hook
      /// failure is treated as a transient (retryable) outcome.
      fn persist_settlement_outcome(
          &self,
          receipt: &ChioReceipt,
          status: &settlement_observer::SettlementObserverStatus,
      ) -> Result<(), crate::SettlementStoreError> {
          use settlement_observer::SettlementObserverStatus as S;
          let Some(store) = self.settlement_attempt_store.as_ref() else {
              return Ok(());
          };
          let outcome = match status {
              S::Observed { outcome } => outcome.clone(),
              S::HookFailed { error } => chio_settle::SettlementOutcome::retryable(error.clone()),
              S::NotRegistered | S::Skipped { .. } => return Ok(()),
          };
          let attempt = store.load_attempt(&receipt.id)?.unwrap_or(0);
          match chio_settle::classify_attempt(&self.settlement_retry_policy, attempt, &outcome) {
              chio_settle::RetryDecision::Skip { .. } => {
                  store.clear_attempt(&receipt.id)?;
                  Ok(())
              }
              chio_settle::RetryDecision::Retry {
                  attempt: next_attempt,
                  backoff,
              } => {
                  let now = current_unix_timestamp();
                  store.upsert_attempt(&crate::SettlementAttemptEntry {
                      receipt_id: receipt.id.clone(),
                      finalized_at: receipt.timestamp,
                      attempts: next_attempt,
                      next_visible_at: now.saturating_add(backoff.as_secs()),
                      last_reason: settlement_outcome_reason(&outcome),
                  })?;
                  Ok(())
              }
              chio_settle::RetryDecision::DeadLetter { reason } => {
                  let record = chio_settle::DeadLetterRecord::new(
                      receipt.id.clone(),
                      receipt.timestamp,
                      attempt.saturating_add(1),
                      reason,
                  );
                  store.record_dead_letter(&record)?;
                  store.clear_attempt(&receipt.id)?;
                  Ok(())
              }
          }
      }
  ```
  and add this free helper at the end of the file (outside the `impl` block):
  ```rust
  fn settlement_outcome_reason(outcome: &chio_settle::SettlementOutcome) -> Option<String> {
      match outcome {
          chio_settle::SettlementOutcome::Retryable { reason, .. }
          | chio_settle::SettlementOutcome::Permanent { reason, .. }
          | chio_settle::SettlementOutcome::Skipped { reason, .. } => Some(reason.clone()),
          chio_settle::SettlementOutcome::Accepted { .. } => None,
      }
  }
  ```
  If `settlement_observer` is not already a path in scope inside `receipt_persistence.rs` (it is re-exported at `kernel/mod.rs` as `pub mod settlement_observer`, reachable via `super::settlement_observer` through the file's `use super::*;`), qualify the references as `super::settlement_observer::SettlementObserverStatus` and confirm with `cargo build -p chio-kernel`.

- [ ] Run the tests to verify they pass:
  ```bash
  set -o pipefail
  cargo test -p chio-kernel --test settlement_routing 2>&1 | tail -8
  cargo test -p chio-kernel --test settlement_observer_byte_identity 2>&1 | tail -5
  ```
  Expected: `retryable_outcome_records_attempt_and_increments_metric` and `no_hook_leaves_receipt_bytes_identical` PASS; the pre-existing observer byte-identity suite stays green (the routing consumer is a no-op when no hook is registered).

- [ ] Run the whole kernel lib and integration suites to confirm no regression:
  ```bash
  set -o pipefail
  cargo test -p chio-kernel --lib 2>&1 | tail -5
  cargo test -p chio-kernel 2>&1 | tail -5
  ```
  Expected: the `chio-kernel` suites match the Task 1 baseline plus the new tests; no receipt-path test regresses (the drop-to-route change is behavior-preserving when no hook is installed, which is every existing test).

- [ ] Pre-commit check and commit (exact commands):
  ```bash
  set -o pipefail
  cargo clippy -p chio-kernel -- -D warnings 2>&1 | tail -3
  cargo fmt --all
  cd "$(git rev-parse --show-toplevel)"
  git add crates/kernel/chio-kernel/src/kernel/kernel_struct.rs \
          crates/kernel/chio-kernel/src/kernel/construction.rs \
          crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs \
          crates/kernel/chio-kernel/tests/settlement_routing.rs
  git commit -m "fix(kernel): route the settlement observer outcome instead of dropping it (F68)"
  ```

---

### Task 7: Phase gate (workspace gate) and PR

**Files:**
- Test: no file changes; runs the workspace gate, the house-rule scans, and walks the Phase 1 acceptance checklist against Tasks 1-6.

**Interfaces:**
- Consumes: everything produced by Tasks 1-6.
- Produces: a verified, PR-ready branch `chio/ws1-first-light` with six commits.

- [ ] Run the workspace one-liner gate:
  ```bash
  cd "$(git rev-parse --show-toplevel)"
  cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check
  ```
  Expected: build, clippy, and fmt clean; `cargo test --workspace` matches the `main` baseline captured in Task 1 plus the new tests. Any pre-existing environmental failures (e.g. wasm toolchain) must be identical to the baseline and none may be in `chio-config`, `chio-control-plane`, `chio-cli`, `chio-metering`, `chio-store-sqlite`, `chio-metrics-spec`, or `chio-kernel`.

- [ ] House-rule scan on every touched file:
  ```bash
  cd "$(git rev-parse --show-toplevel)"
  grep -rnP '\x{2014}' \
      crates/platform/chio-config/src/schema.rs \
      crates/platform/chio-control-plane/src/lib.rs \
      crates/products/chio-cli/src/main.rs \
      crates/products/chio-cli/src/cli/runtime.rs \
      crates/economy/chio-metering/src/budget_hierarchy.rs \
      crates/kernel/chio-kernel/src/settlement_attempt_store.rs \
      crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs \
      crates/kernel/chio-kernel/src/kernel/construction.rs \
      crates/kernel/chio-kernel/src/kernel/kernel_struct.rs \
      crates/platform/chio-store-sqlite/src/settle_attempts.rs \
      crates/observability/chio-metrics-spec/src/lib.rs
  grep -rn '\.unwrap()\|\.expect(' \
      crates/kernel/chio-kernel/src/settlement_attempt_store.rs \
      crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs \
      crates/platform/chio-store-sqlite/src/settle_attempts.rs \
      crates/platform/chio-control-plane/src/lib.rs | grep -v '#\[cfg(test)\]' | grep -v 'mod tests'
  ```
  Expected: the em-dash grep returns nothing (exit code 1); the unwrap/expect grep returns only lines inside test modules (production code has none).

- [ ] Walk the Phase 1 acceptance criteria (from the WS1 spec "Implementation phases" Phase 1 and RFC-0013 F68/F72):
  1. The `economy` config block parses with all sections defaulted, an absent block yields all-`None` sections, and an unknown field is rejected: PROVEN by `economy_block_absent_installs_no_sections`, `economy_block_parses_all_sections`, `economy_settlement_driver_defaults_to_none`, `economy_rejects_unknown_field` (Task 1).
  2. The three `configure_*` seams validate fail-closed and install nothing when their section is absent: PROVEN by the six `configure_*` tests plus `seams_install_no_settlement_observer_when_absent` (Tasks 2-3).
  3. The seams are chained into every kernel-constructing CLI command with no behavior change: PROVEN by `chio-cli` compiling with the three chained no-op calls and the default-closed integration test (Task 3).
  4. `BudgetTree::evaluate` returns `Deny(CurrencyMismatch)` for a spend-capped node whose currency is absent or differs from the draft, and still `Allow`s a within-cap matched-currency draft (F72): PROVEN by `currency_mismatch_denies_instead_of_skipping`, `absent_draft_currency_denies_against_spend_cap`, `matching_currency_still_allows_within_cap`, `spend_capped_node_never_allows_on_currency_mismatch` (Task 4).
  5. A settlement hook returning retryable/permanent or failing for a money-bearing receipt produces a `settle_attempts` or `settle_dead_letters` row plus a warn and a `chio_settlement_unresolved_total` increment; nothing is dropped at `receipt_persistence.rs:185`: PROVEN by `retryable_outcome_records_attempt_and_increments_metric`, the five `settle_attempts` store tests, and `scrape_renders_settlement_unresolved_total` (Tasks 5-6).
  6. The default-closed invariant holds: with no `economy` block and no settlement hook, receipts are byte-identical: PROVEN by `no_hook_leaves_receipt_bytes_identical` and the unchanged `settlement_observer_byte_identity` suite (Task 6).
  7. No `.unwrap()`/`.expect()` in production code; `cargo clippy --workspace -- -D warnings` and `cargo fmt --all -- --check` pass; no em dashes: PROVEN by the gate and grep steps above.

- [ ] Update the knowledge graph (house rule) and confirm branch state:
  ```bash
  cd "$(git rev-parse --show-toplevel)"
  graphify update .
  git log --oneline main..chio/ws1-first-light
  ```
  Expected: exactly six commits in order:
  1. `feat(config): add economy configuration block to ChioConfig`
  2. `feat(control-plane): add economy settlement, payment, and oracle configure seams`
  3. `feat(cli): chain economy configure seams into the kernel runtime`
  4. `fix(metering): deny on BudgetTree currency mismatch (F72)`
  5. `feat(kernel): add settlement-attempt store seam and unresolved-total metric`
  6. `fix(kernel): route the settlement observer outcome instead of dropping it (F68)`

- [ ] Open the PR (only after the gate is green):
  ```bash
  cd "$(git rev-parse --show-toplevel)"
  git push -u origin chio/ws1-first-light
  gh pr create --title "WS1 First Light Phase 1: economy seams and fail-closed corrections" \
      --body "$(cat <<'EOF'
  Phase 1 of WS1 (First Light): the economy config block, three control-plane
  configure_* seams and their CLI-runtime chaining (installing nothing when the
  economy block is absent), the F72 BudgetTree currency-mismatch deny, and the
  F68 settlement-outcome routing consumer (settle_attempts table plus the
  chio_settlement_unresolved_total metric) replacing the drop at
  receipt_persistence.rs:185. No behavior change when the economy block is unset.

  Closes F72 and F68 (per RFC-0013). Phases 2-4 land the durable money journal,
  the production settlement/credit driver, and the always-on end-to-end proof.

  🤖 Generated with [Claude Code](https://claude.com/claude-code)
  EOF
  )"
  ```
  Do not push or open the PR unless the caller asks; if the caller wants a review first, stop after the gate walkthrough and report the branch state.
