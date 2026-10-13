# ADR-0035: Web3-Free Distribution

- Status: Proposed. Scope is an open owner decision (D11); this record lays out options and adopts none.
- Decision owner: project owner
- Related: ADR-0016, ADR-0017, ADR-0022, ADR-0038; [UNIFIED_ROADMAP.md](../operations/UNIFIED_ROADMAP.md) SHARE-4

## Context

### What is being decided

Which Chio crates must build, with default features, without web3
settlement, anchoring and contract code, and without finding-market code.
"Web3 code" here means `chio-web3`, `chio-web3-bindings`, `chio-settle`,
`chio-anchor`, the `web3` feature of `chio-link`, and the `alloy-*` and
`secp256k1` crates they bring in. "Finding-market code" means `chio-finding`,
`chio-finding-*`, `chio-open-market` (which depends on `chio-finding`),
`chio-swarm-authority`, and the kernel's `finding-market` feature.
`chio-market` is a liability-market crate with no web3 or finding
dependency and is outside both sets.

### Inputs

- SHARE-4 in [UNIFIED_ROADMAP.md](../operations/UNIFIED_ROADMAP.md) asks for
  ADR-0035 "at its real scope: the kernel, core, control plane and CLI",
  `finding-market` and `web3` off by default, and the x402 and ACP clients
  moved out of the kernel (KSPEC-01 R13). Its exit requires that default
  builds of those four crates pull in no web3 or finding-market code.
- Section 8 of the same document lists "ADR-0035 at full scope" under
  "Recorded, not open".
- The 2026-10-12 status note on the KDEF owners item in the same document
  and row D11 of
  [the FTL lessons program design](../superpowers/specs/2026-10-04-ftl-lessons-program-design.md)
  record ADR-0035's scope as an owner decision that is still open.
- The candidate text in
  [06-strategy-and-roadmap.md](../research/nvidia/06-strategy-and-roadmap.md)
  section 12 scopes ADR-0035 as "an authority-and-evidence distribution
  without web3 settlement, anchoring and contract crates, starting by
  feature-gating two crates in `chio-cli`", and treats a monorepo split as a
  separate decision.

The roadmap records the scope both as recorded and as open. This ADR treats
it as open, matches the D11 register, and leaves the choice to the owner.

### Current dependency graph

All paths below are on `main`. The workspace uses resolver 2, and
`chio-settle`, `chio-anchor`, `chio-link` and `chio-web3-bindings` each
declare `default = ["web3"]`.

| Crate | Web3 dependencies | Finding-market dependencies |
|---|---|---|
| `chio-core` | `chio-web3` unconditional ([Cargo.toml:33](../../crates/core/chio-core/Cargo.toml)), which depends on `alloy-primitives`. Re-exported as `chio_core::web3` ([lib.rs:44](../../crates/core/chio-core/src/lib.rs)). | `chio-open-market` unconditional ([Cargo.toml:31](../../crates/core/chio-core/Cargo.toml)), re-exported as `chio_core::open_market` (lib.rs:41). |
| `chio-kernel` | `chio-settle` unconditional with default features ([Cargo.toml:92](../../crates/kernel/chio-kernel/Cargo.toml)). `chio-link` with `default-features = false` (Cargo.toml:86). Uses `chio_core::web3::anchors::OracleConversionEvidence` in the price-oracle path. In-crate `X402PaymentAdapter` and `AcpPaymentAdapter` over `ureq` ([payment.rs](../../crates/kernel/chio-kernel/src/payment.rs)). | `finding-market` feature, off by default, gates `finding_pool` and `chio-swarm-authority` (Cargo.toml:29). `finding_purchase` and `finding_recovery` compile unconditionally. Re-exports `chio_core::open_market` items ([lib.rs:415-431](../../crates/kernel/chio-kernel/src/lib.rs)). |
| `chio-control-plane` | `chio-settle` unconditional ([Cargo.toml:69](../../crates/platform/chio-control-plane/Cargo.toml)). Uses `chio_core::web3::anchors` in the finding challenge coordinator. | Six `chio-finding*` crates unconditional (Cargo.toml:26-31), `chio-open-market` (Cargo.toml:56), and `chio-kernel` with `finding-market` on (Cargo.toml:52). |
| `chio-store-sqlite` | `chio-settle` unconditional ([Cargo.toml:52](../../crates/platform/chio-store-sqlite/Cargo.toml)). | `chio-finding` (Cargo.toml:47) and `chio-kernel` with `finding-market` on (Cargo.toml:49). |
| `chio-cli` | `chio-web3` (Cargo.toml:58), `chio-settle` (Cargo.toml:50), and `chio-proof-room` (Cargo.toml:66), which depends on `chio-web3`. All unconditional ([Cargo.toml](../../crates/products/chio-cli/Cargo.toml)). | `chio-finding`, `chio-finding-verifier`, `chio-open-market` (Cargo.toml:47-49); `chio-control-plane` and `chio-store-sqlite` (Cargo.toml:34, 86), which both turn on the kernel's `finding-market`. |

Three facts constrain every option:

1. `chio-settle`'s whole crate body is `#![cfg(feature = "web3")]`
   ([lib.rs:9](../../crates/economy/chio-settle/src/lib.rs)). Its `web3`
   feature pulls `alloy-primitives`, `alloy-sol-types`, `secp256k1`,
   `chio-web3`, `chio-web3-bindings`, `chio-finding` and `chio-open-market`.
   The kernel uses settlement types from it (`SettlementIdempotencyKey`,
   `SettlementStoreBinding`, the `channel` module, `SettlementFailureCode`,
   `RetryPolicyError`, `SETTLEMENT_OUTCOME_SCHEMA`) in 10 non-test modules.
   Turning the feature off removes those types, so the kernel does not build
   without `web3` until they move to a crate with no web3 dependencies.
2. `chio-store-sqlite` and `chio-control-plane` both enable the kernel's
   `finding-market` feature. Feature unification turns it on in any build that
   links either crate, including the CLI and the kernel's own tests (through
   its `chio-store-sqlite` dev-dependency, Cargo.toml:124).
3. `cargo build --workspace` unifies features across all members. A
   "default build has no web3 code" property holds only for per-package
   builds (`cargo build -p <crate>`) and has to be checked that way.

## Options

Effort is stated as the code surface each option touches, counted with
`grep` on `main`.

### Option A: full scope (kernel, core, control plane and CLI)

Default builds of `chio-kernel`, `chio-core`, `chio-control-plane` and
`chio-cli` contain no web3 or finding-market code. Both are opt-in features.

Crate and feature changes:

- `chio-core`: make `chio-web3` and `chio-open-market` optional behind `web3`
  and `finding-market` features; gate the `web3` and `open_market`
  re-exports.
- `chio-settle`: move the types the kernel uses into a crate with no web3
  dependencies (or split `chio-settle` into a web3-free core module and a
  `web3` feature), and flip `default = ["web3"]` to `default = []`. The same
  flip applies to `chio-anchor`, `chio-link` and `chio-web3-bindings`.
- `chio-kernel`: depend on the web3-free settlement types; move the
  `OracleConversionEvidence` dependency off `chio_core::web3`; move
  `X402PaymentAdapter` and `AcpPaymentAdapter` (and the `ureq` dependency
  they use in `payment.rs`) to a separate crate (KSPEC-01 R13); gate
  `finding_purchase`, `finding_recovery` and the `open_market` re-exports
  behind `finding-market`.
- `chio-store-sqlite`: make `chio-finding`, `chio-settle` and the kernel's
  `finding-market` feature optional behind matching features.
- `chio-control-plane`: add `web3` and `finding-market` features; make the six
  `chio-finding*` crates, `chio-open-market`, `chio-settle` and the kernel's
  `finding-market` optional; gate the modules that use them (38 source files
  reference `chio_finding`, 19 `chio_open_market`, 16 `chio_settle`).
- `chio-cli`: add `web3` and `finding-market` features forwarding to the
  crates above; make `chio-web3`, `chio-settle`, `chio-finding`,
  `chio-finding-verifier`, `chio-open-market` and `chio-proof-room` optional;
  gate the code that uses them (15 source files, mainly the `finding` and
  `proof` dispatch trees).
- A CI gate that runs `cargo tree -e normal -p <crate>` with default features
  for each of the four crates and fails on any crate in the web3 or
  finding-market sets.

Consequences: the SHARE-4 exit is met as written. The kernel's trust
boundary no longer includes `alloy-*`, `secp256k1` or the x402 and ACP HTTP
clients. Market and settlement deployments build with explicit features.

Risks: the change crosses the kernel, the SQLite store and the control plane,
which other lanes are actively changing; conflicts are likely. Every
`cfg(feature)` split doubles the build matrix that CI has to cover, and a
missing gate compiles silently in one configuration. Tests that exercise
settlement or markets need the features turned on explicitly.

Effort: large. The settlement-type extraction and the control-plane gating
are the bulk; ADR-0022's rule that each step keeps the suite green applies,
so it lands as a sequence of independent changes.

### Option B: narrower scope (CLI and control plane only)

`chio-cli` and `chio-control-plane` gain `web3` and `finding-market`
features, off by default. `chio-kernel` and `chio-core` keep their current
dependencies.

Crate and feature changes:

- `chio-cli` and `chio-control-plane`: as in Option A.
- `chio-store-sqlite`: make `chio-finding` and the kernel's `finding-market`
  feature optional, since the CLI links it.
- `chio-core`, `chio-kernel`, `chio-settle`: unchanged.

Consequences: the default CLI and control plane drop the finding-market
services (challenge coordinator, Postgres market store, hosted edge, worker)
and the `finding` and `proof` command trees. The kernel's `finding-market`
lane stays off in the default CLI build. Finding-market code remains through
`chio-core` (`chio-open-market`, `chio-finding`) and the kernel's
unconditional `finding_purchase` and `finding_recovery` modules. Web3 code remains in the default
CLI binary, because `chio-core` still depends on `chio-web3` and
`chio-kernel` still depends on `chio-settle` with `web3` on. The SHARE-4 exit
is not met; the kernel and core rows stay open.

Risks: the distribution can be described as "no finding market by default"
but not as "no web3 code". A reviewer who reads `chio-kernel/Cargo.toml` or
`cargo tree` sees `alloy-*` and `secp256k1` in the kernel closure.

Effort: medium. Most of the work is the control-plane gating listed under
Option A.

A narrower variant, gating only `chio-web3` and `chio-settle` as direct
`chio-cli` dependencies (the first step in the research candidate text),
removes them as direct CLI dependencies but leaves both in the CLI's build
through `chio-core`, `chio-kernel` and `chio-proof-room`.

### Option C: status quo with documentation

No dependency changes. Document the current graph (the table above) in the
distribution and install docs, and state that the default build includes web3
settlement types and finding-market code, with the kernel's `finding-market`
lane compiled in whenever the control plane or SQLite store is linked.

Consequences: no code churn. The SHARE-4 item is rewritten or dropped,
and the KSPEC-01 R13 item stays open on its own.

Risks: the boundary is described rather than enforced, so any later
dependency can widen it without a failing check. Readers who require a
distribution without web3 code get a documented "no".

Effort: small.

### Out of scope

Splitting web3 and market crates into a separate repository or workspace. The
research candidate text treats a split as a separate, irreversible decision;
none of the options above depend on it.

## Tradeoffs

| | Option A | Option B | Option C |
|---|---|---|---|
| SHARE-4 exit met | Yes | No (kernel and core open) | No |
| Web3 code in default CLI | None | Present through core and kernel | Present |
| Finding-market code in default CLI | None | Present through core (`chio-open-market`, `chio-finding`) and the kernel's unconditional finding modules | Present |
| Kernel trust boundary changes | Yes | No | No |
| Crates touched | 9 or more | 3 | 0 |
| Conflict exposure with active lanes | High | Medium | None |

## Decision

None yet. The owner selects an option, or a variant of one, and this record
is amended to state it.
