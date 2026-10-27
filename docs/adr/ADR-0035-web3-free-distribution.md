# ADR-0035: Web3-Free Distribution

- Status: Accepted, 2026-10-27. Owner decision D11 = A (full scope). Not implemented.
- Decision owner: project owner
- Related: ADR-0016, ADR-0017, ADR-0022, ADR-0038; [UNIFIED_ROADMAP.md](../operations/UNIFIED_ROADMAP.md) SHARE-4

## Decision

Option A. Default builds of `chio-kernel`, `chio-core`, `chio-core-types`,
`chio-control-plane` and `chio-cli` contain no web3 code and no
finding-market code. Web3 anchoring, contract bindings and on-chain
settlement rails live in separately built crates that a build reaches only
through an explicit `web3` feature. Finding-market code is reachable only
through an explicit `finding-market` feature.

The property is enforced by a gate, `cargo xtask check web3-free-closure`,
specified under [Acceptance gates](#acceptance-gates). Every edge listed
under [Edges to cut](#edges-to-cut) is closed before the gate is required in
CI.

## Context

### What is being decided

Which Chio crates must build, with default features, without web3
settlement, anchoring and contract code, and without finding-market code.

The web3 set is `chio-web3`, `chio-web3-bindings`, `chio-anchor`,
`chio-settle` (whose whole body is `web3` code today), the `web3` feature of
`chio-link`, and the `alloy`, `alloy-*`, `secp256k1` and `ethers*` crates.
`chio-autonomy` is not in the set, but it depends on `chio-web3`
unconditionally.

The finding-market set is `chio-finding`, `chio-finding-*`,
`chio-open-market` (which depends on `chio-finding`), `chio-swarm-authority`,
and the kernel's `finding-market` feature. `chio-market` is a
liability-market crate with no web3 or finding dependency and is outside
both sets.

### Inputs

- SHARE-4 in [UNIFIED_ROADMAP.md](../operations/UNIFIED_ROADMAP.md) asks for
  ADR-0035 "at its real scope: the kernel, core, control plane and CLI",
  `finding-market` and `web3` off by default, and the x402 and ACP clients
  moved out of the kernel (KSPEC-01 R13). Its exit requires that default
  builds of those four crates pull in no web3 or finding-market code.
- Row D11 of
  [the FTL lessons program design](../superpowers/specs/2026-10-04-ftl-lessons-program-design.md)
  records ADR-0035's scope as an owner decision. This record closes it with
  option A.
- The candidate text in
  [06-strategy-and-roadmap.md](../research/nvidia/06-strategy-and-roadmap.md)
  section 12 scopes ADR-0035 as "an authority-and-evidence distribution
  without web3 settlement, anchoring and contract crates" and treats a
  monorepo split as a separate decision.

### Current dependency graph

The graph below is traced from the `Cargo.toml` files on `main` at
`2df26f433d`, with default features, normal dependencies only (target
sections for non-loom, non-wasm, non-Windows builds included). The workspace
uses resolver 2. `chio-settle`, `chio-anchor`, `chio-link` and
`chio-web3-bindings` each declare `default = ["web3"]`; `chio-web3` has no
features and depends on `alloy-primitives` unconditionally.

Reachable from each root with default features:

| Root | Web3 crates reached | Finding-market crates reached |
|---|---|---|
| `chio-core-types` | none | none |
| `chio-core` | `chio-web3`, `alloy-primitives` | `chio-open-market`, `chio-finding` |
| `chio-kernel` | `chio-settle` (with `web3`), `chio-web3`, `chio-web3-bindings`, `alloy`, `alloy-primitives`, `alloy-sol-types`, `secp256k1` | `chio-open-market`, `chio-finding` |
| `chio-control-plane` | as `chio-kernel` | ten crates: `chio-finding`, `chio-finding-challenge`, `chio-finding-hosted-edge`, `chio-finding-market-migrations`, `chio-finding-market-port`, `chio-finding-market-store-postgres`, `chio-finding-verifier`, `chio-finding-worker`, `chio-open-market`, `chio-swarm-authority` |
| `chio-cli` | as `chio-kernel` | as `chio-control-plane` |

`chio-link` is reached from the kernel with `default-features = false` and
no feature turns `web3` on for it in any of the five closures today.
`chio-anchor` is reached by none of the five closures; it appears only in
dev-dependencies and test crates (see [Anchor consumers](#anchor-consumers)).

Three facts constrain the implementation:

1. `chio-settle`'s whole crate body is `#![cfg(feature = "web3")]`
   ([lib.rs:9](../../crates/economy/chio-settle/src/lib.rs)). Its `web3`
   feature pulls `alloy-primitives`, `alloy-sol-types`, `secp256k1`,
   `chio-web3`, `chio-web3-bindings`, `chio-finding` and `chio-open-market`.
   The kernel uses settlement types from it in 10 non-test modules: the
   hook, outcome-store and retry vocabulary, the completion-flow id
   helpers, and a family of signed and verified channel types. Turning the
   feature off removes all of them, so the kernel does not build without
   `web3` until the generic vocabulary moves to a crate with no web3
   dependencies and the channel consumers are gated. W3 lists the closed
   extraction inventory and the channel disposition.
2. `chio-store-sqlite` and `chio-control-plane` both enable the kernel's
   `finding-market` feature. Feature unification turns it on in any build that
   links either crate, including the CLI and the kernel's own tests (through
   its `chio-store-sqlite` dev-dependency).
3. `cargo build --workspace` unifies features across all members. The
   "default build has no web3 code" property holds only for per-package
   resolution (`cargo tree -p <crate>`, `cargo build -p <crate>`) and is
   checked that way.

## Edges to cut

Each row is one dependency edge reachable from a root with default features.
The method is one of: feature gate (the dependency becomes `optional` behind
the named feature and the code using it is `cfg`-gated), crate split (types
the root needs move to a crate with no web3 or finding dependency), or trait
seam (the root depends on a trait it owns and the web3 or finding crate
implements it).

### Web3 edges

| # | Edge | Where | Method |
|---|---|---|---|
| W1 | `chio-core` -> `chio-web3` | [chio-core/Cargo.toml:33](../../crates/core/chio-core/Cargo.toml); re-exported as `chio_core::web3` and its `anchors`, `chain`, `contracts`, `error`, `identity`, `qualification`, `settlement` and `trust_profile` items ([lib.rs:45, 348-383](../../crates/core/chio-core/src/lib.rs)) | Feature gate: `chio-core` feature `web3 = ["dep:chio-web3", "chio-autonomy/web3"]`; the re-exports are `cfg(feature = "web3")`. |
| W2 | `chio-core` -> `chio-autonomy` -> `chio-web3` | [chio-core/Cargo.toml:24](../../crates/core/chio-core/Cargo.toml), [chio-autonomy/Cargo.toml:17](../../crates/economy/chio-autonomy/Cargo.toml); `chio-autonomy` re-exports `chio_web3 as web3` and its model carries `latest_web3_settlement_state: Option<Web3SettlementLifecycleState>` | Feature gate on `chio-autonomy`: `web3 = ["dep:chio-web3"]`, gating the re-export and the field. `chio-core` keeps `chio-autonomy` unconditional and forwards `web3` to it (W1). |
| W3 | `chio-kernel` -> `chio-settle` | [chio-kernel/Cargo.toml:94](../../crates/kernel/chio-kernel/Cargo.toml), 10 non-test modules | Crate split plus feature gate. The generic settlement vocabulary moves to a new crate `chio-settle-types` (inventory below); the channel consumers move behind `chio-kernel/web3` (channel disposition below). `chio-settle` becomes `default = []`. |
| W4 | `chio-kernel` -> `chio-core::web3::anchors::OracleConversionEvidence` | [payment_pricing.rs:19, 240](../../crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal/payment_pricing.rs), [price_oracle.rs:44, 72](../../crates/kernel/chio-kernel/src/kernel/validation/price_oracle.rs) | Path change: the type already lives in `chio_core_types::oracle` and `chio-web3` re-exports it. The kernel imports it from `chio_core_types::oracle`, so W1 does not break the price-oracle path. |
| W5 | `chio-kernel` -> `chio-link` with `web3` | [chio-kernel/Cargo.toml:88](../../crates/kernel/chio-kernel/Cargo.toml) (`default-features = false`) | Already cut. `chio-link` becomes `default = []` so the edge stays cut without the override, and the gate fails if any crate in a root closure turns `chio-link/web3` on. |
| W6 | `chio-store-sqlite` -> `chio-settle` | [chio-store-sqlite/Cargo.toml:53](../../crates/platform/chio-store-sqlite/Cargo.toml), 19 source files | Crate split plus feature gate: the store depends on `chio-settle-types` (W3) for the generic vocabulary. The channel consumers (`channel_lifecycle_store`, `channel_release_publisher_store`, `economic_state_cache` and the channel reservation path in `admission_operation_store/obligation.rs`) move behind a `chio-store-sqlite` feature `web3 = ["dep:chio-settle", "chio-settle/web3", "chio-kernel/web3"]`, matching the kernel channel disposition. |
| W7 | `chio-control-plane` -> `chio-settle` | [chio-control-plane/Cargo.toml:71](../../crates/platform/chio-control-plane/Cargo.toml), 15 source files | Crate split for the settlement vocabulary (`chio-settle-types`); feature gate `web3` on `chio-control-plane` for the on-chain settlement paths. |
| W8 | `chio-control-plane` -> `chio_core::web3::anchors::AnchorInclusionProof` | [finding_challenge_coordinator.rs:51](../../crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator.rs) and its e2e test | Feature gate: the finding challenge coordinator compiles only with both `finding-market` and `web3`. |
| W9 | `chio-cli` -> `chio-web3` | [chio-cli/Cargo.toml:58](../../crates/products/chio-cli/Cargo.toml), 6 source files | Feature gate `web3` on `chio-cli`. |
| W10 | `chio-cli` -> `chio-settle` | [chio-cli/Cargo.toml:50](../../crates/products/chio-cli/Cargo.toml); one use, `chio_settle::FindingFinalityRequirement` in [finding/operator.rs:842](../../crates/products/chio-cli/src/cli/dispatch/finding/operator.rs) | Feature gate: `chio-settle` becomes optional behind `chio-cli/web3`, and the operator path that sets a finality requirement compiles only with both `web3` and `finding-market`. |
| W11 | `chio-cli` -> `chio-proof-room` -> `chio-web3` | [chio-cli/Cargo.toml:66](../../crates/products/chio-cli/Cargo.toml), [chio-proof-room/Cargo.toml:37](../../crates/products/chio-proof-room/Cargo.toml); proof-room verifies `chio_web3::settlement_proof` bundles | Feature gate: `chio-proof-room` becomes optional in `chio-cli` behind `web3`, gating the `proof` dispatch tree (5 source files). |

The `web3` features forward downward: `chio-cli/web3` enables
`chio-control-plane/web3`, `chio-store-sqlite/web3`, `chio-kernel/web3`,
`chio-core/web3` and `dep:chio-proof-room`; `chio-control-plane/web3`
enables `chio-store-sqlite/web3`, `chio-kernel/web3` and `chio-core/web3`.

### W3 extraction inventory

`chio-settle-types` holds the complete public signature, error and constant
closure of the generic settlement vocabulary. It depends on
`chio-core-types` and `chio-security-types` and on no `chio-settle`,
`chio-core`, web3 or finding crate. `MonetaryAmount`, `PublicKey` and the
hash and canonical-JSON primitives are imported from `chio-core-types`; the
`chio-core` facade is not a dependency, because its default closure is what
W1, W2, F1 and F2 cut.

| Source in `chio-settle` | Items that move |
|---|---|
| [hook.rs](../../crates/economy/chio-settle/src/hook.rs) | `SettlementObservation`, `SettlementIdempotencyKey`, `SettlementSkipReason`, `SettlementFailureClass`, `SettlementFailureCode`, `SettlementFailureCodeParseError`, `SettlementFailureReason`, `SettlementOutcome`, `SettlementHookError`, the `SettlementHook` trait, `SETTLEMENT_OBSERVATION_SCHEMA`, `SETTLEMENT_OUTCOME_SCHEMA`, and their validators and classifiers |
| [outcome_store.rs](../../crates/economy/chio-settle/src/outcome_store.rs) | `SettlementClaimValidationError`, `validate_settlement_claim`, `MAX_SETTLEMENT_WORKER_ID_BYTES`, `MAX_SETTLEMENT_LEASE_MS`, `MAX_SETTLEMENT_CLAIM_BATCH`, `SettlementStoreBinding`, `SettlementRoutingInput`, `SettlementAttemptClaim`, `SettlementRoute`, `SettlementRouteErrorClass`, `SettlementRouteError` (its schema refusal comes from `chio-security-types`), and the `SettlementOutcomeStore` trait |
| [retry.rs](../../crates/economy/chio-settle/src/retry.rs) | `RetryPolicyError`, `RetryPolicy`, `RetryDecision`, `classify_attempt`, `DeadLetterRecord`, `SETTLE_DEAD_LETTER_SCHEMA` and the four retry default constants, with typed validation, disposition and bounded retry behavior unchanged |
| [lib.rs](../../crates/economy/chio-settle/src/lib.rs) | `SETTLEMENT_COMPLETION_FLOW_ROW_ID_PREFIX`, `settlement_completion_flow_row_id`, `settlement_completion_flow_receipt_id`, and `SettlementError` |
| [channel/state.rs:317](../../crates/economy/chio-settle/src/channel/state.rs) | `derive_channel_receipt_authority_digest`, with the domain-separated digest helper it calls and a typed error that carries only the failure modes that helper produces |

`SettlementError` moves with `SettlementHookError`, because
`SettlementHookError::Pipeline` carries it and its classification matches on
it. Its payloads are strings, `std::io::Error` and
`SharedUntrustedJsonError`; the last is imported from
`chio_core_types::canonical` in place of `chio_core::canonical`. The
crate-private `invalid_input` constructor becomes a `chio-settle-types`
constructor and every `chio-settle` caller is updated in the same change.
`chio-settle` depends on `chio-settle-types` and uses these items by their
new path. There is no re-export alias in `chio-settle`, no
string-erased replacement error, and no conversion that lets
`chio-settle-types` depend back on `chio-settle`.

### W3 channel disposition

`chio_settle::channel` does not move. It re-exports `Web3FinalityMode`
([channel/mod.rs:17](../../crates/economy/chio-settle/src/channel/mod.rs)),
`open.rs` and `funding.rs` bind Ethereum escrow and finality terms, and
`derive_channel_payee_binding_digest` validates an EVM address. The on-chain
channel implementation stays in `chio-settle` behind `web3`.

The kernel's channel consumers move behind a `chio-kernel` feature
`web3 = ["dep:chio-settle", "chio-settle/web3"]`:

- [admission_operation/projection.rs:9-13](../../crates/kernel/chio-kernel/src/admission_operation/projection.rs):
  `ChannelEscrowReservationViewV1`, `ChannelLifecycleViewV1`,
  `SignedChannelReservationV1`, `SignedChannelStateV1`,
  `VerifiedChannelTerminalAdvanceV1`,
  `CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY`. The channel-reservation
  projection branches are `cfg(feature = "web3")`; the generic
  `derive_channel_receipt_authority_digest` import switches to
  `chio-settle-types`.
- [admission_operation/projection/channel_terminal_authority.rs](../../crates/kernel/chio-kernel/src/admission_operation/projection/channel_terminal_authority.rs):
  the whole module is `cfg(feature = "web3")`.
- [tool_outcome/release/terminal.rs:9-13](../../crates/kernel/chio-kernel/src/tool_outcome/release/terminal.rs):
  `verify_channel_terminal_outcome_commitment`,
  `ChannelTerminalOutcomeCommitmentBodyV1`,
  `SignedChannelTerminalOutcomeCommitmentV1`,
  `VerifiedAdmittedChannelReservationV1`,
  `CHANNEL_TERMINAL_OUTCOME_COMMITMENT_SCHEMA`. The channel terminal-release
  path is `cfg(feature = "web3")`.
- [admission_operation/remote_projection.rs:18](../../crates/kernel/chio-kernel/src/admission_operation/remote_projection.rs)
  uses only `derive_channel_receipt_authority_digest` and imports it from
  `chio-settle-types`; it stays in the default build.

In a default build, a grant or admission that names a channel reservation
denies with a configuration error, the same fail-closed shape the kernel
uses for finding-market grants when `finding-market` is off. W6 gates the
matching store paths.

### Finding-market edges

| # | Edge | Where | Method |
|---|---|---|---|
| F1 | `chio-core` -> `chio-open-market` | [chio-core/Cargo.toml:31](../../crates/core/chio-core/Cargo.toml); re-exported as `chio_core::open_market` and its `evaluation`, `evidence`, `fee_schedule` and `penalty` items ([lib.rs:42, 290-303](../../crates/core/chio-core/src/lib.rs)) | Feature gate: `chio-core` feature `finding-market = ["dep:chio-open-market", "chio-federation/finding-market"]`. |
| F2 | `chio-core` -> `chio-federation` -> `chio-open-market` | [chio-core/Cargo.toml:27](../../crates/core/chio-core/Cargo.toml), [chio-federation/Cargo.toml:23](../../crates/trust/chio-federation/Cargo.toml); federation re-exports `chio_open_market as open_market` and `open_admission.rs` carries `required_bond_class: Option<OpenMarketBondClass>` | Feature gate on `chio-federation` (`finding-market`), gating the re-export and the bond-class field. |
| F3 | `chio-kernel` re-exports of `chio_core::open_market` | [chio-kernel/src/lib.rs:416-432](../../crates/kernel/chio-kernel/src/lib.rs) | Feature gate: `cfg(feature = "finding-market")`; kernel `finding-market` enables `chio-core/finding-market`. |
| F4 | `chio-kernel` `finding_purchase` and `finding_recovery` modules | [chio-kernel/src/lib.rs:101-103](../../crates/kernel/chio-kernel/src/lib.rs), compiled unconditionally | Feature gate on `finding-market`, keeping the error vocabulary shim that `finding_pool` already uses for builds without the feature. |
| F5 | `chio-store-sqlite` -> `chio-kernel` with `finding-market`, `chio-finding`, `chio-swarm-authority` | [chio-store-sqlite/Cargo.toml:47, 49, 56](../../crates/platform/chio-store-sqlite/Cargo.toml) | Feature gate `finding-market` on `chio-store-sqlite`, forwarding to `chio-kernel/finding-market`. |
| F6 | `chio-store-sqlite` and `chio-control-plane` -> `chio-transaction-passport` -> `chio-finding`, `chio-finding-verifier`, `chio-open-market` | [chio-transaction-passport/Cargo.toml:13-15](../../crates/platform/chio-transaction-passport/Cargo.toml), [chio-store-sqlite/Cargo.toml:57](../../crates/platform/chio-store-sqlite/Cargo.toml), [chio-control-plane/Cargo.toml:74](../../crates/platform/chio-control-plane/Cargo.toml) | Feature gate `finding-market` on `chio-transaction-passport` for the finding-bound passport fields; the passport core builds without it. |
| F7 | `chio-control-plane` -> six `chio-finding*` crates, `chio-open-market`, `chio-kernel` with `finding-market` | [chio-control-plane/Cargo.toml:26-31, 53, 57](../../crates/platform/chio-control-plane/Cargo.toml); 38 source files reference `chio_finding`, 19 `chio_open_market` | Feature gate `finding-market` on `chio-control-plane`, gating the challenge coordinator, Postgres market store, hosted edge and worker services. |
| F8 | `chio-cli` -> `chio-finding`, `chio-finding-verifier`, `chio-open-market`, `chio-swarm-authority` | [chio-cli/Cargo.toml:47-49, 79](../../crates/products/chio-cli/Cargo.toml); 12, 2 and 13 source files | Feature gate `finding-market` on `chio-cli`, gating the `finding` dispatch tree. |
| F9 | `chio-cli` -> `chio-runtime`, `chio-runtime-core`, `chio-proof-room` -> `chio-swarm-authority` | [chio-runtime/Cargo.toml:19](../../crates/kernel/chio-runtime/Cargo.toml), [chio-runtime-core/Cargo.toml:22](../../crates/kernel/chio-runtime-core/Cargo.toml), [chio-proof-room/Cargo.toml:34](../../crates/products/chio-proof-room/Cargo.toml) | Trait seam: the runtime crates take swarm authority through a trait they own, implemented in `chio-swarm-authority`; the CLI wires the implementation under `finding-market`. `chio-proof-room` is already behind `web3` (W11) and additionally requires `finding-market` for its swarm-authority path. |

### Anchor consumers

`chio-anchor` declares `default = ["web3"]` and its whole body is
`#![cfg(feature = "web3")]`
([lib.rs:11](../../crates/economy/chio-anchor/src/lib.rs)). It becomes
`default = []` together with `chio-settle`, `chio-link` and
`chio-web3-bindings`, so every consumer that relies on its default feature
names `web3` explicitly in the same change:

| Consumer | Where | Change |
|---|---|---|
| `chio-settle` dev-dependency | [chio-settle/Cargo.toml:63](../../crates/economy/chio-settle/Cargo.toml) | `features = ["web3"]`; the tests using it are already web3-only because the crate body is. |
| `chio-control-plane` dev-dependency | [chio-control-plane/Cargo.toml:121](../../crates/platform/chio-control-plane/Cargo.toml) | `features = ["web3"]`; tests that import `chio_anchor` are `cfg(feature = "web3")` so `cargo test -p chio-control-plane` without features still builds. |
| `chio-conformance` dev-dependency | [chio-conformance/Cargo.toml:201](../../crates/tooling/chio-conformance/Cargo.toml) | `features = ["web3"]`. |
| `chio-formal-diff-tests` dependency | [formal/diff-tests/Cargo.toml:19](../../formal/diff-tests/Cargo.toml) | `features = ["web3"]`. |
| fuzz crate | [fuzz/Cargo.toml:44](../../fuzz/Cargo.toml) | `features = ["fuzz", "web3"]`. |

The same rule applies to the `chio-link` dev-dependencies in
`chio-settle`, `chio-control-plane` and `chio-conformance` that use its
`web3` items: each names `features = ["web3"]` when `chio-link` flips to
`default = []`.

### Out of scope

Splitting web3 and market crates into a separate repository or workspace.
The research candidate text treats a split as a separate, irreversible
decision; this decision does not depend on it.

## Acceptance gates

The decision is implemented when all of these pass at one commit.

1. `cargo xtask check web3-free-closure` passes. For each root in
   `chio-kernel`, `chio-core`, `chio-core-types`, `chio-control-plane` and
   `chio-cli` it runs
   `cargo tree -p <root> -e normal,features --prefix none --format "{p} {f}"`
   with default features and fails if any line names:
   - a package in the web3 set: `chio-web3`, `chio-web3-bindings`,
     `chio-anchor`, `chio-settle`, `alloy`, `alloy-*`, `secp256k1`,
     `ethers*`;
   - the `web3` feature of `chio-link`, or of any crate;
   - a package in the finding-market set: `chio-finding`, `chio-finding-*`,
     `chio-open-market`, `chio-swarm-authority`;
   - the `finding-market` feature of any crate.

   The deny list lives in one data file read by the check. The failure
   output names the root, the forbidden package or feature, and the
   inverted path (`cargo tree -i`) that reaches it.
2. The gate fails on `main` at `2df26f433d` and names edges W1, W2, W3, W6,
   W7, W9, W10, W11 and F1 to F9. A run against that commit is kept as the
   negative control.
3. `cargo tree -p chio-cli --features web3,finding-market -e normal` reaches
   `chio-settle`, `chio-web3`, `chio-proof-room` and `chio-finding`, which
   shows the gate inspects the graph the opt-in build uses.
4. `cargo check -p <root>` passes for each of the five roots with default
   features, and `cargo check -p chio-cli --features web3,finding-market`
   passes.
5. The W3 boundary compiles on both sides:
   - `cargo check -p chio-settle-types` passes, and
     `cargo tree -p chio-settle-types -e normal` names no `chio-settle`,
     `chio-core`, web3 or finding-market crate.
   - `cargo check -p chio-kernel` and `cargo check -p chio-store-sqlite`
     pass with default features, with the channel modules compiled out.
   - `cargo test -p chio-kernel --features web3` and
     `cargo test -p chio-store-sqlite --features web3` run the channel
     projection, terminal-authority, terminal-release, lifecycle-store and
     release-publisher tests.
   - A default-build kernel test shows a channel-reservation grant denies
     with a configuration error.
6. `cargo test -p chio-control-plane`, `cargo test -p chio-conformance`,
   `cargo test -p chio-formal-diff-tests` and the fuzz build pass with the
   anchor consumer changes above.
7. `X402PaymentAdapter` and `AcpPaymentAdapter` and the kernel's `ureq`
   dependency live outside `chio-kernel`
   ([payment.rs](../../crates/kernel/chio-kernel/src/payment.rs), KSPEC-01
   R13), so the SHARE-4 exit is met in full.

ADR-0022's rule applies: the edges close as a sequence of changes that each
keep the suite green, and the gate joins required CI after the last edge
closes.

## Options considered

### Option A: full scope (kernel, core, control plane and CLI)

Selected. The crate and feature changes are the edge tables above.

Consequences: the SHARE-4 exit is met as written. The kernel's trust
boundary no longer includes `alloy-*`, `secp256k1` or the x402 and ACP HTTP
clients. Market and settlement deployments build with explicit features.

Risks: the change crosses the kernel, the SQLite store and the control plane,
which other lanes are actively changing. Every `cfg(feature)` split doubles
the build matrix that CI has to cover, and a missing gate compiles silently
in one configuration; acceptance gates 3 to 6 cover both sides. Tests that
exercise settlement or markets turn the features on explicitly.

Effort: large. The `chio-settle-types` extraction and the control-plane
gating are the bulk.

### Option B: narrower scope (CLI and control plane only)

`chio-cli` and `chio-control-plane` gain `web3` and `finding-market`
features, off by default, and `chio-kernel` and `chio-core` keep their
dependencies. Web3 code stays in the default CLI binary through `chio-core`
and `chio-kernel`, so the SHARE-4 exit is not met. Rejected because the
distribution cannot be described as free of web3 code.

### Option C: status quo with documentation

No dependency changes; the graph is documented instead. Rejected because the
boundary is described rather than enforced, so any later dependency widens
it without a failing check.

## Tradeoffs

| | Option A | Option B | Option C |
|---|---|---|---|
| SHARE-4 exit met | Yes | No (kernel and core open) | No |
| Web3 code in default CLI | None | Present through core and kernel | Present |
| Finding-market code in default CLI | None | Present through core and the kernel's finding modules | Present |
| Kernel trust boundary changes | Yes | No | No |
| Crates touched | 14 or more | 3 | 0 |
| Conflict exposure with active lanes | High | Medium | None |
