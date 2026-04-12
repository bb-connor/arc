# ARC Link Profile

## Purpose

This profile closes `v2.35` by freezing the bounded `arc-link` runtime that ARC
now actually ships for cross-currency budget enforcement.

It covers four connected surfaces:

- the Base-first Chainlink plus Pyth oracle runtime
- the kernel receipt and settlement evidence boundary
- the operator control and runtime health surface
- the qualification matrix proving fail-closed behavior

## Shipped Runtime Boundary

`arc-link` now claims one off-chain oracle runtime only:

- Chainlink Data Feeds over Alloy RPC as the primary path
- Pyth Hermes as the bounded secondary path for configured pairs
- `arc_link_runtime_v1` as the only supported receipt-side FX authority model,
  with backend `source` labels preserved separately for Chainlink or Pyth
- cache freshness checks using feed `updated_at`, TWAP for volatile pairs, and
  explicit divergence circuit-breaking
- conservative integer conversion with configured margin
- optional degraded stale-cache grace with extra margin and explicit report
  status
- Base and Arbitrum operator chain inventory with sequencer-uptime monitoring
- operator-visible global pause, pair disable, chain disable, and forced-
  backend overrides
- one structured runtime report under `arc.link.runtime-report.v1`

## Machine-Readable Artifacts

- `docs/standards/ARC_LINK_BASE_MAINNET_CONFIG.json`
- `docs/standards/ARC_LINK_MONITOR_REPORT_EXAMPLE.json`
- `docs/standards/ARC_LINK_QUALIFICATION_MATRIX.json`
- `docs/standards/ARC_LINK_KERNEL_RECEIPT_POLICY.md`

## Operator Surface

The shipped operator surface is explicit and narrow:

- operators pin one trusted chain inventory with chain id, CAIP-2 identifier,
  RPC endpoint, enabled flag, and sequencer-uptime feed
- every supported pair is pinned to one explicit chain and one explicit
  Chainlink feed address, with optional Pyth fallback
- operators can pause all cross-currency oracle resolution, disable a specific
  pair, disable a specific chain, or force a specific backend
- runtime health reports distinguish `healthy`, `fallback_active`,
  `degraded_grace`, `paused`, `tripped`, and `unavailable`
- the optional on-chain `ArcPriceResolver` contract is reference-only; it does
  not replace `arc-link` as the authority for receipt-side conversion evidence

## Supported Inventory

The shipped pair inventory remains Base-first:

- `ETH/USD`: Chainlink + Pyth, TWAP-enabled
- `BTC/USD`: Chainlink + Pyth, TWAP-enabled
- `USDC/USD`: Chainlink + Pyth, spot-only because peg deviation is the signal
- `LINK/USD`: Chainlink only

The shipped chain inventory is:

- Base Mainnet: enabled by default, monitored through the official Chainlink
  sequencer uptime feed
- Arbitrum One: explicit standby operator inventory, disabled by default until
  later web3-runtime milestones consume it

## Failure Posture

`arc-link` is fail closed by default.

Cross-currency enforcement is denied when:

- no supported pair is pinned
- the trusted chain is disabled
- the L2 sequencer is down or still inside the configured recovery grace
  window
- primary and secondary prices diverge beyond the configured threshold
- neither backend can produce a bounded fresh rate
- the operator has paused the runtime or disabled the pair

Optional degraded mode is explicit, bounded, and conservative:

- it reuses the last cached rate only inside a configured stale grace window
- it increases the applied conversion margin
- it marks the source as degraded and surfaces that state in the runtime report

## Qualification Closure

The qualification matrix proves the bounded runtime claim across:

- healthy primary-path conversion
- fallback activation
- missing unsupported pairs
- stale-cache degraded grace
- divergence trip and manipulated-price defense
- disabled-chain and global-pause operator controls

## Non-Goals

This profile does not yet claim:

- Chainlink Data Streams premium tier
- Chainlink Functions, Automation, or CCIP
- x402 or machine-payment interop
- multi-chain settlement execution
- anchoring or proof publication

Those surfaces remain later milestones in the appended web3-runtime ladder.
