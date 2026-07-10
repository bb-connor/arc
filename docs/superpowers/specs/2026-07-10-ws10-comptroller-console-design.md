# WS10 Design: Comptroller Console (live spend observability)

- Date: 2026-07-10
- Program: agent-economy program, wave 1 (see 2026-07-10-agent-economy-program-design.md)
- Depends on: none (WS1 settlement telemetry enriches it when present)
- Claim track: implementation (the documented roadmap-Next observability item)
- Branch: chio/ws10-comptroller-console off main

## Goal

Turn the signed receipt log into a live comptroller surface: a spend-event
stream, budget-utilization webhooks, deterministic burn-rate projections, and
corpus-level spend-anomaly detectors. The differentiator is that every finding
is a signed, independently recomputable artifact feeding the existing
underwriting signal path, so observability compounds into underwriting posture
rather than terminating at a dashboard. No detector or webhook enforces
anything; the receipt spine and guards remain the only authority.

## Context

`docs/reference/AGENT_ECONOMY.md:1242-1247` names observability as the next
roadmap phase: a spending dashboard (query layer over the receipt store),
budget-utilization webhooks, and real-time cost streaming from the receipt log.
Section 4.4 (lines 806-816, 1074-1076) already sketches the Chio Watch surface,
including webhook thresholds at 50/80/95 percent.

The substrate exists:

- `FinancialReceiptMetadata`
  (`crates/core/chio-core-types/src/receipt/economics.rs:32-62`) carries
  `cost_charged`, `currency`, `budget_remaining`, `budget_total`,
  `delegation_depth`, `root_budget_holder`, and `settlement_status`
  (`SettlementStatus`, same file lines 113-124).
- The receipt query surface is cursor-paginated over the `seq` column with
  `minCost`/`maxCost` filters and a 200-row cap
  (`docs/reference/RECEIPT_QUERY_API.md:14-63`; `ReceiptQuery` at
  `crates/kernel/chio-kernel/src/receipt_query.rs:93-127`). Cost filtering runs
  as `json_extract(r.raw_json, '$.metadata.financial.cost_charged')`
  (`.../receipt_store/evidence_retention.rs:549-550`), not a dedicated indexed
  column (the `chio_tool_receipts` table has none:
  `.../receipt_store/bootstrap/open.rs:131-158`). This corrects the doc and the
  brief; see Open questions.
- `VelocityGuard` throttles per `(capability_id, grant_index)` with integer
  milli-token buckets (`crates/guards/chio-guards/src/velocity.rs:128-200`).
- `derive_underwriting_signals`
  (`crates/platform/chio-control-plane/src/trust_control/underwriting_and_support/policy_support.rs:315-555`,
  called at line 93) already builds a `Vec<UnderwritingSignal>` including
  pending/failed settlement signals (lines 484-505). Signal, class, reason, and
  evidence enums live in `crates/economy/chio-underwriting/src/lib.rs:87-147`.
- `chio-siem` ships a reusable webhook exporter with HTTPS enforcement, a typed
  `HttpEgressContract`, and 5xx/429 retry
  (`crates/observability/chio-siem/src/exporters/webhook.rs:143-353`).
- The mixed-currency null-unless-converted rule is already implemented in
  metering (`crates/economy/chio-metering/src/query.rs:163-170`).

## In scope

1. A pure detector and projection crate `crates/observability/chio-spend-telemetry`
   (`#![forbid(unsafe_code)]`, no I/O) holding the `chio.spend.*` artifact
   types, deterministic burn-rate math, and the three v1 anomaly detectors.
2. A trust-control spend surface: a cursor spend-event stream, a webhook
   registration and delivery path, and signed burn-rate and anomaly report
   endpoints, wired through `chio-control-plane` and persisted behind
   `chio-store-sqlite` traits.
3. New spend metric names in `chio-metrics-spec` and their emission from the
   trust-control spend surface.
4. New `UnderwritingReasonCode` and `UnderwritingEvidenceKind` variants plus a
   spend-anomaly evidence input to `derive_underwriting_signals`.
5. A `chio spend` CLI subcommand group mirroring the `chio receipt` and
   `chio trust <family> export` conventions.
6. JSON schemas under `spec/schemas/chio-spend/`, schema-id constants, and
   conformance coverage; a `spec/PROTOCOL.md` spend-family subsection.

## Out of scope (explicit cuts)

- A web UI. The deliverable is API and CLI first. A dashboard consumes these
  endpoints later and is a separate track.
- Any automatic enforcement. Detectors and webhooks never revoke, clamp, or
  deny. Enforcement stays with the guards and policies.
- A dedicated indexed cost column on `chio_tool_receipts`. The stream reads the
  existing `json_extract` path; a computed cost index is a WS1 or follow-on
  store change, not a WS10 gate (Open questions).
- Overloading `chio-otel-receipt-exporter`. That crate is OTLP-span ingress into
  signed receipts (`crates/observability/chio-otel-receipt-exporter/src/lib.rs:1-6`),
  not receipt-to-OTel egress; WS10 does not route financial dimensions through
  it.
- Distributed-linearizable spend truth. The HA overrun bound (ADR-0006) stands;
  `budget_remaining` is a best-effort snapshot (economics.rs:24-28).

## Design

### Spend event stream

A spend event is a projection of one already-signed receipt: it copies the
`FinancialReceiptMetadata` financial dimensions plus the source `receipt_id`,
`content_hash`, `tool_server`, `tool_name`, `timestamp`, and `seq`. The frame is
digest-bound to the signed receipt, so it is not independently signed; authority
stays on the receipt.

Transport is pull-based long-poll and Server-Sent Events over the existing
seq-cursor pagination (`GET /v1/spend/stream?cursor=<seq>`), extending the
receipt query surface (`RECEIPT_QUERY_PATH` at
`crates/platform/chio-control-plane/src/trust_control/service_types/paths.rs:117`).
Justification: the receipt store already exposes forward-only `seq` cursors and
a total count, so a tail is a thin read over proven machinery with no
per-consumer delivery state to persist, and trust-control stays the read
authority under its existing tenant boundary. Webhook push is reserved for the
discrete threshold crossings below, not the full firehose, because a firehose
over webhook is an unbounded at-least-once delivery obligation the stream tail
does not incur.

### Webhooks

Budget-utilization webhooks fire on threshold crossings per grant and per
tenant at 50, 80, 95, and 100 percent of `max_total_cost`, plus velocity-guard
trip events. Crossings are computed from `budget_remaining`/`budget_total` on
spend events (and, when WS1 settlement telemetry is present, from budget-store
events directly). Each crossing is emitted at least once as a signed
`chio.spend.budget-threshold-crossing.v1` payload; the receiver verifies the
signature and treats the webhook as evidence, never as authority. Delivery
reuses the `chio-siem` webhook exporter machinery
(`crates/observability/chio-siem/src/exporters/webhook.rs`): HTTPS enforcement,
the typed `HttpEgressContract`, bounded exponential retry on 5xx/429, and
secret-zeroizing auth. At-least-once plus idempotency: each payload carries a
deterministic crossing key `(tenant, capability_id, grant_index, threshold,
window_epoch)` so receivers dedupe replays.

### Burn-rate projections

Given a trailing window `[now - W, now)` with `W` declared on the request, the
projection sums `cost_charged` per currency over matching spend events and
computes, in integer arithmetic only, `spend_in_window` (saturating sum of minor
units), `time_to_exhaustion_seconds` as `budget_remaining * W / spend_in_window`
(integer division, `null` when the window spend is zero), and
`projected_window_spend` as `spend_in_window` scaled by an integer window
multiple. Aggregates are `MonetaryAmount`. Mixed-currency windows follow the
null-unless-converted rule (query.rs:163-170): a per-currency partition is
always returned, and any cross-currency total is `null` unless
`OracleConversionEvidence` is attached. The same projection runs over commerce
mandate allowances, whose `chio.commerce.mandate-allowance-ledger.v1` binds a
maximum amount, currency, validity window, and usage count
(`spec/PROTOCOL.md:1118-1119`, section 6.3.4). Output is a signed
`chio.spend.burn-rate-projection.v1` carrying the window bounds, the inputs, and
the integer results so a verifier recomputes it exactly.

### Anomaly detectors

Three deterministic corpus-level detectors, all integer or fixed-point so a
verifier independently recomputes the statistic from the cited receipts. Each
emits a signed `chio.spend.anomaly-finding.v1` carrying the detector class, a
severity, subject and lineage references, the digest-bound evidence receipt
refs, and the statistic plus the threshold it crossed.

- Delegation-chain cost amplification. Sum `cost_charged` for a child subtree
  keyed by `root_budget_holder` and `delegation_depth` (economics.rs:44-47),
  compare against the parent-level norm across the capability lineage, and flag
  when the child-to-parent ratio in basis points exceeds a declared bound.
- Spend-pattern drift. Per `(subject, tool_server, tool_name)`, compare the
  current window's mean per-invocation cost against a trailing baseline mean;
  the divergence is a fixed-point ratio in basis points against a declared
  threshold. No floats enter the recorded statistic.
- Velocity clustering. `VelocityGuard` buckets are per grant
  (velocity.rs:128-130), so N sibling grants each just under the limit aggregate
  to N times the intended rate. The detector sums sibling-grant invocation and
  spend counts within a window under a shared `root_budget_holder` and flags
  when the aggregate exceeds a declared multiple of the per-grant ceiling.

### Underwriting feedback loop

Anomaly findings become underwriting signals. Add `UnderwritingEvidenceKind::SpendAnomalyFinding`
and `UnderwritingReasonCode` variants (`SpendDelegationAmplification`,
`SpendPatternDrift`, `SpendVelocityClustering`) to
`crates/economy/chio-underwriting/src/lib.rs:98-124` and to the taxonomy default
(lines 167-194). Extend `derive_underwriting_signals` with a spend-anomaly
evidence input that maps each finding to an `UnderwritingSignal` whose class is
`Guarded`, `Elevated`, or `Critical` by finding severity, alongside the existing
reputation, certification, runtime-assurance, and settlement signals. Findings
carry digest-bound `evidence_refs` to the source receipts, matching the existing
settlement-signal pattern (policy_support.rs:568-584).

### Artifacts and types (schema ids chio.spend.<artifact>.v1)

- `chio.spend.event.v1`: stream frame; digest-bound to a signed receipt, not
  independently signed.
- `chio.spend.budget-threshold-crossing.v1`: signed webhook payload with the
  crossing key.
- `chio.spend.burn-rate-projection.v1`: signed; window, inputs, integer results.
- `chio.spend.anomaly-finding.v1`: signed; class, severity, statistic,
  threshold, evidence refs.

All monetary fields are `MonetaryAmount` (u64 minor units, ISO-4217). Signed
artifacts are canonical JSON (RFC 8785) with schema-id constants and JSON
schemas under `spec/schemas/chio-spend/` (the schemas directory already
partitions by family, for example `spec/schemas/chio-commerce`).

### Integration points

- `chio-control-plane` gains `/v1/spend/stream`, `/v1/spend/webhooks`
  (register and list), `GET /v1/reports/burn-rate`, and
  `GET /v1/reports/spend-anomalies`, registered beside the existing report paths
  (paths.rs:117-190) under the same Bearer auth and tenant read boundary.
- `chio-store-sqlite` persists webhook registrations and delivery attempts and
  the emitted findings behind new traits; signed receipts stay immutable, so
  findings and crossings live in sidecar tables keyed by `receipt_id`, matching
  the settlement-reconciliation sidecar pattern (AGENT_ECONOMY.md:753-760).
- `chio-metrics-spec` gains spend-family metric names next to the existing
  `CHIO_*` constants (`crates/observability/chio-metrics-spec/src/lib.rs:115+`),
  for example `chio_spend_events_total`, `chio_spend_burn_rate_units`, and
  `chio_spend_anomaly_findings_total`.
- CLI: a `Spend` variant on `Commands`
  (`crates/products/chio-cli/src/cli/types.rs:262-330`) with
  `chio spend stream` (tail the cursor stream), `chio spend burn-rate`
  (fetch or export a projection), `chio spend anomalies export`, and
  `chio spend webhook add|list`.

### Error handling (fail-closed)

Verification errors deny. A malformed spend event (missing or non-canonical
financial metadata) is skipped and counted, never coerced into a zero-cost
frame. Mixed-currency aggregates without conversion evidence return `null`
totals with a per-currency partition, never a wrong sum. A webhook that cannot
be signed is not delivered, and egress fails closed when the
`HttpEgressContract` is absent (webhook.rs:158-165). A detector that cannot
recompute its statistic deterministically (truncated corpus page, missing
lineage row) emits no finding rather than a guessed one, and records the gap.

## Alternatives considered

1. New pure crate `chio-spend-telemetry` plus control-plane endpoints
   (recommended). Keeps deterministic detector and projection math in a
   no-I/O contract crate matching the economy-crate pattern, reuses the receipt
   query surface for the stream and the `chio-siem` exporter for delivery, and
   keeps enforcement out. Highest cohesion, lowest coupling.
2. Extend `chio-siem`. The SIEM path is security-signal-shaped: severity-graded
   events (`AlertSeverity`, `derive_severity` at
   `crates/observability/chio-siem/src/alerting.rs:62,124`) over guard denials,
   not deterministic financial statistics or signed `chio.spend.*` artifacts.
   WS10 reuses its webhook exporter but should not inherit its severity model or
   its export cadence. Rejected as the home crate; adopted for delivery only.
3. Extend `chio-metering`. Metering owns per-receipt cost attribution and budget
   hierarchy enforcement (`crates/economy/chio-metering/src/`). Folding
   observability detectors there blurs the enforcement and observation boundary
   and would let a detector change perturb charge-path code. Rejected; WS10
   reuses metering's windowing and null-unless-converted logic as a dependency.

## Claim and release framing

Implementation track within the bounded release posture. WS10 ships an
observability and signed-evidence surface; it makes no settlement, custody, or
finality claim, and asserts no market-position threshold (those remain unproved,
per the program design's external-evidence framing). Findings and webhooks are
evidence, not authority; the receipt spine and guards remain the only
enforcement. The public claim is "signed spend observability that feeds
underwriting signals," never "automatic spend control."

## Testing strategy

- Determinism: burn-rate and every detector are property-tested for
  recompute-equality, and a fixed corpus yields byte-identical signed findings
  across runs and platforms (insta-style snapshots with sorted maps). A
  mixed-currency corpus returns `null` totals with per-currency partitions and
  never a coerced sum.
- Velocity clustering: a fixture of sibling grants each just under the per-grant
  `VelocityGuard` ceiling produces exactly one aggregate finding.
- Webhooks: threshold crossings fire once per crossing key, replays dedupe,
  signature verification is exercised, and missing `HttpEgressContract` fails
  closed.
- Underwriting: a spend-anomaly finding produces the expected
  `UnderwritingSignal` class and reason and carries digest-bound evidence refs.
- Conformance: `chio.spend.*` schema coverage; the workspace gate passes.

## Implementation phases

1. Contract crate and schemas. `chio-spend-telemetry` types, burn-rate math, the
   three detectors, schema-id constants, `spec/schemas/chio-spend/`, and the
   `spec/PROTOCOL.md` spend-family subsection. Pure, no I/O.
2. Read surface. `/v1/spend/stream`, `GET /v1/reports/burn-rate`,
   `GET /v1/reports/spend-anomalies`, spend metrics in `chio-metrics-spec`, and
   the `chio spend stream|burn-rate|anomalies` CLI.
3. Webhooks and underwriting loop. Webhook registration, signed delivery via the
   `chio-siem` exporter, the sidecar persistence, and the new underwriting reason
   and evidence variants wired into `derive_underwriting_signals`.

## Open questions

- The receipt store has no dedicated `cost_charged`/`cost_currency` column or
  `idx_chio_tool_receipts_cost` index despite `AGENT_ECONOMY.md:556-568` and the
  brief. Cost filtering is a `json_extract` over `raw_json`
  (evidence_retention.rs:549-550), which does not scale to a high-volume tail. A
  computed cost index is the clean fix but is a store change: own it in WS10
  phase 2 or defer to WS1? Recommendation: add the generated column and index in
  WS10 phase 2 and reconcile the doc.
- Spend-pattern drift needs a baseline window policy (fixed lookback versus
  adaptive). v1 uses a declared fixed trailing window to keep the statistic
  recomputable; adaptive baselines are deferred.
- Velocity-guard trip events are not currently emitted as receipts or store
  events; the guard returns a deny decision inline (velocity.rs:177-179).
  Sourcing trip webhooks may require WS1 telemetry or a guard-side event hook.
  Until then, velocity clustering is inferred from spend events, and the
  guard-trip webhook is best-effort.
