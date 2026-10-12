# chio-trust-market-context architecture

## Responsibility and boundary

`TrustMarketBundle` contains the passport, scoped/signed-root graphs,
verifier policy, artifact map, caller-trusted passport keys, and
market-authority keys. `verify_trust_market_context` produces
`TrustMarketVerifierReport` with verified/unsupported claims and references
to the selected artifacts and provider.

The library evaluates completed evidence supplied by the caller. Provider
discovery, live selection, reputation maintenance, SLA monitoring,
collateral custody, and sanction execution are external operations. A signed
artifact records an authority assertion whose consistency and bindings this
verifier checks.

## Structure

`lib.rs` orders the family checks and intersects trusted key sets.
`evidence.rs` validates graph structure, resolves role nodes, binds bytes to
hashes/schemas, and authenticates signed artifacts and referenced auxiliary
evidence. `artifacts.rs` defines discovery, selection, scorecard,
reputation, SLA, collateral, guarantee, and jurisdiction types and
validation. `policy.rs` validates family policy; `claims.rs` defines
supported/blocked claim names.

## Data and control flow

Verification first bounds input work, authenticates the passport against
caller pins, checks any scoped graph is a subset, and verifies baseline
graph/policy commitments. It parses policy and rejects required unsupported
market claims. Effective market keys are the intersection of caller pins and
policy-selected keys; an empty intersection fails.

Ten required role artifacts are digest-bound and signature-checked.
Validation orders discovery, reputation import, scorecard, selection/risk,
SLA, jurisdiction, and collateral/guarantee checks so each reference is
bound to a prior verified section. Required supported claims must appear
before report construction.

## Trust and invariants

Imported reputation weight is constrained by policy and local scorecard
recomputation. Selection binds candidates, rankings, selected subject, local
scorecard, and order/SLA context. Lower-rank overrides require authenticated
evidence. Risk reports use the common comptroller checks plus role-aware
authenticated reference lookups.

Discovery/scorecard freshness and selection/SLA/guarantee windows use
supplied artifact timestamps; there is no separate live marketplace clock
query. Unsupported-market declarations must be nonempty and drawn from the
blocked claim vocabulary, but the validator does not require every blocked
name to be listed. `sla_remedy_ref` and `slash_authority_ref` are internal
report fields marked `serde(skip)` and disappear on serialization.

## Dependencies

`chio-transaction-passport` supplies bounded original-byte parsing, root
authentication, and graph/policy checks. `chio-risk-comptroller` validates
risk accounting and evidence references. `chio-core-types` supplies
canonical signatures and hashes. `chrono` compares evidence windows;
`serde`/`serde_json` project strict artifact types. No Cargo features are
declared.

## Verification

`tests/trust_market_context.rs` constructs signed bundles and mutates
candidate/ranking identity, freshness windows, score arithmetic, import
weight, SLA metrics, guarantees, collateral, jurisdiction, and risk
references. Original-input tests reject auxiliary duplicate fields while
preserving native causes. Run `cargo test -p chio-trust-market-context
--test trust_market_context`. The README demonstrates missing root-pin
rejection with a compile-time fixture and no service access.
