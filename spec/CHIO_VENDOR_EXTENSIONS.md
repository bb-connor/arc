# Chio Vendor Extension Module (`vendor.chio`)

**Module ID:** `vendor.chio`
**Module Version:** 0.1.0
**Status:** Normative for the Chio engine; opaque to all other engines
**Date:** 2026-07-16
**Registry entry:** `hush:spec/vendor-registry.md` (backbay-labs/hush)

---

## 1. Purpose

This document is the registered specification for the `extensions.vendor.chio` block in HushSpec documents, per the hush vendor-registry rules. It is the single conformant home for every Chio-specific extension key. After the migration window (Section 5), the legacy locations `extensions.reputation`, `extensions.runtime_assurance`, and `extensions.chio` are no longer accepted outside migration mode; their content lives here.

A document using this block declares:

```yaml
requires:
  - module: vendor.chio
    version: "0.1"
    enforcement: required   # required for any security-relevant sub-block; see 3.7
```

To engines other than Chio, this block is an opaque mapping (round-tripped, never interpreted). To the Chio engine it is normative configuration with the schemas below. The authoritative Rust types live in `crates/guards/chio-policy/src/models/extensions.rs`; this document is their wire-format contract, and the two MUST NOT drift (enforced by a schema-parity test, see the execution plan).

## 2. Block layout

```yaml
extensions:
  vendor:
    chio:
      reputation: { ... }          # 3.1  (moved from extensions.reputation)
      runtime_assurance: { ... }   # 3.2  (moved from extensions.runtime_assurance)
      market_hours: { ... }        # 3.3  (moved from extensions.chio.market_hours)
      signing: { ... }             # 3.4  (moved from extensions.chio.signing)
      k8s_namespaces: { ... }      # 3.5  (moved from extensions.chio.k8s_namespaces)
      rollback: { ... }            # 3.6  (moved from extensions.chio.rollback)
      security:
        crypto_floor: { ... }      # 3.7  (new; the policy-declared signing floor)
      human_in_loop:
        approve_when: [ ... ]      # 3.8  (expressions only; approvers moved OUT, see below)
```

`extensions.chio.human_in_loop.approvers` does NOT move here: threshold approval is the portable `hushspec.approval` module (`hush:spec/hushspec-approval.md`, `rules.human_in_loop.approvers`). Only the Chio-specific `approve_when` expression list remains vendor-scoped.

Unknown keys under `vendor.chio` are validation errors for the Chio engine (deny-unknown-fields applies inside the vendor block exactly as in core).

## 3. Sub-block schemas

### 3.1 `reputation`

Reputation-gated issuance ceilings, materialized by the control plane at capability issuance (`chio-control-plane/src/policy/issuance.rs`). Shape (authoritative type `ReputationExtension`):

- `scoring` (optional): `weights` with eight optional 0.0-1.0 fields (`boundary_pressure`, `resource_stewardship`, `least_privilege`, `history_depth`, `tool_diversity`, `delegation_hygiene`, `reliability`, `incident_correlation`); `temporal_decay_half_life_days` (u32); `probationary_receipt_count` (u64); `probationary_score_ceiling` (f64); `probationary_min_days` (u64).
- `tiers` (map name to tier): `score_range` ([f64; 2], inclusive, low <= high); `max_scope` (operations list plus scope ceiling fields per `ReputationTierScope`); optional `promotion` / `demotion` rules.

Validation is unchanged from the current engine behavior (`chio-policy/src/validate.rs` reputation checks): malformed tiers, out-of-range weights, and inverted score ranges are load-time errors.

### 3.2 `runtime_assurance`

Attestation-tier issuance gating (authoritative type `RuntimeAssuranceExtension`):

- `tiers` (map name to rule): `minimum_attestation_tier` (`RuntimeAssuranceTier`), `max_scope` (as in 3.1).
- `trusted_verifiers` (map name to rule): `schema` (string), `verifier` (string), `effective_tier` (`RuntimeAssuranceTier`), optional `verifier_family` (`AttestationVerifierFamily`), optional `max_evidence_age_seconds` (u64), `allowed_attestation_types` (string list), `required_assertions` (string map).

### 3.3 `market_hours`

`tz` (IANA zone), `open`/`close` (HH:MM), `days` (weekday list). Interpreted by chio-bridge consumers; the kernel does not evaluate it.

### 3.4 `signing`

`algo` (string), `required` (bool, default true), optional `key_ref`. Bridge-consumer configuration; distinct from HushSpec document signing (which is the hush `PolicySignature` sidecar).

### 3.5 `k8s_namespaces`

`allow`, `human_in_loop`, `deny` (string lists). Bridge-consumer configuration.

### 3.6 `rollback`

`on_guard_fail` (bool), `on_timeout` (bool), optional `strategy` (string). Bridge-consumer configuration.

### 3.7 `security.crypto_floor`

New in module 0.1.0; this is the policy-declared minimum signing posture the v2 design's arc-corrections section calls for (there is no such field in core HushSpec):

```yaml
security:
  crypto_floor: allow_classical | allow_hybrid | pq_required
```

Semantics: the effective kernel floor is the **stricter** of the operator-configured floor and this declaration; a document can never lower the operator floor. Load-time rule: `allow_hybrid` and `pq_required` reject at load when the required PQ key material is not provisioned (mirrors `CryptoFloor` load validation). The control-plane loader translates the effective floor to `set_capability_crypto_floor` at kernel construction.

Enforcement classification: security-relevant. Any document declaring `security` MUST use `enforcement: required` (3.9).

### 3.8 `human_in_loop.approve_when`

List of Chio expression strings evaluated by bridge consumers. Not part of the portable approval module.

### 3.9 Enforcement classification

`reputation`, `runtime_assurance`, and `security` are security-relevant: a document declaring any of them MUST mark `vendor.chio` as `enforcement: required`, and the Chio engine rejects such a document under `enforcement: optional` (validation error at load). `market_hours`, `signing`, `k8s_namespaces`, `rollback`, and `human_in_loop.approve_when` are bridge configuration and may ride under either enforcement level.

## 4. Merge semantics

Registered structured merge (per the vendor-registry rules, applies to the Chio engine only; all other engines replace wholesale): each top-level sub-block of `vendor.chio` merges independently by the document `merge_strategy`, preserving the engine's existing per-field extension merge behavior (`chio-policy/src/merge.rs`). `security.crypto_floor` merges by strictest-wins regardless of strategy: a child may raise the floor, never lower it.

## 5. Migration

Legacy locations and their targets:

| Legacy | Target |
|---|---|
| `extensions.reputation` | `extensions.vendor.chio.reputation` |
| `extensions.runtime_assurance` | `extensions.vendor.chio.runtime_assurance` |
| `extensions.chio.market_hours` / `.signing` / `.k8s_namespaces` / `.rollback` | `extensions.vendor.chio.<same>` |
| `extensions.chio.human_in_loop.approvers` | `rules.human_in_loop.approvers` (module `hushspec.approval`) |
| `extensions.chio.human_in_loop.approve_when` | `extensions.vendor.chio.human_in_loop.approve_when` |

Rules: legacy keys parse only in migration mode, emit deprecation warnings naming the target location, and `chio policy migrate` rewrites them (including synthesizing the `requires` entries). A document carrying both a legacy key and its target is rejected as ambiguous (no last-writer-wins). Removal of migration-mode aliases: two arc minor releases after the release that ships this module, with a dated changelog entry and legacy-load telemetry reviewed before removal.
