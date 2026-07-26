# Clawdstrike active-defense provenance

Source repository: `https://github.com/backbay-labs/clawdstrike`

Source commit: `666303e5f3428f3b6e6b72f118c269a02388e0a4`

Source license: Apache-2.0. The reviewed source `NOTICE` identifies ClawdStrike and Backbay Industries. The entries below use concepts or independently written Chio tests. No Clawdstrike source text is copied, so no source header or `NOTICE` text is incorporated in these destinations.

| Source path | Destination | Reuse class | Chio modification boundary |
| --- | --- | --- | --- |
| `crates/libs/clawdstrike-policy-event/src/edr/deception.rs` | `crates/security/chio-security-types/src/deception.rs`, `crates/security/chio-decoy/src/registry.rs` | concept | Closed Chio types, bounded collections, private storage, and receipt identifiers |
| `crates/libs/clawdstrike-policy-event/src/edr/honey.rs` | `crates/security/chio-decoy/src/lifecycle.rs`, `crates/security/chio-decoy/src/materialize.rs` | concept | Explicit lifecycle transitions, tenant isolation, and fail-closed persistence |
| `crates/libs/clawdstrike-policy-event/src/edr/response.rs` | `crates/security/chio-security-types/src/response.rs`, `crates/security/chio-quarantine/src/state_machine.rs`, `crates/security/chio-quarantine/src/executor.rs` | concept | Durable reversible state, threshold-bound plans, and Chio receipt evidence |
| `crates/libs/hunt-correlate/src/rules.rs` | `crates/security/chio-quarantine/src/rules.rs` | concept | Ordered stages over Chio event kinds with explicit predecessor validation, bounded windows, grouping, policy-version binding, and bounded state estimates |
| `crates/libs/hunt-correlate/src/engine.rs` | `crates/security/chio-quarantine/src/correlation.rs` | concept | Verified Chio event ingress, tenant-rule-group partitioning, deterministic event-time watermarks, transactional durable partials, stable finding identifiers, and detector-health suppression |
| `crates/libs/clawdstrike/src/watermarking.rs` | `crates/security/chio-decoy/src/watermark.rs` | concept | Canonical Chio envelope, domain separation, and typed verification errors |
| `crates/services/clawdstrike-brokerd/src/api.rs` | `crates/security/chio-security-kernel/src/tripwire.rs` | concept | Guard ordering before invocation and denial on matcher failure |
| `crates/services/clawdstrike-brokerd/tests/e2e.rs` | `crates/security/chio-security-kernel/src/tripwire.rs` | test-vector adaptation | Chio-native controls and mutation-sensitive pre-invocation assertions |

The information-label and lattice implementation is derived from the Chio DLM contract and is not adapted from Clawdstrike.

Review record: source identity, listed paths, Apache-2.0 text, and source `NOTICE` verified on 2026-07-12.

Signed off: Chio security review, 2026-07-12.
