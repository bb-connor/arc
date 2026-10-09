---
id: "CT-COOP.2"
title: "Signed passport lifecycle status, holder pickup proof, HTTP DPoP profile"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-COOP.1"]
paths: ["spec/CHIO_PASSPORT_STATUS.md", "spec/CHIO_HTTP_DPOP.md", "spec/schemas/chio-trust/v1/passport-status-statement.schema.json", "spec/schemas/chio-federation/v1/issuance-pickup-proof.schema.json", "spec/schemas/chio-http/v1/dpop-proof.schema.json", "tests/bindings/vectors/passport-status/**", "tests/bindings/vectors/issuance-pickup/**", "tests/bindings/vectors/http-dpop/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-COOP ("issuer-signed passport lifecycle status; DPoP possession for federated grants at the door"), D6 (recommended: require DPoP; parked UR-D6). Facts on #1160: federated issue is `handle_federated_issue` in `crates/platform/chio-control-plane/src/trust_control/passport_handlers.rs:1056-1501`; lifecycle status is read only from B's own `--passport-statuses-file` (`config_and_public.rs:679`); `PassportLifecycleResolution` (`crates/trust/chio-credentials/src/passport.rs:111`) is unsigned; `PassportStatusDistribution {resolve_urls, cache_ttl_secs}` exists but nothing pulls it; DPoP exists in `crates/kernel/chio-kernel/src/dpop.rs` (`DpopProofBody` v2, `verify_dpop_proof` at 747) with a durable replay store, but the HTTP door rejects DPoP-required grants (`crates/platform/chio-http-core/src/authority.rs` around 1404) and projects calls with `dpop_proof: None` (line 1012). Specify: an issuer-signed lifecycle statement (passport_id, subject, issuer, state, revoked_at, issued_at, `next_update`; relying parties fail closed after `next_update`; optional epoch-root non-inclusion proof from `crates/trust/chio-revocation-oracle`); a holder pickup proof signed by the passport subject key over challenge_id, audience (B's advertise URL), nonce and issued_at (60-second window, single use); HTTP DPoP reusing `DpopProofBody` v2 with `tool_server="http"`, `tool_name="<METHOD> <route_pattern>"` (matching the `HttpReceipt` projection) and `action_hash` over a canonical request (method, path, query, body sha256), header convention as chio-mcp-remote's `dpop`. ADR-0007 (`docs/adr/ADR-0007-dpop-binding-format.md`) is the existing binding ADR: cite and extend, do not contradict. Shared spec files: `spec/schemas/MANIFEST.sha256`, `spec/schemas/registry.json` and `spec/wire-schemas.lock` are touched by every schema-adding item. Do not hand-merge them: regenerate the manifest with `scripts/check-chio-schema-registry.sh --write` (UR-G0-SPECTOOL.1) at rebase and append registry and lock entries; the check train lands schema items one at a time.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Wire-schema check passes; negative vectors: wrong audience, replayed nonce, stale `next_update`, wrong route binding.

## Log
- 2026-10-09T04:51:58Z connor: created
