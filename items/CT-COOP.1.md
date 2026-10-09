---
id: "CT-COOP.1"
title: "Partner card and evidence trust-anchor format"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-G0-SPECTOOL.1"]
paths: ["spec/CHIO_PARTNER_CARD.md", "spec/schemas/chio-federation/v1/partner-card.schema.json", "spec/schemas/chio-federation/v1/evidence-trust-anchor.schema.json", "tests/bindings/vectors/partner-card/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-COOP ("the partner card: org DID, trust-control URL, authority key history, receipt-signer keys, status resolve URL ... the evidence trust-anchor format"). Facts on #1160: federated issue is `handle_federated_issue` in `crates/platform/chio-control-plane/src/trust_control/passport_handlers.rs:1056-1501`; lifecycle status is read only from B's own `--passport-statuses-file` (`config_and_public.rs:679`); `PassportLifecycleResolution` (`crates/trust/chio-credentials/src/passport.rs:111`) is unsigned; `PassportStatusDistribution {resolve_urls, cache_ttl_secs}` exists but nothing pulls it; DPoP exists in `crates/kernel/chio-kernel/src/dpop.rs` (`DpopProofBody` v2, `verify_dpop_proof` at 747) with a durable replay store, but the HTTP door rejects DPoP-required grants (`crates/platform/chio-http-core/src/authority.rs` around 1404) and projects calls with `dpop_proof: None` (line 1012). Freeze `chio.partner-card.v1`, signed by the org `did:chio` key, carrying: trust-control advertise URL; authority key history (key, generation, activated_at, retired_at, lifecycle; mirror `AuthorityTrustedKeySnapshot`, `crates/kernel/chio-kernel/src/authority.rs:1196`); receipt-signer keys by role (`trust-control`, `api-protect`, `mcp-edge`) with validity windows; status resolve URL plus TTL; inbox submit and pickup URLs; revocation feed URL; optional `CheckpointPublicationTrustAnchorBinding` (`chio-core-types/src/receipt/checkpoint.rs:12`); `dpop_required` (D6); optional mTLS SPKI pins (CT-CROSS); serial plus `previous_card_hash` (a new card must be signed by a key in the previous card's history). `chio.evidence-trust-anchor.v1` is the verifier-side projection replacing repeated `--trusted-kernel-pubkey`. Reuse vocabulary from `chio-federation/v1/peer-pins.schema.json`, `verifier-trust-bundle.schema.json`, `chio-trust/v1/trust-root.schema.json`, `key-state.schema.json`. Boundary: `detect_only` for offline verification against operator-pinned keys, `planning_status: ready_after_adr`. Shared spec files: `spec/schemas/MANIFEST.sha256`, `spec/schemas/registry.json` and `spec/wire-schemas.lock` are touched by every schema-adding item. Do not hand-merge them: regenerate the manifest with `scripts/check-chio-schema-registry.sh --write` (UR-G0-SPECTOOL.1) at rebase and append registry and lock entries; the check train lands schema items one at a time.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/check-wire-schemas.py` passes with the new identifiers; vectors cover positives and negatives (bad signature, broken continuity, rolled-back serial, receipt signed outside its signer window), executed by CT-COOP.3.

## Log
- 2026-10-09T04:51:58Z connor: created
