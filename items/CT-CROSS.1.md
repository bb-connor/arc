---
id: "CT-CROSS.1"
title: "Cross-org transport contract for co-signing and bilateral delivery (D4)"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-COOP.1"]
paths: ["spec/CHIO_CROSS_ORG_TRANSPORT.md", "spec/schemas/chio-federation/v1/cross-org-envelope.schema.json", "spec/schemas/chio-federation/v1/bilateral-delivery.schema.json", "tests/bindings/vectors/cross-org/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-CROSS, D4 (recommended: HTTPS with mTLS or signed bodies by default; iroh optional with self-hosted relays; parked UR-D4), U9 (decide early: n0's free public iroh relays end 2026-12-31). `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md` defines the predicate and DSSE envelope with no transport; `chio_federation::bilateral::BilateralCoSigningProtocol` (`crates/trust/chio-federation/src/bilateral.rs`) has only `InProcessCoSigner` and `IrohBilateralCoSigner`; #1161's peer transport is example-only and does not satisfy STRAT-F15. Specify two HTTPS auth profiles: mTLS with the client SPKI pinned from the partner card, or an Ed25519 signed envelope over method, path, audience, body sha256, timestamp, nonce and sender key id. Messages wrap the existing `CoSigningRequest`/`DsseCoSigningRequest` and bilateral delivery with idempotency keyed on the original statement. Cite #1173's owner-services rules (`docs/superpowers/specs/2026-10-03-work-owner-services-design.md`): authenticate the expected peer, reconstruct the signing body, check retained invocation, treaty and audience before signing; never act as a generic signing RPC. Shared spec files: `spec/schemas/MANIFEST.sha256`, `spec/schemas/registry.json` and `spec/wire-schemas.lock` are touched by every schema-adding item. Do not hand-merge them: regenerate the manifest with `scripts/check-chio-schema-registry.sh --write` (UR-G0-SPECTOOL.1) at rebase and append registry and lock entries; the check train lands schema items one at a time.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Wire-schema check passes; vectors include replay, wrong audience, wrong peer and body swap negatives.

## Log
- 2026-10-09T04:51:58Z connor: created
