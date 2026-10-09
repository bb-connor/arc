---
id: "COOP-3.3a"
title: "HTTPS remote co-signer (closes the STRAT-F15 relay or mTLS lane)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-CROSS.2", "WORK-W2.1b", "WORK-SLICE-G.1"]
paths: ["crates/trust/chio-federation/src/bilateral_https.rs", "crates/trust/chio-federation/tests/bilateral_https.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-3 ("the HOST-M3 door"), G4/G5 claim "the receiver admits a co-signed work commitment at its own door" (`prevent`, `ready_after_adr` CT-WORK, CT-CROSS); success-test criterion (b). Roadmap COOP-3 ("the remote co-signer over CT-CROSS. This also closes STRAT-F15's relay or mTLS lane"). Client and server types implementing `BilateralCoSigningProtocol` over CT-CROSS HTTPS, following the #1173 owner-services rules (authenticate the expected peer, reconstruct the signing body, never act as a generic signing RPC). No party holds both co-signer keys (STRAT-F15).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cosigner_down_yields_pending_not_redispatch` and `wrong_peer_refused` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
