---
id: "COOP-2.4"
title: "Live revocation feed at the door (replaces startup-only revocation load)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-CTRL.2", "COOP-1.1"]
paths: ["crates/products/chio-api-protect/src/proxy/state.rs", "crates/products/chio-api-protect/src/proxy/config.rs", "crates/products/chio-api-protect/src/proxy/revocation_feed.rs", "crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs", "crates/platform/chio-control-plane/src/trust_control/service_runtime/router/door.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-2 ("a production-grade pair"), G2 exit (revocation propagates live; rotation exercised; independent-operation record published). Roadmap gap: "The door ignores revocations made after it started". `load_revocation_db_ids` (`proxy/mediated.rs:38`) loads once (`proxy/state.rs:515-532` logs "Revocations recorded after startup are not observed here"); trust-control's cursor-based `/v1/internal/revocations/delta` (`trust_control/cluster/deltas.rs:32`) is behind cluster-peer auth only. Add a door-scoped delta (cursor plus stream id) under the `DoorWorkload` principal in the `door` router fragment; the door polls it; a stale feed denies with a signed `revocation_feed_stale` receipt.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-api-protect revocation_feed` passes: `revocation_after_start_is_enforced`, `stale_feed_fails_closed`.

## Log
- 2026-10-09T04:51:58Z connor: created
