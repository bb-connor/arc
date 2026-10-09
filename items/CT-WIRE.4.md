---
id: "CT-WIRE.4"
title: "Freeze bilateral co-sign bytes (DSSE PAE)"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-WIRE.1"]
paths: ["spec/schemas/chio-federation/v1/bilateral-cosign-invocation.schema.json", "tests/bindings/vectors/cosign/v1.json", "crates/tooling/chio-conformance/tests/cosign_frozen_vectors.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: CT-WIRE (co-sign bytes). `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md` defines the predicate and DSSE envelope; the slice and invocation schemas exist but no predicate schema; existing tests (`chio-conformance/tests/b4_*`, `c2_*`) are round-trips, not frozen vectors. #1173 slice gamma rewrites the spec (+727/-111) and adds `bilateral_dsse/preimage.rs::reconstruct_dsse_pae` (the co-signer must not be a signing oracle). Freeze the gamma revision (WORK-SLICE-G.1 lands it in wave 2) as the preview bytes: write the vectors from #1173's revised spec now, and require G.1 to pass this test at landing. Record the choice in the freeze inventory.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-conformance --test cosign_frozen_vectors` covers DSSE PAE bytes plus negatives for a missing predicate field and a wrong payloadType (the positive vectors may be marked pending until WORK-SLICE-G.1 lands, and the test fails if they stay pending after it).

## Log
- 2026-10-09T04:51:58Z connor: created
