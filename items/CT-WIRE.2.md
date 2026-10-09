---
id: "CT-WIRE.2"
title: "Freeze passport and presentation challenge bytes"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-G0-SPECTOOL.1", "CT-WIRE.1"]
paths: ["spec/schemas/chio-trust/v1/agent-passport.schema.json", "spec/schemas/chio-trust/v1/agent-passport-presentation-challenge.schema.json", "spec/schemas/chio-trust/v1/agent-passport-presentation-response.schema.json", "tests/bindings/vectors/passport/v1.json", "crates/trust/chio-credentials/tests/passport_vectors.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: CT-WIRE. Passport lifecycle status is a separate artifact (CT-COOP.2). Also fix the test fixture at `crates/platform/chio-control-plane/src/trust_control/service_types/requests.rs:912` that uses the non-existent id `chio.passport-presentation-challenge.v1`. Shared spec files: `spec/schemas/MANIFEST.sha256`, `spec/schemas/registry.json` and `spec/wire-schemas.lock` are touched by every schema-adding item. Do not hand-merge them: regenerate the manifest with `scripts/check-chio-schema-registry.sh --write` (UR-G0-SPECTOOL.1) at rebase and append registry and lock entries; the check train lands schema items one at a time.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-credentials --test passport_vectors` passes; registry check passes; the bad fixture id is corrected.

## Log
- 2026-10-09T04:51:58Z connor: created
