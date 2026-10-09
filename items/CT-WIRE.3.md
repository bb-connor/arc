---
id: "CT-WIRE.3"
title: "Freeze federated issuance and evidence package bytes"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-WIRE.1", "CT-COOP.2"]
paths: ["spec/schemas/chio-federation/v1/federated-issue-request.schema.json", "spec/schemas/chio-federation/v1/federated-issue-response.schema.json", "spec/schemas/chio-federation/v1/federated-delegation-policy.schema.json", "spec/schemas/chio-federation/v1/federated-evidence-share.schema.json", "spec/schemas/chio-evidence/v1/**", "tests/bindings/vectors/issuance/v1.json", "tests/bindings/vectors/evidence/v1.json", "crates/products/chio-cli/tests/evidence_export_vectors.rs", "crates/platform/chio-control-plane/tests/federated_issue_vectors.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: CT-WIRE (issuance and evidence bytes). The existing `chio-federation/v1/issuance-*.schema.json` files belong to the separate chio-federation-authority flow; these schemas cover `trust federated-issue` (`service_types/requests.rs:44,60`) and the evidence export manifest family. Include the inbox pickup response and door receipt (`chio_http_receipt_v1`) embedding that COOP-1 needs, consistent with CT-COOP.2. Shared spec files: `spec/schemas/MANIFEST.sha256`, `spec/schemas/registry.json` and `spec/wire-schemas.lock` are touched by every schema-adding item. Do not hand-merge them: regenerate the manifest with `scripts/check-chio-schema-registry.sh --write` (UR-G0-SPECTOOL.1) at rebase and append registry and lock entries; the check train lands schema items one at a time.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-cli --test evidence_export_vectors` and `cargo test -p chio-control-plane --test federated_issue_vectors` pass; `cargo xtask freeze-vectors --check` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
