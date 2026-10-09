---
id: "CT-SETTLE.1"
title: "Settlement composition contract, schemas and vectors (D1)"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-G0-SPECTOOL.1"]
paths: ["spec/SETTLEMENT_COMPOSITION.md", "spec/schemas/chio-settle/v1/**", "spec/vectors/settle/v1/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-SETTLE (one sweep owner; #1179's historical hold becomes a classified durable per-item deferral, never a `?` that aborts; delivery and money are separate facts; holds versus successors; read before finalizing; one signer-rotation rule), D1 (recommended; parked UR-D1). Sources: #1174 cross-spec decision 4 ("Reservation classes", `docs/superpowers/specs/2026-10-04-ftl-lessons-program-design.md:289-294`) and spec 9 (`2026-10-04-pure-admission-machine-design.md`): M7a (528-553: only `ReleaseAuthorized` in `Terminal(OutcomeUnknownAfterDispatch)` with a `Frozen` hold releases money; `Released` only on acknowledgement; per-attempt keys), M7b (554-558: `CaptureWaiverAuthorized` only in `Finalizing` with a known return and a reversible hold with a pending capture; illegal on unknown outcome), M11a (605-622: delivery refusal never decides money; an `Open` positive hold is retained for the payment owner's successor), R-9-05 (24, 1214: read the journal stage first; `Final` is recognized with no new capture, release or refund; `InFlight` completes under its original identity; tests at 1003-1009). #1160's sweep: `crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery.rs:124-201`, `recovery/page.rs`, `recovery/failure.rs::classify`, `recovery/deferral.rs` (`AdmissionRecoveryDeferralV1`, kinds at `admission_operation/recovery.rs:99-109`). Restate the rules for #1160's legacy sweep without depending on the spec 9 machine. Freeze: one sweep owner (#1160 `page.rs` and `operation.rs`); a closed deferral-kind taxonomy including a historical-hold kind; read the effective journal before finalizing; a stage table (`NotRequired`, `Open`, `InFlight`, `Final`); delivery separate from money; holds block finalization, receipts and delivery but never a co-signed monetary successor; a placeholder section for the D2 rule (CT-SETTLE.3). Schemas: deferral record (matching `AdmissionRecoveryDeferralV1`), payment-stage projection, delivery refusal, successor-authority binding. `MutuallyAgreedUnknown` and `ContractualCaptureWaiver` exist only on #1173 (slice delta); mark M7a and M7b vectors `pending: work-delta`. Shared spec files: `spec/schemas/MANIFEST.sha256`, `spec/schemas/registry.json` and `spec/wire-schemas.lock` are touched by every schema-adding item. Do not hand-merge them: regenerate the manifest with `scripts/check-chio-schema-registry.sh --write` (UR-G0-SPECTOOL.1) at rebase and append registry and lock entries; the check train lands schema items one at a time.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `bash scripts/check-chio-schema-registry.sh` and `cargo xtask codegen --lang rust --check` pass; every vector validates against its schema.

## Log
- 2026-10-09T04:51:58Z connor: created
