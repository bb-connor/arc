# Receipt evidence lifecycle implementation plan

> Use superpowers:executing-plans inline, with one fresh integrated review.

**Goal:** close AP9/AP10 and the API receipt/export/retention continuation.
**Architecture:** signed HTTP projections in the existing immutable receipt writer;
shared kernel sink; authenticated retained snapshots; explicit custody/maintenance.
**Tech Stack:** Rust, SQLite, existing Ed25519/checkpoint and custody primitives.
**Spec:** [design](../specs/2026-10-03-receipt-evidence-lifecycle-design.md).

## Global Constraints

Fail closed; preserve typed causes and redact public errors. No new dependencies,
raised debt allowances or em dashes. Root implements in the existing isolated
worktree. Serialize Cargo; retain terminal evidence. Publication is authorized.

### Task 1: Truthful receipt semantics and complete HTTP projections

Files: chio-http-core receipt/evaluation and API-protect sidecar submission.
Interface: HttpReceipt::to_chio_receipt_with_keypair preserves the original signed
HTTP record and classification; VerifyReceiptResponse separates validity/authority.

- [x] Reproduce submitted record authorized=true through /chio/verify and missing
  fields in the core projection. Expected: RED.
- [x] Implement the closed observation profile, verified original HTTP projection
  and non-authorizing verification. Reject mixed profiles and foreign signers.
- [x] Run HTTP core and focused API semantic controls. Expected: all pass.

### Task 2: One immutable API receipt sink and stable private custody

Files: API proxy state/new evidence module/router/mediated/config; SQLite strict
append method; CLI runtime; owner fixtures and tests.
Interfaces: shared Arc<SqliteReceiptStore> backs HTTP, direct tool and kernel
receipts. Existing private custody loads signer; no secondary kernel receipt copy.

- [x] Reproduce duplicate replacement, missing export entries, ephemeral durable
  signer and receipt-history preload. Expected: RED.
- [x] Implement strict atomic sidecar append, core sink composition and kernel
  persistence, existing private seed requirement and no production history mirror.
- [x] Exercise real SQL update/delete refusal, duplicate/restart/write failures,
  stable signer, unsafe custody, mediated export and legacy row handling.
  Expected: pass without dropped legacy revocations.

### Task 3: Authenticated archive queries and exports

Files: SQLite retained read module, query helper and evidence export; tests.
Interfaces: retained snapshot supplies pinned live/archive connections and trusted
watermark; bounded query returns original sequence cursors and authorized scope.

- [x] Reproduce archived receipt omission in query/export. Expected: RED.
- [x] Implement retained pagination, prefix limits, complete child/tool export and
  original inclusion proofs using authenticated snapshots; refuse legacy omissions.
- [x] Test mixed live/archive pagination, tenant isolation, restart, missing and
  corrupted archives, uncommitted archive tails, and proof validation. Expected: pass.

### Task 4: Explicit owned retention in API-protect and chio start

Files: API config/state/evidence maintenance; CLI types/dispatch/runtime; docs/tests.
Interfaces: explicit retention config consumes Tasks 2/3 sink and stable signer;
one worker per store, stop/flush tied to serving lifetime.

- [x] Add failing CLI/config/scheduled rotation controls. Expected: RED.
- [x] Wire days/archive/interval, pre-effect validation and owned maintenance.
- [x] Exercise interval rotation, archive export, append/reopen, shutdown flush and
  persistent failure health. Expected: pass.

### Task 5: Integrated qualification, review and publication

- [x] Run changed-owner runtime suites, strict all-target Clippy, formatting and
  affected contract gates. Expected: pass with retained terminal command/log hashes.
- [x] One independent integrated review; retain rulings and verify required fixes.
- [x] Update roadmap/operator records, commit/push, verify remote SHA and propose
  next substantial remaining evidence/security batch.

## Review Focus

- Observation projections cannot upgrade into authorization through HTTP/core/export.
- Crash/retry and duplicate IDs cannot replace evidence or falsely report persistence.
- Archive path substitution, same-inode mutation, suffix rows and tenant filters
  cannot escape the authenticated snapshot/prefix boundary.
- Startup validates custody/retention before effects; legacy history remains explicit.
- Maintenance lifetime, writer failures and shutdown cannot silently lose receipts.
