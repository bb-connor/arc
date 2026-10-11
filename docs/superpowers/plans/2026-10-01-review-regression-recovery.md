# Review regression recovery implementation plan

> Use `superpowers:executing-plans` inline. The user selected fixing the newly
> reviewed regressions before the queued 23-reader batch. One independent review
> covers the completed source batch; no delegated implementation.

**Goal:** Repair SR1, PB1, PR1 and PR6, the related PB2/PR2 numeric regressions,
and GT1/CA1's structural CI blockers through real producer and recovery paths.

**Architecture:** Preserve authentication, canonical signed-record contracts,
file custody and fail-closed authority checks. Unsigned documents use original
duplicate-aware ordinary JSON decoding. Recovery distinguishes authenticated
expiry and supported schema evolution from corruption or authority outages.

**Tech stack:** Existing Rust/Serde/SQLite/clock and custody owners, Python/Bash
source gates, provider conformance and xtask fixtures.

**Spec:** `docs/reviews/2026-10-01-execution-review.md` and its GT, SR, PB and PR
slice reports; the existing unrepresentable-defects design, mechanisms A/B/C.
Base: `fb1cfc30241592e6852226efbca6162f1b39c8e3`, existing isolated source
worktree `/tmp/arc-security-launch`, branch `packet/3-retention-accounting`.

## Constraints and review focus

- No permissive fallback for signed input, higher size caps or lint allowances.
- Unsigned producer documents accept ordinary finite floats and native integer
  values, including `21.0`, `0.0`, `0.50`, `1e-05` and `9007199254740993`.
  Typed field constraints still apply. Invocation bytes remain canonical and
  bound to the evaluated arguments; duplicate keys reject before projection.
- SDK/operator input is distinct from embedded signed capability/receipt input.
- Old retained stores must reopen and append while corrupt, missing or
  substituted archive evidence continues to refuse authority.
- Expired authenticated Ready sessions terminalize durably without spawning an
  upstream. Clock rollback/outage and failed persistence cannot erase authority.
- Private seed files keep owner, single-link, no-follow and permission checks;
  their unsigned JSON accepts formatting. Producers must write secure files.
- Keep new raw logs outside Git. Commit concise results and hashes. Existing
  published history is preserved; no history rewrite or merge is authorized.
- Qualification is local until exact-candidate hosted checks actually finish.

## Task 1: Restore structural CI execution (GT1/CA1)

Files: `scripts/check-review-slices.py`, the domain and lint parity self-tests,
`.github/workflows/ci.yml` and a shared structural-gate runner if needed.

- [x] Reproduce unclassified paths and both stale-debt self-test failures.
- [x] Classify `.config/**` and `chio-profile-probe` under their existing owners.
- [x] Make debt fixtures create their own explicit live entries, independent of
  the production debt table, with expired/stale/over-cap controls intact.
- [x] Execute every structural command even when an earlier one fails, preserve
  each terminal result, and fail the required step if any command fails.
- [x] Run the complete structural step and resolve failures introduced by this
  batch; record pre-existing blockers and distinguish external prerequisites
  from passing results. See the execution report for the expanded failure queue.

## Task 2: Decode according to the producer (PR1/PB2/PR2)

Files: provider-adapter-core input/SSE/stream assembly, eight provider adapters
and provider conformance, egress JSON helper, tool-call-fabric validation,
MCP frame/request readers, OpenAPI JSON, API-protect request bodies and CLI
operator configuration. Reuse the existing shared `UntrustedJsonText` methods.

- [x] Add real lift/lower/stream and SDK/operator producer controls with ordinary
  floats and full-width integers; retain duplicate, malformed and bound controls.
- [x] Observe their failures before replacing signing canonicalizers on unsigned
  ingress. Keep signed headers, nonce/capability and persisted artifacts strict.
- [x] Preserve exact normalized invocation bytes and object shape through the
  actual invocation validator; separate unsigned and signed helper call sites.
- [x] Run affected provider/MCP/OpenAPI/product suites and conformance selectors.

## Task 3: Restore archived-store upgrades (SR1, related SR6)

Files: SQLite receipt-store checkpoint/retention support and
`receipt_store/tests/writer_checkpoint_boundaries.rs` or an owned child module.

- [x] Add a full live-plus-archive v6 downgrade/reopen/append regression, with a
  live-only downgrade control and corrupted archive negative controls.
- [x] Observe the startup serving failure. Restore authenticated predecessor
  projection across supported archive schema evolution before accepting the
  retained head; do not infer trust from a watermark alone.
- [x] Preserve read-only archive access where possible, verify archive identity
  and signatures, and include predecessor identity in co-copy consistency checks.
- [x] Run checkpoint upgrade, retention rotation/repair and serving-fence suites.

## Task 4: Expire persisted MCP sessions before restore (PB1)

Files: `remote_mcp/http_service.rs`, `session_core/factory.rs`, existing durable
session ledger/store owners and `tests/session_recovery.rs`.

- [x] Seed an authenticated expired Ready row, run production startup restore,
  and prove it neither calls the upstream factory nor poisons subsequent restart.
- [x] Observe the failure; durably fence/tombstone expired rows before activation
  and refuse unresolved clock or persistence failures without deleting the row.
- [x] Cover expiry during restoration and future/rollback timestamps.
- [x] Run session recovery, clock custody and persistence suites.

## Task 5: Align private seed producers and readers (PR6)

Files: CLI private input and relay/iroh key readers, xtask relay key producers and
assurance fixtures, relay runbook and production-linked fixture tests.

- [x] Reproduce rejection of a secure pretty-printed key with a trailing newline,
  and verify repository fixture workflows fail with their current file modes.
- [x] Parse unsigned seed objects directly into zeroizing fields with duplicate
  and unknown-field rejection; retain secure filesystem custody.
- [x] Make xtask writers and fixture staging produce owner-only files without
  weakening production permissions or mutating the committed example key.
- [x] Run the real relay tick/export/archive/package fixture paths and iroh key
  reader controls; retain wrong-mode/link/duplicate negatives.

## Task 6: Review, qualify and publish

- [x] Update decoder contracts where behavior actually changes and describe all
  six shared decode methods with their producer contracts (TR10/CA8 scope).
- [x] Run owner tests and direct consumers, source gates and appropriate Clippy.
  Obtain one fresh independent review and fix material findings with regressions.
  Complete within the stated owner boundaries; broader CI, CLI integration and
  unchanged-source Clippy failures are retained in the execution report.
- [x] Record exact review finding dispositions, retained failures, source hashes
  and remaining priorities. No reader-census completion claim for this batch.
- [x] Commit/push authorized security source and concise evidence; verify the
  remote SHA. Obtain exact-candidate hosted results where the environment allows,
  preserving any actual external blocker without claiming green CI.
