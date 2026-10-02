# Operational regression recovery implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan inline. Steps use checkboxes for tracking.

**Goal:** Close PB3, PR3, PR5, NC2 and TR2 with current-source regression evidence and production-safe recovery.

**Architecture:** Keep failed authority decisions separate from service liveness. Recover service epoch time from a validated monotonic anchor; never freeze expiry. Give certificate input its own complete bounded contract. Preserve ordered repeated response headers through persistence. Distinguish definitive threat-intelligence outcomes from provider failures.

**Tech Stack:** Rust, Tokio, SQLite, Cargo, Python and GitHub Actions.

**Spec:** The next queue in `docs/reviews/2026-10-02-ci-authority-time-repair-execution.md`; PB3 in `2026-10-01-execution-review-protocol-boundaries.md`, PR3/PR5 in `2026-10-01-execution-review-product-cli-provider-readers.md`, NC2 in `2026-10-01-execution-review-native-consumers.md`, TR2 in `2026-10-01-execution-review-trust-guard-platform-economy-readers.md` (all under `docs/reviews/`); `docs/security/trusted-time.md`.

## Global constraints

- Fail closed on unavailable authority time, invalid signed input, unknown receipt membership, incomplete collections and malformed provider responses.
- Canonical signed payloads, existing custody/size/credential protections and strict Clippy rules remain enforced.
- No new lint allowances, skips, production unwrap/expect or dependency exemptions. No em dashes.
- Work in `/tmp/arc-security-launch`; preserve unrelated worktrees and `output/`.
- Commit and push the existing authorized security branch. No merge or operator activation.
- Serialize Cargo graphs. Preserve raw terminal evidence outside Git and report source, local and hosted acceptance separately.

## Review focus

- Background clock failures cannot lose pending work or accidentally dispatch it.
- Submillisecond polling, forward wall steps and intermittent errors cannot extend expiry or discard a monotonic floor.
- Ambiguous or corrupt session membership cannot silently disappear from a certificate.
- Repeated response fields must remain ordered after durable replay; request-header uniqueness stays enforced.
- Only a documented, bounded VirusTotal NotFoundError response is an unseen outcome; authentication, malformed bodies and transport failures still deny.

### Task 1: PB3 MCP session liveness

**Files:** `crates/protocol/chio-mcp-edge/src/runtime/tasks.rs`, `runtime/runtime_tests/protocol_boundaries.rs` and a dedicated clock-recovery test module.
**Interfaces:** Existing Clock and serve_message_channels; background ticks preserve queued tasks on clock failure, request handlers retain typed errors.

- [x] Add actual serve-loop controls for idle and pending work, failed requests and recovery; reproduce premature session termination.
- [x] Skip clock-dependent background work when there is no pending work, and contain only clock errors at the background service boundary.
- [x] Run `cargo test --locked -p chio-mcp-edge --lib`. Expected: all owner tests pass, including no dispatch under failure and recovery without reconnecting.

### Task 2: PR3 service clock recovery

**Files:** `crates/security/chio-security-types/src/clock.rs`, `src/clock/system.rs`, a dedicated advancing-clock module/tests; `crates/products/chio-api-protect/src/proxy/clock.rs` and owning kernel/replay integration tests; `docs/security/trusted-time.md`.
**Interfaces:** Shared Clock readings remain fallible. API-protect uses an elapsed-time epoch floor rather than a frozen high water. Existing strict ClockFence consumers retain their contract.

- [x] Reproduce backward-step outage and pin advancing expiry, unavailable/monotonic-regression refusal, forward steps and fractional elapsed time.
- [x] Implement one checked monotonic epoch projection and a native adapter using the existing native sampling owner; connect API-protect and its existing shared owners.
- [x] Exercise actual kernel and replay owners with the shared recovering clock.
- [x] Run changed security-types and API-protect suites. Expected: recovery permits fresh valid work, expired authority and replay remain rejected.

### Task 3: PR5 certificate session collection

**Files:** `crates/products/chio-cli/src/cert.rs`, a dedicated receipt-collection owner/tests, certificate operator documentation.
**Interfaces:** `load_session_receipts` returns every matching signed receipt within explicit session bounds, never a silently truncated result.

- [x] Reproduce a valid session beyond 4,096 entries and contamination by a provably unrelated corrupt row.
- [x] Implement certificate-specific bounds and exact, unambiguous membership checks. Unknown membership or an incomplete/over-budget target session fails with row context.
- [x] Run certificate unit and command integration controls. Expected: long valid sessions certify; exact identifiers, malformed target rows and all bounds remain enforced.

### Task 4: NC2 repeated provider response headers

**Files:** `crates/security/chio-secret-broker/src/generic_https.rs`, `protocol.rs`, `receipt.rs` and service dispatch/replay tests.
**Interfaces:** Response header commitments cover a stable name-sorted vector retaining value order. Request header uniqueness is unchanged.

- [x] Reproduce rejection of repeated Vary/Link fields through real broker dispatch and durable replay.
- [x] Separate response validation from request uniqueness and use stable sorting before signing.
- [x] Run broker owner tests. Expected: repeated fields delivered and replayed unchanged, provider executes once, credential/size/framing controls still pass.

### Task 5: TR2 VirusTotal unseen outcomes

**Files:** `crates/guards/chio-external-guards/src/external/threat_intel/virustotal.rs`, `tests/threat_intel.rs` and threat-intelligence documentation.
**Interfaces:** A bounded, valid HTTP 404 NotFoundError is a successful guard decision, with explicit unseen policy defaulting to Deny. Provider failures retain the existing error path.

- [x] Reproduce repeated unseen results opening the circuit, using the real ExternalGuardAdapter and HTTP fixture.
- [x] Add explicit unseen-result policy and strict documented error decoding; keep actual provider errors distinct.
- [x] Run external-guard and affected adapter suites. Expected: unseen decisions cache and do not open the failure circuit; malformed/transport failures retain denial behavior.

### Task 6: Qualification, review and publication

**Files:** Execution report and compact qualification artifact under `docs/reviews/`.
**Interfaces:** Prior task results feed exact commands, terminal logs/hashes and source manifests.

- [ ] Run formatting, warnings-denied Clippy for changed owners and affected source/CI contracts. Expected: terminal successful outcomes without exceptions.
- [ ] Obtain one fresh independent review; repair Important/Critical findings with regression evidence.
- [ ] Record the prior broader consumer workflow's terminal result separately from its passing native acceptance.
- [ ] Commit and push the batch, verify remote SHA, confirm each task and propose the next queue.
