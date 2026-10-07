# Chio Controller and Omarchy Plugin Implementation Plan

| Boundary scope | `boundary_class` | `planning_status` | Decision and execution gate |
| --- | --- | --- | --- |
| `operator_admission` | `prevent` | `blocked_by_adr` | Owner decisions F2/F3 on shared ABI and native operator principal; then P0 exact compatibility. P1 continues to refuse mutation methods. |
| `status_projection` | `detect_only` | `blocked_by_adr` | Owner decisions F1/F2/F5 on first product, shared task model and Omarchy surface; then P0-OPERATOR-FACADE and P0-READONLY-TUPLE. |
| `navigation_guidance` | `advisory_only` | `blocked_by_adr` | Owner decisions F2/F5 govern this proposed UI; navigation and displayed guidance never grant scope or stand in for native approval. |

Metadata follows [ADR-0011](../../../adr/ADR-0011-boundary-taxonomy-product-wording.md) and the [plan-set inheritance and owner-decision gate](README.md#boundary-metadata-and-inheritance). Classes describe proposed boundaries, not delivered qualification.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the shared operator API/controller scaffold and a qualified P1 read-only native Omarchy plugin, with every execution/approval/export mutation refused until its later native phase is qualified.

**Architecture:** A new Rust product crate hosts the session controller, stdin/stdout client shim and navigation opener. One QML service owns the desktop connection; monitor widgets and the lazy panel consume bounded projections. Native authorities retain admission, effect and recovery ownership; the P1 scaffold never substitutes simulated approval or agent execution.

**Tech Stack:** Existing workspace Rust 2021/toolchain and dependencies, Tokio AF_UNIX, Serde, existing strict Chio canonical JSON, SQLite through workspace rusqlite, Qt Quick/Quickshell, Python standard-library qualification orchestration and Omarchy's validator.

---

Status: Proposed implementation plan, not executed. All new runtime paths below are proposed. Confidence: high in the module and test boundaries; moderate in actual Qt/Omarchy integration until rendered Linux acceptance. Follow [controller ownership](../../specs/2026-10-07-omarchy-integration/04-controller-architecture.md), [operator protocol](../../specs/2026-10-07-omarchy-integration/05-operator-protocol.md), [plugin contract](../../specs/2026-10-07-omarchy-integration/03-omarchy-plugin.md), [experience](../../specs/2026-10-07-omarchy-integration/02-desktop-experience.md), [state](../../specs/2026-10-07-omarchy-integration/14-state-evidence-data.md) and their machine contracts. Tests and code sketches below specify concrete interfaces to create; they are not claims that those interfaces already exist.

## Entry gate, scope and ownership

Before execution, create an isolated worktree under the normal project workflow and inspect its actual instructions and dirty state. P0 must supply a named compatibility record and source pins. If P0 has only source analysis, implementation/unit tests may proceed, but rendered P1 acceptance remains open. Test fixtures can exercise unavailable paths but cannot satisfy native guest, approval, operator-enrollment, provider or publication gates.

The first implementation has no guest launch capability. `task.create`, `task.cancel`, `task.resume`, `approval.submit` and `receipts.export` return the specified `prerequisite_unavailable` error in P1; inspect existing task/evidence references only through qualified read adapters. Reserving code paths or tests for future mutation semantics does not enable them. Do not claim a fresh P1 installation has live tasks when the native read adapter is unavailable.

The canonical editable QML source is `integrations/omarchy/fixtures/plugin/`. Task 13 exports it to a separately publishable Git repository whose root is the installable plugin. That delivery repository is generated and must not be edited independently; its provenance maps back to the exact publicly available canonical source revision and subtree. P7 publishes a pinned qualification candidate and installs it before the independent clean-host gate, then promotes the supported release only after P7 passes. No source-ownership transfer is needed for this generated delivery model. The implementation worker owns only this plan's files; coordinate shared contract/Cargo changes and preserve other workers' work.

## File map

| Proposed path | Responsibility |
|---|---|
| `crates/products/chio-desktop/Cargo.toml`, `src/lib.rs` | Product crate and explicit module exports; three named binaries below. |
| `src/bin/chio-desktop-controller.rs` | Session-scoped entry, no raw task execution logic. |
| `src/bin/chio-desktop-client.rs` | Fixed `--stdio` bridge entry. |
| `src/bin/chio-desktop-open.rs` | Validated navigation-only opener. |
| `src/contracts/{mod.rs,frame.rs,message.rs,validation.rs,canonical.rs}` | Bounded wire framing, exact machine-contract types and strict semantic validation. |
| `src/controller/{mod.rs,server.rs,peer.rs,dispatch.rs,events.rs,health.rs}` | Authenticated operator transport, negotiated session and read-only dispatch. |
| `src/store/{mod.rs,schema.sql,projection.rs,snapshots.rs}` | Single-owner SQLite projections, events and consistent snapshot cursors. |
| `src/adapter/{mod.rs,readonly.rs,refusing.rs}` | Qualified native observation or explicit unavailable response, never fabricated authority. |
| `src/supervision/{mod.rs,session.rs}` | Controller-session lifecycle and shutdown; no P1 guest launcher. |
| `src/client/{mod.rs,stdio.rs,open.rs}` | Bounded byte bridge and literal argv opener. |
| `tests/{frame_contract.rs,request_contract.rs,store_contract.rs,socket_contract.rs,event_contract.rs,client_contract.rs,p1_readonly.rs}` | Independent boundary and negative-control tests. |
| `integrations/omarchy/fixtures/plugin/{manifest.json,Service.qml,BarWidget.qml,Panel.qml,Model.js,compatibility.json}` | Canonical development QML fixture. |
| `integrations/omarchy/fixtures/p1/` | Clearly identified synthetic protocol fixtures; never installed as live task state. |
| `integrations/omarchy/tests/{test_contracts.py,test_model.mjs,test_qualify.py,test_registration.py}` | Machine contracts, pure QML model, qualifier refusal and ownership tests. |
| `integrations/omarchy/qualify.py` | Future reproducible P1 runner with host inventory, external oracles and structured results. |
| `integrations/omarchy/README.md` | Developer invocation, real-host prerequisites and exact unsupported capabilities. |
| `packaging/omarchy/export_plugin.py`, `packaging/omarchy/tests/test_plugin_release.py` | Reproducible export and complete-inventory tests for the generated plugin delivery repository. |
| `packaging/omarchy/plugin-release.json` | Public canonical/delivery source commitments, artifact and plugin-inventory hashes handed to P7. |

Paths beneath `src/` in the table are relative to `crates/products/chio-desktop/`. Existing files changed: root `Cargo.toml` workspace member list and `Cargo.lock`; no unrelated crate refactor. Existing strict parser is `crates/core/chio-core-types/src/canonical.rs::canonical_json_bytes_from_str`, re-exported as `chio_core_types::canonical_json_bytes_from_str` in that crate's `src/lib.rs`. It rejects duplicate keys and unsafe/rounded numeric input before signing. Use that existing API; do not canonicalize a lossy `serde_json::Value` first.

## Task 1: Lock down corpus and P1 test harness

**Files:** Create `integrations/omarchy/tests/test_contracts.py`, `integrations/omarchy/tests/test_qualify.py`, `integrations/omarchy/qualify.py`, `integrations/omarchy/fixtures/p1/README.md`, `integrations/omarchy/README.md`. Read `docs/superpowers/specs/2026-10-07-omarchy-integration/contracts/fixture-catalog.json`, `method-catalog.json` and `README.md`. The exact wire schemas are `operator-request.schema.json`, `operator-response.schema.json`, `operator-event.schema.json` and `common.schema.json` in that contracts directory. Example names and expected validity come from the catalog, including `request-<method-hyphen>.json`.

- [ ] **Write the failing corpus test.** Read every example declared by the contract catalog, assert it names an existing schema, validate its schema and declared semantic outcome, and require both structurally valid and invalid requests for every known method. Derive coverage from the request schema binding and decoded `method`, never the filename; an unknown method does not cover a known method's negative case. For structurally valid Hello candidates, separately validate catalog `hello_outcome` against identifier equality and the selected protocol in `method-catalog.json`. A well-formed unsupported or mismatched Hello remains schema-valid but must produce its typed negotiation refusal. Require the malformed date-time fixture to fail with format checking active. The Python test must invoke the existing specification validator when available; do not make a second incompatible schema dialect. Add this concrete qualifier refusal sketch:

  ```python
  def test_missing_host_evidence_cannot_pass(self):
      result = subprocess.run(
          [sys.executable, "integrations/omarchy/qualify.py",
           "--phase", "P1", "--profile", "observe-v1",
           "--bundle", str(self.missing_bundle), "--output", str(self.output)],
          text=True, capture_output=True, check=False)
      self.assertNotEqual(result.returncode, 0)
      self.assertFalse((self.output / "PASS").exists())
  ```

  Define `self.output` in `setUp` as a new child of `tempfile.TemporaryDirectory`; set `self.missing_bundle` to a nonexistent sibling JSON path; release the temporary root in `tearDown`. Import `subprocess`, `sys`, `tempfile`, `unittest` and `Path` in the test file. A missing runner initially makes this fail on the required structured refusal artifact added next, not falsely pass because the command is absent.
- [ ] **Run red:** `python3 -m unittest discover -s integrations/omarchy/tests -p 'test_contracts.py' -v`. Expected: failure naming the absent corpus runner/catalog binding. Also require `test_missing_host_evidence_cannot_pass` to assert a parsed JSON `status="blocked"` and `missing_evidence` list, so an arbitrary exit code is insufficient.
- [ ] **Create only the harness skeleton and fixture provenance.** Document fixture mode as synthetic, require exact schema catalog entries, and define the future qualifier arguments `--phase P1 --profile observe-v1 --bundle /absolute/qualified-bundle.json --output /absolute/new-evidence-dir` with `--fixture-only` as a separately labeled mode. Missing real host evidence writes `qualification.json` with blocked status and exits nonzero; fixture mode never writes a P1 PASS claim. The bundle contains the pinned host/profile/evidence prerequisites; no independent `--host-record` convention is introduced.
- [ ] **Run green:** the focused corpus and qualifier-negative tests pass with fixture outputs clearly labeled. Record the source/schema digests used by each fixture.
- [ ] **Commit:** stage only the five created files and use `test: define omarchy p1 contract and qualification oracles`.

## Task 2: Add crate and strict bounded frame decoder

**Files:** Modify root `Cargo.toml`/`Cargo.lock`; create product `Cargo.toml`, `src/lib.rs`, `src/contracts/mod.rs`, `src/contracts/frame.rs`, `src/contracts/canonical.rs`, `tests/frame_contract.rs`.

- [ ] **Write failing decoder tests** against this explicit proposed interface:

  ```rust
  pub const MAX_FRAME_BYTES: usize = 65_536;
  pub enum FrameError { TooLarge, InvalidUtf8, Incomplete, InvalidJson }
  pub struct FrameDecoder { buffer: Vec<u8> }
  // new() starts empty; feed() returns complete raw JSON frames without LF;
  // finish() rejects a nonempty unterminated buffer.
  ```

  Test `FrameDecoder::new().feed(&vec![b'a'; MAX_FRAME_BYTES])` returns `TooLarge` because an LF cannot fit. Feed a valid request one byte at a time; assert exactly one complete frame. Test a 65,536-byte frame including LF, one byte over, invalid UTF-8, literal LF inside strings, duplicate keys, unpaired surrogate, depth 17 and unsafe integer. Use `Result`-returning tests and pattern assertions, not `unwrap`/`expect`.
- [ ] **Run red:** `cargo test -p chio-desktop --test frame_contract`. Expected: crate/interface absence first; after the crate exists, named decoder assertions fail until implemented.
- [ ] **Implement the bounded byte state machine and strict parser.** Declare workspace Serde/serde_json/Tokio/thiserror dependencies and the existing canonical library; no additional JCS implementation. The core bound is `if buffered_len + incoming_segment_len + required_lf > MAX_FRAME_BYTES { return Err(FrameError::TooLarge); }`. Parse only complete valid UTF-8 frames; strict canonical input validation precedes typed deserialization; depth and nonnegative field rules remain explicit. Retain neither rejected frame bodies nor raw secrets in errors.
- [ ] **Run green:** `cargo test -p chio-desktop --test frame_contract` and `cargo clippy -p chio-desktop --all-targets -- -D warnings`. Expected: corpus passes, maximum unfinished allocation remains below the bound, no forbidden unwrap/expect.
- [ ] **Commit:** `feat: add bounded desktop protocol framing` after staging only crate/Cargo changes for this task.

## Task 3: Typed negotiation and explicit mutation refusal

**Files:** Create `src/contracts/message.rs`, `src/contracts/validation.rs`, `src/controller/mod.rs`, `src/controller/dispatch.rs`, `src/controller/health.rs`, `tests/request_contract.rs`.

- [ ] **Write failing dispatch cases.** Load exact request fixtures from the machine-contract catalog. Define `dispatch_for_test(negotiated: bool, request: &[u8]) -> Result<Response, ProtocolError>` in the test helper using the same production parser/dispatcher. For every mutation fixture, assert the same outcome:

  ```rust
  for name in ["task.create", "task.cancel", "task.resume",
               "approval.submit", "receipts.export"] {
      let reply = dispatch_fixture(name, true)?;
      assert_eq!(reply.error_code(), Some("prerequisite_unavailable"));
      assert_eq!(native_effect_count(), 0);
  }
  ```

  Define `dispatch_fixture` as a fixture-loader wrapper around `dispatch_for_test`; define `native_effect_count` as the refusing adapter's independent test counter. Add matching supported Hello, matching unsupported Hello, mismatched Hello identifiers, malformed/65-character identifiers, non-Hello wrong ABI, pre-Hello request, unknown field/method, invalid revision and differing canonical-order cases. Assert `unsupported_version` versus `invalid_request`, null operation references, the server v1 response envelope and connection closure on both typed Hello failures, with zero native effects.
- [ ] **Run red:** `cargo test -p chio-desktop --test request_contract`. Expected: missing typed contract/dispatcher or specific refusal/negotiation assertions fail.
- [ ] **Implement exact schema types and P1 dispatch.** Use `#[serde(deny_unknown_fields)]` on closed objects and an exhaustive method enum. Structurally parse both Hello protocol fields as the bounded identifier in `common.schema.json`; compare them first and return `invalid_request` on mismatch. For matching candidates, select only `chio.omarchy.operator.v1` or return `unsupported_version`. Close after either failure, encode every response with the supported v1 schema, and never echo an unselected protocol into the response. Non-Hello protocol fields remain the exact v1 constant, and pre-negotiation methods refuse. A single explicit mutation branch returns `prerequisite_unavailable` without persisting an effect intent or invoking an effect adapter. Define the canonical digest from validated semantic params using the native canonicalizer; include no transport request ID in logical effect identity.
- [ ] **Cover the reviewed wire refinements.** Add native SHA-256 and UUIDv7/string identity fixtures, owner-bound operation and evidence references, all stop-status dimensions, typed health/session observations and scope.get. Exercise nonempty evidence through task.get, tasks.list and task_changed, accepting the shared evidence_ref shape and rejecting missing owners or invalid native IDs in each envelope. Verify unavailable/stale session observations cannot enable sensitive views or effects. Reject omitted enrollment_epoch on every mutation.
- [ ] **Bind scope and recovery semantics.** Deserialize the complete typed scope, including operator/authority/trust root, project selection, policy, host/provider/account/credential, fixed verification plan, network and private local review destination bindings. Display those fields before Start; display strings cannot replace them. Reject duplicate limit dimensions and missing/null/unavailable required bindings, while preserving the enforced non-null safe-integer rule. The qualified adapter resolves native records and computes the JCS digest of scope value excluding only reviewed_scope_digest; P1 fixtures do not qualify an adapter or enable Start. Bind each error code to the exact retry/reference row in the protocol table: outcome_unknown requires its original owner-bound reference and reconcile_original; invalid_request requires never and null. Test positive variants and contradictory metadata before wiring client recovery behavior.
- [ ] **Run green:** focused tests plus `python3 -m unittest discover -s integrations/omarchy/tests -p 'test_contracts.py' -v`. Expected: schema and Rust type acceptance agree on the entire corpus; all mutation effect counts are zero.
- [ ] **Commit:** `feat: add read only desktop protocol dispatch`.

## Task 4: Durable projection store and exclusive owner

**Files:** Create `src/store/mod.rs`, `src/store/schema.sql`, `src/store/projection.rs`, `src/store/snapshots.rs`, `tests/store_contract.rs`.

- [ ] **Write failing store tests** using the proposed `ProjectionStore::open(path)`, `begin_snapshot(limit)`, `next_page(cursor)` and read-only projection ingestion boundary. Seed fixtures only under tests; production startup never inserts sample tasks. Verify this sequence:

  ```text
  open first store -> succeeds and retains exclusive state-root lock
  open second live owner -> owner_conflict
  commit projection revision 2 and event N atomically
  kill before commit -> reopened store has neither revision 2 nor event N
  kill after commit -> reopened store has both
  open newer schema with old binary -> incompatible_schema
  ```

  Use a child process and kill cutpoints for real SQLite reopen checks, rather than mocking `commit` return values.
- [ ] **Run red:** `cargo test -p chio-desktop --test store_contract`. Expected: absent store or atomicity/ownership failures.
- [ ] **Implement the exact tables and P1 writes from the state spec.** Use SQLite WAL and FULL synchronous mode; set owner-only root/database/WAL/SHM permissions; retain an exclusive lock for process lifetime. P1 writes observed projections/events and enrollment references only. It does not create authority/grants or synthesize native terminal outcomes. Snapshot cursors retain a fixed watermark and 60-second expiry; page size is at most 200 and is reduced by encoded-envelope byte count to fit 65,536 bytes including LF. An indivisible result returns response_too_large without truncating bindings. Commit snapshot-visible revision and its event together.
- [ ] **Run green:** focused tests including empty-store, pagination-at-200/201, cursor expiry, restart epoch persistence, newer schema and write/ENOSPC refusal. Expected: no partial state/event pair, no second owner and no implicit task record generation.
- [ ] **Commit:** `feat: persist consistent desktop projections`.

## Task 5: Operator socket authentication and session boundary

**Files:** Create `src/controller/server.rs`, `src/controller/peer.rs`, `src/supervision/mod.rs`, `src/supervision/session.rs`, `src/bin/chio-desktop-controller.rs`, `tests/socket_contract.rs`.

- [ ] **Write failing Linux socket tests.** Define the installed endpoint as `$XDG_RUNTIME_DIR/chio-desktop/operator.sock`. Test an owner-controlled directory and enrolled peer succeeds; wrong owner, symlink parent, non-socket endpoint, wrong peer UID and absent enrollment all refuse. Admission to inspect data must use the enrolled principal, not a `setup_complete` environment variable. Test 17 clients against the 16-client limit and ensure the rejected connection dispatches nothing.
- [ ] **Run red on Linux:** `cargo test -p chio-desktop --test socket_contract -- --test-threads=1`. Expected: missing server or explicit peer/path assertions fail. On macOS, tests may compile portable portions but must report Linux peer tests unexecuted, not passed.
- [ ] **Implement checked path creation, peer credentials and bounded connection admission.** Open each path component without following symlinks using existing project/platform primitives after inspecting their contracts. Validate UID/type/ownership before bind/connect and unlink only a proved stale socket owned by this installation. Start the controller as the graphical-session service; retain its owner lock and gracefully close clients on logout. No daemon linger or QML-child controller. The shutdown function returns a projection-store result; it never invents native task termination evidence.
- [ ] **Run green:** the real two-UID/namespace positive and negative socket matrix plus focused unit tests. Expected: allowed enrolled peer connects, excluded peers cause zero dispatches, mode bits are 0700 directory/0600 socket and one retained controller owner.
- [ ] **Commit:** `feat: bind desktop operator socket to enrolled session`.

## Task 6: Snapshot/event streaming and backpressure

**Files:** Create `src/controller/events.rs`, `tests/event_contract.rs`; modify server/store snapshots.

- [ ] **Write failing event tests** with a fake monotonic clock and real bounded async channels. Define `EventCursor { epoch: Uuid, sequence: u64 }`, validating the protocol safe-integer maximum. The independent reference model applies a complete ordered state history, while the client model receives snapshot pages and injected duplicates/gaps/restarts. Assert equal task revisions after resync. Required race:

  ```text
  read first page at W -> commit event W+1 -> read remaining pages at W
  subscribe from W -> receive W+1 exactly once -> final revision equals oracle
  ```

  Stop reading after enqueueing 256 KiB; require connection loss and later snapshot recovery, not silently skipped events.
- [ ] **Run red:** `cargo test -p chio-desktop --test event_contract`. Expected: consistency/backpressure cases fail until implemented.
- [ ] **Implement epoch/sequence replay, expiry and bounded queues.** Persist ordinary-restart epoch; return `cursor_expired` for replaced epoch or trimmed cursor. Heartbeat every 5 seconds, never as task authority. Cap output queues at 256 KiB, projection history at 10,000 events/16 MiB, and safe sequence counters. Before a hard bound would be exceeded, atomically invalidate blocking snapshots and return cursor_expired before trimming; the 60-second TTL is an upper bound. Use unfiltered global events in v1, filter only in the view, and leave heartbeat watermarks unchanged. Do not block the single store writer on a slow QML consumer.
- [ ] **Run green:** focused tests with slow consumer, reconnect, stale cursor, 60-second snapshot expiry, gap, duplicate, interleaved two-task global sequences, pressure during a live snapshot, maximally escaped 200-row pages and safe-integer boundary. Expected: bounded memory and state-equivalent resnapshot with no native mutation.
- [ ] **Commit:** `feat: stream bounded desktop state with snapshot recovery`.

## Task 7: Literal-argv client and navigation opener

**Files:** Create `src/client/mod.rs`, `src/client/stdio.rs`, `src/client/open.rs`, `src/bin/chio-desktop-client.rs`, `src/bin/chio-desktop-open.rs`, `tests/client_contract.rs`; declare all three binaries explicitly in crate Cargo.toml.

- [ ] **Write failing integration tests** launching the actual built client against a temporary fake operator socket. Send prompt-like inert strings containing quotes, LF escapes, dollar substitutions, backticks, Unicode and leading dashes through stdin; compare exact parsed values at the socket. Inspect `/proc/<pid>/cmdline` and its allowed environment on Linux. For the opener, test only `--view overview|task|review|diagnostics` and optional validated UUID are accepted; any extra command/URL/path field refuses.
- [ ] **Run red:** `cargo test -p chio-desktop --test client_contract`. Expected: binaries absent or literal-boundary assertions fail.
- [ ] **Implement fixed commands and bounded byte forwarding.** Client accepts only `--stdio` for the QML bridge, validates both directions, and writes no request content to stderr. Opener invokes the installed `omarchy-shell` with an argv vector for `shell summon computer.chio.desktop <navigation-json>`; use no `sh -c`, `bash -c`, `bar.run` or quiet success suppression. Refuse invalid navigation before invoking any process. Resolve installed executable identities through package metadata; fixture overrides are test-only.
- [ ] **Run green:** focused tests and process audit. Expected: literal data preserved, no sentinel command executed, no seeded secret appears in argv/environment/stderr, absent shell produces a visible nonzero diagnostic.
- [ ] **Commit:** `feat: add bounded desktop client and navigation opener`.

## Task 8: Qualified read-only native adapter and lock state

**Files:** Create `src/adapter/mod.rs`, `src/adapter/readonly.rs`, `src/adapter/refusing.rs`, `tests/p1_readonly.rs`; modify health/dispatch/session.

- [ ] **Write failing tests** for a narrowly defined `NativeReadAdapter` that exposes health, task/operation projections and a lock observation, never a generic execute function. Test `KnownUnlocked`, `KnownLocked` and `Unknown` lock categories. Fixture test adapter must be compiled only for tests or explicit fixture binaries and label every returned projection synthetic. Unknown backend ABI or absent enrollment yields unavailable health with zero effect calls.
- [ ] **Run red:** `cargo test -p chio-desktop --test p1_readonly`. Expected: absent adapter or lock/refusal assertions fail.
- [ ] **Implement delegation to the P0-selected existing native observation path.** Record source/profile/ABI identities from the qualification tuple. If that path cannot supply a required observation, return its explicit unavailable reason; do not parse human logs or inspect an authority SQLite file directly. On locked/unknown state stop sensitive projection delivery, invalidate reviews and refuse all mutations. Unlock requires a new snapshot and original grant expiry checks; never extend sessions/leases. Preserve `operation.get` provenance as a projection.
- [ ] **Run green:** fixture tests, then the independent real native read-only positive control named in P0. Expected: real values match the native owner's separate query, unsupported backend remains visibly unavailable, no fixture data can masquerade as installed task history.
- [ ] **Commit:** `feat: project qualified native state without execution authority`.

## Task 9: Shared QML service and pure model

**Files:** Create canonical plugin `manifest.json`, `Service.qml`, `Model.js`, `compatibility.json`; create `integrations/omarchy/tests/test_model.mjs`.

- [ ] **Write failing pure-model tests** before QML process integration. Define these exact proposed exports in Model.js: `applySnapshot(model, snapshot)`, `applyEvent(model, event)`, `connectionState(lastHeartbeatMs, nowMs, connected)`, `appendVisibleActivity(rows, event)`, `parseNavigation(payload)`. Tests use an immutable initial model with `{epoch:null, sequence:0, tasks:[], rows:[], sensitive:false}`. Assert wrong-epoch/gap results request resync, duplicates do not change revision, 15 seconds is stale, and activity stays under 500 rows/1 MiB. Export for Node tests using the repository's existing dual QML/Node pattern.
- [ ] **Run red:** `node --test integrations/omarchy/tests/test_model.mjs`. Expected: missing model/exports, then concrete cursor/boundary failures.
- [ ] **Implement manifest and connection service.** Copy the proposed schema-1 manifest from the spec, with `keepLoaded:false`. Wait for host-injected shell/manifest before starting one fixed `Process`. Use stdin JSON and streaming stdout, generation guards, validated frames, one subscription, 1/2/4/8/16/30-second reconnect with at most 20% jitter and no reconnect loop after protocol incompatibility. On destruction close transport and clear sensitive memory; never send cancel/resume/approval. Theme or monitor changes do not restart this service.
- [ ] **Run green:** `node --test integrations/omarchy/tests/test_model.mjs` and the service lifecycle fixture with synthetic nullable host properties. Expected: no late-injection exception or duplicate client on repeated readiness. Full manifest validation and three-monitor rendered testing follow in Task 10 once both visual entry files exist; do not create empty production entry files to manufacture a green validator.
- [ ] **Commit:** `feat: add shared omarchy desktop projection service`.

## Task 10: Read-only bar/panel, accessibility and private notifications

**Files:** Create plugin `BarWidget.qml`, `Panel.qml`, `components/StatusRow.qml`, `components/AccessibleAction.qml`; extend test_model with navigation/private-label cases.

- [ ] **Write failing behavior fixtures** for empty/unavailable/connected/stale/offline/locked/unknown-lock, and each native task state. The P1 rendered harness must enumerate the rendered controls, assert that mutation controls are disabled, and verify that enabled controls route only to inspection or navigation. Add an accessible-tree expected list containing the Chio opener, connection status, task list names, diagnostics and close action. Include malicious rich text, bidirectional controls, overlong labels and forged "Verified" output.
- [ ] **Run red:** `python3 integrations/omarchy/qualify.py --phase P1 --profile observe-v1 --fixture-only --bundle /absolute/synthetic-p1-bundle.json --output /absolute/new-fixture-evidence-dir`. Supply the explicitly synthetic bundle produced by Task 1's fixtures. Expected: missing rendered surfaces fail fixture acceptance; this mode must still say `fixture_only`, never real qualification PASS.
- [ ] **Implement native surfaces from the spec.** Bar reads `bar.shell.serviceFor` for its own ID; unavailable service produces degraded status. Panel root implements validated `open`, `close`, `opened`; it shares injected service. Use theme roles, explicit Accessible properties, keyboard focus, inert text and safe motion fallback when `Style.duration` is absent. Notifications use a generic body, Chio app identity, normal urgency and navigation-only opener. No automatic credential UI or approval button exists in P1.
- [ ] **Run green fixture checks** and `omarchy plugin validate integrations/omarchy/fixtures/plugin`, then real v4.0.4 and HEAD screen-reader/keyboard/multi-monitor/theme/scaling cases. Observe that three monitor widgets still produce one shim/subscription. Expected: named accessible controls, no focus stealing, no stale detail after lock, no DND bypass, no effect from a historical notification and no HEAD-only parse failure on release.
- [ ] **Commit:** `feat: render native read only chio desktop status`.

## Task 11: Ownership-aware desktop registration fixture

**Files:** Create `integrations/omarchy/fixtures/desktop/computer.chio.desktop.desktop`, `integrations/omarchy/fixtures/desktop/menu-fragment.json`, `integrations/omarchy/tests/test_registration.py`; update developer README. Native package installation itself belongs to the distribution plan.

- [ ] **Write failing registration tests** over temporary copies of existing user menu/shortcuts/default-agent settings. Assert unique owned Chio entry insertion is idempotent, unknown JSONC preserves original bytes and returns an actionable refusal, conflicting shortcut remains unchanged, and removing only the owned entry leaves every other semantic field intact. Record before/after hashes of the default-agent selection and shipped Omarchy tree; they must match.
- [ ] **Run red:** `python3 -m unittest discover -s integrations/omarchy/tests -p 'test_registration.py' -v`. Expected: fixture registration behavior missing or incorrect.
- [ ] **Create the static desktop entry/menu fragment and ownership contract.** `.desktop` uses a literal `Exec=chio-desktop-open` command resolved by packaging. The menu uses an owned `chio` key with a static action only. Document optional operator-selected shortcut and exact removal ownership. Do not write live user configuration while implementing or testing this plan; the distribution plan applies fixtures transactionally.
- [ ] **Run green:** focused tests with duplicate install, manually edited owned entry, malformed JSONC, preselected Pi and existing Agents widget. Expected: original customization preserved and no claim that upstream Pi launches are Chio-confined.
- [ ] **Commit:** `feat: define reversible chio desktop registration`.

## Task 12: Finish qualification runner and independent P1 evidence

**Files:** Create/finish `integrations/omarchy/qualify.py`, tests/test_qualify.py; update README and exact P1 requirement mapping.

- [ ] **Write failing qualifier tests** requiring recorded host/source/package identities, schema and binary digests, actual shell compositor session, artifact existence/digests, negative controls and independent counters. Corrupt each one separately. A missing/skipped/cancelled case cannot pass; fixtures and non-Omarchy hosts cannot pass a real P1 profile. Require every report to include `status`, `profile_id`, `host_record`, `cases`, `artifacts` and `qualification_limits`.
- [ ] **Run red:** `python3 -m unittest discover -s integrations/omarchy/tests -p 'test_qualify.py' -v`. Expected: unsupported evidence mutation is accepted by the incomplete runner, then fails once the test is installed.
- [ ] **Implement the orchestration and artifact verifier.** The runner invokes the scoped Rust/Node/Python checks, upstream manifest validator, real process/socket observers and rendered manual/automated cases defined above. It hashes artifacts and names their independent oracle. Never replace unexecuted AT-SPI or two-UID guest-boundary cases with screenshots. Keep rendered fixture results, actual Omarchy observations and native runtime qualification separate in the report.
- [ ] **Run complete P1 checks** from the implementation checkout:

  ```bash
  cargo fmt --all -- --check
  cargo test -p chio-desktop --all-targets
  cargo clippy -p chio-desktop --all-targets -- -D warnings
  node --test integrations/omarchy/tests/test_model.mjs
  python3 -m unittest discover -s integrations/omarchy/tests -p 'test_*.py' -v
  python3 integrations/omarchy/qualify.py --phase P1 --profile observe-v1 --bundle /absolute/qualified-bundle.json --output /absolute/new-evidence-dir
  ```

  The final two paths are operator-supplied evidence/output arguments, not claimed existing artifacts. Expected: all required P1 tests pass on the named actual host, missing native mutation features remain refused, and the report explicitly leaves P2-P7 open. If actual host evidence is unavailable, return blocked qualification with completed local checks and no P1 PASS.
- [ ] **Review and commit** the completed P1 evidence mapping with `test: qualify read only chio omarchy integration`. Commit only reviewed nonsecret evidence appropriate for source control; store large machine captures using the release evidence policy. No release or deployment follows automatically from this plan.

## Task 13: Produce the installable plugin delivery candidate

**Files:** Create `packaging/omarchy/export_plugin.py`, `packaging/omarchy/tests/test_plugin_release.py`, `packaging/omarchy/plugin-release.json`; update the developer README. This task prepares source/export tooling and the delivery handoff. P7 Task 5a owns authorized public candidate publication and installation.

- [ ] **Write failing export tests** requiring `manifest.json` at the delivery-repository root with ID `computer.chio.desktop`, plus the exact `Service.qml`, `BarWidget.qml`, `Panel.qml`, `Model.js`, `compatibility.json`, `components/StatusRow.qml` and `components/AccessibleAction.qml` files. Include every imported component and referenced icon/asset, license and operator README in a complete path/mode/SHA-256 inventory. Delete each required member, alter an import target and introduce an extra runtime file; all must fail. Synthetic P1 task-state fixtures, secrets, native binaries and implementation-checkout paths are excluded.
- [ ] **Run red:** `python3 -m unittest discover -s packaging/omarchy/tests -p test_plugin_release.py -v`. Expected: missing export/inventory/provenance fails, including a plugin directory whose manifest exists only beneath `integrations/omarchy/fixtures/plugin/` instead of at the delivery root.
- [ ] **Implement the deterministic export.** Select the canonical subtree only from an immutable publicly available source revision, copy its reviewed complete inventory into a new generated delivery repository, and create a deterministic source archive of that same root. Exporting twice from the same canonical revision must produce matching file/mode inventories and archive hashes. The fixture subtree stays the sole editable source; corrections flow through a new canonical revision and regenerated delivery commit. Do not export an unpublished private source revision or manually repair the generated repository.
- [ ] **Bind the P7 handoff.** `plugin-release.json` requires `plugin_id`, `canonical_repository_url`, `canonical_public_revision`, `canonical_subdirectory`, `repository_url`, `public_revision`, `archive_url`, `archive_sha256`, `inventory_sha256`, `manifest_sha256`, `protocol_version`, `omarchy_revisions` and `signer_identity`. Both revisions must be immutable 40-hex publicly reachable commits; hashes are 64-hex SHA-256. `canonical_subdirectory` is `integrations/omarchy/fixtures/plugin`; `plugin_id` is `computer.chio.desktop`. Repository/archive URLs are real public publisher locations selected at release time, never invented install endpoints. The delivery repository must expose the recorded commit through a retained public ref, while the signed handoff binds the commit itself rather than trusting a movable branch/tag. The declaration remains an incomplete prerequisite until those public objects actually exist.
- [ ] **Run green component checks:** the export suite above, both independently generated inventory/archive comparisons, and `omarchy plugin validate` against the exported root using each selected frozen Omarchy implementation. Missing QML imports/assets, mismatched protocol declaration, changed manifest, unsigned/untrusted handoff, missing public commit and independent edits to the delivery tree must block P7. These checks qualify export structure and correspondence only.
- [ ] **Hand off publication and clean installation.** Give P7 the generated repository, immutable archive, complete inventory, signed provenance and pending-publication state. P7 must publish the candidate at the recorded public locations, independently retrieve and verify it, then perform the disabled-install/pin/verify/enable sequence in [distribution Task 5a](07-distribution-qualification.md#task-5a-publish-and-install-the-pinned-plugin-candidate). Commit tooling and reviewed source metadata with `build(omarchy): prepare reproducible plugin delivery`. Supported release publication remains gated by P7; a prepared local export is not a public artifact.

## Coverage and later-phase handoff

| Scope | Tasks and oracle | Remaining gate |
|---|---|---|
| Strict API framing/negotiation, bounds, socket peer | 2, 3, 5, 6, 7 | Full P2 durable mutation reservation/CAS and native effect recovery are later work. |
| State projection/one owner/snapshot | 4, 6, 8 | Native outbox and preparation crash matrix wait for qualified task creation. |
| Service lifecycle, bar, navigation, hot reload | 9, 10, 12 | Active-task reload evidence must be repeated in P2, not inferred from P1 fixtures. |
| First-session setup and unavailable features | 3, 8, 10 | Trusted operator enrollment/provisioning must be implemented and independently qualified before Start is enabled in P2. |
| Accessibility, lock/privacy, DND, theme, version skew | 8, 9, 10, 12 | Actual host/AT-SPI evidence required; fixture screenshots alone are insufficient. |
| Reversible registration and independent packaging | 11, 13 | Generated plugin delivery and provenance are handed to P7 for candidate publication, exact installation and paired native/plugin release qualification. |
| Exact approvals, exports and publication | Refusal tested in 3, 8, 10 | P3 native decision and disclosure qualification; no controller approval surrogate. |

The P1 handoff includes the exact tested profile, fixture-versus-real evidence distinction, public-source pins, generated plugin delivery/inventory commitments and publication state, native read-adapter identity, failed/unexecuted case list, qualified API version and artifact digests. It does not claim confined project tasks, enforceable provider budgets, desktop tool effects, configuration repair, delegated workers or public release.
