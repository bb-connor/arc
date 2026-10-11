# PR #1160 architecture, design and Rust quality review

Head `d0496c14d824a327f00b98576132834306ff6694`, merge base `c009aced79d6` (main). Static review. Metrics come from the head tree and from the base..head diff, measured with `git`, `rg` and small Python scripts; counts that depend on heuristics (test detection, regexes) are marked as approximate. Finding numbers (F001 and so on) refer to [findings.md](findings.md); per-area detail is in [slices.md](slices.md).

## Verdict

At the level of individual functions, this is careful, fail-closed Rust. Across thirteen review slices covering about 600K hand-written lines, the review found one security check that fails open (F001, a macOS ACL custody check), one gap in a sandbox guarantee (F012, hard-linked files under a forbidden directory), and no reachable panics in the admission path. Checked arithmetic, bounded decoders, domain-separated signatures, descriptor-relative filesystem access and sealed request types are applied with real discipline.

The structure is well below the elite production bar the code's local quality suggests. Four system-level patterns account for most of the 15 P0/P1 findings: errors that discard their cause, recovery and readiness loops that stop the whole service when one item is bad, security invariants enforced by call-site convention instead of by type, and crates and modules that have grown past the point where review can see boundaries. None of these is a local coding mistake, and none will be fixed by more per-finding patches. The September 26 code-quality reviews (`docs/reviews/2026-09-26-security-code-quality-review*.md` on the PR branch) already named two of them (Q1 `include!` fragments, R2 error provenance). Both have grown since.

## Shape of the change

| Measure | Value |
| --- | --- |
| Files, lines | 5,904 files, +1,173,887 / -97,694, 912 commits (25 merges) |
| Hand-written non-test Rust added under `crates/` | about 322K lines in 1,945 files (approximate; inline `#[cfg(test)]` modules are counted as non-test) |
| Workspace crates | 145 to 161 under `crates/`; 168 `chio-*` packages in the workspace |
| Largest crates at head (including tests) | chio-store-sqlite 329K lines (base 196K), chio-kernel 233K (164K), chio-control-plane 210K (143K), chio-cli 195K (159K), chio-core-types 50K plus a 130K-line generated file |
| Vendored code | 161K lines under `third_party/`, of which 153K (nine forks) no lockfile selects (F-series, third-party slice) |
| Scripts | 177 new files, about 67.7K lines, including an 8.3K-line CI contract checker |
| Process records | `docs/security` 35 MB including a 1,602-requirement ledger; 86 files in `docs/reviews` |

### Crate graph

Measured from the workspace manifests (direct `[dependencies]`, internal `chio-*` edges only):

| Crate | Direct internal deps | Transitive internal deps | Direct dependents |
| --- | ---: | ---: | ---: |
| chio-cli | 69 | 110 | - |
| chio-control-plane | 48 | 79 | 10 |
| chio-secret-broker | 7 | 47 | - |
| chio-store-sqlite | 14 | 38 | 12 |
| chio-kernel | 1 (chio-core facade) | 20 | 43 |
| chio-core-types | 1 (chio-security-types) | 1 | 112 |

The graph is acyclic, which is worth keeping. Three edges are structural problems:

- **The secret broker sits on top of the persistence god crate.** chio-secret-broker depends on chio-kernel, chio-store-sqlite and chio-mcp-adapter. chio-store-sqlite in turn depends on chio-credit, chio-fiscal, chio-settle, chio-finding, chio-federation and chio-agent-web-interop. A component that should be the smallest piece of the trusted computing base links 47 internal crates, including settlement and credit code it never calls. The broker also depends on chio-keyring only for a macOS ACL helper, which is how it inherited F001.
- **The substrate crate now depends on a security crate and carries a domain state machine.** chio-core-types (112 dependents) depends on chio-security-types and contains the active-response lifecycle validator (`receipt/security_parts/lifecycle_and_validation.inc`). The same rules are implemented again in `chio-response-model/src/state.rs:569-1005`, and the same error-code literals are defined in three crates.
- **"core" and "runtime" names no longer describe layers.** chio-runtime-core depends on chio-kernel, chio-federation, chio-weights, chio-attest-buyer-core and chio-swarm-authority and owns a SQLite store. chio-process classifies outcomes by reading `chio_kernel::admission_operation::AdmissionReceiptMetadataV1` instead of a typed outcome API.

## The ten structural problems, ranked

Each item states the problem, the evidence, the findings it causes, and the better pattern.

### 1. The error model discards causes and cannot tell a denial from an outage

Evidence, in code added by this PR: 676 `map_err(|e| ... .to_string())` sites (252 in chio-store-sqlite, 132 in chio-kernel, 102 in chio-control-plane) and 112 new `Variant(String)` error variants. In chio-kernel admission there are 279 `KernelError::DurableAdmission(String)` and 82 `Internal(String)` sites. Active response funnels every outcome into `GovernedTransactionDenied(String)` or `Internal(String)` and maps store unavailability to a denial. `BrokerError` decides whether the daemon exits by which string variant a call site happened to pick. `CliError` is a 30-variant catch-all with `Other(String)` and about 2,300 `cli_other_error` call sites, and it lives in the control-plane library crate. `Error::CanonicalJson(String)` is the catch-all at 89 sites in chio-core-types, including all 47 lifecycle violations.

Consequences: F003 (startup recovery cannot quarantine one bad operation because it cannot classify the failure), F011 (a missing credential is `Storage`, so the broker exits), the privileged-audit crash path, and the active-response compensation-on-transient-error finding. Tests can only assert that something failed, which the R3 pass measured at 39 percent of negative assertions in the security crates.

Better: per-module `thiserror` enums that keep `#[source]` causes privately, plus one shared classifier such as `fn disposition(&self) -> Disposition { Deny, Retry, Quarantine, Fatal }` that every recovery loop and IPC endpoint uses. Convert to registry codes and redacted wire text only at the public boundary. Where a stable reason code is all that is needed, use `&'static str` as `ToolOutcomeError::Binding` already does. Replace the 20-to-40-clause `||` binding chains with an `ensure_eq!(actual, expected, "field")` helper that fails closed and names the field.

### 2. Fail-closed is implemented as stop-the-world

Fail-closed should deny the affected operation. In several places it stops the service instead:

- F003: `reconcile_durable_admission_startup` runs before every evaluation and only marks itself done when every recoverable operation reconciles, so one stuck row fails every tool call kernel-wide. F002, F004 and F005 each produce such a row.
- F006: one failed read of a health-only timestamp latches `accounting_poisoned` and closes the receipt writer until restart.
- F007: one declassification receipt in backoff makes the outbox report "no progress" and stops response planning.
- F009 and the witness-restart finding: a late witness signature or a decided candidate leaves the key-log store or witness unable to open.
- The 4,096-row active-response recovery batch refuses to start above its bound; the native participant journal has a hard cap with no compaction; mobile challenges fill capacity permanently; readiness probes run full-history SQLite audits and authority IPC on every event.

Better: quarantine at the granularity of the failing item (mark the operation, emit an audit fault, deny its own retries, continue), make sweeps paginated and resumable, design every capped store with compaction or rotation from the start, and separate a one-time startup audit from a cheap health snapshot that readiness reads. Each of these keeps the security property (nothing proceeds on unverified state) without converting a single fault into a full outage.

### 3. Security invariants are enforced by call-site convention instead of by type

- **Signature strictness is opt-in.** `PublicKey::verify` and `verify_canonical` remain permissive (crypto.rs:439-470). The PR hardens specific paths and adds about 30 scattered `is_weak_ed25519()` checks, but capability tokens (`token.rs:893`), delegation links (`attenuation.rs:165`), governed approval tokens, declassification grants, security events and the OID4VP holder binding still use the loose verifier. The keyring (F008) and cage policy signer use it too, and Codex found two more instances on #1173.
- **Clock sourcing is optional.** `SqliteRuntimeOrchestrationStore::open`, `DpopNonceStore::new` and `LocalCapabilityAuthority::new` fall back to the system clock, and the pinned remote authority hardcodes it. That is how the repaired Codex clock threads happened, and how the mailbox lease and remote-authority clock findings in this review happened.
- **JSON number rules are chosen per call site.** Whether a decoder applies signed-record rules or document rules is decided ad hoc, which produced the A2A decimal thread and its ACP and data-guards siblings.
- **Validated construction is bypassed.** `ThresholdApprovalRequest::new` validates but the type derives `Deserialize`; `GovernedResponsePlanIntentBody` has a validating constructor and getters yet keeps every field `pub`.
- **Private-file custody is reimplemented about eight times** in the CLI and control plane with different owner, mode, link-count and chmod rules, and the broker and keyring add four more copies of socket lifecycle code and five of length-prefix framing, although chio-secure-ipc and chio-sqlite-file-identity exist for this. The copies have drifted: the keyring sockets have no peer authentication.
- **Identifiers are strings.** 804 parameters named `*_id` are `&str` or `String` against 7 string newtypes in the added code, and SHA-256 digests have three representations. F-series findings on cross-tenant `request_id` lookups (kernel and store sides) are this pattern.

Better: a `TrustedPublicKey` newtype whose constructor rejects weak and small-order keys and is required by every verifier, with the permissive form renamed (for example `verify_legacy_permissive`) behind a lint. Clocks as required constructor arguments with no default. Distinct JSON input types per contract (`SignedRecordJson`, `DocumentJson`) and a clippy `disallowed-methods` entry for `decode_signed` outside signed-record modules. `#[serde(try_from = "...Wire")]` with private fields. One `chio-secure-fs` crate with descriptor-relative `open_private`, `create_new_private` and `atomic_publish` taking an explicit policy. Newtypes for operation, request, tenant and capability identifiers and one `Sha256Digest`.

### 4. God crates

chio-kernel (233K lines) owns DPoP, approvals and threshold collection, two durable admission-operation families, tool outcome and security release, payments, the finding pool and market, compliance, receipts, budget stores, sessions, transport and active response. chio-store-sqlite (329K lines) is one crate for every domain. chio-cli (195K lines) has no library target. chio-control-plane carries about 22K production lines of an active-defense pipeline that no binary runs. Every change lands in a CODEOWNERS TCB crate, so review scope, incremental compile time and blast radius are all maximal.

Better: extract leaf crates behind trait seams (chio-dpop, chio-approval, chio-admission-journal, chio-tool-outcome, chio-active-defense) and let chio-kernel compose them; split chio-store-sqlite by domain over a small shared connection and migration core; give chio-cli a library crate with per-domain modules and a thin binary; make the secret broker depend only on custody, IPC and security types. Expose `ToolCallResponse::outcome_class()` so chio-process stops parsing receipt metadata.

### 5. `include!` fragments, duplicate names and module plumbing

There are 176 `include!` sites at head (202 at base) and 16 new `.inc` fragment files totalling 16,970 lines. `chio-kernel/src/security_admission_operation.rs` is six lines that splice in three fragments (3,583 lines, tests included). The file-hygiene script now counts fragments toward their parent and freezes 39 fragment-assembled modules with caps "until the fragments become modules". Fragments share one privacy scope, are never formatted by rustfmt (lines over 100 columns exist in `receipt/security_parts/*.inc`), carry no module docs, and degrade navigation and tooling. Two public type families in chio-kernel share the names `AdmissionOperationStore`, `AdmissionOperationState`, `AdmissionDispatchState`, `AdmissionOperationKind` and `ADMISSION_OPERATION_SCHEMA`; the crate root re-exports the security family while chio-process uses the other. chio-store-sqlite repeats the pattern with a second `SqliteAdmissionOperationStore` assembled from `.inc` files and used only by tests and benches. chio-cli is assembled from 209 `#[path]` attributes and about 200 glob re-exports under `#[allow(unused_imports)]`. `bin/chio.rs` is `include!("../main.rs")`.

Better: convert fragments to real modules with deliberate `pub(super)`/`pub(crate)` visibility and `#[cfg(test)] mod tests;` in its own file; ban new `include!` of Rust source in an xtask gate; rename the security admission family (`SecurityAdmissionOperation`, `SECURITY_ADMISSION_OPERATION_SCHEMA`) and stop re-exporting either family at the crate root; use default module resolution and explicit imports.

### 6. Functions too large to review, with hand-placed cleanup

`finalize_durable_tool_return_with_security_release` is 937 lines, `begin_durable_tool_admission_for_transport` 477, the async evaluation core about 1,980, the broker's `execute_inner` about 615 with nine hand-copied release-and-return blocks, and `validate_response_snapshot_lifecycle` about 500 under a blanket `#[allow(clippy::indexing_slicing)]`. There are 161 new `#[allow(clippy::too_many_arguments)]` (62 in chio-kernel, 58 in chio-store-sqlite), many with the same reason string. Each early return picks its cleanup by hand, which is the direct cause of several findings: a clock-read `?` in the deny builders skips all pre-dispatch cleanup, a DPoP claim is released for reuse, a failed native capture can be retried, and a cancelled session call loses its threshold claim.

Better: model each admission phase as an owned type whose `Drop` performs the compensation and whose success path consumes it (`PreparedAdmission -> DispatchCommitted -> Finalized`). Cleanup then cannot be skipped by an early return. Replace positional parameter lists with context or options structs. Split replay validators per record variant and use `get()`/iterators so the indexing allow can go.

### 7. Blocking work and locks in async code

The process-static admission mutation lock is a `std::sync::Mutex` held across SQLite transactions, payment-rail HTTP calls and FX oracle lookups, all reached from async code (terminal_payment.rs:188). chio-api-protect holds a tokio `Mutex` over the whole `ChioKernel` while calling `*_blocking` methods. Trust-control handlers perform SQLite writes synchronously inside async handlers. The control-plane scheduler runs a hand-built thread with its own runtime, seven channels and a global reaper polling every 10 ms, and a running tick cannot be cancelled. The broker's serving workers poll non-blocking accepts with 2 ms sleeps. chio-mcp-remote does SQLite and fsync work on async worker threads, and request-bound responses travel over a shared broadcast channel that can drop them.

Better: never hold a lock across I/O; run kernel and store calls through `spawn_blocking` with owned guards or behind a dedicated actor thread fed by a channel (the FROST coordinator's `blocking(..)` helper already does this correctly); supervise background work with a `CancellationToken` and an owned `JoinHandle` whose `Drop` cancels; use blocking accept or readiness notification instead of sleep loops.

### 8. Unwired and dead code shipped as production surface

- 153K lines of vendored forks that nothing compiles, still listed in `[patch.crates-io]`, in six Docker build contexts, in supply-chain reviews that claim they are selected, and under file-hygiene allowlists that will expire and break CI on unchanged upstream code.
- About 22K production lines of the control-plane security pipeline with roughly 90 public re-exports and no binary that runs the host, orchestrator, scheduler or SIEM delivery.
- A legacy public governed active-response commit path that skips the finding, proof, attestation and resolver checks and is called only by tests.
- A 2.4K-line duplicate admission store used only by tests and benches, a 1,228-line `.inc` that is never included, about 356 lines under `#[cfg(any())]`, and a lifecycle-owner proof API with no production caller.

Unwired code still costs review, compile time and attack surface, and it hides which paths are real. Better: delete it, or put it behind a non-default feature with a named owner and an activation milestone; add gates for unreferenced `.inc` files, `#[cfg(any())]` blocks and unused `[patch]` entries.

### 9. Contracts without a single source of truth

The `chio.process.v1` worker protocol has no schema in `spec/schemas` and no section in PROTOCOL.md, so Python and TypeScript re-implement frames, limits and error codes and have already drifted (the TS client lacks `known_outcome_only` and `prepare_invocation`). Five new error URNs are missing from `spec/errors/registry.yaml`, and no CI step runs the registry drift check. The active-response plan validator in Rust is stricter than the published schema. The newly enforced `bind_security_context` caveat is not specified. Go strict decoding is opt-in per type, which is how `ReceiptRecord` was missed. The generated `chio_wire_v1.rs` (130K lines) sits in the library crate's `src/` although only one test target uses it.

Better: generate SDK types and fixture corpora from schemas derived from the Rust types; run `xtask errors regen --check` and schema-versus-validator property tests in CI; move generated bindings to a `publish = false` dev-dependency crate, one module per schema.

### 10. Gate and landing machinery that costs more than it protects

The 8.3K-line `check-security-ci-contract.py` pins exact workflow text and AST shape, its 5.5K-line test edits that text, and CI runs it from the PR head, so it detects accidental drift but cannot stop a hostile change. The trust protocol (binding, mirror publication, tombstones) lives in inline bash and jq inside YAML (the finalizer workflow is 3,382 lines) and is tested by regex-extracting functions from the YAML. Rust source policy is enforced by regex lexers in Python while xtask already has a `syn`-based visitor. `formal/proof-manifest.toml` adds 3K lines of per-function hashes that force re-blessing on every refactor. The documented ruleset requires linear history and allows only squash or rebase while the landing plan requires a merge commit, the admin-override audit looks for checks on a commit where they never exist, and routine CI cancellations permanently tombstone authority. The guarantee the capture provides is provenance (owner-authorized source ran on a hosted runner); with zero required reviews and the same owner authoring, authorizing and merging, it is not independent review, and the four mirror contexts carry no authority because any same-repo job with `checks: write` can create them.

Better: one typed controller program (Rust xtask or a typed Python package) with explicit state types and a fake GitHub API in tests; Rust source gates in xtask with `syn`; a small digest manifest of protected files plus code-owner review instead of text pinning; generated proof anchors from source annotations; state the provenance guarantee precisely in the docs; and land work in reviewable increments. A 912-commit, 1.17M-line integration PR is itself the largest risk in this list, because no reviewer, human or automated, can hold it at once.

## What is genuinely good

- **Fail-closed discipline is real.** Poisoned locks, capacity exhaustion, store errors and elapsed horizons deny. DPoP verification writes nothing before `verify_strict`; nonce reservation happens only after the signature check.
- **Sealed and typestate APIs where it matters most.** `ActiveResponseExecutionRequest` has origin-keyed private constructors and compile-fail doctests; recovery mode comes from the origin.
- **Deterministic, domain-separated identities.** Dispatch ids, policy decision hashes and evidence ids converge on one dispatch across crash retries; receipt digests use per-kind NUL-terminated domains.
- **Persistence done carefully.** `BEGIN IMMEDIATE` with CAS predicates, exact-predecessor migrations (v34/v35 to v36), append-only triggers, and successor-payment records re-checked against the original journal and global commit on every read.
- **OS-level hygiene in the CLI.** Descriptor-relative `openat`/`O_NOFOLLOW` walks with identity re-checks, pidfd process control, `PR_SET_PDEATHSIG` with the `getppid` race check, and all 43 new `unsafe` sites sound with accurate SAFETY comments.
- **Well-built trust channels.** The response-authority IPC checks `SO_PEERCRED` before parsing, binds responses to request digests and keeps a bounded replay cache; FROST round two is recipient-sealed with zeroizing plaintext types.
- **Supply-chain basics.** Every third-party action is SHA-pinned, downloaded tools are digest-checked, and the evidence container runs without network, read-only, with all capabilities dropped and distinct uids.

## Rust quality scorecard

| Dimension | Assessment | Evidence |
| --- | --- | --- |
| Memory and panic safety | Meets the bar | `unsafe` audited with SAFETY comments; no production `unwrap`/`expect` on admission paths; `catch_unwind` around guard callbacks |
| Fail-closed security logic | Meets, with exceptions | F001, F012; strictness opt-in (problem 3) |
| Error handling | Below | Problem 1 |
| Type-driven design | Partial | Typestate in active response and DPoP binding; strings for ids, digests and errors elsewhere |
| Module and crate structure | Below | Problems 4 and 5 |
| Function design | Below | Problem 6 |
| Async and concurrency | Partial | Problem 7; CAS and transaction discipline are good |
| Testing | Partial | Large suites and some property and model checking, but tens of thousands of lines compiled inside `src/`, tests that cannot fail, and negative tests that only assert failure |
| Dependency hygiene | Partial | Pinned and audited, but 153K lines of dead forks and a TCB crate linking 47 internal crates |
| Tooling and gates | Below | Problem 10 |

## Recommended sequence

1. **Before merge:** F001 and every P1 in [findings.md](findings.md), the ruleset and merge-strategy contradiction, the admin-override audit, the loom gate on `receipt_store`, and the nine dead `[patch.crates-io]` forks.
2. **First structural step:** the error taxonomy and a shared disposition classifier (problem 1). It is the prerequisite for item-level quarantine (problem 2) and for tests that assert specific denials.
3. **Mechanical cleanups that make later refactors reviewable:** fragments to modules, the duplicate admission family renamed, dead code deleted or feature-gated, tests moved to `tests/`.
4. **Types for the invariants:** `TrustedPublicKey`, required clocks, typed JSON contracts, `chio-secure-fs`, identifier newtypes (problem 3).
5. **Crate extraction and async cleanup:** kernel leaf crates, store split, CLI library, broker dependency diet, lock and blocking discipline (problems 4 and 7).
6. **Gate consolidation:** typed controller, xtask gates, digest manifest plus code-owner review (problem 10).
