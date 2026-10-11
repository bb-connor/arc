# Review of PR #1160: process and security foundation

[PR #1160](https://github.com/bb-connor/arc/pull/1160) consolidates the durable agent-process and security-roadmap histories into one landing candidate against `main`. This review covers head `d0496c14d824a327f00b98576132834306ff6694` (merge base `c009aced79d6`): 5,904 files, +1,173,887 / -97,694 lines, 912 commits.

| Document | Contents |
| --- | --- |
| [findings.md](findings.md) | Every P0, P1, P2 and P3 finding, numbered F001 onward, with location, evidence, failure scenario and fix direction |
| [architecture.md](architecture.md) | Architecture, design-pattern and Rust-quality critique: crate graph, the ten structural problems ranked, what is done well, a scorecard and a remediation sequence |
| [slices.md](slices.md) | Per-area reports: scope, what was read and not read, the area's findings, and its design critique |

## Method

The diff was split into thirteen review areas (kernel admission; kernel active response and the remaining kernel crates; SQLite security state; SQLite admission and budget stores; control-plane security pipeline; trust control, CLI and products; secret broker and keyring; cage and active defense; protocol adapters and guards; core types, trust crates and wire; workflows, scripts and supply chain; vendored forks; SDKs, examples and integrations). Each area was reviewed statically against the repository's review checklist (`.cursor/skills/review-pr-swarm/references/CHECKLIST.md`) for bugs and against modern production Rust practice for design. Every P0 and P1 and a sample of P2 findings were then checked again against the code before inclusion; two severities were raised as a result (F001 and the receipt-writer latch) and two pairs of duplicate findings were merged. Cross-cutting measurements for the architecture critique were taken directly from the head tree and the diff.

The review is static. Nothing was built, tested or run. Statements about compile or test outcomes are inferences from reading signatures and assertions. Existing PR threads (8 Codex and 18 maintainer inline threads at review time) were read first and are not repeated; where a finding is a sibling of an existing thread, it says so.

## Headline

Locally, the code is careful and fail-closed: across about 600K hand-written lines the review found one security check that fails open (F001, a macOS ACL custody check that passes any non-empty ACL), one gap in the cage's forbidden-path guarantee (F012), and no reachable panics on the admission path. The P1 findings cluster around availability and recovery rather than authority: several ways for one durable operation, receipt or journal to stop an entire kernel, broker, store or scheduler, plus payment finalization that fails after the tool already ran. The structural problems in [architecture.md](architecture.md) explain why these recur: errors that discard their cause, fail-closed implemented as stop-the-world, security invariants enforced by call-site convention, and crates and modules too large for review to see boundaries.

The landing plan itself has two blockers independent of the code: the documented `main` ruleset requires linear history while the plan requires a merge commit, and the admin-override audit looks for checks on a commit where they never exist. See the CI and supply-chain section of [findings.md](findings.md).

## Findings by area

| Area | P0 | P1 | P2 | P3 |
| --- | ---: | ---: | ---: | ---: |
| Kernel admission, evaluation, dispatch and recovery | 0 | 4 | 11 | 2 |
| Kernel active response, DPoP, approvals, process and runtime crates | 0 | 0 | 8 | 1 |
| SQLite security state, serving owner and receipt store | 0 | 1 | 3 | 2 |
| SQLite admission operation and budget stores, manifest, Postgres | 0 | 0 | 3 | 2 |
| Control-plane security pipeline (adapters, event consumer, scheduler) | 0 | 1 | 6 | 3 |
| Control-plane trust control, CLI and products | 0 | 0 | 3 | 3 |
| Secret broker, keyring, secure IPC, hardware custody | 1 | 4 | 6 | 3 |
| Cage sandbox, quarantine, decoy, flow and security kernel | 0 | 1 | 5 | 2 |
| Protocol edges, provider adapters and guards | 0 | 2 | 9 | 3 |
| Core types, trust crates, tooling, spec and wire | 0 | 0 | 3 | 3 |
| Workflows, scripts, xtask, supply chain and formal | 0 | 0 | 6 | 2 |
| Vendored third-party forks | 0 | 0 | 4 | 1 |
| SDKs, examples and integrations | 0 | 1 | 4 | 2 |
| **Total** | **1** | **14** | **71** | **29** |

## Must fix before merge

The P0 and P1 findings. Two (F013, F014) predate this PR in files it modifies; they are listed because the adapters ship in this candidate.

- **F001 [P0]** Fix Darwin ACL scan: acl_get_entry returns 0 on success, so ACLs pass ([`crates/security/chio-keyring/src/lib.rs:581`](https://github.com/bb-connor/arc/blob/d0496c14d824a327f00b98576132834306ff6694/crates/security/chio-keyring/src/lib.rs#L581))
- **F002 [P1]** Complete pre-dispatch compensation for settled prepayments and Settling releases ([`crates/kernel/chio-kernel/src/kernel/admission_coordinator.rs:1788`](https://github.com/bb-connor/arc/blob/d0496c14d824a327f00b98576132834306ff6694/crates/kernel/chio-kernel/src/kernel/admission_coordinator.rs#L1788))
- **F003 [P1]** Stop one unrecoverable admission from failing every later tool call ([`crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery.rs:358`](https://github.com/bb-connor/arc/blob/d0496c14d824a327f00b98576132834306ff6694/crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery.rs#L358))
- **F004 [P1]** Replay durable settlement from the persisted disposition, not a live FX quote ([`crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal_payment.rs:93`](https://github.com/bb-connor/arc/blob/d0496c14d824a327f00b98576132834306ff6694/crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal_payment.rs#L93))
- **F005 [P1]** Settle over-reported or unconvertible costs instead of failing finalization ([`crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal_payment.rs:103`](https://github.com/bb-connor/arc/blob/d0496c14d824a327f00b98576132834306ff6694/crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal_payment.rs#L103))
- **F006 [P1]** Stop a post-commit clock error from permanently closing the receipt writer ([`crates/platform/chio-store-sqlite/src/receipt_store/writer_accounting.rs:174`](https://github.com/bb-connor/arc/blob/d0496c14d824a327f00b98576132834306ff6694/crates/platform/chio-store-sqlite/src/receipt_store/writer_accounting.rs#L174))
- **F007 [P1]** Stop a backed-off declassification receipt from halting response planning ([`crates/platform/chio-control-plane/src/security/scheduler_worker/outbox.rs:228`](https://github.com/bb-connor/arc/blob/d0496c14d824a327f00b98576132834306ff6694/crates/platform/chio-control-plane/src/security/scheduler_worker/outbox.rs#L228))
- **F008 [P1]** Reject weak Ed25519 lifecycle keys and verify key-log signatures strictly ([`crates/security/chio-keyring/src/event.rs:739`](https://github.com/bb-connor/arc/blob/d0496c14d824a327f00b98576132834306ff6694/crates/security/chio-keyring/src/event.rs#L739))
- **F009 [P1]** Late witness signature on an activated checkpoint bricks the key-log store ([`crates/security/chio-keyring/src/sqlite_parts/part_01.rs:362`](https://github.com/bb-connor/arc/blob/d0496c14d824a327f00b98576132834306ff6694/crates/security/chio-keyring/src/sqlite_parts/part_01.rs#L362))
- **F010 [P1]** Witness ignores retained gossip when deciding whether to sign a candidate ([`crates/security/chio-keyring/src/witness.rs:277`](https://github.com/bb-connor/arc/blob/d0496c14d824a327f00b98576132834306ff6694/crates/security/chio-keyring/src/witness.rs#L277))
- **F011 [P1]** Stop treating a missing or disabled credential as a fatal broker fault ([`crates/security/chio-secret-broker/src/encrypted_blob_backend.rs:412`](https://github.com/bb-connor/arc/blob/d0496c14d824a327f00b98576132834306ff6694/crates/security/chio-secret-broker/src/encrypted_blob_backend.rs#L412))
- **F012 [P1]** Reject hard-linked descendants of forbidden directories at admission ([`crates/security/chio-cage/src/lib.rs:1131`](https://github.com/bb-connor/arc/blob/d0496c14d824a327f00b98576132834306ff6694/crates/security/chio-cage/src/lib.rs#L1131))
- **F013 [P1]** Assemble Cohere tool calls from content instead of trusting tool-call-end ([`crates/protocol/chio-cohere-tools-adapter/src/streaming.rs:38`](https://github.com/bb-connor/arc/blob/d0496c14d824a327f00b98576132834306ff6694/crates/protocol/chio-cohere-tools-adapter/src/streaming.rs#L38))
- **F014 [P1]** Gate every client-executed Responses tool item, not only function_call ([`crates/protocol/chio-openai-adapter/src/streaming.rs:166`](https://github.com/bb-connor/arc/blob/d0496c14d824a327f00b98576132834306ff6694/crates/protocol/chio-openai-adapter/src/streaming.rs#L166))
- **F015 [P1]** Stop following host-planted symlinks when writing Hermes launcher evidence ([`sdks/python/chio-hermes/src/chio_hermes/restricted.py:430`](https://github.com/bb-connor/arc/blob/d0496c14d824a327f00b98576132834306ff6694/sdks/python/chio-hermes/src/chio_hermes/restricted.py#L430))
- **Landing plan:** reconcile the documented ruleset (linear history, squash or rebase only) with the required merge-commit landing, and fix the admin-override audit (see the CI and supply-chain P2 findings).

## Coverage limits

Each area records what it did not read in [slices.md](slices.md). The main gaps are the bodies of the largest `.inc` fragments, most of the 26K lines of script tests, the full bodies of the two largest CI checkers, the generated wire file (checked only for reproducibility and placement), and parts of the effect backends and teardown code in the control-plane security pipeline. Upstream code in the vendored forks was compared against checksum-verified crates.io sources, not reviewed line by line.

## Relationship to earlier reviews

The PR branch carries its own review history under `docs/reviews/`. Two earlier findings are directly relevant and remain open in a larger form: the September 26 code-quality review's Q1 (`include!` fragments hiding module size; sites have fallen from 208 to 176 and the hygiene gate now counts fragments, but 16 new `.inc` files were added) and the pass-2 review's R2 (the error taxonomy discards rejection provenance; the PR adds 676 new `map_err(.. to_string())` sites).
