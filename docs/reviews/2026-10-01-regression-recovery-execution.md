# Regression recovery execution

This batch follows the user's priority decision to repair SR1, PB1, PR1/PB2/PR2
and PR6 before the queued reader campaign. The starting source is
`fb1cfc30241592e6852226efbca6162f1b39c8e3` on `packet/3-retention-accounting`.
It also repairs the original GT1/CA1 classifiers and self-tests and makes the
structural CI step report every gate before returning failure.

## Changes and acceptance boundaries

| Work | Implementation | Required evidence |
|---|---|---|
| SR1, SR6 | Authenticate v6 predecessors without rewriting the archive; accept fully mirrored legacy repair archives; compare predecessor identity before deleting live rows | Complete receipt-store suite, upgrade/restart/append and corruption cases, divergent co-copy case |
| PB1 | Check persisted authority before launching an upstream; durably fence expired Ready sessions; keep the original deadline across restore | Recovery, clock and persistence tests, restored transport shutdown, failed fence/finalization and restart controls |
| PR1, PB2, PR2 | Use duplicate-aware ordinary JSON for provider/MCP/OpenAPI/SDK/operator documents; retain original strict credential slices and canonical invocation bytes | Eight provider producer matrices, fragmented stream, affected protocol and product suites |
| PR6 | Decode formatted unsigned private seed DTOs directly into wiping fields; create fresh private fixture files and stage committed public example keys | Relay and Iroh key reader controls; real relay, relay-ops, export, archive and archive-package fixture flows |
| GT1, CA1 | Classify missing paths, isolate self-test debt, aggregate terminal structural results | Classifier and mutation controls, complete structural step with retained failures |

## Independent review

One fresh read-only review found three Important issues and no Critical or Minor
issues: unversioned archive repair compatibility, unsigned governed-intent context,
and the unsigned runtime-attestation CLI evidence loader. All three were repaired
in the single author fix pass. The review independently passed the aggregate runner, domain
separation and lint parity self-tests. No merge-readiness claim was made. The fixes receive author verification; the
review was not repeated after them.

The archive repair failures reproduced in existing production-path tests. New
SDK and CLI producer tests exercise the real owning handlers/loaders. Embedded
call-chain proof and continuation tokens keep original strict numeric decoding.
The separate signed runtime appraisal loader keeps its original signed contract.

The reviewer also requested a cutpoint after the terminal fence commits but
before tombstone finalization. Its control requires no upstream launch, a durable
replay fence, no active row, successful restart and refused active-row replay.
An absent diagnostic tombstone never restores authority.

## Qualification record

Terminal commands, outcomes, durations and SHA-256 log digests are recorded in the
[qualification artifact](artifacts/2026-10-01-regression-recovery/qualification.json). New raw logs remain outside Git. Failed,
interrupted and superseded runs are retained distinctly from final acceptance.
Qualification is local; publication and exact-candidate hosted checks are separate.

| Accepted local boundary | Result |
|---|---|
| Receipt-store module | 404 passed, 2 existing ignored; upgrade/append, legacy repair, corruption and co-copy deletion controls included |
| MCP remote unit suite | 107 passed; all 7 recovery controls passed |
| API-protect unit suite | 221 passed; actual SDK and governed-intent handlers included |
| CLI unit suite with Iroh | 745 passed; relay/Iroh private files and operator loaders included |
| Eight-provider producer matrix and fragmented stream | 9 passed in the actual conformance target |
| OpenAI full owner rerun with provider-adapter | 107 passed across unit, lift, lower, streaming, error taxonomy and transport targets |
| Groq full unit rerun | 31 passed; malformed request never reaches transport |
| Other changed protocol unit owners | Passed in `owner-unit-final`; per-target results are in the artifact |
| CLI input final focused rerun | 10 passed, including the final operator-policy initializer |
| Relay fixture flows | `relay`, `relay-ops`, `relay-alert-assurance-export`, `relay-alert-assurance-archive`, `relay-alert-assurance-archive-package` all exited 0 |
| Formatting | `cargo fmt --all -- --check` passed |

The owner commands are not relabeled as passing jobs: the first run includes
superseded regression-test failures and 112 remaining failures across 18 CLI
integration targets; both owner runs also record the interrupted broad SQLite
child. Later targeted runs supply the acceptance evidence above. No full-workspace
or broad CLI integration pass is claimed.

The first broad SQLite run was interrupted while testing unrelated admission
schema migrations. The changed receipt-store owner is qualified as a complete
module. The later owner runs both launched the same 1,372-test SQLite binary;
those duplicate broad child runs were interrupted and replaced by the complete
receipt-store module. Neither interrupted SQLite run counts as passed.
A pre-existing overflow fixture used `u64::MAX` in a SQLite INTEGER and
failed before aggregation. It now uses three individually representable values
whose aggregate exceeds `u64::MAX`, preserving the actual report-overflow test.

The first owner run also caught two new API tests using a current-thread Tokio
runtime where the production bridge requires a multithread runtime. Their test
annotations now provide two workers. The missing-archive CLI test asserted a
wrapper and message no longer returned by the archive owner; it now verifies the
native `NotFound` cause and the actual structured I/O report. Neither correction
relaxes production behavior. Groq and OpenAI malformed JSON tests now expect the
duplicate-aware parser diagnostic. The old OpenAI full-width integer rejection
became a byte-exact preservation and invocation-validation control, with a
non-finite exponent retained as a numeric rejection case.

The relay flow required one stale schema constant to use its existing public
reexport. Clippy exposed one unnecessary borrow in relay persisted-batch loading;
the corrected expression has the same decoding contract. Proof-room doctor output
no longer converts its error back into the same error type; its I/O cause and
context remain intact. The provider HTTP mock now checks that its initial socket read received bytes rather than ignoring EOF.

The broad CLI integration run remains a failed qualification boundary. Existing
federation seed fixtures use public file modes, and MCP launch fixtures select
`EnterpriseMigrationStage::Disabled`, which production correctly refuses. Native
Python conformance additionally requires explicit cage helper, independent anchor
and identity material on an enforcing Linux x86_64 host; this host is aarch64.
No enforcement bypass, file permission relaxation or environment skip is counted
as a passing test. Other retained CLI failures include missing
`CHIO_PROCESS_REPORT_TOOL`, process directory custody, an unsupported process
journal fixture, and an operator-report HTTP 500 that still needs diagnosis.
These failures belong in the next CI repair batch; this report does not claim
that every broad integration failure has a proven root cause.

The final all-target Clippy command exited 101 with 26 distinct diagnostics in
files byte-identical to the starting commit. The new test-initializer lint was
repaired and is absent from this run; its ten-test CLI input suite passes.
The remaining locations, messages and base comparisons are in the artifact.
This is a failed lint qualification, with no added allowances or suppressed checks.

## Remaining work

The final aggregate CI step executed all 95 gates and returned failure for 19.
The original classifier/debt self-tests, aggregate-runner controls, MCP admin
mutation tests and both trust-boundary gates passed. The remaining failures are
in required-agent custody fixtures,
web3 prerequisites, generated Docker workspace/context parity, architecture docs,
enterprise provenance, the kernel-to-quarantine dependency boundary, log/egress
classification, release terminology and security/deception/temporal/cage/proof
inventories. These are not repaired by claiming the runner passes. Final gate
results identify the remaining commands precisely.

The next batch should restore the required CI job, the remaining Clippy sites
and the 18 failing CLI integration targets, and repair authority-time
regressions RC1 and AC1: sample challenge filing time after the client-paced body
read, and remove the production thread-local clock override in favor of explicit
clock injection. Reconcile the queued reader work with the latest review's TCB
scope recommendation, then enforce per-reader decode contracts (SF1/CA2).

No milestone, roadmap, reader census, hosted qualification, merge or release
completion is claimed by this batch.
