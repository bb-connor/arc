# Execution resumed after Claude usage exhaustion

Claude stopped with K and the census integrated, B/C/D committed but awaiting
acceptance, unfinished J/M files, and an X Miri failure. The root history is
session `a17733e5-ffc4-4e77-8f7c-b9a65f418804`. Codex resumed the existing isolated
worktrees, retained the original tips under `refs/codex/resume-20260926/`, and
archived the unfinished J/M files before modifying anything. The original source
checkout at `/home/connor/backbay/arc` was left at `f5566d9a76`.

Work was implemented directly. One independent reviewer was reused for security
and final diagnostic review; no implementation tasks were delegated.

## Integrated locally

The candidate is on `integration/process-security-m4` in
`/home/connor/lanes/integration`. The production checkpoint is `1e791271dc`;
`dc018fab21` adds the composite benchmark and `f3eb124962` adds the retention
diagnostic. These are local integration results, not hosted qualification or a
release. Local evidence and retained failures are under
`/tmp/chio-resume-20260926/`.

| Work | Concrete result | Local evidence |
|---|---|---|
| X: FFI ownership | Transfer buffers with `Box::into_raw` and recover the matching allocation when freeing. The previous pointers lost provenance when their owning boxes moved. | 44 Miri tests and 44 native tests passed; strict Clippy and unsafe census passed. |
| B and held A | Recover or fence poisoned store connections; verify serving-owner anchors before reuse; retain overflow checks in both shipped release profiles. Repair the DPoP caller-deadline regression using the live request without persisting its credential. | Full SQLite crate suite passed at `3b596d22bb`, including 1,793 library tests and all integration/doc targets. Both profile probes trapped overflow; negative gate probes failed as expected. |
| C: exact reports | Schema v6 preserves the full unsigned attempted-cost domain. Checked aggregates reject overflow. Reports verify signed receipts and their projections inside the same snapshot; a shared SQL instruction budget covers sparse scans. | Receipt/migration suite, 17 analytics cases, corruption and sparse-scan regressions, strict Clippy and independent review passed. |
| D: response authority | Execution bindings validate at construction/deserialization. Deployment configuration authenticates execution mode. Fresh kernel admission accepts only a bound live plan. Exact committed-dispatch and pre-dispatch governed-admission recovery are distinct. Missing committed dispatches return unknown instead of creating replacement work. | Owning type, authority, quarantine, kernel and control-plane tests passed. Combined source passed 373 receipt tests, five kernel response tests and 47 control-plane response tests; strict all-target Clippy passed. |
| D: signed JSON | Receipt and manifest readers reject duplicate keys and lossy numeric input while preserving established ordinary/canonical encodings, whole-valued floats, negative zero and full-width unsigned integers. Existing strict I-JSON parsing remains unchanged. | Original compatibility failures retained; new shared-parser tests, 43 strict-canonical tests, 68 manifest tests and receipt readback coverage passed. Default and no-default shared-parser targets passed. |
| J: retention diagnostic | Observe real public-store sync and lock ownership; preserve failed-open cleanup; bound completion after releasing a held sync. | Five tests passed under 3 ms per-sync delay, including two induced ordering gates and a timeout regression. Independent review accepted the repairs. The unchanged library property passed under 25 ms syscall delay. |

The full no-default core library test harness still fails to compile because
existing economic-continuity error types lack the required core error
implementations. The no-default library check and standalone shared-parser
tests passed. `d-canonical-no-std.log` retains the distinct failing command.

Final composition at `f3eb124962` passed all five retention diagnostic tests
with 3 ms sync delay in 68.93 seconds. Strict all-target SQLite Clippy passed,
including the new benchmark and diagnostic. Workspace formatting, logical file
hygiene, negative-assertion, wire-schema and domain-separation gates also passed.
`combined-retention-diagnostic.log`, `combined-store-clippy.log` and the
`integrated-*.log` files retain these terminal results. The final documentation
commit changes no production source, test, fixture or benchmark.

The [measurement report](../security/store-measurements-2026-09-26.md) records a
material cost: verifying an unfiltered 20,000-receipt report takes 4.8587 seconds,
versus 397.51 ms on the earlier source. Removing integrity verification would
reopen the reproduced corruption defect. The new populated authorization-store
composition measures 108.39 ms at one history size; it is not an end-to-end
kernel or scaling result.

The [retention evidence](../security/retention-diagnostic-2026-09-26.md) separates
controlled stalls from the historical hang. The unchanged original property
already executes normally on the present source. It passed in 254.69 seconds
with 25 ms interposed on 6,837 actual sync calls. That does not identify the
historical cause or establish million-entry acceptance.

## Remaining acceptance work

1. The [next execution checkpoint](2026-09-26-execution-boundaries.md) replaces
   bare-plan fresh preparation and creation with `FreshLiveAdmission`, and moves
   recovery preparation behind the kernel's sealed request. The raw persistence
   DTO remains a trusted store interface; the documented guarantee covers
   high-level construction and admission.
2. Finish D/1C's legacy obligation inventory and retirement condition, including
   automatic discovery of commitments without a dispatch. The next checkpoint
   covers migration/restart at that crash boundary with a retained plan/binding;
   the complete inventory and retirement enforcement remain open.
3. Complete the parent production dry-run: isolated version-bound simulation,
   shared transition rules, signed report persistence, real composition and the
   six-effect negative/recovery corpus. The simulator does not yet exist.
4. The [signed readback batch](2026-09-27-signed-readback.md) extends the
   [boundary inventory](../security/signed-json-boundaries.md) through checkpoint,
   broker direct/prepared, lineage and economy readers. Signed simulation-report
   parsing remains part of the unimplemented production simulator; the named
   census does not establish workspace-wide decoder closure.
5. Continue J with an evidence-backed disposition of #1045 and both original
   million-entry campaigns on stable source, followed by the real process and
   native boundary gates. This aarch64 development host does not substitute for
   the required x86_64 native runner.
6. Resume M after the production contracts stabilize. Preserve its uncommitted
   models. The original legacy temporal run failed after its 3,600-second bound;
   response lifecycle length 8 passed, length 12 timed out after 5,400 seconds,
   and the automatic length-14 follow-up was interrupted. These are not complete
   temporal or production-linkage proofs. Stateful fuzzing and production-linked
   Kani work remain.
7. Continue the dispatch plan's remaining F/H/G/S work, genuine AWS-LC audits and
   trusted delivery qualification. Then freeze the actual candidate, complete
   local/hosted gates and review, and separately establish release and operator
   acceptance. No exemption, deployment or release was added during this resume.

The execution ledger remains in the integration worktree at
`.superpowers/sdd/2026-09-26-security-execution-dispatch/progress.md`. It records
the exact retained red/green logs and intermediate decisions.
