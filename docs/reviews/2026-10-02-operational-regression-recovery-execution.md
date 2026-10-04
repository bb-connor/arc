# Operational regression recovery execution

This batch implements the five-item queue in
[the prior execution record](2026-10-02-ci-authority-time-repair-execution.md#next-queue)
from base `df9f1791b32b3bd18fd83bb5758587607a20e753` on
`packet/3-retention-accounting`. All five repairs, the review fix pass and local
qualification are complete at source commit
`be925005f6e4a37b6a6f6588fb907b7e55a9b5f2`. Local owner evidence is distinct from
hosted qualification, merge, release and operator activation.

## Implemented boundaries

| Finding | Result | Regression evidence |
| --- | --- | --- |
| PB3 | MCP background clock failures preserve the live session and queued work; time-dependent requests still return a typed failure. An empty queue needs no background clock read. | Three new controls failed before the repair. The full 131-test MCP owner suite passed, including actual idle/pending serve-loop recovery, prior no-dispatch/expiry controls and retained terminal outcomes without automatic retry after evaluation starts. |
| PR3 | API-protect projects an advancing epoch floor from monotonic elapsed time, retaining fractional time across polling. Native strict clocks retain their original contract. The kernel, nonce store, durable admission store and configured local budget share the service clock. | Backward-step controls failed first. All 226 API-protect and 26 security-types tests passed, including signed-capability expiry, nonce replay, durable read refusal/recovery, budget mutation refusal/recovery, forward steps, overflow and monotonic regression. |
| PR5 | Certificate collection has independent 100,000-receipt / 128 MiB session limits, 1 MiB selected-row limits and a 16 MiB membership inspection bound. It preserves exact session IDs and store sequence numbers, refuses ambiguous membership and never truncates a session. | The old 4,096-entry rejection, unrelated oversized-row contamination and hidden duplicate/conflicting membership all reproduced. A 4,097-receipt session generated and fully verified through the actual CLI. Uninspectable input produced no certificate. All 12 final certificate owner tests and the final CLI round trip passed, including exact count/byte limits, native decoding causes with row context and UTF-16 database compatibility. |
| NC2 | Responses retain repeated field values in wire order within a stable name sort. The signed digest and durable validator accept that representation. Request uniqueness and framing checks remain enforced. | All 174 broker owner tests passed. A real production-service execution, SQLite close/reopen and durable replay returned identical repeated Vary/Link fields, invoked the provider once, and rejected reordered signed values. Existing credential, size, framing and process-boundary controls passed. |
| TR2 | A bounded, documented VirusTotal 404 NotFoundError returns a successful unseen-policy decision. Explicit policy defaults to Deny; Allow is opt-in. Provider failures retain the error path. | The old adapter opened its breaker on unseen results. All 49 external-guard tests/doc tests and 21 shared adapter tests passed. Repeated unseen decisions cache without opening the breaker; subsequent malicious content still denies even with advisory circuit policy. Malformed, duplicate, oversized, wrong-status and authentication responses remain failures. |

The implementation follows
[the approved batch plan](../superpowers/plans/2026-10-02-operational-regression-recovery.md).
Repeated response field order follows
[RFC 9110 section 5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3).
The unseen response is pinned to
[VirusTotal's documented error contract](https://docs.virustotal.com/reference/errors).

## Bounded claims and decisions

The advancing clock is an explicit process-local service policy. It cannot turn
an unavailable sample, monotonic regression or overflow into authority. Retained
durable time floors still apply across restart. Broader AC2/AC3 ambient-clock
owners remain separate work; passing this batch does not claim all kernel paths
have been migrated.

Certificate selection validates original JSON before metadata projection. An
unambiguously different session may be excluded even if its body is invalid;
this does not authenticate excluded bodies. Unknown, malformed or conflicting
membership aborts. Selected receipts still require trusted signatures, and global
row-ID gaps remain visible. Deleted or archived receipts require restored source
evidence; collection cannot establish their coverage from an unsigned index.
Private error causes preserve row IDs and decoder failures without publishing
receipt payloads. See the [collection contract](../protocols/SESSION-COMPLIANCE-CERTIFICATE.md#cli-receipt-collection-limits).

The new certificate owner uses the existing bounded original-document decoder
and typed projection helper, and is explicitly registered in the reader inventory.
No inventory baseline or source-size cap was raised. Source tripwires do not
constitute closure of the remaining SF1/CA2 contract-enforcement findings.

The VirusTotal decision is implemented in the Rust guard library. This does not
claim that an application or policy loader newly wires that guard into a shipped
binary. The operator reference now accurately distinguishes permanent errors
(which count against the breaker but do not retry) from successful Deny decisions.

## Independent review

The fresh read-only review covered all five tasks in
`df9f1791b32b3bd18fd83bb5758587607a20e753..83d5e8a47a31d01150034ee9a3c4fc8627adbfd4`.
It found no Critical or Important issue, and one Minor: SQLite TEXT conversion
could reject invalid UTF-8 before attaching the receipt row ID. The missing row
context reproduced before the fix. The repaired conversion retains the row ID
and native cause, and controls cover both UTF-16 database byte orders. The
[review record](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-02-operational-regression-recovery/independent-review.md)
preserves the original assessment and exclusions. Root verified the fix pass;
no second independent review is claimed.

The evaluator boundary was examined explicitly. Before evaluation, failed clock
reads preserve pending work. After evaluation starts, errors remain terminal
results and are not automatically retried, because authority consumption or tool
effects may already have occurred. A passing scripted late-clock control proves
retained denial, no dispatch on the failed first evaluator read, no automatic
retry, and successful fresh work after recovery in both background processors.

The reviewer set aside historical certificate truth/archival completeness,
authentication of excluded bodies, cross-process clock projection, broader
AC2/AC3 and SF1/CA2 findings, and hosted/operational acceptance. These are explicit
limits and remaining work, not completed acceptance claims.

## Qualification evidence

Raw terminal logs and SHA-256 metadata are preserved under
`/home/connor/chio-security-evidence/2026-10-02-operational-regression-recovery/`.
The [qualification artifact](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-02-operational-regression-recovery/qualification.json)
selects passing acceptance runs, verifies their raw log hashes, records the
committed source manifest and retains all failed/intermediate runs separately.
The accepted suites passed **640 tests and doc tests**, with no failures or
ignored tests. All-target Clippy for the six changed owners passed with
`-D warnings`. Formatting, file hygiene, clock inventory, HTTP egress contracts,
trust-boundary census and source review-slice checks passed. These are focused
owner and source-gate results, not a full workspace test run.

Cargo graphs were serialized on local Linux aarch64 with Rust 1.94.1, four build
jobs and incremental compilation off.
Workspace formatting is supplemented by direct checks of CLI modules that Cargo's
formatter cannot reach through the existing binary include root.

No new lint allowances, ignored tests, dependency exemptions, enforcement bypasses
or timeout relaxations were introduced. Original RED results and fixture/command
repairs remain in the archive; none is relabeled as a passing run.

## Prior hosted workflow terminal result

[Workflow 36983882538](https://github.com/bb-connor/arc/actions/runs/36983882538),
source `66d1ab85075abb84b328fff1f84091161b474d05`, is now terminal **failure**.
Its four scoped native acceptance steps and all five native targets passed.
The subsequent broader consumer job failed on a missing `x86_64-linux-musl-gcc`
compiler, a later `CHIO_DOCKER_ADAPTER` environment lookup, and Ruff formatting of
`crates/products/chio-cli/tests/process_host/runner.py`. The environment lookup
may be a consequence of the failed build; it needs confirmation after that repair.

Job `110764373932` has a retained complete log with SHA-256
`71bdda4ac5a9abac688c1ba31e1cb8125a25dc039ffc5e886159a671da174a9a`.
This preserves the earlier scoped native acceptance while recording that the
whole consumer workflow did not pass. It does not qualify this batch's source.

## Next execution queue

1. Reproduce and close AC2/AC3: route remaining kernel, SQLite and process-host
   decisions through explicit clock owners; expand the gate to actual trust
   boundaries, adapter calls, aliases and function-path clock reads.
2. Reproduce and close SF1/CA2: make producer-specific signed/canonical/document
   decoding contracts checked code claims, with downgrade and inventory-only
   mutation controls. Census counts alone are not acceptance evidence.
3. Repair and rerun the broader hosted consumer workflow: provision the intended
   musl toolchain, verify Docker adapter exports and format the process-host runner.
   Preserve its prior terminal failure and qualify the new exact source separately.

The security roadmap and last-week review backlog are not fully complete.
