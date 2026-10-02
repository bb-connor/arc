# Clock ownership, checked decoding contracts and consumer qualification

This batch executes the three-item queue in
[the operational recovery record](2026-10-02-operational-regression-recovery-execution.md#next-execution-queue)
from base `491f585e9013dcb6335589c82d00ac219efbf0a6` on
`packet/3-retention-accounting`. Source and terminal qualification are recorded
separately below. This is bounded progress on the roadmap, not full security,
merge, release or operator acceptance.

## Implemented work

| Task | Implemented boundary | Acceptance controls |
| --- | --- | --- |
| AC2 authority clocks | Removed kernel global wall-time helpers; aggregate validators, finding-pool, active-response, nested child receipts and security release use the kernel owner. SQLite receipt writers, checkpoints, retention, finding stores, revocation and relocation use explicit clocks. Process host passes the owner to policy, reputation, keyring, native broker, swarm and evidence consumers. | Old/future epochs; unavailable and regressing clocks; actual authority issuance; callback rechecks before lock replacement; durable floor across restart; composite capture and expiry with injected time; actual host composition; zero remote issuance RPCs with failed time. |
| AC3 source enforcement | Derives complete crate coverage from TCB and signed-boundary catalogs. Detects aliases, function references, native adapters, independent time traits and SQL clock literals. Pins native constructor bodies and immutable base-source debt. | Inventory-only debt increases and native promotions reject; a second same-named method cannot borrow a constructor permit; escaped SQL is detected; historical scope evidence reproduces byte-for-byte. |
| SF1/CA2 decoding contracts | Pins decoding methods per constructor and named source owner; non-baseline raw readers require owner-scoped code evidence for their contract. Supports reviewed unsigned documents without relabeling them as signed input. | Signed/canonical downgrade, same-count constructor swaps, aliases, missing evidence, unrelated functions, lookalike helpers and inventory-only reclassification reject. |
| Consumer workflow | The prepared broker action owns musl compiler/target setup and checks all four executable outputs before writing environment exports. Corrected process-host runner formatting. Separated native build, host/protocol tests and installed-consumer execution after a terminal job timeout. | Missing/nonexecutable transport outputs write no environment; valid outputs export exact paths. Binary transfers require the exact producer artifact ID and digest. The existing required check aggregates every job and refuses failed, cancelled or skipped dependencies. Whole hosted acceptance is recorded separately below. |

The [implementation plan](../superpowers/plans/2026-10-02-clock-contract-consumer-closure.md)
contains the task checklist. Public capability-response validators now require a
final `UnixMillis` argument. Checkpoint owners use `CheckpointSigningContext` and
explicit `_at` builders; existing native convenience constructors delegate to
explicit-clock variants. No second clock abstraction was added.

## Limits of the source claims

The expanded immutable scan of the base found 471 observations, including 317
previously invisible observations. After this batch, 436 observations remain as
explicit debt and 38 native constructor functions have reviewed source contracts.
Both counts include fixtures; neither is a count of production vulnerabilities.
This closes the named owner gaps and scope-enforcement repair, not every ambient
clock migration throughout the repository.

The decoding gate covers 468 constructors, 85 tenant tables and 170 SQL principal
contracts. There are 45 raw-input-baseline files still recorded. Checked lexical
contracts do not resolve Rust names, expand arbitrary macros, prove dataflow, or
cover framework ingress such as every `Json<T>` extractor. CA3 and the remaining
TCB semantic reader work stay open. Inventory prose alone can no longer establish
the repaired checked classifications.

Native conveniences remain explicit composition choices. Injected services share
their existing fenced clock. SQLite durable high-water state remains authoritative
across restart. Post-commit clock faults cannot retroactively undo committed work;
failed subsequent operations refuse new work. No timeout, guard, tenant check,
signature check, size cap, lint rule or dependency policy was weakened.

## Independent review and repairs

One fresh read-only review found no Critical issue, two Important issues and one
Minor. Reputation scoring still used host time, and remote issuance sent its RPC
before reading clock health. Both reproduced through real owner behavior: a recent
signed denial decayed under the wrong epoch, and a loopback server observed one
issuance request despite a failed clock. The fix supplies the shared reputation
context and probes before remote mutation while retaining response-time validation.
The Minor escaped-SQL scanner gap also failed before its repair and passed after.

The [review record](artifacts/2026-10-02-clock-contract-consumer-closure/independent-review.md)
preserves the original assessment and the root fix pass. The same reviewer later
performed a bounded CI-only follow-up, described below. Compiler-found callsite,
module-import and unused-helper repairs
are retained in the raw terminal record, not reported as passing attempts.

## Local and hosted qualification

The first full SQLite suite completed with 1,910 passed, four failed and three
pre-existing ignored campaigns. That run remains a failure. Its four failures
were corrected in test code: two state-machine controls now hold an explicit
fixture epoch, legacy dead-letter rejection checks the typed native decoding
cause, and qualified tool-outcome expiry controls use a fresh owner rather than
rewinding a clock after a failed expiry probe. The repaired and affected SQLite
owner groups passed 84 tests. No production clock or expiry check was relaxed.
The unchanged cases from the first full run were not rerun or relabeled green.

The broad control-plane diagnostic was interrupted after two reproducible
federation JSON error assertions failed and native capture cases continued.
The assertions now require the preserved signed-input parsing cause while retaining
separate I/O and version checks. Its SIGINT result is retained as non-acceptance;
final acceptance uses the selected changed authority/federation owner suite.

Final local acceptance totals 1,681 Rust tests: 1,495 kernel, 84 selected SQLite,
85 selected control-plane, eight keyring, one actual process-host clock composition
control and eight process-host integration tests. These runs have no failures or
ignored tests. Changed-owner warnings-denied Clippy, workspace formatting, Rust
hygiene, clock and decoder source gates, consumer export controls, Ruff and native
protocol CI checks passed. Calibration includes ten clock, 35 decoder and eleven
native protocol tests, plus three actual consumer-transfer and dependency-result
controls. The committed-source review gate accounts for 116 changed
files across six review slices.

The [qualification artifact](artifacts/2026-10-02-clock-contract-consumer-closure/qualification.json)
records commands, exit codes, raw-log digests, source-manifest digest and separate
non-acceptance runs. Raw evidence remains in
`/home/connor/chio-security-evidence/2026-10-02-clock-contract-consumer-closure/`.
Local source is `d7a33ba9341b78458cd639df352ad5618d31e38c`.

The first hosted retry,
[37031065118](https://github.com/bb-connor/arc/actions/runs/37031065118),
ran `604549fb854741201483f3eda7792209c0cc3c23` and was cancelled at the existing
90-minute job limit. Its annotations explicitly report maximum execution time.
Authenticated Python/JavaScript workers passed. Host/protocol tests, enforcement
qualification, the optimized CLI and repaired broker build passed. Docker worker
recovery and native mini-SWE baseline, known-outcome and unknown-outcome profiles
also completed before cancellation during operator qualification. Later installed
consumer steps were skipped. This is not a passing workflow.

The terminal host log has SHA-256
`71479b2fc059c1471c8e8e54cbb8c227f6e18717102eec4852dc7dcb5d30dab3`.
All three available artifacts were downloaded and matched their GitHub archive
digests. Compilation occupied roughly 82 minutes before installed recovery began.
The repair separates binary production from installed-consumer execution, keeps
the same 90-minute limits on each substantive job, and keeps every original
installed-consumer command. It does not change any runtime test timeout. The new
consumer runner performs its own unchanged enforcement probe and prepares fresh
authority grants. Same-run artifact ID and producer digest pin binary transfer;
the existing required check name is an aggregate that requires every job's success.
Local controls exercise the real transfer and aggregate shell scripts, including
altered archives, malformed/mismatched digests and every non-success job result.
Process-workflow Actionlint passed. Checking both workflows also exposed that the
installed Actionlint does not recognize the pre-existing `artifact-metadata`
permission in `ci.yml`; that failed attempt is retained, and no permission or
lint rule was changed to conceal it.

The CI follow-up caught one additional Important download-layout mistake. The
root reproduced it against the pinned action's path-selection behavior, then set
`merge-multiple: true` for the one exact producer artifact ID. The reviewer checked
the correction and independently reran its three passing controls.
[37042343075](https://github.com/bb-connor/arc/actions/runs/37042343075) at
`9a7892297669ad3c8cb86290dcd2fa192a1dcf99` was deliberately cancelled early after
that finding, rather than allowed to consume a complete build before a known
failure. Its terminal logs are retained. The aggregate check correctly failed
when its dependencies were cancelled. It supplies no passing hosted acceptance.

The corrected exact-source retry,
[37043188904](https://github.com/bb-connor/arc/actions/runs/37043188904),
runs `d7a33ba9341b78458cd639df352ad5618d31e38c` and remains in progress. Scoped
hosted acceptance is pending; its eventual terminal result must be recorded before
closing the consumer-qualification task.

All production Rust behavior changes are in
`604549fb854741201483f3eda7792209c0cc3c23`. Later source commits repair test
fixtures, their clock inventory and the consumer job layout. No full required-CI,
merge, release, publication or operator-activation result is implied.

## Next execution queue

The [next implementation plan](../superpowers/plans/2026-10-02-identity-authority-release-closure.md)
records the source owners, failure controls and acceptance boundaries.

1. AP1: replace deterministic sidecar private-key derivation from public subject/job
   labels with caller-supplied validated public subject keys. Verify both mint routes,
   SDK interoperability and DPoP sender binding with honest and attacker keys.
2. KG1: authenticate authority snapshots with pinned signer identity and exact
   generation/freshness/replay contracts before import. Require authenticated peer
   transport and prove a service token alone cannot install an issuer.
3. RL1: align installation and publication verification with the actual release
   repository/workflow identity and test the documented verification commands.
   Account ownership or release activation remains a separate operator action.

Current source was checked for this queue: sidecar issuance still derives a keypair
from public labels; cluster authority sync still imports a peer snapshot directly;
verification documentation still contains the old signer identity. Runtime run/step
writers also still lack lease-token predicates (AC4). CA3 ingress coverage, remaining
proof sealing/error provenance, full required CI, branch decomposition and the
compliance/product backlog remain open after these priorities.
