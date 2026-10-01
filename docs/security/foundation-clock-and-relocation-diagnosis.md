# Foundation clock and relocation diagnosis

September 16, 2026. Confidence is high for the reproduced causes below. This
diagnostic evidence does not establish a passing foundation on a newer source.

## Preserved source and executable

The original workspace run used source
`94e0da1fb758c6759dd78439a6d34d3358ba638a`. Its control-plane test executable has
SHA-256 `79ef30eb0485c4967b59ee04db5b6e2b52543b6b153a0f957031d7771465820d`.
The executable, environment, original failures and complete reruns are retained
under `output/process-security-20260915/` in the primary checkout.

## Clock regression

The first complete serial rerun reported 1,132 passes and six failures. Its
clock observer recorded 41 backward wall-clock steps, approximately 94 to 124
milliseconds. The guest-agent journal recorded time synchronization events at
the corresponding times. Errors included regressed trusted authority time and
recovery reconciliation failures.

A controlled rerun temporarily removed `CAP_SYS_TIME` from `lima-guestagent`,
with NTP still active, then restored the original service configuration. It
used the same source, executable, captured environment, serial execution and
original test deadlines. It recorded zero backward clock steps and passed all
six previously failing cases and the original native capture expiry case.
The terminal result was 1,137 passes and one failure in 2,774.90 seconds.

Evidence: `foundation-failure-diagnostic-94e0da1fb/` and
`foundation-controlled-clock-94e0da1fb/`. The latter retains the controller,
service states, observer samples, complete output and terminal result.

## Relocation fixture

The remaining case was
`durable_admission::tests::unchecked_relocation_validates_seed_before_any_import_mutation`.
Its initial runtime open refused a group-writable temporary ancestor. The test
set private permissions on its child directories but used an unhardened
`tempfile::tempdir()` for their parent.

The unchanged executable reproducibly fails under `umask 002` and passes under
`022` and `077`, with the same captured environment and working directory.
The original workspace controller explicitly set `022`; the diagnostic
controller inherited `002`. Thus the new failure reveals a fixture assumption
introduced by the diagnostic launch environment, not a failure observed in
the original workspace invocation.

The fixture now uses the existing `private_tempdir()` helper. Runtime ancestry
validation, all malformed relocation inputs, mutation assertions and deadlines
remain unchanged. The rebuilt test passes under the original failing `002`
umask at frozen source `6554383cc2acb4fe79f9085b8f5f7bc7443a9b69`.
Its executable SHA-256 is
`c3ab362444ec4b6b970c06a160188a4ee1fcb8b2f910ad3ec1568f2b96eebd55`.
The complete owning target and workspace gates are still required.

Evidence: `foundation-relocation-diagnostic-94e0da1fb/`, including the exact
executable digest, first isolated failure and three-case umask matrix.
The passing rebuilt case and its source, lock and binary identities are in
`linux-foundation-6554383cc/relocation-umask-002.json` and its adjacent log.

## Terminal foundation and forward clock steps

The `6554383cc` workspace run finished September 17. Build, workspace format,
generated security vectors and strict workspace Clippy passed. The full
control-plane target passed all 1,138 tests, including native capture expiry.
The workspace test command nevertheless exited 101 because one SQLite test
failed:

`admission_operation_store::tests::security_participant_state::mutations::authority_binding::first_join_cannot_substitute_another_valid_native_authority`.

Its error was `trusted_now_unix_ms exceeds the permitted system-clock skew`.
The SQLite target reported 1,675 passes, one failure and four ignored tests.
Proof coverage separately failed on a stale input digest at that frozen source;
the current candidate regenerates and checks it after dependency selection.

Removing the guest agent's clock-setting capability prevented backward steps,
but the retained observer still recorded five forward wall-clock jumps of
approximately 6,636, 3,209, 924, 1,237 and 916 seconds. Each occurred within
about one second of monotonic elapsed time. Every jump exceeds the authority's
five-minute skew limit. The original test log has no timestamp for the failed
case, so it cannot prove which jump coincided with the error.

On September 20, the exact SQLite executable was copied and hash-verified before
any new build. Its SHA-256 is
`253a2856751216e1f872c73d0ba01e03e0e5860755e558ae29a55ae37581a177`.
The isolated failing case passed. Its complete owning target then passed
1,676 tests, with the same four ignored cases, in 1,426.49 seconds. The run used
the frozen source, original serial execution and deadlines, umask 022, the
recorded controller environment and Cargo's owning-package working directory.
The original child environment was not captured in full; that limit is stated
in the diagnostic identity record.

This rerun temporarily disabled guest-agent clock setting, kept NTP active,
inhibited host idle sleep with `caffeinate -i` and observed both backward steps
and wall/monotonic divergence. It recorded zero discontinuities and restored
the guest-agent service afterward.

A separate fault-injection experiment used the same unchanged executable.
A retained preload library adds 600 seconds to `CLOCK_REALTIME` after a selected
read in that test process only; it does not set the guest clock or change
`CLOCK_MONOTONIC`. Five injection positions reproduced the exact original
skew error. Six other positions passed, as did no-step controls before and
after the sweep. Thus a forward jump is a demonstrated cause of this error,
with high confidence. Attribution of the historical failure to a particular
recorded jump remains moderate confidence because that run lacks per-test
timestamps. No production skew limit, lease duration or test deadline changed.

Evidence under the same primary-checkout output root:

- `linux-foundation-6554383cc/`: all terminal foundation gates and clock samples.
- `foundation-sqlite-diagnostic-6554383cc/`: retained executable, launch identity,
  full target log, clock observations and restored service state.
- `foundation-sqlite-forward-step-6554383cc/`: injection library, all 13 cases,
  commands, digests and explicit historical-attribution limit.
- `resume-20260920/diagnose-sqlite.py`, `sqlite-forward-step.py` and
  `realtime-step.c`: reproducible controllers and the injection source.

## Remaining acceptance

The selected dependency graph has changed since the preserved executable was
built. A frozen current-source workspace run and affected confinement gates
remain required. Qualification must reject both backward clock steps and
forward discontinuities, and preserve a host-awake assertion for the run.
The earlier passes are diagnostic evidence only. Inventory
and fuzz queues require an explicit restart after a passing foundation.
