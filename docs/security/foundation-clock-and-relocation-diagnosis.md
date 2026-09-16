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
remain unchanged. Requalification must include the original failing `002`
umask and the owning target before claiming resolution.

Evidence: `foundation-relocation-diagnostic-94e0da1fb/`, including the exact
executable digest, first isolated failure and three-case umask matrix.

## Remaining acceptance

The selected dependency graph has changed since the preserved executable was
built. A frozen current-source workspace run and affected confinement gates
remain required. The earlier passes are diagnostic evidence only. Inventory
and fuzz queues require an explicit restart after a passing foundation.
