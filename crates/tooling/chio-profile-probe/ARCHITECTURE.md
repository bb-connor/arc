# chio-profile-probe architecture

## Responsibility and boundary

The crate owns a diagnostic executable named `chio-profile-probe`.
Its public surface consists of two positional operands and process output.
It probes the effective integer-overflow behavior of the executable that
Cargo built. Release qualification uses this observation because ordinary
unit tests run under the test profile.

An unchecked subtraction from an exhausted `u64` budget can wrap to a large
remaining value. The probe deliberately exercises that arithmetic boundary
using `0 - 1`. The surrounding qualification gate interprets the process
failure as evidence that this operation traps under the selected profile.

## Structure

The entire implementation is in [src/main.rs](src/main.rs).
`operand(position, default)` reads one command-line argument and parses a
`u64`. It supplies the default when the argument is missing or invalid.
`main` selects defaults of zero remaining and one spent, subtracts spent
from remaining, prints the result, and returns `ExitCode::SUCCESS`.

There is no argument parser dependency, library target, feature table,
persistence layer, or internal unit-test module. The package uses `std`
and inherits the workspace lint and toolchain settings.

## Data and control flow

Operands are read at runtime so constant folding cannot replace the probe
with arithmetic on literal constants while compiling.
Successful subtraction reaches a line beginning with `wrapped:`.
That line also appears for safe operand pairs, so the qualification command
must supply a pair that underflows.

With checks enabled, the subtraction panics before the print statement.
The workspace release profile sets `panic = "unwind"`, producing exit
status 101 for the README invocation. An aborting profile can produce a
different process status and needs its own expected-result handling.

With checks disabled, `0 - 1` produces `u64::MAX`, prints its decimal
representation, and returns zero. A verifier must distinguish this result
from a failed build, missing executable, or unrelated execution error.

## Trust and invariants

The probe owns no capability authority and handles no signed payloads.
Its security role is to expose one compiler-profile behavior relevant to
budget arithmetic. Effective Cargo configuration and environment overrides
are part of the build context that determines this behavior.

The root manifest explicitly sets `overflow-checks = true` in both
`release` and `docker-release`. `docker-release` inherits `release` while
changing optimization settings. Merely reading those entries cannot establish
the behavior of a particular already-built executable.

The probe's operand fallback is permissive: malformed input invokes the
default underflow case. Consumers should pass explicit `0 1` arguments
and assert both failure status and the distinctive overflow diagnostic.

## Verification

[check-release-overflow.sh](../../../scripts/check-release-overflow.sh)
checks manifest settings, builds the probe under a selected profile, and
requires a nonzero exit with the subtraction-overflow diagnostic.
It then invokes the standalone profile checker.

[check-standalone-release-overflow.py](../../../scripts/check-standalone-release-overflow.py)
copies this source into temporary manifests for selected shipping contexts.
It inspects profile inheritance, Cargo configuration, and unsupported profile
overrides before running isolated arithmetic probes.

The [README example](README.md#usage) separately checks the release build and
asserts status 101, the panic diagnostic, and absence of a result print.
Its evidence applies to the tested build context and subtraction operation.
