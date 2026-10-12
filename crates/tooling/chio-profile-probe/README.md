# chio-profile-probe

`chio-profile-probe` exercises a `u64` subtraction under the Cargo profile
that compiled its binary. Release checks use this small executable to detect
whether exhausted-budget arithmetic traps or wraps under shipping settings.
The package contains one binary and has no dependencies or Cargo features.

## Usage

Run this from the workspace root with Cargo and a POSIX shell. The workspace
release profile enables overflow checks and uses unwinding panics, so `0 - 1`
must exit with status 101 and report the subtraction overflow.
The build is checked separately before interpreting the probe result.

```sh
set -eu
probe_demo=$(mktemp -d)
trap 'rm -rf "$probe_demo"' EXIT
cargo build --locked --release -p chio-profile-probe
probe_status=0
cargo run --locked --quiet --release -p chio-profile-probe -- 0 1 \
  > "$probe_demo/output.log" 2>&1 || probe_status=$?
test "$probe_status" -eq 101
grep -F 'attempt to subtract with overflow' "$probe_demo/output.log"
if grep -Fq 'wrapped:' "$probe_demo/output.log"; then
  exit 1
fi
```

The shell succeeds when the probe panics as expected. With overflow checks
disabled, the binary prints `wrapped: 0 - 1 = 18446744073709551615`
and exits zero, causing the assertion above to fail.

Arguments are positional unsigned integers: remaining amount, then spent
amount. Missing or unparsable arguments fall back to `0` and `1` respectively.
Passing operands whose subtraction is representable prints the result and
exits zero even when overflow checks are enabled.

## Guarantees

- `operand` reads command-line values at runtime, preventing the example
  subtraction from being resolved solely from compile-time constants.
- `main` performs ordinary `u64` subtraction and prints only after it returns.
  Its behavior therefore depends on the effective build profile.
- The workspace `release` and `docker-release` profiles explicitly enable
  `overflow-checks`; the probe observes the resulting executable behavior.

## Status

This unpublished diagnostic binary measures one arithmetic operation in its
own executable. Product builds, platform behavior, and acceptance of release
artifacts require their own qualification. The broader overflow scripts inspect
profile configuration and execute additional isolated profile probes.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol evidence boundary](../../../spec/PROTOCOL.md#54-safety-properties-and-evidence-boundary)
- [Release evidence](../chio-release-evidence/README.md)
- [Overflow gate](../../../scripts/check-release-overflow.sh)
- [License](../../../LICENSE)
