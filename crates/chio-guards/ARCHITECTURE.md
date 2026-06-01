# chio-guards Architecture Notes

## Boundary

`chio-guards` owns Chio's built-in pre-invocation and post-invocation guard
implementations. The crate converts kernel `GuardContext` values into typed
action categories, evaluates policy-specific guard logic, and returns
fail-closed `Verdict` values to the hosted kernel. It should not own receipt
signing, capability validation, budget mutation, or persistent kernel state.

## Current Pain Point

The shell-command guard now recursively checks shell interpreter command strings
for destructive root deletion, but forbidden-path extraction still stops at the
outer command line. Some sensitive-path substrings are caught accidentally when
they remain visible inside the outer `sh -c` argument, but bare relative targets
such as `sh -c "cat .env"` are collapsed into one token and the delegated
`ForbiddenPathGuard` never sees `.env` as a path. That creates a weaker path
boundary for `sh -c`, `bash -lc`, and wrapper-mediated shell execution than for
top-level commands.

## Security And API Constraints

- Guard evaluation must remain fail-closed for malformed guard configuration.
- Public guard constructors and re-exports should remain compatible.
- Wrapper handling must preserve existing `sudo`, `env`, `command`, quoted
  separator, root-deletion, and forbidden-path behavior.
- Nested shell analysis must share the existing maximum recursion depth.
- Path extraction must remain best-effort and fail closed through the existing
  guard verdict path rather than adding kernel-side state.

## Affected Dependents

The owning-crate change is internal to `chio-guards`. It affects callers that
install `ShellCommandGuard` directly or through `GuardPipeline`, including
kernel and CLI policy paths. No dependent API change is planned.

## Planned Improvement

Extend structured path extraction to recurse into shell interpreter `-c` command
strings. The nested analysis should pass the same candidate paths to
`ForbiddenPathGuard` that top-level shell commands already expose, including
redirection targets and flag-embedded paths.
