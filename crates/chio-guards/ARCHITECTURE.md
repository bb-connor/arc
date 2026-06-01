# chio-guards Architecture Notes

## Boundary

`chio-guards` owns Chio's built-in pre-invocation and post-invocation guard
implementations. The crate converts kernel `GuardContext` values into typed
action categories, evaluates policy-specific guard logic, and returns
fail-closed `Verdict` values to the hosted kernel. It should not own receipt
signing, capability validation, budget mutation, or persistent kernel state.

## Current Pain Point

The shell-command guard has two detection layers: regexes over the raw command
line and structured token analysis for command wrappers, root deletion, and
forbidden path access. The structured layer understands wrappers such as
`sudo`, `env`, and `command`, but it does not descend into shell interpreter
command strings such as `sh -c` or `bash -lc`. That leaves the regex layer as
the only protection for nested shell commands, which is weaker for quoted or
token-split destructive patterns.

## Security And API Constraints

- Guard evaluation must remain fail-closed for malformed guard configuration.
- Public guard constructors and re-exports should remain compatible.
- Benign shell data such as `echo rm -rf /` must not become a denial merely
  because a nested shell string contains those words.
- Wrapper handling must preserve existing `sudo`, `env`, `command`, quoted
  separator, and forbidden-path behavior.

## Affected Dependents

The owning-crate change is internal to `chio-guards`. It affects callers that
install `ShellCommandGuard` directly or through `GuardPipeline`, including
kernel and CLI policy paths. No dependent API change is planned.

## Planned Improvement

Extend the structured shell-command analysis to recurse into shell interpreter
`-c` command strings. The nested analysis should detect the same destructive
root-deletion forms that are already blocked at top level while preserving the
current distinction between executable shell syntax and inert command text.
