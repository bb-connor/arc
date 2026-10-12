# chio-guards

Native request guards and response sanitizers for the Chio runtime kernel.
Guards implement `chio_kernel::Guard`; callers register them individually or
compose them with `GuardPipeline`. The kernel owns capability checks, tool
dispatch, and signed receipt persistence.

## Usage

Build an explicit pipeline without invoking a tool or contacting a service:

```rust
use chio_guards::{ForbiddenPathGuard, GuardPipeline, ShellCommandGuard};

let mut pipeline = GuardPipeline::new();
pipeline.add(Box::new(ForbiddenPathGuard::new()));
pipeline.add(Box::new(ShellCommandGuard::new()));
assert_eq!(pipeline.len(), 2);
```

The example uses ordinary crate dependencies and requires no runtime or files.
Register the resulting pipeline through `ChioKernel::add_guard` in your runtime.
Install post-invocation hooks separately when response sanitization is required.
The crate declares no Cargo features.

## Guarantees

- `GuardPipeline::evaluate` runs children in registration order. Denials and
  evaluation errors stop processing and produce a deny with guard evidence.
- `PendingApproval` remains pending while later guards run; a later deny wins.
  An empty pipeline, including `GuardPipeline::default()`, allows evaluation.
- `default_pipeline()` installs forbidden-path, shell-command, egress-allowlist,
  path-allowlist, MCP-tool, secret-leak, and patch-integrity guards in that order.
- `default_runtime_guard_profile()` installs internal-network, agent-velocity,
  and advisory guards, followed by a separate output sanitizer hook. Its velocity
  thresholds are unlimited and its advisory detector roster is empty.
- `SanitizerHook::durable_identity` rejects tokenization because that strategy
  cannot supply a deterministic durable identity.

`AsyncGuardAdapter` denies external evaluation errors. Circuit-open and rate-limit
fallbacks default to deny, but callers can explicitly configure either to allow.
Choose those settings according to the guard's enforcement role.

## Status

Implemented guards cover file paths, shell commands, egress, tool access,
secrets, patches, rate limits, session flow, computer use, browser automation,
code execution, content review, and finding memory governance. Detection guards
also expose heuristic and statistical signals. Their effectiveness depends on
configured rules, inputs, and deployment wiring.

The implementation uses standard-library facilities and Tokio for async external
adapters. Unix input-file reads add no-follow and nonblocking open flags;
other platforms use ordinary opens with regular-file and byte-limit checks.
Repository tests exercise native kernel integration and individual guards.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol verification rules](../../../spec/PROTOCOL.md#53-verification-rules)
- [Policy compiler](../chio-policy/README.md)
- [Kernel](../../kernel/chio-kernel/README.md)

[License](../../../LICENSE)
