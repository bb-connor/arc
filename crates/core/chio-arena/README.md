# chio-arena

Scenario parsing, deterministic scheduling, kernel evaluation, and replay
artifact generation for Chio tests. Callers supply configured kernels and
`ToolCallRequest` values; the arena compares their results with scenario
expectations and collects the kernel's signed receipts.

The crate also provides adversary populations, a toy guard evaluator,
co-evolution, promotion helpers, and JSON/Markdown leaderboards.

## Usage

Parse and schedule a scenario without a kernel, services, or file writes:

```rust
use chio_arena::{parse_scenario_str, DeterministicScheduler};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(r#"
schema_version = "chio.arena.scenario/v1"
id = "example"
title = "One recorded step"
rng_seed = 42
virtual_clock_start = "2026-04-30T00:00:00Z"

[determinism]
rng_seed = 42
virtual_clock_start = "2026-04-30T00:00:00Z"
scheduler = "single-agent-v1"
locale = "C"

[[agents]]
id = "agent-a"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/example.txt"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/example.txt" }
expect_verdict = "allow"
"#)?;
    let scheduler = DeterministicScheduler::from_scenario(&scenario)?;
    assert_eq!(scheduler.schedule()[0].step_id, "step-1");
    Ok(())
}
```

For kernel-backed runs, use `ArenaRuntime::run` with one agent or
`run_multi_agent` with `AgentKernelBinding` values. Construct capabilities,
guards, tool servers, and requests in the calling harness.

## Guarantees

- `parse_scenario_str` calls `validate_scenario`, rejecting unsupported schema,
  scheduler, locale, mismatched witnesses, duplicate ids, invalid references,
  and recognized inline-secret and provider markers.
- `DeterministicScheduler` assigns declaration-order virtual slots and orders
  by virtual time, agent id, and per-agent step counter.
- `ArenaRuntime` checks request count, step IDs, and expected verdicts, returning
  typed errors for mismatches and kernel failures. The harness owns matching
  each request's server, tool, arguments, and agent content to its scenario step.
- `write_arena_bundle` checks scenario identity and receipt step membership,
  canonicalizes receipt data, and writes replay artifacts with `arena.json`.

## Status

Implemented test-support library, marked `publish = false`. Co-evolution scores
against `evaluate_against_guards`, a toy evaluator. Virtual-clock advancement
in the multi-agent runtime does not replace the kernel's clock or randomness.
Replay frames carry a synthetic tenant signature. Adversarial promotion emits
an arena envelope requiring conversion before the suite loader can accept it.
These artifacts establish test evidence within those boundaries.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [Adversarial suite](../chio-adversarial-suite/README.md)
- [Kernel](../../kernel/chio-kernel/README.md)
- [License](../../../LICENSE)
