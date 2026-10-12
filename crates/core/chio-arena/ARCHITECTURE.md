# chio-arena architecture

## Responsibility and boundary

`Scenario` describes recorded agents, steps, budgets, guards, and adversaries.
`ArenaRuntime` owns sequencing and result comparison around supplied
`Arc<ChioKernel>` handles. The caller owns kernel configuration, capabilities,
request construction, and tool-server registration. The harness must match each
request's server, tool, arguments, and agent content to its scenario step.
Scenario guard and budget
blocks are metadata here; the runtime does not install them into a kernel.

`ArenaRun` stores scenario identity and ordered `ArenaReceipt` values containing
actual kernel receipts. The separate adversary and co-evolution surfaces generate
mutations and score them with a toy evaluator. A fitness score measures that
evaluator's behavior, with no production policy-equivalence guarantee.

## Structure

| Module | Responsibility |
| --- | --- |
| `scenario` | TOML envelope, witness, validation, and file loading |
| `scheduler` | Declaration-order slots and per-agent step counters |
| `clock` | Explicit virtual ticks and start-time parsing |
| `rng` | ChaCha20 root and agent streams derived with stable FNV-1a seeds |
| `runtime` | Single-agent and multi-agent kernel evaluation |
| `link` | Tokio channel endpoints and a separate kernel multiplexer |
| `adversary` | Prompt injection, overrequest, replay, and scope-escape populations |
| `coevolve` | Fitness, seed corpus, mutation, crossover, and generation driver |
| `promote` | Replay bundles and corpus-file writers |
| `leaderboard` | Ranked fitness serialization and Markdown rendering |

## Data and control flow

`parse_scenario_str` deserializes TOML and calls `validate_scenario`. The
scheduler checks agent references, assigns each step its declaration index,
and sorts by virtual slot, agent id, and intra-agent counter.

`run` checks one-agent cardinality, request count, and positional step IDs before
calling `evaluate_tool_call` sequentially. `run_multi_agent` indexes requests
by step id and kernels by agent id, rejects duplicate entries, and dispatches
in schedule order. Missing requests or bindings and unexpected verdicts return
errors. Earlier kernel evaluations can already have occurred when a later step
fails; the API does not return a partial run on that error path.

Allow responses with receipt metadata `post_invocation.sanitized = true` map
to `Rewrite`; pending approval maps to `Deny`. The arena retains each returned
receipt. The virtual clock advances after each successful multi-agent step,
and an RNG snapshot is consumed at the end. Neither is injected into the
kernel. Fixed witnesses alone cannot guarantee byte-identical signed receipts.

`KernelLink` supplies paired in-process channels. `KernelMultiplexer::route`
selects a registered kernel and calls its evaluation API. These are separate
helpers; `run_multi_agent` dispatches directly through its binding map.

## Trust and artifact invariants

Scenario validation rejects unsupported witness settings, duplicate ids,
dangling agent references, zero budgets, and recognized secret/provider markers.
Marker scanning only recognizes the markers listed in `scenario.rs`.
Publicly constructed `Scenario` values require caller validation; runtime entry
points perform their own narrower request checks.

`write_arena_bundle` rejects empty runs, scenario mismatch, and receipt step ids
outside the scenario. It canonicalizes receipt and arena-receipt bytes, hashes
them, builds frames, delegates bundle writing to `chio-replay-corpus`, then
writes canonical `arena.json`. It removes an existing arena manifest first;
this is filesystem output without an all-files atomic transaction.
The frames use synthetic tenant signatures. The writer does not independently
verify embedded kernel signatures or require one receipt per scenario step.

`promote_to_fixtures` requires `CHIO_BLESS=1`, a matching scenario-prefixed
`BLESS_REASON`, a non-CI environment, and a positive cap. The adversarial
promotion helper has no corresponding bless gate. It writes deny/rewrite entries
to the existing suite cases directory, or a `target/arena/promote-pending` tree
when that directory is absent. Its string-versioned arena case envelope differs
from the suite's integer-versioned `AdversarialCase`; writing a file does not
make it suite-loadable or register it in the embedded corpus.

## Dependencies and evolution

`chio-core-types` supplies canonical JSON and hashing under the `chio-core`
dependency alias. `chio-kernel` evaluates requests. `chio-tee-frame` models
frames, while `chio-replay-corpus` writes replay fixtures. Serde, JSON, and TOML
encode envelopes; Tokio supplies channel transport; Rand and ChaCha implement
seeded streams; `thiserror` carries failures.

`evaluate_population` counts toy denials as defeats and other verdicts as
survivals. Mutation and crossover produce population blueprints. The driver
uses fitness ranking, elites, and offspring selection. The seed corpus is
recorded through its fingerprint; this driver does not inject its artifact bytes.
Generation and wall-clock budgets can return `BudgetExceeded` with the current
population pool and completed generation trace. Wall-clock cutoffs can change the completed generation
count. Seed loading records missing directories and sorts discovered paths.
`render_leaderboard` writes canonical JSON and Markdown from the fitness report.

## Verification

Run `cargo test -p chio-arena` from the workspace root.
`scenario_parse`, `scheduler_determinism`, `rng_determinism`, and `virtual_clock`
tests exercise parsing and reproducibility primitives. `single_agent_runtime`
and `multi_kernel_routing` exercise configured kernels and routing boundaries.
`determinism_gate` compares schedule bytes, RNG snapshots, clock traces, and
verdict tuples across repeated reference runs; it does not compare full signed
receipts. Adversary and co-evolution tests exercise toy outcomes, mutation,
crossover, deterministic traces, and budget termination.

`bundle_writer`, `promote_to_fixtures`, `promote_to_adversarial_suite`, and
`end_to_end_smoke` cover artifact production. Promotion tests inspect the arena
envelope; they do not establish suite-loader compatibility. These are local
harness checks, with deployment acceptance outside this crate's boundary.
