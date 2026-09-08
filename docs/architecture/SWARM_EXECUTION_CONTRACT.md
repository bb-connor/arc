# Swarm execution contract: execution record

## Objective

Build and validate Chio as a reusable execution contract for heterogeneous
agent swarms operating on shared mutable resources. Use the existing process
stack. Establish a live-workload baseline, implement the smallest missing
capability that materially improves coordination or recovery, and demonstrate
reuse across two independent integrations. Every implementation slice must
remove a measured obstacle, pass its relevant correctness checks, and produce
a usable integrated result. Reassess the hypothesis when improvements fail to
change workload outcomes or adoption effort.

## Starting point and ownership

- Published process stack: PR #1152, commit
  `cfd608f79339129a9d810b6a62c28043beb13afb`.
- Work branch: `feat/swarm-execution-contract`, in an independent local clone.
- Incorporated existing macOS descriptor fix from PR #1136, original commit
  `dcd455f07e163abba68f61f42f131d29964bceee`, as `a0443c3f1` with provenance.
- Security launch integration enters through PR #1131 and its pinned PR #1117
  ancestor. Ongoing security-roadmap changes remain a separate workstream.
- Preserve the original checkout's dirty work and all existing configurations.

## Acceptance ledger

| Requirement | Required evidence | State |
| --- | --- | --- |
| Existing process stack | Real kernel dispatch, signed receipts and stable identities | Boundary experiment and 44 selected process tests passed locally |
| Live-workload baseline | Actual provider decisions, retained identities, accepted task outputs, effects, usage and interventions | Pending connectivity |
| Credible comparison | Same task/model/tools/bounds; persistent IDs, outcome lookup and conditional updates in baseline | Native resource has duplicate-delivery controls and version checks; live comparison pending |
| Measured missing capability | Reproduction of what existing resource/kernel guarantees do and do not prevent | Superseded mailbox holder committed a new resource mutation after reading the current version |
| Smallest improvement | Effect-boundary behavior changes under the same reproducer, without a second authority/replay coordinator | Not implemented |
| Two independent integrations | LangGraph/Python and AI SDK/TypeScript run useful tasks under the same contract, including recovery | Not demonstrated |
| Usable integrated result | Reproducible installation, versioned inputs, failure checks, instructions and clean reviewed candidate | Not achieved |
| Reassessment | Before/after accepted outcomes, integration effort, interventions and runtime cost justify continuing | Pending baseline |

A deterministic experiment does not satisfy the live-model requirement.
Package installation does not establish independent adoption. Neither is
evidence that the full objective is complete.

## First experiment

A worker loses a mailbox delivery claim, a replacement changes a shared
resource, and the old worker resumes. The independent resource already has
durable operation deduplication and compare-and-swap versions. Check replay of
one logical operation, rejection of a stale version, and a superseded worker's
new operation against the current version. Verify actual kernel receipts and
the committed resource state. Live application workloads remain required.

Ownership enforcement must participate at the resource mutation boundary.
A pre-dispatch lease read followed by an independent mutation retains a race.
Reuse existing kernel authority and outcome recovery; keep unqueryable
external outcomes explicitly uncertain.

## Environment observations, 2026-09-08

- Local host: macOS arm64, Rust 1.94.1. Linux/container profiles need a usable
  Linux environment; local Docker daemon access is denied to this session.
- Provider credentials are configured, but the OpenAI models endpoint fails
  DNS resolution here. No live inference completed.
- The unmodified process-crate build completed. Its existing competing-consumer
  test and the new boundary test both failed before workload execution with
  `sqlite read companion borrowed file identity changed`. This reproduced the
  platform issue addressed by the existing descriptor fix. After incorporating
  it, the boundary experiment passed in 6.07 seconds.
- Python installation hit a uv/system-configuration panic; the locked AI SDK
  installation is missing cached artifacts.
- Source changes use `.worktrees/chio-swarm-execution` because the file-editing
  tool refuses the otherwise writable temporary checkout outside the project.

These observations establish environment limits, not protocol defects or
cyber-access entitlement. Continue useful local work while retaining every
live-workload and integration requirement above.

## Native boundary result

Command: `cargo test -p chio-process --features worker-server,mailboxes --test
mailbox_effect_boundary --offline --locked -- --nocapture`.

| Observation | Result |
| --- | --- |
| Old claim expires; replacement claims the same pending message | Claim generation advances from 1 to 2 |
| Old worker completes the message under generation 1 | Kernel denies; signed denial verifies |
| Replacement commits a conditional resource update | Resource advances to version 1 |
| Same replacement operation is replayed | Original receipt is unchanged; no extra resource transition |
| Every admitted resource request is delivered twice inside the test server | Resource's own deduplication returns the same result |
| Old worker writes using version 0 | Known `version_conflict`, no resource transition |
| Old worker reads version 1 and submits a new operation | Commit succeeds; resource advances to version 2 |
| Operator explicitly cancels the old process | Further process invocation is refused |

The result is a documented composition boundary, not a claim that ordinary
tool grants should expire with every mailbox claim. A new contract must make
the work-to-resource dependency explicit and operator-authorized. A mailbox
claim by itself must not expand resource authority. A participating service
must verify current ownership in the same serialized transition that commits
its effect. Runtime run leases elsewhere in the workspace do not, by their
existence, establish this property for an arbitrary resource service.

This experiment uses a real kernel and SQLite resource, in-process trusted host
calls, actual clock expiry, generated test worker keys, and signed receipts.
It uses no model, network tool server, OS worker crash, or independent adopter.
It identifies a correctness obstacle; it does not yet quantify workload value.

## Local validation

- `chio-sqlite-file-identity`: four tests passed; its ignored subprocess probe
  was exercised by the transaction-lock preservation test.
- `chio-process`, features `worker-server,mailboxes`: 44 top-level tests passed
  across the library, `child_submission`, `crash_recovery`,
  `mailbox_effect_boundary`, `mailboxes`, `processes`, and `state_blobs` targets.
  Subprocess invocations are not counted again. The existing competing-consumer
  case that failed on the published base now passes.
- Formatting for both affected packages passed. `cargo fmt --all -- --check`
  cannot resolve the excluded vendored `third_party/nono-chio` package from this
  nested checkout: Cargo associates it with the original outer workspace.
  This does not establish that full-workspace formatting passes.
- Clippy passed for the new boundary test with `worker-server,mailboxes` and
  warnings denied. The repository Rust file hygiene check passed without
  changing its allowlists. Native experiment commit: `8d5695c87`.
- Live-provider access and hosted-secret inventory both failed connectivity.
  No model call or hosted qualification is claimed.
- The live LangGraph workload is wired to the existing process adapter and
  public host. Eighteen local application checks passed using installed
  LangGraph 0.6.11, langgraph-checkpoint 3.0.1 and langchain-core 1.4.0. They
  use scripted provider responses and a retained in-memory graph checkpointer,
  real MCP subprocesses, and persistent resource/model SQLite journals.
  They do not prove persistent graph recovery, live inference or Chio host
  qualification. CI now schedules these checks for both existing framework
  profiles; no hosted result is claimed.
- Rechecked provider and registry DNS: OpenAI, PyPI and npm still fail
  resolution. Retrying the locked AI SDK install with the correctly laid-out
  task cache confirms that required zod 4.5.4 is absent. No version substitution
  was made. The LangGraph SQLite checkpointer is also missing locally.
- Native CLI build exposed a published macOS permission-width error in
  `write_new_private_file_unix`. Commit `f27cba9f4` preserves the permission
  bits and converts to the platform's `mode_t`. The CLI build and five existing
  prepared-directory tests passed. Unrelated pre-existing macOS warnings in
  platform-specific security and remote-MCP code remain; no full Clippy pass
  for the CLI is claimed.
- Public-host qualification first hit a 90-second provisioning timeout. A
  separate bounded diagnostic completed successfully in 27.34 seconds without
  changing the SDK timeout. Initialization then correctly rejected this host's
  non-sticky, mode-0777 `/private/tmp`. Staging under the protected per-user
  `TMPDIR` allowed initialization and credential issuance. Serving stopped with
  `Operation not permitted` before readiness. No directory or runtime checks
  were relaxed. The native host recovery qualifier is scheduled in Linux CI;
  its required host kill, original receipt recovery and verification remain
  unproven until that run succeeds.
- Worker socket/client tests, Linux runner/container profiles, both installed
  framework integrations, full-workspace validation, and independent review
  remain outstanding.
- OpenRouter is now an explicit provider option for the live workload. Provider
  selection is bound across graph recovery and retained separately from scripted
  evidence; credentials remain environment-only. Intercepted HTTP checks cover
  saved request identity, credentials excluded from the journal, and refusal to
  resend a request with an unknown outcome. These are not live provider results.
  OpenRouter hostname resolution still fails in this execution environment.
  All 21 local application checks passed after this addition, using the installed
  LangGraph compatibility profile described above; isolated Ruff checks passed.
- The pinned AI SDK 6 install also failed with `ENOTCACHED` for zod 4.5.4.
  The existing outer checkout has AI SDK 5.0.196, outside this adapter's supported
  range of 6 and 7, and no OpenAI-compatible provider package. It was not used
  as substitute integration evidence.

## Delivery checkpoint

The implementation through OpenRouter support is committed locally as
`5d1e54c4679dc3c2e279b25f82b07324bfc866ca`, with tree
`8a09383626132684e5960b4c4565fe298b40a7e5`. It is based on the published
PR #1152 head `cfd608f79339129a9d810b6a62c28043beb13afb`.

The GitHub connector read the current PR and repository successfully. Creating
the proposed tree was rejected with `MCP tool call requires approval, but
approval policy is never`. No remote tree, branch, commit or PR creation was
confirmed. The Linux workflow additions exist locally and have not run on
GitHub. Provider credentials were not included in the proposed tree.

A verified Git bundle preserves the local commit history and exact objects.
It requires the PR #1152 base commit. On a connected checkout containing that
base, import the bundle without replacing another agent's branch:

```sh
git bundle verify /path/to/chio-shared-resource-execution.bundle
git fetch /path/to/chio-shared-resource-execution.bundle HEAD:refs/heads/feat/shared-resource-import
git worktree add ../chio-shared-resource-import feat/shared-resource-import
cd ../chio-shared-resource-import
cargo build --locked -p chio-cli --bin chio
uv sync --project sdks/python/chio-langgraph --locked --extra dev --extra process
sdks/python/chio-langgraph/.venv/bin/python -m unittest discover -s examples/shared-resource-swarm -v
SWARM_RUNS=$(mktemp -d "${TMPDIR:-/tmp}/cs.XXXXXX")
sdks/python/chio-langgraph/.venv/bin/python examples/shared-resource-swarm/qualify_native.py \
  --chio target/debug/chio --output "$SWARM_RUNS/qualification"
```

The live comparison commands are in the example README. Run them with the
provider credential in the worker environment after host qualification passes.
Retain `report.json`, resource state, original receipts and model responses for
evaluation; keep the private connection files separate from shared evidence.
Neither the portable bundle nor passing local checks closes the acceptance
ledger. The shared-resource AI SDK workload remains to be implemented and run
against a supported installed profile.

## Next execution

1. Use the application resource in `examples/shared-resource-swarm` for the
   credible comparison. It supplies an ordinary MCP service with a durable
   operation journal, outcome lookup, conditional document updates and retained
   mutation evidence. Nine subprocess/storage tests passed, including death
   after effect commit before response delivery. It does not fence job owners.
2. Prepare a live workload through the existing LangGraph and AI SDK adapters.
   Preserve provider response identities before effects; distinguish a live
   provider response from a saved or scripted response in retained evidence.
3. Run the credible baseline on a connected environment and measure accepted
   task outputs and coordination failures. The local native result alone is
   insufficient to claim user value or select an unrestricted feature roadmap.
4. Implement an explicit, resource-authorized work dependency only if the
   workload establishes its value. Reject stale ownership atomically with the
   mutation; preserve kernel authority, idempotency and uncertain outcomes.
5. Validate reuse through both independent framework integrations and a second
   resource adapter, then reassess the product hypothesis against the ledger.
