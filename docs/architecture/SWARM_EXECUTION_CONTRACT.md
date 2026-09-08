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
| Live-workload baseline | Actual provider decisions, retained identities, accepted task outputs, effects, usage and interventions | Three accepted live runs per backend on the synthetic board; wider workload validation remains open |
| Credible comparison | Same task/model/tools/bounds; persistent IDs, outcome lookup and conditional updates in baseline | Normal and worker-death comparisons passed with durable model/graph state and the same protected resource in both backends |
| Measured missing capability | Reproduction of what existing resource/kernel guarantees do and do not prevent | Native mailbox test and live handoffs reproduced new mutations by superseded workers using the current version |
| Smallest improvement | Effect-boundary behavior changes under the same reproducer, without a second authority/replay coordinator | Explicit resource assignment and kernel caller forwarding implemented; local native and live validation passed |
| Two independent integrations | LangGraph/Python and AI SDK/TypeScript run useful tasks under the same contract, including recovery | Live task acceptance, worker recovery and ownership handoff passed across frameworks; PostgreSQL now also passes native qualification and both live framework handoff directions |
| Usable integrated result | Reproducible installation, versioned inputs, failure checks, instructions and clean reviewed candidate | Draft PR #1153; hosted CI, dependency audits and independent review remain open |
| Reassessment | Before/after accepted outcomes, integration effort, interventions and runtime cost justify continuing | Resource assignment prevented live stale-worker overwrites; the competent baseline also succeeds with that contract. Reuse now covers SQLite and existing PostgreSQL jobs. Independent adoption and an integration-effort advantage remain unproven |

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

### Connected execution resumed

Execution permissions changed on 2026-09-08. OpenRouter, npm, PyPI and GitHub
now resolve. The locked LangGraph 1.2.11 profile installed, and all 21 application
checks passed on it. The TypeScript workspace installed; the existing AI SDK
adapter built and its 42 tests passed. These supersede the earlier connectivity
observations; the full acceptance ledger remains open.

The first public-host call was denied because the example named its document
snapshot operation `read`, which the existing action classifier treats as a
filesystem operation requiring a path. Renaming this example tool to `snapshot`
preserves the guard configuration. Native qualification then passed: kill the
host, resume the retained graph against the restarted host, recover and verify
the original receipt, and observe one resource mutation and one delivery.
This uses a scripted provider and a graph checkpointer retained by the driver.

OpenRouter authenticated successfully. The initial inference request returned
HTTP 404 while requiring support for `parallel_tool_calls`, which was absent
from the selected model's endpoint parameter inventory. Removing that unsupported
provider option enabled live inference; application tool dispatch remains serial.
The original failed experiment state was preserved.

The first live OpenRouter GPT-4.1-mini runs completed both workers but failed
mechanical task acceptance in both backends. The direct MCP run used nine model
responses; the Chio run used seven and verified its original receipts. Retained
calls show malformed board shape and discarded assessments. These exploratory
runs exposed ambiguous workload instructions and do not establish a Chio
coordination advantage or a kernel defect. The shared framework contract now
specifies the document ID, exact output shape, assigned-service scope and merge
rule before repeating the comparison.

### Live comparison and recovery results

The shared instructions in `d611c83ae24ef5a749677bba3e6dbaadf691e8f2` produced
three accepted runs in each LangGraph backend using OpenRouter GPT-4.1-mini.
Every run had two resource mutations and one known version conflict. Each pair
used identical task inputs, tools, instructions and bounds. All Chio runs
verified their original receipts. This small normal-operation sample shows no
task-acceptance advantage for Chio.

The application in `8c3229ee21a1e33d03c98a12dd174a41341a75ca` also runs through
the packed, installed AI SDK adapter. Its worker-death scenario exits the
performance worker after a committed replacement and permits one restart with
the original input and journals. Results:

| Integration | Task accepted | Exit sequence | Total mutations | Deliveries of the interrupted operation | Original signed receipt recovered |
| --- | --- | --- | --- | --- | --- |
| Direct MCP with LangGraph 1.2.11 | Yes | 77, 0 | 2 | 2 | Not supplied by this backend |
| Chio with LangGraph 1.2.11 | Yes | 77, 0 | 2 | 1 | Yes |
| Chio with AI SDK 7.0.93 | Yes | 77, 0 | 2 | 1 | Yes |
| Chio with AI SDK 6.0.277 | Yes | 77, 0 | 2 | 1 | Yes |

Each recovery run retained nine original model responses. The direct MCP
resource deduplicated the repeated delivery, so both approaches preserved the
same task outcome. This comparison supports Chio's signed replay boundary and
framework reuse; it does not demonstrate a task-completion improvement over a
capable baseline. No new ownership authority was added to obtain these results.

The [evidence archive](../evidence/shared-resource-2026-09-08.zip) preserves all
15 live experiment reports, including the four exploratory failures, original
receipt text, verification keys, attempt counts and a hash index. It also
includes the scripted host-death qualification. API credentials, private host
state and machine paths are excluded. Archive SHA-256:
`2df0d5cac2183c692a2dc975ee9f2db59189b56562fb19194901697fa278f7f0`.
The preliminary AI SDK report-export failure is retained: AI SDK 7 omits raw
response bodies from step results unless requested explicitly. The application
now requests them before accepting its evidence export.

These recovery results motivated a live handoff experiment. At that checkpoint,
the MCP dispatch context carried operation and attempt identity without the
kernel's validated caller binding. The implementation and results below extend
that boundary so a resource can check its explicit assignment atomically with
the effect. An agent-supplied owner string or a pre-dispatch lease read remains
insufficient.
Hosted CI on PR #1153 is still running. Its cargo-vet gate reports 21 unvetted
dependencies; no audit exception or fabricated audit was added.

The exported archive was extracted into a fresh directory and all nine receipt
groups passed the CLI verifier with their pinned public keys. The current
mailbox/resource boundary test also passed again and still records one new
mutation by a superseded mailbox holder. The live worker-death successes do not
close that ownership boundary.

## Live ownership handoff and resource assignment

The harness in `500ab3a132f82296028acb687c0f5ffc6091bbba` pauses the first worker
after reading its task. The operator retains that original input, publishes a
new revision correcting a latency measurement, and starts a replacement. The
replacement correctly marks the candidate blocked. When released, the old
worker reads the current document version and replaces the assessment with its
outdated ready decision. The baseline, Chio/LangGraph and Chio/AI SDK all
reproduced this sequence with real provider responses. The old tool capability
was deliberately left valid; scheduling alone did not revoke it.

Commit `60d6aa308fb3c4348e3a5732bbfb2c965812da5a` implements an explicit resource
assignment using the kernel's existing exact-capability binding. Durable stdio
MCP calls forward `chioCallerCapabilitySha256`; the operator's connection
descriptor supplies the matching digest. The resource checks its current owner
inside the same SQLite transaction as each new mutation. A handoff transaction
publishes the revised input and changes that owner. A superseded write produces
a known refusal. Previously completed operations retain their original replay
results without another effect. No framework SDK changes or second kernel
replay coordinator were needed. The MCP adapter's monetary dispatch now also
preserves its operation and caller context while retaining its existing cost
reporting behavior.

The reference application binds a caller to each private MCP subprocess and uses
the same resource ownership check. This is a competent baseline, not an
ownership-free comparison disguised as an implementation limit. Chio supplies
the validated capability binding through its adapter; the baseline application
owns that connection binding itself. Native fixture runs do not establish OS
isolation against arbitrary code running as the same local user.

The digest is not a wire credential. A participating resource must trust its
kernel-owned connection and serialize assignment changes with writes. Changing
a mailbox claim or scheduler plan alone does not change arbitrary resource
ownership. A replacement capability needs an explicit assignment; rotating only
a worker connection credential retains the same owner binding. This contract
does not make mailbox and external-resource stores one atomic system, or prove
that every output is semantically based on the newest input.

Local checks passed: 29 Python application tests, two kernel tests spanning the
resolved value/cost/stream and blocking dispatch routes, and three MCP adapter
checks including monetary dispatch and omission of caller metadata from plain
contexts. Native host qualification refused a fresh-version superseded write,
model-argument identity spoofing and a missing caller binding; it preserved the
original receipt and allowed the replacement owner. A separate owned-resource
host-death run recovered the original signed receipt after socket and credential
rotation with one mutation and one resource delivery.

The unchanged mailbox/resource boundary test still permits a superseded mailbox
holder to mutate an unassigned resource. That is intentional: resource assignment
is explicit and does not silently attach every tool grant to a mailbox claim.

### Matched live results

The updated instructions and code in `60d6aa308` were used with ownership both
disabled and enabled. All runs used OpenRouter GPT-4.1-mini and retained eight
original model responses. Each replacement first produced an accepted corrected
assessment. The old worker then attempted one write with document version 1:

| Integration | Superseded mutations without assignment | Superseded mutations with assignment | Final task accepted with assignment |
| --- | --- | --- | --- |
| Direct MCP / LangGraph 1.2.11 | 1 | 0 | Yes |
| Chio / LangGraph 1.2.11 | 1 | 0 | Yes |
| Chio / installed AI SDK 7.0.93 | 1 | 0 | Yes |
| Chio / installed AI SDK 6.0.277 | Not run in this comparison | 0 | Yes |

Every unassigned run in this table lost the corrected assessment. Every assigned
run returned a known `superseded` result for the old worker's attempted write.
All Chio receipt groups verified. This is a controlled synthetic-workload result
with one run per configuration, not an estimate of a general success rate.

The [handoff evidence archive](../evidence/shared-resource-handoff-2026-09-08.zip)
retains these seven runs, the three initial unassigned reproductions, and both
final native qualifications. It contains original reports, provider responses,
input revisions, phase snapshots, caller digests, original receipt text, public
verification keys, source commits, versions and file hashes. It excludes API
keys, private host state and machine paths. All nine receipt groups verified
again after extracting the archive into a fresh directory. Archive SHA-256:
`d3b198927ee51ad38e716a3e419407208a8bdae6f0421406f61449c52610f810`.
The final qualification binary SHA-256 is
`7675984d963fb243fd0dbd1982bbbcd06d202f5e17d5e6bbd3ba4bb76c779af0`.

## Second resource: existing PostgreSQL jobs

The [PostgreSQL adapter and reproducer](../../examples/postgres-job-swarm/README.md)
reuse `PostgresFindingMarketStore` and its existing tenant, lease and result
tables. The worker gateway derives the lease owner exclusively from kernel
caller metadata. Its 350 lines of Rust adapt the public API and describe the
worker/operator tools; they add no database schema, authority issuer or replay
journal. Python and JavaScript retain their existing Chio execution adapters.
The Python example model loop now accepts operator-bound task instructions and
tool definitions, matching the existing JavaScript application's configuration.

An actual worker-role call exposed a pre-existing public API defect. The role
passed the production connection checks, but `begin_tenant` issued `SELECT ...
FOR SHARE`, requiring a direct UPDATE privilege deliberately denied to that
login. Assignment failed before reaching its approved job function. Existing
worker-boundary tests called those functions directly and missed this wrapper.
Commit `5b863de80` fixes job transitions to use a nonlocking preliminary tenant
read. Each existing privileged transition function still locks and rechecks the
enabled tenant in the transaction containing its mutation. Job reads and
readiness probes use the existing read-only snapshot boundary. No migration or
role grant changed. A new public-API regression passes with `connect_worker`,
exercising all six transitions, owner/fence mismatch, terminal replay, forbidden
runtime writes and disabled-tenant refusals.

The native qualification at `66c37dda90a7ad315affa73e0cae9e0105cb0dbe` uses
PostgreSQL 17.11 with TLS and the production migration/runtime/worker checks.
The root process assigns and releases jobs through a receipt-verifying
`ProcessClient` operator interface. Children cannot call the operator tools.
Both gateway modes use the restricted database worker role. Database credentials
are supplied only to the host/tool-server processes, separately from model
credentials. The native checks refuse a missing caller, model-supplied owner
spoofing and an old caller using the current fence. The replacement commits;
after a real host restart its exact logical operation recovers the original
receipt. A new logical call for that same result returns `already_completed`,
which does not attribute a new mutation to that call.

### Live PostgreSQL handoffs

Workload code: `4d463f6c4af7da65047c26030c426a42f89a8d69`. Each run retains eight
original OpenRouter GPT-4.1-mini responses. The operator pauses the first worker
after its task read, releases its lease, and assigns the job to the replacement.
The old worker then resumes and finishes **before** the replacement starts.
It refreshes the task, learns fence 2, and attempts completion. Thus neither a
stale fence nor an already-completed result explains its refusal.

| Superseded worker | Replacement | Old completion with fence 2 | Replacement completion | Correct final task |
| --- | --- | --- | --- | --- |
| LangGraph 1.2.11 | AI SDK 7.0.93 | `superseded` | `completed` | Yes |
| AI SDK 7.0.93 | LangGraph 1.2.11 | `superseded` | `completed` | Yes |

All worker tool outcomes replayed with identical receipts. The
[PostgreSQL evidence archive](../evidence/postgres-job-handoff-2026-09-08.zip)
contains both live runs, the native qualification, original receipts/public
keys, source commits and hashes. Its three receipt groups verified again after
fresh extraction. The 56,248-byte archive has SHA-256
`6cf84bf85547a8d392063c4f40423e5481fb8fc3ded0de2b39c7eef8904c0a9e`.
The gateway binary built from `66c37dda9` has SHA-256
`7f8837f035938cc7e6664fd4bbc5986cceb638a2a0862704fe0e506921cef0e7`.
The host uses the previously qualified `60d6aa308` binary; its digest is recorded
above and in every report. Subsequent Python formatting was checked to preserve
the tested source's AST. No fresh current-head host binary claim is implied.

Local validation also passed the 16 PostgreSQL library tests, 29 shared-resource
application tests, and 15 Python process-client tests (three optional tests
skipped). Targeted PostgreSQL Clippy, Rust formatting, Python Ruff/formatting and
Rust file hygiene passed. The new hosted workflow schedules the actual public
worker API and native PostgreSQL qualification using an installed process wheel.
Hosted success remains a separate requirement.

This is a second resource and a supported operator path, not independent
adoption. It uses synthetic task evidence. PostgreSQL already provided correct
transactional fencing; there is no measured task advantage over an application
that uses that API correctly. Chio contributes authenticated process binding,
tool scoping and original-outcome recovery. The integration required a resource
adapter and explicit operator setup, so reduced adoption effort is not yet
established. A release and subsequent claim are separate transactions with an
explicit pending state. Claim has no resource request-id parameter; an uncertain
claim must not be retried under a new logical identity. `known_outcome_only`
permits first dispatch and must be retained from that first invocation onward;
changing the policy on recovery conflicts.

## Common operator client and SQLite assignment tools

Commit `4edb3b20e0a86c807c0f9f39724ad6aaffcb88f8` moves the receipt-preserving
operator invocation into the installed Python SDK as
`chio_process.invocation.invoke_recorded` and `python -m
chio_process.invocation`. It freezes the full request, including the recovery
policy, and syncs that record before invoking. Responses and original receipt
text are retained; verification uses the operator-selected kernel public key.
Transport and verification failures never trigger automatic retry. A verified
signed denial is still a denial, not a completed resource mutation.

The separate PostgreSQL operator client is removed. Both PostgreSQL and SQLite
now call this same helper. SQLite exposes `assign`, `assignment` and `outcome`
on an operator-only `board-admin` server; child capabilities exclude that
server. Its existing SQLite transaction now commits the assignment, optional
task revision and caller-bound operation outcome together. Earlier assignment
replay returns the original result without moving ownership back. Known
generation/revision conflicts are retained without partial publication. The
Chio live handoff uses this supported interface for both assignments. Its
database inspections remain read-only experiment instrumentation. The competent
baseline retains its own operator API to the same resource transition.

Two live LangGraph/OpenRouter GPT-4.1-mini handoffs retained eight responses each,
two verified operator calls each, and zero superseded-worker mutations. Each
old worker attempted one write with the current document version and received
`superseded`; the replacement's corrected assessment remained accepted. The
final run used the clean committed source at
`52ab423f1697892c471a2667e493123088ca797c`. The first run is also retained,
including its source-provenance scope, rather than replacing it with the rerun.

Native qualification also passed on the final source: assignment receipt
recovery after an actual host restart, recovery through the installed SDK CLI,
refusal of a child capability through both direct and recorded invocation paths,
and rejection of a wrong trusted verification key. A separate owned-resource
host-death qualification preserved the original worker receipt after credential
and socket rotation. PostgreSQL passed its native qualification using the same
installed operator helper. The installed wheel has SHA-256
`e2fb393cefb53e7f997a157af9a0b0ea5085d2d8b089bc0f79efd658b56c70f8`.
Local tests passed: 33 shared-resource application tests and 18 Python process
client tests, with three optional tests skipped. Formatting and Ruff passed.

The [operator evidence archive](../evidence/operator-assignment-2026-09-08.zip)
contains the two live runs, three final local native qualifications, and the
downloaded Linux PostgreSQL qualification. All six receipt groups verified
after fresh extraction. The 83,900-byte archive has SHA-256
`eca2218e3a6fdd3d1938c8c3f20489f7920a3b3c2506381e4b1d56c324cc78a1`.
Its index distinguishes tested application, SDK, host-binary and gateway
sources. It contains no connection credentials, provider key, private host
state or machine paths.

### Hosted result at the published predecessor

[PostgreSQL workflow run 34267575055](https://github.com/bb-connor/arc/actions/runs/34267575055)
passed at `46886c865c1592218a0d5c80f67fe55c01bb30ab`, including the public Rust
worker-role API and real native process qualification. Its exported receipt
group also verified locally after download. The authenticated Python/JavaScript
worker job in run `34267574943` passed at that same commit. Its broader host job
was still running when recorded. Cargo-vet run `34267575110` again failed with
the same 21 inherited unvetted dependencies. No exception was added. These
results do not qualify the subsequent common-operator changes by inheritance.

This slice removes direct database mutation from the Chio assignment path and
centralizes operator transport, retention and verification. It does not yet
establish lower total integration cost or external adoption. Interruptions
after a PostgreSQL claim commits but before its response reaches the kernel
remain a distinct required check; known receipt recovery does not prove that
case.

## Remaining execution

1. Complete current hosted checks and review on the published candidate. Keep
   dependency audit failures and full-workspace acceptance distinct from local
   qualification.
2. Measure integration effort and operational cost against a competent existing
   resource integration. Reuse is now demonstrated in two resources; reduced
   application-owned authority code and independent adoption remain unproven.
3. Complete current-head hosted verification of the common operator interface.
   Both resources now use it locally, including signed denial and original
   receipt recovery. Retain each resource as the authority for its atomic
   mutation boundary.
4. Test assignment/dispatch races and operator interruptions across the second
   adapter, retaining prior known receipts and explicit unknown outcomes.
5. Reassess adoption value. The current evidence shows a task-correctness
   improvement from an explicit resource contract reused through two frameworks.
   It does not establish external adoption or a category-level breakthrough.
