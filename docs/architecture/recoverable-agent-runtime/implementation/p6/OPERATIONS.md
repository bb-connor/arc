# P6 operating contract

The protected product composition uses the existing Rust kernel, fenced SQLite
authority, process journal, selected semantic operator and native knowledge
broker. Those owners continue to authorize every command, capture and release.
The CLI and host adapters carry stable canonical commands and expose bounded
categories; they do not implement effects, issue approvals or retry ownership.

## Guided setup

Compose `RecoverySetupService` with the actual installed profile and the exact
operator-pinned self-test workflow. Mount `protected_recovery_router`, handling
its fallible construction before serving traffic. The native tenant/domain
marker gates new protected command, semantic, knowledge and physical capture
mutations. Missing mediation, profile mismatch and an unqualified serving fence
refuse. Historical inspection, cancellation and settlement remain available.

An authenticated operator first runs the reviewed model-free self-test through
the ordinary native owner. It must produce one actual benign effect and receipt
and prove a denied counterpart. Use the installed CLI and private capability
file to retain its signed probe:

For a newly pinned workflow, complete native action selection and the existing
approval first. Fresh authorized preparation binds its Resume revision once,
inside the native transaction, before the first probe executes it. Subsequent
preparation and replay preserve those exact command bytes; ordinary revision
and conflict checks remain strict. Previously persisted selections default to
already bound during upgrade. An older unfinished stale selection therefore
requires explicit operator replacement after profile change or probe expiry,
rather than silent rewriting of an advertised command.

```sh
chio recovery setup probe \
  --endpoint "$RECOVERY_ENDPOINT" \
  --capability "$RECOVERY_CAPABILITY_FILE" \
  --workflow-id "$SELF_TEST_WORKFLOW" > setup-probe.json
```

Restart the native writers through the deployment's ordinary operator procedure.
Retain the same stores and original self-test identity. The new serving fence
must recover the identical operation and receipt without another effect or tree
charge. Qualification from the original writer deliberately refuses:

```sh
chio recovery setup qualify \
  --endpoint "$RECOVERY_ENDPOINT" \
  --capability "$RECOVERY_CAPABILITY_FILE" \
  --probe setup-probe.json > setup-report.json
```

CLI stdout is the verified canonical envelope, with no trailing newline, so the
probe can be consumed without reserialization. Setup waits are explicitly
bounded at 120 seconds. Ordinary CLI calls retain 20 seconds. Neither deadline
permits a retry or changes native authority. Preserve the original identity on
ambiguity and reconcile through the native owner.

The probe lasts at most 15 minutes and binds store, scope, policy, source/profile
and serving fence. A later writer may replace its predecessor readiness report
from the identical still-fresh probe. An altered same-writer report conflicts.
Policy/profile changes invalidate readiness inside the native transaction. The
operator then pins and reviews a new exact self-test; old reports never grant
new work. Legacy unmarked P0-P5 compositions retain their earlier contract and
must not be described as P6 protected setup.

## Classified feedback and independent maintenance

Mount `recovery_maintenance_router` on the authenticated private control
listener. Report and proposal bodies are bounded, untrusted classified input.
Current workflow/source restrictions and every immutable attachment label are
joined before storage or release. Native reads reauthorize capability and
clearance before returning data or revealing a retained-content conflict.
Tenant/domain quotas and bounded transport intake apply to all reporters.

`Report`, `Inspect` and `Maintain` capabilities permit only their named product
operations. The selected independent operator must review and sign a
`PolicyDeploymentChangeV1` for an exact retained proposal, complete current
base, target package/routes, generation and serving context. The trusted
`apply_reviewed_semantic_deployment` API compiles the complete target outside
the transaction and rechecks all bindings atomically before installation.
There is no agent-facing HTTP apply endpoint. Complaint replay, an old
signature, reporter signature or maintenance capability cannot apply a policy.

An acknowledged or lost-acknowledgement application retains one deployment
identity. Exact replay cannot reapply it. Rollback requires a new proposal,
current base, operator signature and generation. Reload the selected semantic
connector after a route change, then run fresh protected setup. Native guard
engine reload remains a separate operator configuration/restart procedure.

## Capacity, disconnects and recovery

The recovery listener reserves two dedicated settlement workers, with two total
outstanding jobs including active, queued and disconnected work. Ordinary
command intake is separately bounded at four. Setup and maintenance each have
their own two-request intake bounds. Excess work receives a fixed generic
unavailable response; it is never buffered in an unbounded waiting queue.

Disconnect and listener shutdown do not release the permit for accepted native
work. The owning job finishes reconciliation, without resubmission, before its
permit drops. Partial worker startup refuses listener construction. A caught
job panic refuses its response while preserving the worker. These guarantees
require the native operations' existing bounded I/O/deadline contract; they are
not a promise of fairness for an arbitrary hung provider.

The actual overload case holds four captured provider effects, disconnects
their callers and floods intake while a fifth owned operation settles within
two seconds. Effects and replay charges are independently checked after writer
restart. This model-free test separates native settlement capacity from model,
framework and human latency.

## Framework composition

`RecoveryHostSession` owns private endpoint/capability and at most eight selected
commands. Each explicit framework action freshly calls Rust, including replay.
Its default wait is 20 seconds; a host may select an integer from 1 through 120.
The wait does not renew authority, add retries or increase outstanding native
capacity. StateGraph checkpoints retain categories and opaque IDs only. CrewAI
uses `RecoveryTool` with cache, memory, planning, tracing and delegation disabled.
Both adapters expose a fixed refusal category without raw errors or results.

Pinned qualification uses LangGraph 1.2.12, CrewAI 1.15.23 and OpenAI SDK 2.36.0
with exact model `gpt-5.4-2026-03-05`. The qualification provider implements
CrewAI 1.15.23's declared `BaseLLM._apply_stop_words` contract before the Crew
parser. Evidence retains the full provider output, actual stop sequences and
framework-visible frame. It never manufactures an omitted tool action. The earlier complete
`gpt-5.4-mini-2026-03-17` cohort failed the artifact utility gate and remains retained. The support workflow crosses the actual
private recovery listener. Artifact reuse crosses a private trusted Rust test
bridge around real native knowledge custody/read/release; this does not qualify
a general production artifact HTTP tool.

## Qualification and expansion

The immutable precollection manifest defines two hosts, two workflows, both
arms, four cases and three repetitions per stratum. The competent baseline
supervises the identical native owners, stable operation IDs, idempotency,
original-outcome lookup and current ACL. Results measure these integrations,
not superiority over an independent runtime. No production migration or
supervisory code savings was measured.

The original account-quota cohort has 51 retained failed rows, two interrupted
started slots and 43 unstarted slots. Those 45 measurements remain unknown.
The complete mini-model cohort retained all 96 identities but failed two
CrewAI artifact positive strata. A separately declared additional 96-trial
matched cohort selects the exact more capable model. That cohort also failed:
all 48 CrewAI rows skipped the tool because the custom provider ignored the
framework's declared stop contract. Its 24 completed and 24 refused LangGraph
rows and all skipped CrewAI rows remain retained. Native/SDK sources, tasks, authority,
host versions, budgets and thresholds are unchanged. Two-file precollection
corrections make retained model prompts independent of framework mutation and
apply the pinned CrewAI stop contract. The corrected provider completes eight
actual model-free host/native preflights before its separate full 96-trial
campaign. Its 384 planned slots remain visible as the original reviewed package.
That corrected cohort retained all 96 identities: 47 complete, 45 refused and
four skipped-tool outcomes. All sixteen positive strata met the unchanged
minimum of one completion in three repetitions. Independent native records,
authority hashes, exact request snapshots and framework-visible stop frames
recompute, with zero observed unauthorized or duplicate effects. Across all
four attempts, 339 measurements and 45 unknown slots account for the full
384 planned denominator. The fresh whole-phase review identified two P1
availability/reproduction failures: premature setup command revision binding
and missing model-free preflight attempt bookkeeping. The primary TDD pass
fixed both and retained the original verdict. Final fix bytes are explicitly
bound and verified; they were not silently assigned a second fresh review.

The native Rust owner change requires one more complete predeclared 96-trial
campaign at the final source. That fifth cohort uses the identical full model,
tasks, authority, versions, protocol, budgets and thresholds. All fourteen
pinned harness tests and eight shipped real-native model-free preflights passed
before collection. It retained 46 complete, 44 refused and six skipped-tool
outcomes. All sixteen positive strata met the unchanged one-of-three threshold.
Every final native fact, request hash and framework-visible frame independently
recomputes. All five attempts account for 480 planned slots, 435 measurements
and 45 unknown slots; no all-planned safety claim is made. Final qualification
requires the current complete gates, performance bounds and joined package seal.
Earlier failed cohorts retain 25 prompt-snapshot gaps as unavailable request
content recomputation. The qualifying cohort requires every prompt hash to
recompute. Reports distinguish host completion, native completion, refusals, skipped tools
and errors and preserve per-stratum Wilson intervals. Three repetitions do not
establish general utility or availability.

P5's enforced Linux profile remains Boolean-only and model-disabled. Nested
launches, model-enabled cages, additional return channels, covert-channel
resistance, broad provider/platform coverage, hosted CI and production release
require separate qualification. The roadmap ends at P6; next operational work
is a reviewed release/integration candidate for the exact supported profile,
or a separately specified provider/platform expansion with fresh owning tests.

Original successful and noisy Mac performance measurements remain retained.
The primary Rust fix invalidates their reuse for final source acceptance. A
fresh Mac run reached p95 450534584 ns during heavy concurrent load and failed
the unchanged 220683049 ns ceiling. The user reports no quiet Mac period.
The separately predeclared matched Linux profile reconstructs immutable P0
from the exact base commit and its 293-source sealed overlay. P0 and current
P6 run on the identical isolated Linux host, Rust 1.94.1 and debug profile,
after other task jobs finish. Acceptance takes the tighter of the original
220683049 ns absolute ceiling and floor(6 * Linux P0 p95 / 5) + 1000000 ns.
All pure ceilings and sample counts remain unchanged. Current Mac performance
remains unqualified; this profile does not establish a cross-host latency SLA.

The complete E4 comparison is retained as a failed hardware attempt: immutable
P0 p95 203400825 ns and final P6 p95 224502188 ns exceeded the unchanged
220683049 ns absolute limit. Its original declaration also named the older
6.17 kernel, while its measured profile correctly recorded 7.0.0-1012-oracle;
no E4 performance acceptance is claimed. The next hardware profile was declared
before any E6 measurements, using the same owned VM with eight OCPUs/64 GiB,
actual AMD EPYC 9J45 and kernel 7.0.0-1012-oracle. E6 P0 p95 was 128652683 ns;
final P6 p95 was 142600820 ns, passing the tighter matched ceiling 155383219 ns.
Both subjects retained all 64 samples, eight warmups, eight replays, 72 effects
and 72 charges without errors. All four pure budgets passed unchanged.
Native suites and live trials retain their actual earlier E4 profile.
