# Research swarm benchmark

`benchmark/run.py` measures the same AI SDK research swarm in two configurations
under induced failures, operator intervention, a shared budget and a conflicting
action. Chio runs the swarm as native processes under `chio process run`. The
baseline runs the same model loop in one Node process with local tool callbacks
and a restart-on-failure supervisor, which is how an existing AI SDK application
typically recovers today. One scripted planner drives both configurations through
the real OpenAI-compatible HTTP provider path, so every difference in outcomes
comes from execution, not from model behavior.

## Workload

A coordinator delegates sixteen 8 KiB sources to four researchers, joins them,
receives one findings handoff per researcher, publishes one checked report and
acknowledges the handoffs. Each researcher reads its four sources through the
`sources/read` tool and sends one findings message with the size and checksum
of each source. Checksums travel as letters only, because the kernel's output
guards redact digit runs that resemble identifiers. The report is checked against the corpus: it must list every
source exactly once with the correct checksum. The publication is a
non-idempotent SQLite insert; reads and handoffs are recorded the same way in
both configurations so duplicate effects are counted identically.

| Scenario | Induced condition |
| --- | --- |
| steady | No failure |
| worker-death | Researcher 1 exits after its second read |
| coordinator-death | The coordinator exits after its publication receipt |
| host-death | The native host is killed while the coordinator waits for children; the baseline process is killed while researchers run |
| cancel | Host death as above, then an operator cancels the coordinator subtree offline before resuming; the baseline supervisor restarts as usual |
| budget | The shared tree call ceiling is one call short of the publication |
| conflict | Researcher 1 is offered a publication it is not authorized to make and attempts it |
| random-N | A seeded kill of a random role after a random tool receipt |

Chio must complete the steady, death and random scenarios with one valid report,
sixteen distinct reads, four handoffs and no duplicate effect; it must end the
cancel, budget and conflict scenarios without any publication. The baseline's
expected duplicates and extra publications are also asserted. `check` in
`run.py` fails the benchmark when either configuration deviates.

## Measurements

- Completed useful work: completion, publications, valid reports, distinct and
  duplicate reads, duplicate handoffs, worker attempts and provider requests.
- Kernel contribution: the worker-observed round trip of every mediated call,
  split into originals and recoveries, next to the tool handler's own execution
  time recorded inside the tool server. The difference is the kernel, durable
  admission and Unix socket transport cost. The baseline's in-process callback
  time is the reference.
- Integration effort: the line difference between `baseline_worker.mjs` and
  `chio_worker.mjs`, and the time from run start to the first mediated call.
- End-to-end wall time per scenario.

All native receipts are verified against the initialization key. The scripted
planner makes deterministic decisions with generated tool-call IDs; the
benchmark does not call a live model and does not measure model quality.

## Run

From the repository root, with Python 3.11+, Node 22+, network access for the
first consumer installation and a built `chio` binary:

```sh
python3 sdks/typescript/packages/ai-sdk-process/benchmark/run.py \
  --chio target/debug/chio --output /path/to/new-benchmark-directory
```

`--sdk ai7` limits the run to one SDK major, `--trials` sets the number of
seeded random-failure trials per SDK and `--scenarios` selects a subset for
development. The output directory receives `benchmark.json`, `results.md`, the
installed consumer locks, per-scenario summaries, provider requests, receipts
and the kernel key. CI runs AI SDK 7 with one random trial.

## Where the kernel's time goes

Tracing the host during one steady run attributes its durable writes. The
serving owner syncs its rollback anchor after every authority commit, and each
sync used to clear the slot marker, write the slot body and write the marker
with a device flush after each step. Installing the record with one write and
one data sync removed two flushes per commit. The same run, traced before and
after that change with release builds on the same machine, 33 mediated
invocations plus the model journal's checkpoints and response blobs:

| Durable file | fsync calls before | after |
| --- | ---: | ---: |
| Authority serving lock and rollback anchor | 1,653 | 551 |
| `authority.db` (admission operations, outcomes, receipts, budgets) | 572 | 572 |
| `process.db` (checkpoints, response blobs, waits) | 126 | 126 |
| `receipts.db` | 39 | 39 |
| Host process (initialization, run setup, status) | 429 | 426 |
| Total | 2,830 | 1,725 |

That is roughly 85 `fsync` calls per invocation before and 50 after. Each costs
about 2.3 ms on this machine. Untraced, the same steady run's median `read`
moved from 239 ms to 151 ms (p95 from 429 ms to 169 ms) and its wall time from
9.0 s to 6.7 s. What remained was one SQLite commit and one anchor sync per
authority transition, eighteen per mediated call, seven of them recovery-claim
writes in their own transaction. Persisting each claim with the transition it
protects removed three of the eighteen: `authority.db` went from 572 to 482
fsync calls and the anchor from 551 to 464 on the same steady run, and the
median `read` from 154 ms to 143 ms (p95 179 ms to 155 ms) back to back on a
quieter machine. The fifteen that remain are the modeled admission
transitions, the budget hold and capture, the tool-return record with its
three post-return stages, and the four claims that precede joint budget and
tool-return transactions; folding those claims into the transactions they
precede is the next step of the same shape and is tracked in the
[direction document](../../../../docs/architecture/AGENT_PROCESS_DIRECTION.md).

## Observed limits

- A mediated call in flight when the host dies stays dispatch-committed with
  no recorded outcome. Recovery terminalizes it as unknown and denies its
  redispatch on every later attempt for side-effecting tools, so a swarm
  interrupted inside such a call cannot finish without operator repair. Tools
  declared free of side effects now earn a bounded fresh dispatch under a
  later attempt's request id. The host interruption scenario still holds each
  worker at a durable point before the kill so its outcome stays deterministic
  across both kinds of tool.
- Every restart after a failure consumes an attempt. A suspended
  coordinator's relaunch now spends a separate suspension ceiling, so
  attempt ceilings cover failures only.
- The baseline's failures are silent: it completes with duplicate reads and
  handoffs, publishes twice after a coordinator restart, ignores an operator
  cancellation, and twice produced a report that fails validation because
  duplicated handoffs displaced other researchers' findings.

## Results

Measured at commit `03e9f4778f` with the release build (`f777f283`) on a 12-core Linux
aarch64 host under a load average above 12 from unrelated builds, Node 22.23.2, AI SDK
6.0.277 and 7.0.93, three seeded random trials per SDK. Chio's outcomes were identical
for both SDKs; the baseline's duplicate counts vary with timing, so both SDK rows are
listed where they differ. An earlier run of the same code on a quieter machine put
every mediated call at 200-235 ms median; the loaded run below is the evidence of record.

| Scenario | Chio | Baseline (AI SDK 7) | Baseline (AI SDK 6) |
| --- | --- | --- | --- |
| steady | completed, 1 publication, no duplicate effect | completed, 1 publication | same |
| worker-death | completed, 1 publication, no duplicate effect | completed, 1 publication, 5 duplicate reads | same |
| coordinator-death | completed, 1 publication, no duplicate effect | completed, 2 publications, 16 duplicate reads, 4 duplicate handoffs | same |
| host-death | completed, 1 publication, no duplicate effect | completed, 1 publication, 1 invalid, 16 duplicate reads, 2 duplicate handoffs | same |
| cancel | stopped, 0 publications, no duplicate effect | completed, 1 publication, 1 invalid, 15 duplicate reads, 2 duplicate handoffs | completed, 1 publication, 1 invalid, 16 duplicate reads, 2 duplicate handoffs |
| budget | stopped, 0 publications, no duplicate effect | completed, 1 publication | same |
| conflict | stopped, 0 publications, no duplicate effect | completed, 2 publications, 1 invalid | same |
| random-1 | completed, 1 publication, no duplicate effect | completed, 1 publication, 7 duplicate reads | completed, 1 publication, 3 duplicate reads |
| random-2 | completed, 1 publication, no duplicate effect | completed, 2 publications, 16 duplicate reads, 4 duplicate handoffs | completed, 1 publication, 1 invalid, 16 duplicate reads, 2 duplicate handoffs |
| random-3 | completed, 1 publication, no duplicate effect | completed, 1 publication, 14 duplicate reads | completed, 1 publication, 16 duplicate reads, 4 duplicate handoffs |

Chio finished every death and random-failure scenario with one valid report, sixteen
distinct reads, four handoffs and no duplicate effect, using two coordinator attempts
(one suspension) plus one more for each induced coordinator failure. It ended the
cancel, budget and conflict scenarios with no publication. The baseline always
completed, and in doing so repeated reads and handoffs, published twice after a
coordinator restart, published after an operator cancellation, published an
unauthorized partial report, and produced an invalid report in seven runs.

Wall time per completed scenario was 8-11 s for Chio (including host startup, five worker
launches and the coordinator's suspension and relaunch) against 0.8-3.2 s for the
single-process baseline. The first mediated call landed about 1.1 s after run start.

Round trips as observed by the worker for original calls in the steady scenario, with
the tool server's own handler time where the tool runs in an MCP server:

| Tool | Chio median ms (AI SDK 7 / 6) | Chio p95 ms (7 / 6) | Handler median ms | Baseline local median ms (7 / 6) |
| --- | ---: | ---: | ---: | ---: |
| ack_findings | 269 / 282 | 269 / 282 |  | 3.5 / 5.4 |
| publish | 233 / 248 | 233 / 248 | 0.60 | 3.5 / 4.3 |
| read | 260 / 357 | 351 / 574 | 0.54 | 4.3 / 4.1 |
| receive_findings | 220 / 276 | 220 / 276 |  | 0.4 / 0.3 |
| send_findings | 242 / 409 | 526 / 629 |  | 4.5 / 5.4 |
| spawn_researcher | 817 / 728 | 987 / 1042 |  | 22.3 / 17.2 |
| wait_children | 290 / 348 | 336 / 367 |  | 322.8 / 339.8 |

A replayed call, which the kernel answers from its recorded outcome, took about 35 ms.
A spawn commits the child's capability, signing seed and work record before returning,
and the four spawns run concurrently, so each waits on the others' commits.

The Chio worker is 94 lines against 136 for the baseline: the local tool
implementations, in-process child bookkeeping and queue tables are replaced by the
host's advertised tool definitions, `ChioProcessAgent` and the exit-75 suspension
branch. A line-level diff between the two entry points removes
109 lines and adds 67; the two files are structured
differently, so read that as the size of the two integrations rather than as an
edit distance.
