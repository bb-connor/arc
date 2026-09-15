# Combined process and M4 qualification

Status on 2026-09-15: Task 5 of the
[integration plan](process-security-integration.md) is in progress. A draft
integration PR is a source/CI checkpoint, not completed qualification, a merge,
or M5 acceptance. The user requested execution without subagents; subsequent
review is direct primary-agent review, not independent reviewer evidence.

Retained pre-M5 qualification checkpoint: `58c632ce0f9066a777e6b2e322e661dd18f198a2` on
`integration/process-security-m4`, in [draft PR #1160](https://github.com/bb-connor/arc/pull/1160).
Both reviewed parent histories and all
[109 inherited thread dispositions](process-security-review-dispositions.md)
are retained. Main remains `f5566d9a765c21cb36652a99c79de64968a656bf` at the
remote refresh. Original PR threads have not been represented as resolved.

## Recovery and resumed qualification (2026-09-15)

Execution checkout restored at `/tmp/arc-security-launch`, branch
`integration/process-security-m4`, from live PR head
`b7211ce2d063ea36ea0f512b6f3c0253b65ecd71`. Both parents remain ancestors:
security `5d1a9ec0d900bd03ce55de903919d972be852d79` and process
`2e84f121273df7f205cc218739b86e93c91bdc37`. Their live PR heads are unchanged.
The primary main checkout, its local commit and all pre-existing modifications
remain intact. Execution uses one agent and no subagents.

Two current hosted failures are source gates before runtime execution:
`35006606125/104507817752` stopped on Ruff formatting in the new worker tests;
`35006605899/104507815578` stopped on file-size caps for the swarm verifier and
proof CLI fixture helpers. The resumed source formats the Python tests and
extracts unchanged graph validators and disposable bundle helpers into focused
modules. No hygiene cap, authority check or required test is relaxed. A direct
comparison confirmed the extracted bodies are unchanged. Review is direct owner
review, not independent reviewer approval.

Fresh local artifacts are retained outside temporary checkouts at
`/Users/connor/Medica/backbay/standalone/arc/output/process-security-20260915/`.
Commands below use Rust 1.94.1, locked dependencies, `umask 022`,
`CARGO_INCREMENTAL=0`, `RUST_TEST_THREADS=1`, two build jobs, debug info disabled
and no custom `RUST_MIN_STACK`. External target directories preserve the explicit
owned-checkout fixture boundary. Subprocess fixture executions are not counted
again as distinct tests.

| Gate | Source / platform | Terminal result | Evidence file |
| --- | --- | --- | --- |
| `cargo test --locked -p chio-process --features worker-server,mailboxes` | `b7211ce2` process closure; macOS/aarch64 | Exit 0: 72 tests, no failures or ignores, including all 12 worker protocol cases | `process-initial.log`, `process-counts.json`, `process-initial.exit` |
| `cargo test --locked -p chio-swarm-authority -p chio-runtime-core` | `b7211ce2` plus graph-module extraction; macOS/aarch64 | Exit 0: 348 tests, no failures or ignores; includes 91 runtime admission and 61 swarm stage-0 cases | `m5-runtime-authority.log`, `m5-runtime-authority-counts.json`, `m5-runtime-authority.exit` |
| Python process `unittest discover` | `b7211ce2` plus test formatting; Linux/aarch64 | Exit 0: all 34 tests, no skips | `python-process-linux.log` |
| Node process `node --test test/*.test.mjs` | `b7211ce2`; macOS/aarch64 | Exit 0: all seven tests | `node-process.log` |
| Strict Clippy, all targets of process (worker/mailbox features), runtime core and swarm authority | Current recovery patch; macOS/aarch64 | Exit 0, warnings denied | `m5-clippy.log`, `m5-clippy.exit` |
| Rust formatting / source hygiene | Current recovery patch; macOS/aarch64 | Exit 0 for both; existing size warnings retained | `fmt-fixed.log`, `hygiene-fixed.log` |
| Security CI source contract | Unchanged execution inputs | Exit 1: Cargo.lock digest ratchet mismatch | `security-ci-contract.log` |
| Hosted dependency audits | PR head `b7211ce2` | Terminal failure: 26 missing safe-to-deploy audits | `hosted-cargo-vet.log` |
| Hosted trusted capture | PR head `b7211ce2`, authorized source `f5566d9a` | Terminal failure before isolated capture | `hosted-capture.log` |

The initial macOS Python run is retained as a failed platform invocation
(`python-process.log`: 16 Linux-only errors and five skips). It is superseded for
this SDK gate by the complete Linux result, not counted as a pass. The runtime
suite emitted one unused-import warning from extraction; that import is removed
before strict Clippy and final-source qualification.

The existing default Colima guest refused both Docker and SSH connections. A
separate `chio-m5-qualification` profile now provides Linux/aarch64 kernel
6.8.0-64, Rust 1.94.1, the WASM target, Node 22 and pinned Apalache 0.50.1 for
ordinary local gates. The existing VM was not restarted or reconfigured.
This profile does not provide the required Linux/x86_64 cage qualification or
trusted-controller authority. Full foundation qualification remains open.

All 109 disposition identities remain unique, every cited file and named
regression still exists, and every cited checkpoint remains an ancestor. This
source integrity check does not rerun all disposition tests or resolve threads.
No review record was rewritten or original thread administratively resolved.

### Active frozen-source Linux queue

Local repair commit: `7b57f2ef6ef7a7ec9be9ec55db5653db94979276`.
The complete source is frozen in a separate local qualification checkout at
`/home/connor.guest/chio-foundation-7b57f2ef6` inside
`colima --profile chio-m5-qualification`. Both parent ancestry checks pass there.
The execution checkout remains `/tmp/arc-security-launch`; the Linux snapshot
must not be edited while qualification runs.

The serial runner is the retained `run-linux-gates.py` in the artifact directory
above. It started at 20:55 UTC. Formatting, process (72 tests), runtime/swarm
(348 tests) and the proof CLI contract (147 tests) have terminal exit 0, with
no failures or ignores. Subprocess fixtures are excluded from these counts.
The process-host and response-verifier gate is running after those gates.
At the last live check its guest runner PID was 2742 and Cargo child PID was
23835. Codex command session: `28376`. These are observation handles,
not evidence of continuing liveness; poll the session or guest processes before
deciding whether to resume. Do not launch a duplicate queue after an observation
timeout. No queue completion is claimed.

`linux-7b57f2ef6/identity.json` pins compiler, source, environment and lock hash;
`active.json` names the current command and PID; each terminal gate writes its
exit, retained log hash and test/CLI binary hashes. `results.json` contains only
completed gates. The queue stops at the first failure and retains that output.
After process and M5 suites it runs the full proof CLI contract, process-host
and response verification, signed lineage, exact native restart and caller
inventories, consumer and flow gates, workspace build/test/Clippy, and generated
proof coverage. Fuzz compilation, remaining SDK/generated-wire gates, dependency
audits and trusted x86_64 qualification are still separately outstanding.

### M5 boundary after recovery

The authenticated transport and live verifier changes now have complete fresh
owning test results. Live fan-out needs no future join or terminal receipt;
fan-in still requires its real join. The operation-owned test exercises the
sealed SQLite source, persisted continuation custody, signed capability binding
and identical completed-outcome replay with a single effect. These are local
component/composition results, not the final swarm artifact.

Two host composition primitives are implemented in the next local slice:

- `ProcessRuntime::with_routes` supplies host-selected `ProcessRoute` metadata.
  Each route is included in the existing immutable operation binding. Changing
  or removing it on reopen refuses recovery before another effect or journal
  charge. The worker protocol cannot select a route, and worker context cannot
  replace signed top-level route or process attribution. Unrouted legacy
  operations preserve their previous bindings and wire representations.
- `ChioKernel::issue_aggregate_family_root` requests a signed shared invocation
  limit through the configured authority. It requires qualified durable
  admission in `All` mode and refuses context-free issuance when tenant/lineage
  admission is installed. Local and governed signing authorities support the
  explicit request; other authorities default to refusal. The policy wrapper
  retains reputation and runtime-assurance checks and persists the exact root
  snapshot. Ordinary issuance still rejects unexpected aggregate authority.

Focused tests cover route forgery/rebinding and authenticated sibling contention,
restart and replay under the real SQLite aggregate budget. Verification of this
new slice is ongoing in `m5-host-development/`; this is not the frozen Linux
candidate or a claimed completed reference-host profile.

The next implementation boundary remains the reference host: load actual root
and child capabilities from the process journal, bind them into the signed task
graph, install the sealed live authority, select the aggregate issuance API,
and connect the registered tool routes to `with_routes`.
The Disabled smoke remains unchanged. Actual Enforced tools, all scenario/effect
oracles, independent complete-artifact verification and M6-M10 remain required.

## Retained pre-M5 evidence

These are distinct local runs, not one exact-head acceptance certificate.

The serial qualification queue at `58c632ce0f` completed workspace build,
process features, process host and signed lineage before it was deliberately
interrupted to begin the user-approved local M5 work. The native-restart gate
was interrupted, not passed; later queued gates did not execute. The queue
exited 130 with the candidate still clean and unchanged. Logs remain under
`/tmp/chio-task5-final-gates.niZqyr`. M5 source changes require fresh affected
qualification and do not inherit an exact-head pass from that checkpoint.

| Scope | Result and boundary |
| --- | --- |
| Patched full workspace Clippy | Passed with Rust 1.94.1, locked/offline dependencies and warnings denied. |
| Patched full workspace tests | Exited 101 in the proof-contract target: 138 passed, nine fixture-discovery failures. The repaired target now passes all 147 cases. The workspace invocation stopped at that failure; later targets and full workspace acceptance remain open. |
| Rust dependency policy | cargo-deny advisories, bans, licenses and sources pass after the rustls 0.23.45 repair. |
| Rust dependency audits | Locked cargo-vet fails with 26 missing safe-to-deploy audits. No new exemptions, certificates or trust authorities were added. |
| Python SDK and LangGraph | 206 SDK cases and 58 LangGraph cases pass, including installed wheels and two supported LangGraph profiles. Installed typing passes. All 22 Python lockfiles pass offline consistency checks. |
| TypeScript packages | Full publishable workspace build/test and six owning standalone package gates pass. Dashboard passes 103 tests; web3 example builds and passes six real Chromium tests. |
| JavaScript/Python advisory scan | The final expanded OSV scan passes with three pre-existing policy filters unchanged. This is not a zero-known-vulnerability claim for excluded findings. |
| Native Docker process recovery | Complete patched-snapshot qualification passes, including live owned-container host SIGKILL, restart, credential rotation, one-effect receipts, unresolved custody, shutdown and resource bounds. Container CPU/memory accounting remains explicitly unavailable. |
| Installed process starter | Complete patched-snapshot qualification passes with real external Python/Node consumers, mailbox exchange, independent receipt verification and installed package/sdist tests. |
| Installed AI SDK 6/7 | Complete patched-snapshot qualification passes, including recovery, journals, state pressure, cooperative swarms and supervision. No live model calls. The earlier mixed-binary run remains diagnostic only. |
| M4 SDK parity | Owning Python/Go/TypeScript parity gate passes. Native Rust consumer, M3 and composed gates remain distinct. |
| Fuzz and Docker locks | Full 30-target selector fixture passes. Fuzz locked metadata and generated Docker workspace lock consistency pass after regeneration. This is not a fuzz campaign or full fuzz compilation pass. |
| Security CI contract | Both the full checker and its full fixture suite remain blocked by the execution-image Cargo.lock digest ratchet. Isolated fixture results do not waive it. |

The TLS update addresses
[RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html).
Required AWS-LC and webpki updates preserve existing feature selections. The
source Cargo.lock digest is
`47bf5b6fc16784c18104912b1d90ee1160c2e8e330baff34fde35478e66fdbce`.
The security execution-image ratchet still requires
`a4e631319b00c54f2cbc6457ad0149198a4a367db8dec060fcce376c98728b49`.
No image, controller, trusted-source or enterprise-workflow pin was changed.

## Patched executable and fixture-discovery closeout

All three installed qualifiers completed at clean source `f0ff43b819`, using
the same privately retained CLI, SHA256
`82ba58ec8a8d742b9d22504ff4f0fd604ee6e0361b7f33df7d591163870b92a5`.
This was a Rust 1.94.1 workspace-test build on Linux/aarch64, not an optimized
release or x86_64 confinement certificate. Report SHA256 identities:

- AI SDK: `4d47b452f93fb0616bc1411766a14f3087122ff2f3f8ba42f58e96570dea5352`.
- Docker: `a74d4c975237dc3ed8ba680483158b3f2f87ea54916c3692ffaaaee17c204b73`.
- Starter: `81496d691735292ddc111c4758c6839b38e585d12fc926a7f8aed2a161a32138`.

The workspace failure exposed missing test setup for an external Cargo target
directory. The hardened runtime resolver correctly refuses to infer checkout
authority from the current directory or embedded build paths. The proof-test
command helper now supplies its owned `CHIO_CHECKOUT_ROOT`. The original
recursive-swarm fixture case failed without that anchor and passed with it;
the complete repaired proof target passes 147 cases with no ignores. Production
resolution, installed fixture overrides, verifiers and trust policy are unchanged.

Hosted run `34977549611` passed the authenticated-worker job, but its larger
process-host job exceeded its 90-minute job limit during the research swarm
benchmark. It is not a passing complete workflow. The ordinary process job
also does not run the feature-gated real x86_64 cage-enforcement inventory.

## Remaining gates

Finish the patched workspace and explicit process-feature suites, complete
M1-M4 exact inventories and rollback/caller crash matrix, and check generated
proof coverage and all fuzz binaries. Preserve the completed installed results;
rerun affected profiles after executable or package changes. Keep commands, source,
compiler, features, executable hashes and terminal results together.

The five already-trusted audit feeds have no exact target records for the five
new TLS dependency versions at this refresh. An unlocked cargo-vet refresh also
requires an explicit ownership policy for the locally patched sigstore-verify
0.6.3. That policy was not guessed or changed to bypass source review. Existing
source-review preparation is not a completed package security audit.

Exact-head hosted qualification, protected merge, and required trusted-runner
authorization remain open. Linux/aarch64 process/container evidence is not
Linux x86_64 tool-confinement evidence. The user authorized local Task 7/M5
implementation before protected integration on 2026-09-15. Acceptance still
requires the governed, confined reference swarm and the remaining foundation
gates; existing process demos do not replace it.
