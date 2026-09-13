# Reference swarm

An orchestrator and two workers driving the reference tools through
three Chio edges, with the swarm authority verifying the delegation before
and after the run and every tool call leaving a receipt in trust-control.

This is an integration fixture, not a qualified secure-swarm deployment.
The smoke uses a signed `Disabled` native-launch profile on every architecture.
It does not switch to `Enforced` on x86_64. The signed task graph is checked by
the orchestrator but is not yet bound to the edge-issued capability identities.
The kernel supports `require_swarm_admission()` (Chio YAML:
`kernel.require_swarm_admission: true`), but that setting alone does not wire
this fixture's task authority into its edges. It would deny these unbound calls.
The smoke retains its explicit integration-only status until trusted evidence
provisioning, real issued-capability binding and live task authority are installed.

The orchestrator signs a task graph that delegates a narrower scope to each
worker: the reader worker may list, read and stat inside one repository
through the reader edge, the writer worker may write, read and stat one
artifact through the writer edge, and the orchestrator itself digests
results through the digest edge, whose policy grants `sha256` alone. Each
delegation carries an attenuation witness, a route to its edge, an
allocation from one budget pool and a single-use continuation token bound to
the signed graph. `verify_swarm_authority_bundle` admits the bundle before
any worker starts; after the run the pool is released for the completed
worker and a terminal receipt is signed over the scenario verdicts.

## Scenarios

| Scenario | What happens | Who refuses |
|----------|--------------|-------------|
| `success` | list, read, write, read back, digest | nobody; receipts for every capability |
| `file_denial` | `read_file ../outside`, then `read_file /etc/passwd` | the tool's root check, then the edge's forbidden-path guard (`tool_denied`) |
| `scope_widening` | `canonical_json` on the digest edge; a worker scope wider than the orchestrator's | the edge's grant (`tool_denied`); no attenuation witness exists |
| `budget_exhaustion` | both workers send eight `stat` calls concurrently against grants capped at six invocations | the kernel must deny the two overruns per grant; no local counter or retry masks an authority error |
| `sensitive_output` | a write carrying an AWS credential pattern | the edge's secret-leak guard (`tool_denied`); the artifact is untouched |
| `restart_recovery` | the reader edge is killed without a drain and started again mid-session | nobody: the session continues by id from the session store and keyring; a graceful stop would have ended it on purpose |
| `revocation` | the orchestrator revokes a worker's capability, then re-verifies the bundle with the task revoked | the edge (`tool_denied`); the authority refuses the bundle |

Network denial is not exercised here. It requires a separately provisioned
Enforced launch on a qualified Linux host. Per-grant invocation limits are not
proof of shared task-pool enforcement. Concurrent budget calls run before the
crash/restart scenario so earlier recovery faults remain visible.

## Running

```bash
examples/reference-swarm/smoke.sh
```

The smoke starts trust-control and the three edges, each provisioned under a
signed native-launch policy with `scripts/lib/provision-mcp-launch.sh`, runs
the orchestrator with a restart hook for the recovery scenario, then exports
the receipts with `chio evidence export` and verifies the package offline
with `chio evidence verify`. Artifacts land under `artifacts/live/<time>/`:
the edge logs, the swarm bundle, `run-report.json` with every observation,
and the verified evidence package. Set `CHIO_REFERENCE_TOOLS_DIR` to a
directory holding static builds of the tools to wrap those instead of the
debug binaries.
