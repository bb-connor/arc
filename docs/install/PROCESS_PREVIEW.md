# Try the Chio process preview

This preview runs a Python producer and Node consumer under the native Rust
host. It demonstrates a durable mailbox handoff, recovery after the producer
exits, scoped tool access, and verification of five original signed receipts.
The result is `{"item_count": 3, "total": 10}`. It requires no model API key.

The process stack is under review in
[PR #1154](https://github.com/bb-connor/arc/pull/1154) and its dependencies.
Use this source revision:

```text
repository: https://github.com/bb-connor/arc.git
revision:   d99e03027c57dc9c0929a5bca553e745c6286d99
```

The `backbay-labs/chio` mirror did not contain this starter when checked on
2026-09-08. Its website installer also pointed to missing release downloads.
Neither path substitutes for the revision above.

## Build and run on Linux

Use Linux, Rust with `rustup`, `protoc`, Python 3.11+ with `venv` and `pip`,
Node 22+ with npm, and `uv`. The hosted qualification uses Ubuntu 24.04 x86_64.
Building the host and packages downloads dependencies. The resulting starter
installs its included SDK packages offline and runs outside the checkout.

```bash
git clone https://github.com/bb-connor/arc.git chio-process-preview
cd chio-process-preview
git checkout --detach d99e03027c57dc9c0929a5bca553e745c6286d99
cargo build --locked -p chio-cli --bin chio
python3 scripts/qualify-process-packages.py --chio target/debug/chio \
  --output /tmp/chio-process-starter
cd /tmp/chio-process-starter
python3 -I run.py --state /tmp/my-chio-processes --exercise-recovery
```

Use new output and state directories. Qualification itself runs the installed
application, its recovery checks, and SDK protocol tests before exporting the
starter. Repeat the final command to inspect the completed result: neither
worker runs again and the receipt bytes stay unchanged.

The host grants last one hour. Resume with the same state and recovery option
before expiry. The starter does not renew expired authority.

## Inspect the result

From the exported starter directory:

```bash
bin/chio receipt verify --input /tmp/my-chio-processes/receipts.ndjson \
  --trusted-kernel-pubkey /tmp/my-chio-processes/kernel.pub
bin/chio process status --state /tmp/my-chio-processes/host
bin/chio process logs --state /tmp/my-chio-processes/host \
  --process producer --attempt 1
```

Expected results include one acknowledged mailbox message, two producer
attempts, one consumer attempt, three allowed operations and two scope denials.
The receipt verifier checks signatures, signer pins and action parameter
hashes. It does not prove the arithmetic result or receipt-log completeness.

The workers share the operator's OS account and require trusted application
code. This profile does not sandbox their direct filesystem or network access.
It is a development preview, not a signed release or a claim that all workspace
acceptance gates pass.

## Packaged artifacts and qualification

The [process workflow for this revision](https://github.com/bb-connor/arc/actions/runs/34298643178)
builds and qualifies the starter. A successful `MCP process host recovery` job
uploads `chio-process-starter-Linux-X64`, containing
`chio-process-starter.tar.gz`. GitHub artifact downloads require a signed-in
account and remain subject to retention limits. Check that the run succeeded
at the revision above before using its artifact. If it is still running, fails,
or the artifact has expired, use the source route above.

The tar archive preserves the host's executable file mode. Extract it into a
directory you control and follow the included `README.md`. `manifest.json`
records local artifact hashes and the checked-out source; its hashes detect
drift, and do not authenticate the supplier or establish release provenance.

## Use the execution contract in an application

The starter is a small runtime example. For the shared-resource contract, use
the [SQLite resource example](../../examples/shared-resource-swarm/README.md)
and the [execution evidence and remaining work](../architecture/SWARM_EXECUTION_CONTRACT.md).
Those cover resource ownership, stale-worker rejection, retained outcomes,
and recovery across LangGraph and AI SDK workers. Each resource keeps its own
atomic mutation authority.

An adoption result still requires a real consumer to show which coordination
code or operational interventions Chio removes. Running this starter alone
does not establish that advantage.
