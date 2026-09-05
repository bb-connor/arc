# Run Python and Node workers under Chio

This starter runs a Python producer and a Node consumer under the native Chio
process host. The producer sends a list through a durable mailbox. The consumer
calculates its count and total, checkpoints the result and acknowledges the
message. Each worker also attempts one forbidden mailbox operation so the
example produces signed evidence of its tool scope.

The packaged starter contains the host executable, both SDK packages and this
application. Running it requires Linux matching the supplied binary's
architecture, Python 3.11+ with `venv` and `pip`, and Node 22+ with npm. It
installs the local wheel and npm tarball offline. Rust and a Chio checkout are
not required by the packaged application.

## Run the packaged starter

Extract the starter archive into a directory you control, then run:

```bash
python3 -I run.py --state /tmp/my-chio-processes --exercise-recovery
```

Choose a new state directory whose parents are not writable by other users
(the sticky `/tmp` directory is supported). The application creates private
state, installs its SDKs and initializes the host. In recovery mode, the Python
worker deliberately exits after its committed send. Chio restarts it, returns
the original send receipt and launches the Node consumer after the producer
finishes. The result is `{"item_count": 3, "total": 10}`, with five independently
verified receipt signatures: three allowed operations and two scope denials.

Repeat the same command to inspect the completed result. Completed workers do
not run again, and the original receipts remain unchanged. Keep the same state
and recovery option when resuming an interrupted run. The capability lifetime
is one hour; this starter does not renew expired capabilities. Without
`--exercise-recovery`, the producer completes on its first attempt.

The private state directory contains `result.json`, `receipts.ndjson` and
`kernel.pub`. Verify the original receipts separately:

```bash
bin/chio receipt verify --input /tmp/my-chio-processes/receipts.ndjson \
  --trusted-kernel-pubkey /tmp/my-chio-processes/kernel.pub
```

For a failed or interrupted run, inspect the host before deciding how to resume:

```bash
bin/chio process status --state /tmp/my-chio-processes/host
bin/chio process logs --state /tmp/my-chio-processes/host --process producer --attempt 1
```

Status shows recorded attempts, outcomes and unfinished dependencies. The
snapshot timestamp and sampled host lock distinguish the last observation
from a live-process health claim. Logs belong to a specific completed attempt
and can be absent after abrupt host death. Keep the same state when resuming.

The key is pinned from this application's trusted initialization. The verifier
checks signatures, signer pins and action parameter hashes. It does not prove
the arithmetic result, receipt-log completeness or worker honesty. A local
file export is not an exactly-once external tool effect.

## Build and qualify from a checkout

From the Chio repository root:

```bash
cargo build --locked -p chio-cli --bin chio
python3 scripts/qualify-process-packages.py --chio target/debug/chio \
  --output /tmp/chio-process-starter
```

Building the package artifacts requires `uv` and may fetch Python build
dependencies. The consumer install uses only the built artifacts. Qualification
copies the application and host outside the checkout, exercises both installed
SDKs, tests the rebuilt Python source distribution, and exports the starter
with nonsecret evidence. Failed qualification retains private diagnostic
state and exits unsuccessfully. The `Chio process workers` CI workflow also
uploads a tar archive preserving the executable's file mode.

## Application and deployment boundary

`producer.py` and `consumer.mjs` show the complete worker code. `run.py` owns
one-time installation, the policy, child tool grants, dependency plan and
receipt verification. The host owns worker launch, credentials, admission,
durable calls, mailbox storage and bounded restart attempts. Attempt numbers
never enter logical operation keys. Errors and uncertain effects stop work;
an unrecorded external outcome cannot be made safe by inventing a new key.

Workers are ordinary local processes without an OS sandbox. They share the
operator's user account, so this profile requires trusted application code.
Tool grants restrict kernel-mediated calls; they do not isolate direct file
or network access. Mailbox rights authorize endpoint operations and do not
attest the producer's identity to a reader.

The included executable is a development preview for the producing machine's
platform, not a signed public release. `manifest.json` records artifact hashes
for accidental drift detection. Trust its supplier separately.
The recorded source checkout identifies the SDK and application sources; it
does not establish how the supplied native executable was built. PyPI and npm
publication use the repository's existing release workflows; building this
starter does not publish packages or create release tags.
