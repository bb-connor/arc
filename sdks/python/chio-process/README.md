# chio-process for Python

Experimental, dependency-free client for a local Chio process worker service.
Requires Python 3.11+ and a Unix host. Build and install a local wheel:

```bash
uv build --wheel sdks/python/chio-process --out-dir /tmp/chio-process-packages
python3 -m pip install /tmp/chio-process-packages/chio_process-0.1.0-py3-none-any.whl
```

The trusted host supplies a private socket path and a credential bound to one
process. Keep them outside prompts and logs.

An optional [operator-side container launcher](WORKER_CONTAINERS.md) runs Python
workers with read-only RPC inputs, separate namespaces, bounded scratch and
resource/output ceilings on a local Linux Docker engine. It does not change the
client's worker protocol or require an additional Python dependency.

The [packaged starter](https://github.com/bb-connor/arc/tree/main/examples/process-starter)
includes a native Linux host and runs Python and Node workers from installed
packages outside the checkout. Registry publication is a separate release step.

For operator-owned local demos, `chio_process.launch.provision_native_demo`
calls the CLI's explicit native MCP provisioner and returns a host server
configuration containing the signed launch policy and pinned signer. It starts
the command for tool discovery. Supply a fresh output directory and retain the
resulting policy for restart. This uses migration stage Disabled and provides
no OS containment. Production operators must provision their own launch policy;
the process host never infers authorization from discovery alone.

```python
from chio_process import ProcessClient

client = ProcessClient(socket_path, credential)
result = client.invoke("publish-report", "reports", "publish", {"text": "hello"})
if result["verdict"] == "allow":
    snapshot = client.inspect()
    client.checkpoint(snapshot["checkpoint"]["revision"], {"published": True})
```

Calls are synchronous. An async host can run them in its worker thread pool.
Kernel denials return their signed result; protocol and transport errors raise
`WorkerError` with a `code`. Never treat a timeout as proof that a tool did not
run. Retry with the original key and identical arguments. The client performs
no automatic retry. Preserve `receipt_json` unchanged for independent Chio
verification; this client does not verify signatures.

For a model query or another operation whose unknown outcome must never be
regenerated, pass `known_outcome_only=True` to `invoke`. Chio can dispatch its
initial request and replay a completed response, but cannot redispatch an
unknown outcome even if the tool declares itself read-only. Keep this option
unchanged with the original operation key on recovery. Older hosts reject the
extension; do not remove it as a compatibility fallback. The default omits the
wire field and retains existing read-only recovery behavior. This restriction
does not control a tool's internal provider retries.

The Linux host's optional [adaptive process profile](../../../crates/products/chio-cli/PROCESS_RUNNER.md#adaptive-child-work)
uses the same `invoke` method for `chio-process/spawn_<template>` and
`wait_children`. A waiting parent checkpoints and exits 75 to release its
worker slot, then resumes under its original process identity and attempt
budget. Executable selection and signing stay with the host.

See the [worker contract](../../../crates/kernel/chio-process/WORKER_PROTOCOL.md)
for authentication, cancellation, frame limits and OS isolation requirements.

```bash
PYTHONPATH=sdks/python/chio-process/src python3 -m unittest discover -s sdks/python/chio-process/tests
```

## Recorded operator invocations

The same client supports explicit operator tools such as resource assignment.
The host supplies an operator connection whose capability authorizes those
tools. The helper adds no authority and requires no resource-specific client.

```json
{
  "operation_key": "assign-1",
  "server_id": "resource-admin",
  "tool_name": "assign",
  "arguments": {"resource": "example", "owner": "host-supplied identity"},
  "known_outcome_only": true
}
```

Use the actual tool schema from the operator's connection descriptor. Save the
request above as `request.json`, then invoke it through the installed package:

```sh
python -m chio_process.invocation --chio /path/to/chio \
  --connection operator-connection.json --trusted-kernel-pubkey kernel.pub \
  --request request.json --output operator-attempt-1
```

`chio_process.invocation.invoke_recorded` exposes the same operation in Python.
It freezes and persists the complete request before dispatch, retains the
response and original receipt text, and invokes the supplied Chio verifier
against the selected public key. The output directory must be new. It contains
no connection credential. Exit zero means the response receipt verified;
inspect `verdict` and the tool output to determine whether the requested work
was allowed and completed.

The default `known_outcome_only=True` permits a first dispatch and recovery of
a completed result. It never automatically redispatches an unknown result,
including for a read-only tool. It is not a read-only outcome query. Keep that
policy, the key, target and arguments unchanged across recovery. Reuse the
retained `request.json` with a new output directory; changing the key does not
make a new effect a recovery attempt. A transport error or receipt-verification
failure can follow a committed resource effect. The helper retains evidence
and never retries automatically.

## Immutable process state

Inspect `storage.protocol` for `chio.process.blobs.v1` before using blobs. Earlier
hosts omit this capability. `put_blob(bytes)` returns `{sha256, bytes}` and `read_blob(sha256)` returns `bytes`.
The client snapshots writes, checks read digests and lengths, and never retries
automatically. Each immutable blob is at most 1 MiB and belongs only to the
authenticated process. The host defaults to 64 MiB and 4096 records across its
whole root tree. Duplicate writes within a process consume quota once.

Write blobs before checkpointing their references. Failed checkpoint writes can
leave charged orphan records. There is no deletion or garbage collection API.
Missing/corrupt data stops recovery; a hash does not authenticate model output.
Tool guard evaluation and receipt verification remain separate.

### Structured JSON snapshots

`chio_process.snapshot.JsonSnapshot` stores JSON documents up to 8 MiB using
those same process-owned blobs. It separates large JSON atoms from surrounding
syntax, so edits and insertions can reuse unchanged strings. Small fragments
are packed together. A bounded index records segment order and lengths; reads
verify the index, every segment and the reconstructed document before decoding
it. Unknown reference fields, duplicate JSON keys and nonfinite numbers are
rejected.

```python
from chio_process.snapshot import JsonSnapshot

snapshots = JsonSnapshot(client)
checkpoint = client.inspect()["checkpoint"]
document = {"messages": []} if checkpoint["value"] is None else snapshots.read(checkpoint["value"])
document["messages"].append({"role": "tool", "content": "An application observation"})
reference = snapshots.write(document)
committed = client.checkpoint(checkpoint["revision"], reference)
```

The application owns the checkpoint slot and commits the returned reference
with the existing revision CAS. The helper does not retry checkpoint conflicts
or uncertain writes. A fresh helper can read any retained reference belonging
to the same process. The helper caches successful blob identities for its one
client because the native API neither changes nor deletes those blobs; every
read still verifies their bytes. No cache is shared between processes.

The reference format is `chio.process.json-snapshot.v1`. It uses the existing
blob and checkpoint worker operations and adds no host privilege or Python
dependency. The host's byte and record quotas still apply to all stored
segments and indexes, including writes whose checkpoint later fails. No history
is discarded and no space is reclaimed. Large changes, many snapshots or many
small values can still exhaust the quota.
