# @chio-protocol/process

Experimental, dependency-free Node client for Chio's local worker service.
Requires Node 22+ and a Unix host. Build a tarball with `npm pack` in this
directory and install it into an application with
`npm install /path/to/chio-protocol-process-0.1.0.tgz`.
Registry publication is a separate release step.

The [packaged starter](https://github.com/bb-connor/arc/tree/main/examples/process-starter)
includes a native Linux host and runs Python and Node workers from installed
packages outside the checkout.

```javascript
import { ProcessClient } from "@chio-protocol/process";

const client = new ProcessClient(socketPath, credential);
const result = await client.invoke("publish-report", "reports", "publish", { text: "hello" });
if (result.verdict === "allow") {
  const snapshot = await client.inspect();
  await client.checkpoint(snapshot.checkpoint.revision, { published: true });
}
```

The trusted host privately supplies the socket path and credential. The
credential fixes the process identity. Keep it outside prompts and logs.
Kernel denials retain their signed result; protocol and transport errors throw
`WorkerError` with a `code`. A timeout may follow a committed effect. Retry the
original key and identical arguments. The client never retries automatically.

Preserve `receipt_json` unchanged for a Chio verifier. The client returns
receipts without verifying their signatures. Revision strings remain strings;
application integers outside JavaScript's safe range must use strings too.

The Linux host's optional [adaptive process profile](../../../../crates/products/chio-cli/PROCESS_RUNNER.md#adaptive-child-work)
uses the same `invoke` method for `chio-process/spawn_<template>` and
`wait_children`. A waiting parent checkpoints and exits 75 to release its
worker slot, then resumes under its original process identity and attempt
budget. Executable selection and signing stay with the host.

See the [worker contract](../../../../crates/kernel/chio-process/WORKER_PROTOCOL.md)
for authentication, cancellation, frame limits and OS isolation requirements.
Run client tests with `npm test` in this directory.

## Immutable process state

Inspect `storage.protocol` for `chio.process.blobs.v1` before using blobs. Earlier
hosts omit this capability. `putBlob(Uint8Array)` returns `{sha256, bytes}` and `readBlob(sha256)` returns a `Uint8Array`.
The client snapshots writes, checks read digests and lengths, and never retries
automatically. Each immutable blob is at most 1 MiB and belongs only to the
authenticated process. The host defaults to 64 MiB and 4096 records across its
whole root tree. Duplicate writes within a process consume quota once.

Write blobs before checkpointing their references. Failed checkpoint writes can
leave charged orphan records. There is no deletion or garbage collection API.
Missing/corrupt data stops recovery; a hash does not authenticate model output.
Tool guard evaluation and receipt verification remain separate.
