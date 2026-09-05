# @chio-protocol/process

Experimental, dependency-free Node client for Chio's local worker service.
Requires Node 22+ and a Unix host. This package is private pending protocol
qualification; use it from the checkout or install its local directory.

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

See the [worker contract](../../../../crates/kernel/chio-process/WORKER_PROTOCOL.md)
for authentication, cancellation, frame limits and OS isolation requirements.
Run client tests with `npm test` in this directory.
