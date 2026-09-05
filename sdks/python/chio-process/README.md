# chio-process for Python

Experimental, dependency-free client for a local Chio process worker service.
Requires Python 3.11+ and a Unix host. Install from this checkout:

```bash
python3 -m pip install ./sdks/python/chio-process
```

The trusted host supplies a private socket path and a credential bound to one
process. Keep them outside prompts and logs.

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

See the [worker contract](../../../crates/kernel/chio-process/WORKER_PROTOCOL.md)
for authentication, cancellation, frame limits and OS isolation requirements.

```bash
PYTHONPATH=sdks/python/chio-process/src python3 -m unittest discover -s sdks/python/chio-process/tests
```
