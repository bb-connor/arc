# Local worker protocol, experimental v1

`chio.process.v1` exposes a process-scoped subset of the trusted host API.
Enable it with the `worker-server` Cargo feature. The implementation serves
Unix domain sockets on Linux and macOS. It is not a public network service.

## Host setup

Configure a durable `ChioKernel` and open `ProcessRuntime` as described in the
[crate README](README.md). The host registers the root and children using
authority-issued capabilities, then constructs `WorkerService::new(runtime)`.
For each worker, call `issue_credential(process_id, expires_at)` and privately
deliver `credential.expose_secret()` and the socket path. Bind a `WorkerServer`
in a dedicated private directory and call `serve(shutdown_future)`.

Credentials contain 256 bits of OS randomness. The journal stores their
SHA-256 digests, process bindings and expirations. Expiration cannot exceed
the process capability's validity. `revoke_credentials(process_id)` removes
every credential for that exact process. A fresh credential can recover the
same logical operation; credential rotation does not change request identity.

The host must isolate worker OS processes from its database, signing keys,
administration and other workers' credentials. Mount or otherwise expose only
the socket endpoint and each worker's own credential inside that isolation.
The socket directory requires mode 0700 and the socket is set to 0600. Unix
permissions alone do not isolate mutually hostile processes with the same
UID. The demo launches ordinary processes with disposable credentials and
does not qualify a sandbox. This service does not implement OS isolation.

The default server permits at most 32 active connections, one request per
connection, a five-second input-frame deadline and a five-second response
write deadline. Excess connections close without admission. Kernel execution
uses the kernel's configured deadlines. Graceful shutdown stops accepting and
drains admitted calls. Client disconnect does not drop an in-flight kernel
call. Forcibly dropping the server future or killing its host uses durable
admission recovery. After a crash, the host must select a fresh socket path
or safely dispose of its own stale socket; bind never removes existing paths.

## Frames and operations

Each request is UTF-8 JSON followed by one newline. Maximum request size is
2 MiB including that newline. Maximum response size is 8 MiB including its
newline. Extra operations require separate connections. Unknown request and
operation fields, duplicate struct fields and unsupported versions reject.

```json
{"protocol":"chio.process.v1","credential":"<private bearer secret>","operation":{"op":"invoke","operation_key":"publish-report","server_id":"reports","tool_name":"publish","arguments":{"text":"..."}}}
```

| Operation | Fields beyond `op` | Result |
| --- | --- | --- |
| `inspect` | None | Own process id, parent/root ids, state, depth, limits, shared call count and own checkpoint. No capability token. |
| `invoke` | `operation_key`, `server_id`, `tool_name`, `arguments` | Kernel verdict, output, request id, reason, terminal state, original `receipt_json`, optional `execution_nonce_json`. |
| `checkpoint` | `expected_revision` as a decimal string, `value` | New decimal revision and value, or conflict. |
| `cancel` | None | Number of processes whose admission is permanently cancelled in this worker's subtree. |

Every operation derives its process identity from authentication. The wire
API has no process selector, capability replacement, spawn, mint, revocation,
or administrative operation. Hosts perform child attachment and issuance.
The simple invocation profile carries no worker-supplied DPoP or governed
approval extension. A capability requiring one is still subject to the
kernel's checks and cannot gain access by using this protocol.

Successful protocol responses use `{"protocol":"chio.process.v1","ok":true,
"result":{...}}`. A successful `invoke` response can contain a kernel denial;
the verdict is `allow`, `deny` or `pending_approval`. Its terminal state is an
object with `state` (`completed`, `cancelled`, or `incomplete`), plus `reason`
for cancelled/incomplete. Output is null, `{"kind":"value","value":...}`,
or a fully materialized `{"kind":"stream","chunks":[...]}`. There is no
incremental stream transport in this version.

Protocol/runtime failures use `{"protocol":"chio.process.v1","ok":false,
"error":{"code":"..."}}`. Codes are `unauthenticated`, `invalid_request`,
`cancelled`, `conflict`, `checkpoint_conflict`, `limit_reached`, `runtime_error`,
`response_too_large`, `invalid_frame`, and `frame_timeout`. Internal paths,
SQL errors and credentials are not returned. Transport/authentication errors
have no tool receipt; admitted kernel denials retain their signed receipts.

## Recovery and signed data

Both SDKs return `receipt_json` as original canonical JSON text. Keep it
unchanged for a Chio verifier. Parsing and serializing through JavaScript
numbers can alter large signed integers. Checkpoint revisions likewise use
decimal strings. General application arguments and output use ordinary JSON;
encode large application integers as strings for portable JS handling. The
clients return receipts without independently verifying their signatures.
The Rust qualification test verifies every returned tool receipt.

Retry a failed invocation with the same operation key and identical arguments.
Neither client automatically retries. Timeouts, disconnects, response-size
failures and runtime errors can follow a completed external effect. They do
not prove that nothing happened and must not cause the caller to invent a new
key. The server reconstructs the same kernel request from persisted process
identity, so reissued worker credentials preserve the recovery key. Current
kernel validity, revocation, guard and admission checks still govern replay.

Authentication occurs before the operation and again before returning its
result. Revocation or expiry observed at the return check withholds output;
an already admitted effect may still finish. Cancellation has the separate
process admission boundary described in the README. Neither operation can
recall bytes already released to the transport.

## Executable qualification

```bash
cargo run -p chio-process --features worker-server --example polyglot_swarm
cargo test -p chio-process --features worker-server
PYTHONPATH=sdks/python/chio-process/src python3 -m unittest discover -s sdks/python/chio-process/tests
node --test sdks/typescript/packages/process/test/*.test.mjs
```

Requires Python 3.11+ and Node 22+. The example reads two pinned Chio source
files through the kernel, runs real Python and JavaScript inventory workers,
and mediates each publication to a local append-only file. The host exits
without destructors after the publications. Fresh host and worker processes
authenticate using the persisted credentials and recover the original
receipts. Eight workload invocation attempts produce four logical tool calls
and two publications; two further requests are denied by the shared ceiling.
This is deterministic language integration and recovery evidence, not an LLM
workload, a deployment qualification, or evidence of adoption.

The clients use standard-library IPC:
[Python sockets](https://docs.python.org/3/library/socket.html) and
[Node net](https://nodejs.org/api/net.html#ipc-support). No third-party runtime
dependencies, model accounts or external tool credentials are needed.
