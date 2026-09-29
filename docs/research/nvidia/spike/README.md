# Local test of OpenShell v0.1.2

This directory holds the scripts, policies, prototype code and retained results of one local test of OpenShell v0.1.2, run on 2026-09-29. Documents [01](../01-nvidia-stack.md), [04](../04-integration-design.md), [06](../06-strategy-and-roadmap.md) and [07](../07-ideas-backlog.md) label what it showed "VERIFIED, local test" (01 writes "VERIFIED (local test)"). The Chio middleware here is a Python prototype written for the test, not a Chio component. Its receipts use a test body and a fixed key, not Chio's receipt contract.

## What was run

The table records what the test used and observed (VERIFIED, local test). The release date comes from the [v0.1.2 release page, published 2026-09-28](https://github.com/NVIDIA/OpenShell/releases/tag/v0.1.2) (VERIFIED).

| Component | Detail |
|---|---|
| Host | One aarch64 host with 12 cores. Only the Docker driver ran; the host had no Podman, no `/dev/kvm` and no Kubernetes cluster. |
| OpenShell | Release v0.1.2 (tag `6648bd0`, published 2026-09-28): the gateway with the Docker driver, supervisor image `ghcr.io/nvidia/openshell/supervisor:0.1.2`, and sandboxes `chio-spike-1` and `chio-spike-2` |
| Chio prototype middleware | `middleware/chio_mw.py`, registered as `chio-spike` on port 27601. It serves `openshell.middleware.v1` at HTTP_REQUEST/PRE_CREDENTIALS and answers every HTTP_RESPONSE/PRE_RETURN preflight with skip. In `chio` mode it verifies the Ed25519 signature on the token in `x-chio-capability-token` using the Chio Python SDK's canonical JSON ([`sdks/python/chio-py`](../../../../sdks/python/chio-py)), checks the tool name and a `path_prefix` constraint in MCP `tools/call` bodies, and signs a receipt. A deny carries `chio_` plus 32 hex characters of the receipt id as its reason code. An allow writes `x-chio-receipt-id` and strips the token. |
| Chio MCP edge | `chio mcp serve-http` from a chio-cli 0.1.0 binary built on 2026-09-05, on port 27607, accepting MCP revision 2025-11-25 only. It wrapped `edge/wrapped_server.py`, which offers one tool, `echo_json`, under `edge/policy.yaml`. |
| NVIDIA example | The Rust content-guard example, OpenShell [`examples/supervisor-middleware-content-guard`](https://github.com/NVIDIA/OpenShell/tree/acbac9cb795094986cbab016bfd0352d980b17f6/examples/supervisor-middleware-content-guard), registered as `content-guard-example` on port 27606 with a 262,144-byte payload limit |
| Built-in middleware | `openshell/regex`, with no configuration |
| Clients | Claude Code 2.1.284 and Codex 0.158.0 from npm, run inside the sandbox; the standard-library probes `client/probe.py` and `client/probe2.py` |
| Upstreams | An echo service on port 27604 at `/echo` and an MCP service on port 27605 at `/mcp`. Neither is published. |

Every middleware entry selects `host.openshell.internal` only. Requests to `host.docker.internal` reach the echo upstream through OpenShell's proxy and REST rules without middleware, and serve as the baseline.

## Files

| Path | Contents |
|---|---|
| `bench_all.sh` | Latency matrix. For each variant it runs `policy set --wait`, then `probe2.py bench` against the guarded and baseline hosts. |
| `q5_switch.sh` | Submits `chioB` and `chioA` alternately three times during a request loop, then saves the policy list |
| `q7_restart.sh` | Kills the prototype during a request loop, starts a new one 12 seconds later, and records the times |
| `gateway/gateway.toml` | Gateway settings (`allow_unauthenticated_users`, JWT key paths) and the two middleware registrations: plaintext gRPC with `allow_insecure_transport`, 500 ms timeout |
| `middleware/chio_mw.py` | The prototype. A `control.json` file (next to the script, or at `CHIO_MW_CONTROL`) can add a delay, crash the process or override the mode. |
| `middleware/mint_token.py` | Prints a base64url token with N delegation links and one `file_read` grant limited to `/workspace/`, built from the seeds in [`tests/bindings/vectors/capability/v1.json`](../../../../tests/bindings/vectors/capability/v1.json) |
| `middleware/policy_identity.py` | Reads policy status, the policy list, the sandbox record and a short `WatchSandbox` window through the OpenShell v0.1.2 Python SDK |
| `client/probe.py`, `client/probe2.py` | In-sandbox cases: the MCP sequence, latency, large bodies, header visibility, token size, body sweeps, concurrency and a timeline loop |
| `edge/` | The edge's wrapped server and policy, a logging proxy (`capture_proxy.py`) and an MCP roots probe (`roots_probe.py`) |
| `policies/` | Policy variants as `.yaml`, with an identical `.json` for all but the `clients_*` files |
| `results/` | The retained results described below |

All variants define four network policies: `echo_guarded`, `echo_baseline`, `chio_edge`, and `mcp_guarded`, which allows `initialize`, `notifications/initialized`, `tools/list`, `ping` and `tools/call` for `file_read` and denies `tools/call` for `delete_resource`. Their middleware entries differ, all with `on_error: fail_closed` unless noted:

| Variant | Middleware entry |
|---|---|
| `none` | None |
| `regex`, `cg` | `openshell/regex`; the content-guard example in redact mode with a term that never matches |
| `null` | The prototype in `null` mode, which allows without parsing |
| `chioA`, `chioB` | The prototype in `chio` mode with `policy_ref` `chio-pol-A` or `chio-pol-B` |
| `chio_allowcode`, `chio_nostrip`, `chio_failopen` | `chio` mode with a reason code on allow, with the token left in place, or with `on_error: fail_open` |
| `chio_mcpbig` | `chio` mode, and `mcp.max_body_bytes` 4194304 on `mcp_guarded` |
| `clients_A`, `clients_B`, `clients_rest` | `chio` mode for the Claude Code and Codex runs, with both binaries allowed, `chio_edge` on port 27608 and a `lenient` endpoint on 27609. `clients_B` and `clients_rest` add `mcp.versions` 2025-06-18 and 2025-11-25, and `clients_rest` routes `lenient` as `protocol: rest`. |

## How to run it again

- `$SPIKE_DIR` is the working directory that the scripts and `gateway.toml` read and write. It holds `bin/os` (the OpenShell v0.1.2 CLI), `gw/jwt/signing.pem`, `public.pem` and `kid` (the gateway JWT keys), `policy2/` (the files from `policies/`), `mw/` (the files from `middleware/`, a Python virtual environment in `.venv` and generated stubs in `gen/`) and `logs/` (all output, plus `mw.pid` for the running prototype).
- `$SCRATCH` stands for a directory outside the repository for everything not published: the CLI, keys, virtual environment, stubs and logs. No published file refers to it. Use `SPIKE_DIR=$SCRATCH/<name>`.
- `10.20.1.67`, in `gateway.toml` and `q7_restart.sh`, is the test host's address for the middleware services. Replace it with an address the supervisor can reach.

1. Install the OpenShell v0.1.2 CLI as `$SPIKE_DIR/bin/os` and create the JWT key files. Write the absolute path in place of `$SPIKE_DIR` in `gateway.toml`, for example with `envsubst`. Whether the gateway expands variables is not documented.
2. In `$SPIKE_DIR/mw/.venv`, install `grpcio`, `protobuf` and `cryptography`, and generate Python stubs for OpenShell's `proto/supervisor_middleware.proto` and `proto/extension.proto` into `gen/`. The proto revision used is not recorded. Set `CHIO_REPO_ROOT` to this repository's root, because the prototype imports the Chio Python SDK and the token vectors from it.
3. Start the prototype with `.venv/bin/python chio_mw.py --bind <address>:27601 --log $SPIKE_DIR/logs/mw.jsonl --receipts $SPIKE_DIR/logs/receipts.jsonl` from `$SPIKE_DIR/mw`, and write its PID to `logs/mw.pid`. Start the content-guard example on port 27606 and an echo and an MCP service on ports 27604 and 27605. `probe2.py hdr` expects the echo service to answer with JSON holding a `received_headers` list of name and value pairs.
4. Start the gateway with `gateway.toml`, then create `chio-spike-1` and `chio-spike-2`. The gateway does not start while a registered service is unavailable (VERIFIED, OpenShell@acbac9c [`docs/extensibility/supervisor-middleware/configure.mdx:63`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/supervisor-middleware/configure.mdx?plain=1#L63); VERIFIED, local test).
5. Run `.venv/bin/python mint_token.py 1 > token1.txt` and place `probe2.py` and `token1.txt` at `/sandbox/p2/upload2/` in each sandbox.
6. Run `bench_all.sh`, `q5_switch.sh` and `q7_restart.sh` with `SPIKE_DIR` exported. For the OCSF sequence, enable export with `$SPIKE_DIR/bin/os settings set chio-spike-1 --key ocsf_json_enabled --value true` (the documented form, VERIFIED, [`docs/observability/ocsf-json-export.mdx:25`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/observability/ocsf-json-export.mdx?plain=1#L25)), then run `python3 probe.py mcp host.openshell.internal 27605 <token file>` in `chio-spike-1` under a `chio`-mode policy.

The commands that started the gateway, the edge, the upstreams and the content-guard example, created the sandboxes, copied files in and out of them and enabled OCSF were not recorded.

## Measured results

### Latency: `results/bench2.jsonl`

Sandbox `chio-spike-2`, 2026-09-29 08:09:35 to 08:10:53 UTC. Each run sent sequential keep-alive POSTs of an MCP `tools/call` body with the token from `token1.txt`, after 10 discarded warm-up requests: 1,000 requests at 1,000 bytes, 300 at 64 KiB and 100 at 1 MiB. With 100 requests the p99 is the slowest request. Guarded host, in milliseconds (VERIFIED, local test):

| Variant | 1 KB p50 | 1 KB p99 | 64 KiB p50 | 64 KiB p99 | 1 MiB p50 | 1 MiB p99 |
|---|---|---|---|---|---|---|
| `none`, first run | 1.703 | 2.747 | 2.040 | 4.219 | 4.938 | 10.413 |
| `regex` | 1.896 | 3.212 | 2.188 | 4.264 | No comparable figure | No comparable figure |
| `cg` (Rust example) | 3.747 | 6.685 | 4.606 | 7.276 | Not run | Not run |
| `null` (Python, no checks) | 4.566 | 9.103 | 4.803 | 10.587 | 9.027 | 12.752 |
| `chioA` (Python prototype) | 5.338 | 10.477 | 6.436 | 11.137 | 16.838 | 27.339 |
| `none`, last run | 1.728 | 3.511 | 2.113 | 4.430 | 5.087 | 12.402 |

- Over the first `none` run, p50 at 1 KB rose 0.193 ms for `regex`, 2.044 ms for `cg`, 2.863 ms for `null` and 3.635 ms for `chioA`. For `chioA`, p99 at 1 KB rose 7.730 ms and p50 at 1 MiB rose 11.900 ms.
- The baseline host stayed between 1.670 and 1.745 ms p50 at 1 KB in all six runs.
- At 1 MiB, `regex` returned 51 responses with status 403, 45 `RemoteDisconnected` and 4 `ConnectionResetError`, while its baseline returned 100 with status 200. `bench_all.sh` skips `cg` above its 262,144-byte registration limit. Every other request returned 200.

### OCSF events: `results/ocsf.jsonl`

58 OCSF 1.8.0 events from `chio-spike-1`, product "OpenShell Sandbox Supervisor" 0.1.2, 2026-09-29 05:20:55.864 to 05:20:56.265 UTC: 24 HTTP Activity (4002), 12 Network Activity (4001), 12 Device Config State Change (5019), 7 Detection Finding (2004), 1 SSH Activity (4007) and 2 Base Event. They cover 12 requests to port 27605 that match, in order, the 12 cases of `probe.py mcp`. The events carry no arguments or request headers, so the case names below come from that order (VERIFIED, local test).

| Requests | OpenShell | Prototype | Response in events |
|---|---|---|---|
| `initialize` at 2025-11-25, `notifications/initialized`, `tools/list`, an in-scope `file_read`, and `initialize` with body version 2026-07-28 | Allow | Allow | 200; 202 for the notification |
| `file_read` of `/etc/shadow`, and `file_read` without a token | Allow | Deny | None |
| `tools/call` for `delete_resource` | Deny: "blocked by deny rule" | Not called | None |
| `tools/list` with no version header, and with 2025-06-18 | Deny: versions "2025-03-26" and "2025-06-18" "not allowed by endpoint policy" | Not called | None |
| `server/discover` and sessionless `tools/call` at 2026-07-28 | Deny: "MCP-Protocol-Version names an unsupported protocol version" | Not called | None |

- The two prototype denials carry `status_detail` `middleware_denied:chio-authority:chio_` followed by 32 hex characters of the prototype's receipt id.
- Each Detection Finding shows `finding_info.uid` `chio-spike.finding`, the title "External middleware finding" and a count. The finding type `chio.receipt`, the receipt id label and the metadata that the prototype returned appear nowhere.
- No event contains a `request_id`, and no allow event carries a receipt reference.
- Response-phase events give the plaintext upstream's URL scheme as `https`; request-phase events give `http`.

### Policy switching and restart

- `results/q5_policy_list.json` lists 19 revisions of `chio-spike-2`. `results/q5_events.txt` shows versions 14 to 19 submitted alternately 12 and 6 seconds apart. Versions 15 and 17 became `superseded` with no load time. The 16 revisions with a load time loaded 0.05 to 9.84 seconds after creation, each 5.1 to 5.6 seconds past a ten-second boundary. That pattern fits the supervisor's 10-second default poll (INFERRED; the interval is VERIFIED at OpenShell@acbac9c [`crates/openshell-supervisor/src/lib.rs:1026-1029`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor/src/lib.rs#L1026-L1029)).
- `results/q7_restart_events.txt` records the kill at 07:58:25.789 UTC, a new process 12.005 seconds later and the end of the loop at 07:58:52. The unpublished loop log showed the first 403 `middleware_failed` 0.14 s after the kill, 59 denials and no allows during the outage, and the first 200 0.26 s after the restart, with no gateway restart (VERIFIED, local test).

Findings on headers, body limits, clients and fail-open rest on logs that were not published. [04-integration-design.md](../04-integration-design.md) states them, and [08-sources.md](../08-sources.md) lists the logs.

## Limits

- One host, one driver (Docker) and a single run of each case. Only the no-middleware variant was measured twice.
- Plaintext same-host gRPC with no TLS and no extension JWT. The prototype is Python on a 32-thread pool, so its latencies are not product numbers.
- The prototype signs with a key derived from a constant, verifies no delegation-link signatures, and accepts any issuer, because every `chio`-mode policy sets `trusted_issuers` to an empty list.
- The test ran v0.1.2. The rest of the set cites OpenShell at `acbac9c`, 13 commits later, whose changes include MCP inspection (VERIFIED, GitHub comparison read 2026-09-29, as recorded in [04-integration-design.md](../04-integration-design.md)).
- `results/bench.jsonl` is an earlier run whose lines record neither the variant nor a time. Its lines have the output format of `probe.py bench`.
- In a second run, no OCSF file appeared in the supervisor's `/var/log` although `ocsf_json_enabled` was true. Supervisor Docker logs and a wire capture of Claude Code's requests were not retained.
