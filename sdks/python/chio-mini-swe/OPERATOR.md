# Run a native coding task

`chio-mini-swe` prepares one coding task, runs it under the native Chio host and
exports its retained result with verified receipts. It requires Linux, a local
Docker engine supporting the native container profile, a Chio binary built with
`process state`, and the installed `chio-mini-swe` package. No Rust application
code or custom provider gateway is required.

For an installed repository task, use the [session workflow](SESSION.md).
It captures source and provider settings, emits exact provisioning inputs,
and assembles this operator profile from supplied signed launch policies.

The [installed repository service](REPOSITORY.md) supplies an execution tool
with durable workspace snapshots and patch export. Operators can also supply
their own repository execution tool and sandbox. The tool's
workspace must survive worker and host restarts. This command does not clone a
repository, mount host source into the worker, apply a patch to a user's working
tree or publish changes. See the [execution result contract](README.md#integration)
and [native container boundary](../../../crates/products/chio-cli/PROCESS_CONTAINERS.md).

## Configure the provider gateway

The installed `chio-mini-swe-model` command serves one operator-selected Chat
Completions endpoint. Put its configuration in a file you control:

```json
{
  "schema": "chio.mini-swe.provider.v1",
  "endpoint": "https://inference.example/v1",
  "model": "operator-selected-coding-model",
  "credential_env": "CHIO_CODING_API_KEY",
  "max_output_tokens": 4096,
  "timeout_seconds": 60,
  "input_usd_per_million": 2,
  "output_usd_per_million": 8
}
```

The prices above are illustrative. Set your provider's agreed input and output
prices explicitly. Cost is an estimate from its reported prompt/completion
token counts and these rates. It does not verify an invoice, account for every
provider-specific discount or enforce a hard billing ceiling. Chio checks the
agent's accumulated cost between decisions; set provider-side spending limits
as appropriate for your account.

The endpoint is the API base; the gateway posts to `/chat/completions` beneath
it. Requests use `max_completion_tokens`, one upstream `bash` tool definition
and no streaming. `temperature` is optional. HTTPS certificate verification is
enabled. A loopback IP with HTTP is accepted only when
`"allow_loopback_http": true` is explicit. URL credentials, query strings,
arbitrary provider kwargs and literal API keys are rejected.

Supply the named credential environment variable privately to the trusted
gateway process. The worker receives its scoped Chio connection, not that key.
Configure any tool-server secret isolation in the operator's launch policy.
The gateway ignores proxy environment variables and ambient mini-SWE dotenv
configuration. It uses one HTTP attempt per Chio invocation, refuses redirects,
bounds responses and does not add an SDK retry loop. Provider-internal retries
are outside this contract. The network deadline closes an established
connection; OS name resolution may take longer to return, but cannot dispatch
the request after that deadline has elapsed.

Discover its identity without a credential or inference request:

```sh
/private/coding-venv/bin/chio-mini-swe-model --config /private/provider.json --describe
```

`model_id` derives from the normalized endpoint, model, credential variable
name, token/deadline settings, explicit prices and optional temperature. Rotating
the variable's secret value keeps the identity. This binds request configuration;
it does not attest which model a remote provider actually executed.

## Provision tools once

Follow the [native host configuration contract](../../../crates/products/chio-cli/PROCESS_HOST.md).
The model server's command is:

```json
["/private/coding-venv/bin/chio-mini-swe-model", "--config", "/private/provider.json"]
```

It advertises `model_infer`. Keep the installed environment, provider file and
signed launch policy under operator control. The native host requires a signed
launch policy and pinned signer for this server and the repository execution
server. The operator command never creates a policy, authorizes a new tool or
changes its migration stage. Existing grants and guards remain authoritative.

Declare a child such as `coder` with both `model/model_infer` and
`sandbox/execute` in its concrete tool scope. Give the host explicit call,
process and depth limits. The provider gateway can be discovered before the
credential is available. Actual inference requires it.

## Prepare and run

Create an operator profile beside the host and provider configuration files:

```json
{
  "schema": "chio.mini-swe.operator.v1",
  "chio": "/private/bin/chio",
  "host_config": "host.json",
  "provider_config": "provider.json",
  "process": "coder",
  "worker_image": "sha256:<64 lowercase hexadecimal digits>",
  "model_server": "model",
  "execution": {"server_id": "sandbox", "tool_name": "execute"},
  "environment": {"cwd": "/workspace"},
  "agent": {
    "system_template": "Repair the repository using bash commands.",
    "instance_template": "{{task}}",
    "step_limit": 8,
    "cost_limit": 1,
    "wall_time_limit_seconds": 600
  },
  "max_attempts": 3,
  "timeout_seconds": 300
}
```

Use the immutable local image ID produced by the
[worker image builder](../../../examples/mini-swe-recovery/README.md#execution-boundary).
It must contain the installed `chio-mini-swe-worker` entrypoint. The Chio
executable and its parent directories must be protected from other users'
writes. The state directory must be new, private, and have protected parents;
the sticky `/tmp` directory is supported.

```sh
chio-mini-swe prepare --profile /private/operator.json --task-file issue.md --state /tmp/coding-task
chio-mini-swe run --state /tmp/coding-task
chio-mini-swe status --state /tmp/coding-task
```

Preparation validates routes and bounds, stores the exact task and native plan,
and initializes the host from the supplied policy. It writes a final prepared
marker only after successful initialization. Preserve partial state if preparation
fails; it is not a resumable run. The command does not overwrite an existing
directory or silently reinitialize a failed task.

`run` replaces the operator command with the native Chio process. The native
host owns signals, reconciliation, credentials, attempts and exit status. Resume
with the same command and state. Completed workers stay completed. Changing
the binary, plan or provider configuration is rejected; use a fresh task for
an intentional configuration change, after resolving any earlier unknown effect.
Capabilities are not renewed automatically and native container limits still
apply. Private task state contains prompts, outputs and original receipts.

## Export the retained result

```sh
chio-mini-swe result --state /tmp/coding-task --out /tmp/coding-result
```

The new private output directory receives `result.json`, `receipts.ndjson`,
`kernel.pub` and `verification.json`. The command verifies every exported receipt
against the key pinned during initialization. Verification proves receipt
signatures and bound actions; a model's submitted result still needs application
validation and code review.

Result export uses the native filesystem-authorized `process state` reader.
It neither issues a worker credential nor starts a kernel, provider or execution
server. Cancelled or expired worker authority does not prevent an operator from
reading retained data. The command works when the provider configuration is
unavailable. It refuses missing/corrupt blobs and incomplete trajectories.
Read-only SQLite access can maintain WAL reader bookkeeping but does not
reconcile admission, migrate tables or modify application records.

## Qualification

The [installed operator qualification](../../../examples/mini-swe-recovery/README.md#installed-operator-workflow)
uses controlled local HTTP responses to exercise the real transport and package
entrypoints. It covers configuration drift, native completion, repeated runs,
offline export after cancellation, receipt verification and provider failure
without HTTP redispatch. This does not establish live-model coding quality or
independent adoption.
