# Run a repository coding session

`chio-mini-swe session` imports one Git commit, prepares a native coding task
from operator-supplied launch policies, and exports the resulting patch with
verified Chio receipts. Its two preparation phases let a task service request
exact tool launches from an operator's provisioning system before execution.

This Linux profile requires a non-root operator, a protected installed Python
environment, a Chio binary with `process state`, and the local Docker profile
described in [repository execution](REPOSITORY.md). The agent works on an
imported snapshot. Dirty and untracked files stay in the source checkout;
applying or publishing the resulting patch is a separate operator action.

## Prepare the installation and images

Install `chio-process` and `chio-mini-swe` into a dedicated virtual environment
using a protected Python interpreter. Use installed wheels, with
`uv pip install --link-mode copy` when using uv, so changing file permissions
cannot also change a shared cache entry. Editable installs and nonempty
`PYTHONPATH` or `PYTHONHOME` overrides are refused.

The environment's files and directories must be owned by the operator or root
and must not be writable by other users. The interpreter, Chio executable and
their ancestor directories need the same protection. The root-owned sticky
`/tmp` directory is supported. Session and export directories are created
with mode `0700`; their retained files are private. Use a dedicated private
installation directory and `umask 077` when preparing it.

The [environment preparation helper](../../../examples/mini-swe-recovery/prepare_session_environment.py)
checks a dedicated installation before removing group and other write bits.
It requires owned, unshared regular files and a protected interpreter. It does
not change a shared package cache, system installation or unrelated ancestor
directories. From this checkout, run it with the installed environment's
interpreter so it selects that environment:

```sh
/private/coding-venv/bin/python \
  examples/mini-swe-recovery/prepare_session_environment.py
```

The helper rejects changed entries and shared regular files. A concurrent
installation change can cause failure after some permissions were already
narrowed. Preserve that dedicated environment for inspection; the helper does
not restore permission bits or complete the operation through alternate paths.

Session identity records the native binary digest, launcher digests and
installed `chio_mini_swe` and `chio_process` Python source digests. The Python
interpreter and other installed dependencies remain trusted components; these
records do not authenticate every dependency's contents. Keep the installation
stable for the lifetime of a session.

Supply three immutable local Docker image IDs:

| Configuration field | Required contents |
| --- | --- |
| `worker_image` | The installed `chio-mini-swe-worker` entrypoint and its dependencies. |
| `execution_image` | Bash, GNU `timeout`, Git and the project's runtime and dependencies. |
| `helper_image` | `/bin/sleep` and GNU `/bin/tar` for workspace import and snapshots. |

The [worker image instructions](../../../examples/mini-swe-recovery/README.md#execution-boundary)
and [repository image instructions](REPOSITORY.md#prepare-images-and-a-workspace)
describe the image contracts. Prepare project dependencies in the execution
image: repository commands have no network access. Image IDs must use
`sha256:` followed by 64 lowercase hexadecimal digits; mutable tags are refused.

## Initialize a task and request provisioning

Create the [provider configuration](OPERATOR.md#configure-the-provider-gateway)
with your endpoint, model, credential environment-variable name, request limits
and explicit token prices. That file contains no API key. Initialization and
tool discovery do not require a provider credential or make an inference call.

Create `session-config.json`, replacing the image and revision placeholders:

```json
{
  "schema": "chio.mini-swe.session-config.v1",
  "chio": "/private/bin/chio",
  "repository": "/code/project",
  "revision": "<selected-commit-or-ref>",
  "provider_config": "provider.json",
  "worker_image": "sha256:<64 lowercase hexadecimal digits>",
  "execution_image": "sha256:<64 lowercase hexadecimal digits>",
  "helper_image": "sha256:<64 lowercase hexadecimal digits>",
  "command_timeout_seconds": 90,
  "agent": {
    "system_template": "Repair the repository using bash commands. Validate the change. Submit by running a command whose output starts with COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT, followed by your summary.",
    "instance_template": "{{task}}",
    "step_limit": 8,
    "cost_limit": 1,
    "wall_time_limit_seconds": 600
  },
  "max_attempts": 2,
  "timeout_seconds": 300,
  "max_calls": 32,
  "capability_ttl_seconds": 3600
}
```

All top-level fields are required and unknown fields are refused. Configuration
paths resolve relative to this file. Put the task instructions in a separate
UTF-8 file of at most 128 KiB, then run the installed command:

```sh
umask 077
/private/coding-venv/bin/chio-mini-swe session init \
  --config /private/session-config.json \
  --task-file /private/issue.md \
  --state /tmp/project-session
```

The new directory contains the imported `repository/`, captured `task.md` and
`provider.json`, resolved `configuration.json`, `provisioning-request.json`,
and a final `initialized.json` marker. A source ref resolves to one full commit
identity at import. The task, provider settings, workspace configuration and
installed Chio code are bound to this session; changing them requires a new
session and deliberate provisioning.

`provisioning-request.json` is a versioned **unsigned request**, with schema
`chio.mini-swe.provisioning-request.v1`. It is suitable for an operator's
provisioning automation:

| Field | Meaning |
| --- | --- |
| `state`, `chio`, `binary_sha256` | Exact session location and native executable identity. |
| `source_commit`, `workspace_id`, `configuration_sha256` | Imported source and repository configuration identities. |
| `model_id` | Identity of the normalized provider configuration. |
| `environment` | Installed paths, launcher digests and Chio Python source inventory. |
| `servers.model`, `servers.sandbox` | Exact launch requests for the two tool servers. |

Each server entry contains `id`, `command` as an argv array,
`working_directory`, `execution_uid`, `execution_gid`, `tools` and
`request_timeout_seconds`. The `tools` entries are the expected unsigned MCP
tool definitions. The model definition binds its provider identity; the
repository definition binds this workspace and source configuration.

Use the request to provision the exact commands and signed manifests through
the [native launch-policy flow](../../../crates/products/chio-cli/PROCESS_HOST.md#configure-and-initialize).
Pass argv as an array, without shell interpretation. The provisioning system
selects the permitted migration stage, launch permissions and trusted signing
keys. This command creates no launch-policy signing keys, selects no migration
stage and invokes no demo provisioner. The unsigned request itself grants no
tool authority.

## Supply authorization and prepare the host

Provide an authorization document with exactly these two server entries:

```json
{
  "schema": "chio.mini-swe.session-authorization.v1",
  "servers": {
    "model": {
      "launch_policy": "/private/policies/model.json",
      "launch_policy_signer": "<64 lowercase hexadecimal digits>"
    },
    "sandbox": {
      "launch_policy": "/private/policies/sandbox.json",
      "launch_policy_signer": "<64 lowercase hexadecimal digits>"
    }
  }
}
```

Pin signer public keys through your operator trust configuration. Policy paths
resolve relative to the authorization file. Policies must bind the requested
executable, full argv, working directory and execution UID/GID. Native Chio
verifies their signatures, migration authorization and signed manifests, and
checks discovered tools against those manifests.

```sh
/private/coding-venv/bin/chio-mini-swe session prepare \
  --state /tmp/project-session \
  --authorization /private/authorization.json
```

Preparation captures the exact signed policy bytes and generates `host.json`,
`operator.json` and `policy.yaml`. The generated policy has only
`model/model_infer` and `sandbox/execute` grants, with invoke and delegate
operations. The process tree contains `root` and one `coder` child, with maximum
depth one and the configured call budget. The child receives those two concrete
routes and executes in the immutable worker image, with `/workspace` as its
repository directory. Existing native guards remain authoritative.

Native initialization creates the host's runtime keys and pins its kernel
public key for later verification. `run/` retains native operator and host
state. A final `session-prepared.json` marker identifies successful preparation.
Keep any external migration, receipt and runtime resources referenced by the
signed launch policies available at their provisioned paths.

## Bound the task

The session generates tool request deadlines from the supplied limits:

- Repository request deadline: `command_timeout_seconds + 120` seconds.
- Model request deadline: provider `timeout_seconds + 30` seconds.
- Native attempt `timeout_seconds`: at least the larger request deadline plus
  another 30 seconds.
- Agent `wall_time_limit_seconds`: at least the native attempt timeout.
- `capability_ttl_seconds`: at least the larger of agent wall time and
  `max_attempts * timeout_seconds + 60` seconds.

Repository command deadlines accept 1 to 300 seconds, native attempt deadlines
1 to 3600 seconds, attempts 1 to 16, call budgets 1 to 1024, and capability
lifetimes 1 to 86400 seconds. Agent step, cost and wall-clock limits also undergo
the [worker configuration checks](README.md#native-worker-and-mediated-inference).
One model response can contain several commands, so a step limit does not imply
a particular total call count. Budget exhaustion stops the task with retained
state. Repository storage, output and command-count limits still apply.

Provider token prices produce an estimated accumulated cost checked between
decisions, not a hard account billing ceiling. Capability lifetime begins when
the native host is prepared. Waiting before execution consumes that lifetime;
restarts and recovery never renew authority. Agent wall time includes time
spent stopped after the task starts.

## Run, inspect and recover

Supply the configured credential privately through your operator environment
and launch policy when you are ready to run:

```sh
/private/coding-venv/bin/chio-mini-swe session run --state /tmp/project-session
/private/coding-venv/bin/chio-mini-swe session status --state /tmp/project-session
```

`run` replaces the session command with the native host in the session working
directory. The native host owns signals, worker attempts, admission recovery
and exit status. Repeat the same command to resume the same task; completed
work remains completed. Unknown model or command outcomes stop execution
without automatic redispatch.

`status` returns `chio.mini-swe.session-status.v1`, with the session phase,
source/model identities, native host status when prepared, and repository
status. A busy repository is reported as `{"busy": true}`. Status does not start
a provider or execution server and works without the captured provider file.

After stopping the native host, recover pending repository resources:

```sh
/private/coding-venv/bin/chio-mini-swe session recover --state /tmp/project-session
```

Recovery holds the existing native host lock for its entire operation, together
with the session and repository locks. It refuses an active host and verifies
container ownership before cleanup. Interrupted commands remain interrupted;
their partial changes are not promoted. Recovery does not restart the model,
initialize another host or renew a capability. See the [repository recovery
contract](REPOSITORY.md#persistence-and-limits) for unknown native outcomes and
unavailable Docker engines.

## Export a verified result

With the host stopped and a completed trajectory available:

```sh
/private/coding-venv/bin/chio-mini-swe session result \
  --state /tmp/project-session --out /tmp/project-result
```

The new private output contains:

- `operator/`: retained task result, original receipts, pinned kernel public
  key and native signature verification report.
- `repository/`: baseline and final workspace archives, `changes.patch`,
  configuration, command history, original receipts, public key and verified
  receipt bindings for the ordered workspace transitions.
- `result.json`: the final `chio.mini-swe.session-result.v1` completion marker,
  with source/model identities, export summaries and kernel-key digest.

Export holds the native host lock for the entire read and verification, so it
refuses a running host. It works after cancellation or expiry and without a
provider credential, provider configuration file or Docker access. It does not
start tool servers. Receipt binding requires a nonempty completed repository
trajectory; missing, unknown, interrupted or altered evidence is refused.
Output redaction can prevent matching retained raw results to signed output
hashes. An operator can inspect the last completed workspace separately using
`chio-mini-swe-repository export --state /tmp/project-session/repository --out …`.

A recipient can verify `repository/` using their own source checkout, expected
full source commit and an independently trusted kernel public key:

```sh
chio-mini-swe-repository verify-export \
  --bundle /tmp/project-result/repository \
  --repository /code/project \
  --revision <full-source-commit> \
  --chio /private/bin/chio \
  --kernel-key /private/trusted-operator-kernel.pub \
  --server-id sandbox
```

Verification authenticates the exported changes and their receipt bindings.
It does not prove that the patch solves the task. Review and validate the
change before applying it. The [recipient verification contract](REPOSITORY.md#verify-a-received-patch-bundle)
describes artifact bounds, Git compatibility and the intermediate hash chain.

## Preserve incomplete state

Initialization, preparation and export create fresh directories or final
markers; existing state is never silently overwritten. If one fails, preserve
the partial files for diagnosis. An absent `initialized.json`,
`session-prepared.json` or output `result.json` means that phase did not finish.
Session status refuses incomplete initialization and reports
`preparation_incomplete` after initialization when preparation has partially
written its files. A partially prepared session cannot be prepared again.

Resolve any retained resources or unknown effects before intentionally creating
a fresh session. For a failed export, keep its partial output and select a new
output directory after correcting the cause. These markers distinguish usable
state from partial work; they do not authorize retries or additional execution.
