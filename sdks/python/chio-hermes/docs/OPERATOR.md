# Hermes operator guide

[Back to the README](../README.md)

This guide describes the restricted 0.1.2 source candidate. Public artifact
release qualification remains open.

## Supported mode

`chio-hermes-restricted` launches the pinned Hermes CLI with only `mcp-chio`.
It creates a fresh isolated profile and empty local working directory, disables
user/project plugins and shell hooks, disables dynamic tool search and the
native terminal scanner bootstrap, and exposes
only the exact tool names in an operator-prepared Chio gateway configuration.
The tested initial workflow is external file reading, writing, and editing.
Native shell, local file operations, native/custom network tools, browser,
MCP servers other than Chio, delegation, background jobs, and scheduled jobs
are unavailable in this mode. It does not accept arbitrary Hermes CLI flags.

The real resource lives behind the kernel in a separate resource service. The
Hermes process must receive no protected resource mount or Docker socket. The
launcher-owned HTTP gateway runs in a private parent child and owns the kernel
authentication credential, trusted signer pins, retained session and durable
operation journal. Each effect is sent
through kernel `tools/call`; the launcher never authorizes a local executor.
Gateway configuration and journals must be outside the protected resource's
write scope and outside all host-readable runtime, source and state roots.
The macOS candidate uses a default-deny Seatbelt profile: explicit runtime
libraries, pinned source, the query and isolated host state are readable; only
that host state and required device endpoints are writable. The host receives
ephemeral gateway/model tokens, never the prepared kernel credential or journal.
Hard links, shell
execution, Unix sockets, cross-host files and unrelated network endpoints are
unavailable. Required Python bootstrap descendants inherit the same restrictions;
Node runs only outside the agent sandbox. Only the launcher-owned HTTP gateway
and model-relay loopback ports are reachable, not the kernel port. The relay
accepts the selected supported model route and tool format; provider credentials
remain in the parent. Kernel-owned uncertainty fencing complements the private
gateway journal. Other operating systems and providers are refused pending
qualification. See the [action inventory](../ACTION_INVENTORY.md) and the [current local evidence](../evidence/2026-09-10/static-kernel-native/README.md) for the boundary and supporting source links.

## Installation and launch

This candidate has not yet passed public installation or release acceptance.
For a source installation, use the [README build steps](../README.md#build-from-source).
For an offline installation, use reviewed wheel and packed `@chio/bridge`
artifacts with their recorded checksums. The public CLI 0.1.0 installer does
not supply the required kernel surfaces. The current source qualification pins
Hermes `175054c14b54404663d8614a178280cffe6062eb` (v0.20.5, 2026.8.19), Python
3.11.3, and Chio gateway 0.3.0. The acceptance record identifies tested artifact
hashes and whether each run used source or a packed installation.

1. Install the pinned upstream Hermes revision into a dedicated installation
   and Python environment. Keep that installation's `.env` absent. Hermes
   loads and may rewrite `install/.env` despite an isolated `HERMES_HOME`.
   The launcher checks the inspected dispatch/configuration file hashes and
   refuses a different host contract. Machine-managed Hermes configuration
   requires separate qualification and is refused by this candidate. The public
   source fetch and locked core/MCP install were tested with uv 0.12.11; uv
   0.9.10 cannot parse that upstream lockfile. Upstream explicitly rejects wheel
   builds, so keep its supported editable source installation:

   ```bash
   git init /opt/hermes/pinned-source
   git -C /opt/hermes/pinned-source fetch --no-tags --depth=1 \
     https://github.com/NousResearch/hermes-agent.git \
     175054c14b54404663d8614a178280cffe6062eb
   git -C /opt/hermes/pinned-source checkout --detach FETCH_HEAD
   UV_PROJECT_ENVIRONMENT=/opt/hermes/venv uv sync \
     --project /opt/hermes/pinned-source --python 3.11.3 --locked --extra mcp --no-dev
   ```
2. Install the reviewed `chio_hermes-0.1.2` wheel in an isolated environment.
   Install its dependencies from the reviewed wheelhouse. Local qualification
   builds used `chio-sdk-python==0.1.0`, `chio-code-agent==0.1.0`, and
   `chio-adapter-base==0.2.0`; version strings alone do not identify those
   source-built artifacts. Their hashes are recorded in the evidence.
3. Install the compatible packed bridge and kernel artifacts. Run
   `chio-prepare-gateway` with a private operator request to establish a
   retained kernel session, signer/subject/capability binding, a unique
   session identity, a durable journal, and an exact resource tool allowlist.
   The current prepare request requires distinct bootstrap and administrative
   credentials plus `credentialTtlSeconds` (1 to 3600). It exchanges them for a
   kernel-scoped session credential and persists only that delegated bearer.
   The launcher refuses old bootstrap-token configurations, mismatched scope,
   or expired credential metadata. The kernel must independently enforce the
   token scope; metadata alone cannot prove authority. The protected-mode kernel
   endpoint must use an explicit `http://127.0.0.1:PORT` origin. Keep the administrative
   request and bootstrap credentials outside all host-readable paths. Never
   mount or include them among runtime read allowances.
4. Put the model provider credential in an explicitly named environment
   variable and the task in a query file. Invoke:

```bash
chio-hermes-restricted \
  --host-python /opt/hermes/venv/bin/python \
  --host-root /opt/hermes/pinned-source \
  --node /opt/node/bin/node \
  --gateway-script /opt/chio-bridge/dist/gateway-http.js \
  --gateway-config /private/operator/hermes-gateway.json \
  --state-dir /private/operator/runs/hermes-unique-run \
  --query-file /private/operator/task.txt \
  --model gpt-4.1-2025-04-14 \
  --model-base-url https://api.openai.com/v1 \
  --model-key-env OPENAI_API_KEY
```

A usable macOS `/usr/bin/sandbox-exec` is required. There is no unsandboxed
fallback. The paths above are explicit installation locations, not assumed private
sibling checkouts. The state directory must not already exist. The launcher
stores `launch.json` with configuration and gateway script hashes and exact
command arguments; it does not copy the gateway token or provider credential
into the profile. The supplied environment must contain the named model
credential in the operator launcher only. The host receives a per-run relay token
that cannot call another provider route. The gateway configuration is private (mode `0600`); the gateway
journal is private (mode `0700`).

## ChatGPT subscription model transport

The same restricted launcher also supports the pinned Hermes native
`codex_responses` transport through the parent relay. Select it explicitly:

```bash
chio-hermes-restricted \
  --host-python /opt/hermes/venv/bin/python \
  --host-root /opt/hermes/pinned-source \
  --node /opt/node/bin/node \
  --gateway-script /opt/chio-bridge/dist/gateway-http.js \
  --gateway-config /private/operator/hermes-gateway.json \
  --state-dir /private/operator/runs/hermes-unique-run \
  --query-file /private/operator/task.txt \
  --model gpt-5.5 \
  --model-auth codex-subscription \
  --codex-auth-file /private/operator/codex-profile/auth.json
```

The auth file must be an explicit private regular native Codex ChatGPT login
cache containing an access token and account identity. Keep it outside every
host-readable runtime, source and state directory. The parent reads it once;
it never copies it into the host profile or environment, sends it to the guest,
or refreshes it. Use native Codex login to renew expired authentication, then
start a fresh launcher while preserving any unresolved operation authority.
An authentication error does not authorize replay of a protected effect.

Only `https://chatgpt.com/backend-api/codex/responses` receives that credential,
with the native account header. Hermes uses the supported named custom provider
configuration with `api_mode: codex_responses` pointing at the private local
relay. This uses Hermes's native Responses conversion and stream handling.
The relay accepts complete inline text and the exact Chio function declarations;
it rejects remote item references, hosted tools, account storage, other routes,
and other model names. Opaque reasoning history, provider item IDs and cache
hints are removed; complete inline text and function history remain. Function output history reaches the same signed-result and
request-binding verifier before delivery acknowledgment. Gateway mediation and
the r11 parent-liveness supervisor are unchanged.

Available model names depend on the account. The qualification account accepted
`gpt-5.5`; its `gpt-5.4` request returned HTTP 400 before any protected dispatch.
The API key mode remains explicit and separate. A depleted API account does not
prove a subscription-mode blocker. The subscription route has a per-run request
budget; its upstream output token controls differ from Chat Completions.

Pinned upstream contracts: [provider resolution](https://github.com/NousResearch/hermes-agent/blob/175054c14b54404663d8614a178280cffe6062eb/hermes_cli/runtime_provider.py),
[native Responses transport](https://github.com/NousResearch/hermes-agent/blob/175054c14b54404663d8614a178280cffe6062eb/agent/transports/codex.py),
and [native authentication](https://github.com/NousResearch/hermes-agent/blob/175054c14b54404663d8614a178280cffe6062eb/hermes_cli/auth.py).
These source files are included in launcher compatibility checks.

## Recovery, upgrade, and removal

The launcher gives its trusted host supervisor a private liveness pipe. The
native agent and descendants do not inherit that pipe. Launcher death closes
it, causing termination of the isolated host group and forced cleanup after a
five-second grace period. Operator SIGINT/SIGTERM follows the same path. A
SIGKILL cannot produce a launcher terminal report; retain the journal and treat
any unacknowledged effect as unresolved. Never infer success from process exit.

A normal completed operation has a verified outcome in the gateway journal.
An error after dispatch can mean an unknown external outcome. Stop the session
and preserve the gateway journal, resource observations, host logs, and kernel
receipt data. Do not silently retry, delete a stale gateway lock, replace its
journal, or give an uncertain operation a new identity. Use resource-side
reconciliation before the trusted operator restores admission. A missing or
malformed gateway configuration leaves protected tools unavailable.

This candidate is one-shot. Automatic resume, restart continuation, interactive
slash commands, and background sessions are not exposed by the launcher.
Their availability must not be inferred from the one-shot lifecycle tests. Each host invocation needs a new state directory. It can reuse the same
still-valid prepared kernel authority after prior outcomes are reconciled.
Do not create replacement authority to retry an unknown previous outcome.

For upgrades, retain the prior artifacts and evidence, install the new version
into a separate environment, and rerun the host gates. A new host contract
requires new source inspection and qualification. Do not widen toolsets to fix
an installation error. For removal, stop the host and gateway, revoke/expire
the kernel session authority, retain required audit records, then uninstall
the isolated plugin/bridge installations. No normal Hermes profile is modified
by this launcher.


## Read the terminal outcome

After a host invocation returns, `terminal.json` records the host exit code,
protected outcome, delivery count and any operator interrupt. The protected
outcome takes precedence over the native process exit:

| Outcome | Launcher exit |
| --- | --- |
| Completed with no unresolved, pending or unsuccessful recorded work | `0` |
| Unresolved operation or unconfirmed result delivery | `2` |
| Denied, not dispatched or tool-error result | `3` |
| Awaiting approval | `4` |
| Cancellation without a higher-priority protected outcome | `128 + signal` |
| Other native host failure | Native host exit code |

Launch refusal also exits `2` and may occur before `terminal.json` exists.
SIGKILL can leave no terminal report. Retain `host-delivery.json`,
`model-relay.json` and the private journal alongside the host output. These
records distinguish host termination from tool completion; they do not replace
independent resource observation.

## Reconcile a retained outcome

The gateway records a fence before dispatch. A verified completed owner result
can support explicit delivery acknowledgment; an unknown external result cannot.
Use the matching bridge's [operator commands](https://github.com/backbay-labs/chio-bridge/blob/main/ACCEPTANCE.md#recovery-upgrade-and-removal)
to inspect status, recover a dead owner's lock, and export or import a verified
result. The local final lifecycle record used a separately identified recovery
operator archive. Do not assume an older host-bundled bridge exposes every
current operator command.

The [resource-owner runbook](https://github.com/backbay-labs/chio/blob/70071260afe514b06cac1c319487bd48e465d39e/integrations/required-agents/README.md)
describes independent observation, retained kernel authority and supported
owner restart. Restarting a process never establishes the outcome of an
unacknowledged call.

## Compatibility hook

The legacy plugin entrypoint is retained for compatibility and diagnosis. Its
id-only SDK calls cannot authorize execution. The hook rejects tools outside
the twelve registered Chio names, forged `chio_*` names and missing
configuration. Host callback exceptions or plugin load failure can leave native
tools executable, so this entrypoint does not establish the restricted boundary.
See the [action inventory](../ACTION_INVENTORY.md) for the inspected host paths.
