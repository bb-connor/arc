# chio-cli

`chio-cli` builds the `chio` operator binary. It connects command-line input
and output to Chio's kernel, control plane, protocol edges, artifact verifiers,
and local stores. The package declares a public entrypoint and `publish = false`;
it exposes commands rather than a supported Rust library API.

## Usage

From the workspace root, evaluate one call offline with the checked-in MCP
conformance policy:

```sh
chio_cli_sample_dir=$(mktemp -d /tmp/chio-cli-readme.XXXXXX)
trap 'rm -rf -- "$chio_cli_sample_dir"' EXIT
cargo run --locked -p chio-cli -- --json \
  --session-db "$chio_cli_sample_dir/admission.sqlite3" check \
  --policy tests/conformance/fixtures/mcp_core/policy.yaml \
  --server fs --tool read_file \
  --params '{"path":"/tmp/chio-cli-readme-probe"}'
```

This test policy grants wildcard tool invocation and explicitly allows
in-memory receipts and revocations. `CheckToolServer` returns a synthetic
probe; the command does not read the supplied path or launch a tool server.
The JSON result reports `ALLOW`, `check_mode: "preflight"`, a receipt ID,
and the effective and source policy hashes. No service or optional feature is
needed. `mktemp` creates the required private (0700) custody directory under
`/tmp`; admission state is removed on exit and receipts remain ephemeral.
Durable operator stores require private directories and trusted ancestors.

`check` defaults to preflight. A policy with post-output guards requires
`--mode full --output-fixture <JSON-file>`, which supplies the simulated tool
result. Exit codes are 0 for allow, 2 for deny, and 3 for pending approval;
input or setup errors reach the dispatcher and exit 1.

## Commands

Use `chio <command> [<subcommand>...] --help` for the flag reference.

| Command | Responsibility |
|---|---|
| `run`, `check` | Mediate an agent subprocess over framed stdio, or evaluate one fixture-backed call. |
| `mcp` | Manifest-gated `wrap`, governed stdio `serve`, and HTTP `serve-http` edges. |
| `api protect`, `start` | Configure and launch the HTTP API protection sidecar. |
| `process` | Provision, serve, inspect, and run persistent local worker applications. |
| `trust` | Serve and administer authority, revocation, federation, credit, liability, and underwriting state. |
| `receipt`, `evidence` | Verify receipt exports; query and maintain stores; export, verify, and import evidence packages. |
| `did`, `passport` | Resolve identifiers and create, verify, evaluate, or present Agent Passports. |
| `proof`, `commerce`, `workflow` | Verify Transaction Passport and commerce evidence; preflight workflow plans. |
| `cert`, `certify` | Generate session compliance certificates or evaluate conformance certification artifacts. |
| `finding` | Publish, search, verify, buy, challenge, inspect status, and operate finding packages. |
| `federation`, `runtime`, `pheromone` | Operate federation artifacts, runtime admission/orchestration, and pheromone relays. |
| `security` | Provision native runtime inputs, validate authority artifacts, preflight, and supervise services. |
| `policy analyze` | Analyze HushSpec rules and compare admission refinement against another policy. |
| `guard`, `bind` | Author, inspect, test, package, sign, and distribute guards; bind model-card weights. |
| `replay`, `arena`, `conformance` | Re-evaluate recorded evidence and drive scenario or peer-adapter harnesses. |
| `reputation`, `lineage`, `settle` | Inspect scorecards, lineage graphs, and settlement state. |
| `doctor`, `init` | Diagnose the environment or scaffold a governed example project. |

## Features

There is no `default` feature set. All three declared features are opt-in.

| Feature | Default | Effect |
|---|---|---|
| `real-linux-enforcement` | Off | Enables `chio-cage/real-linux-enforcement` and the feature-required native discovery/process tests. |
| `tee-quotes` | Off | Enables `chio-attest-verify/tee-quotes` for runtime-quote TEE backend verification. |
| `iroh` | Off | Links the optional federation transport and iroh dependency for the pheromone relay's P2P lane. |

Dependency features enable Wasmtime guards, marketplace, worker-server/mailboxes,
BBS disclosure, and native MCP secret-broker support independently of CLI features.

## Guarantees

- `validate_check_mode` rejects output-sensitive preflight policies and full
  checks without an explicit output fixture before runtime construction.
- `cmd_receipt_verify` bounds NDJSON input and `verify_original_receipt`
  checks the supported signed shape, signature, caller-supplied signer pin,
  and action parameter hash. Policy evaluation requires a separate operation.
- `local_receipt_read_context` requires exactly one of `--tenant <id>` or
  `--admin-all` for local receipt list/explain reads.
- `init_redacted_tracing` installs redaction before command execution;
  `format_redacted_event_line` escapes controls in log field names and values.
- `require_durable_or_ephemeral_optin` requires a filesystem receipt store
  and existing signing custody for durable `start`/`api protect` operation,
  or explicit `--allow-ephemeral-receipts` for in-memory operation.

## Global flags

Global store flags select receipt, revocation, authority, budget, and session
paths for commands that consume them. `--control-url` selects a remote backend
where supported; `CHIO_CONTROL_TOKEN` supplies its bearer. Pin remote authority
identity with `--control-authority-public-key` where the edge requires it.
`--json` is global; place the top-level `--format human|json` before the command.

`mcp wrap` rejects `--receipt-db`, including in strict nonce mode. Its ordinary
path gates tool names using `ManifestVerdictGate`; `--strict-execution-nonce`
uses `KernelMediatedMcpTransport` and the default runtime guard profile. Its
velocity thresholds are unlimited and its advisory detector roster is empty.
Successful wrap results carry no receipt-bound verification marker, and
`--self-test-attestation` returns an unsupported error.

## Status

Command dispatch, offline checks, artifact verification, and local/remote store
operations are implemented. The [process host](PROCESS_HOST.md) is an
experimental local host profile: its host operations require Unix, and worker
supervision requires Linux. Its stores belong to `--state`; global store and
control URL overrides are rejected. Native enforcement additionally depends
on the selected feature, platform, and signed launch policy.

Runtime-quote backend verification requires `tee-quotes`; requesting the
relay's iroh lane requires `iroh`. Guard publishing, hosted edges, and remote
administration need their respective credentials, services, and operator
configuration. CLI tests exercise parsing, rejection paths, fixtures, and
selected real process/HTTP round trips; they do not certify a deployment.

Verified-fix seller tests require a self-contained npm installation when npm
and Node.js are on `PATH`. The installed npm package must contain its declared
bundled dependencies and the `npm` and `npx` entrypoints. An official npm
package installed in an operator-owned prefix satisfies this layout; split
distribution packages with dependencies elsewhere are unsupported. Runtime
discovery follows the npm executable independently of the configured global
installation prefix. Only the selected package tree enters the sandbox.

## Related

- [Architecture](ARCHITECTURE.md)
- [Local CLI and kernel contract](../../../spec/PROTOCOL.md#81-local-cli-and-kernel)
- [Control plane](../../platform/chio-control-plane/README.md)
- [Kernel](../../kernel/chio-kernel/README.md)
- [License](../../../LICENSE)
