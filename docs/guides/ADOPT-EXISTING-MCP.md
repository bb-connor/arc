# Put Chio behind an existing MCP configuration

`chio mcp adopt` prepares an existing local MCP setup to run through the Rust
kernel. It keeps your tool server commands, arguments, environment configuration,
and client settings, and replaces each selected launch command with
`chio mcp serve`. Each server receives its own persistent kernel identity,
admission state, and receipt database.

The importer currently requires Linux or macOS for owner-only configuration files.

The input uses an `mcpServers` JSON object, as documented by
[Cursor's MCP configuration reference](https://cursor.com/docs/mcp). This command
generates configuration; it does not install it into an editor or start any tools.
The acceptance checks below verify the generated command using the official
Python and TypeScript MCP clients. An opt-in Claude Code check exercises its
non-interactive client with a real model. Editor UI behavior is not covered.

## Prepare your configuration

[Install the CLI from this checkout](INSTALL.md), then start with an existing
local MCP configuration and a Chio or HushSpec policy:

```bash
chio mcp adopt \
  --config .cursor/mcp.json \
  --policy /absolute/path/to/policy.yaml \
  --output /absolute/path/to/chio-state
```

The output directory must be new or empty. The command validates the configuration
and policy before writing files. It prints a report containing the generated
`mcp.json` location, policy hashes, and each server's state and receipt paths.
Credential values are retained in the private configuration file, not printed in
the report. The original client configuration is never overwritten, and an exact
private backup is saved as `original.json` for rollback after activation.

All servers are selected by default. To import specific local servers from a
configuration that also contains remote URLs, name the selected servers:

```bash
chio mcp adopt \
  --config .cursor/mcp.json \
  --policy /absolute/path/to/policy.yaml \
  --output /absolute/path/to/chio-state \
  --server filesystem --server github
```

The report lists unselected servers under `unchanged_servers`; those connections
remain outside this Chio setup. Selected entries must be local stdio servers.
Remote HTTP/SSE connections, invalid arguments, duplicate JSON members, wildcard
server names, and already wrapped Chio commands are rejected. JSON comments and
trailing commas must be removed before importing.

## Review and activate

Review the generated `mcp.json`, then use its contents in the original client
configuration location and restart the client. Keeping the original location
preserves the client's relative paths, environment-file paths, and workspace
interpolation behavior. The generated Chio binary, policy, and state paths are
absolute. Keep those paths available; rebuilding or moving the Chio binary requires
updating its `command` path.

The referenced policy is loaded when each server starts. The hashes in
`adoption.json` describe the policy at import time; the report is not an
authorization token or a signed receipt. Edit the policy to control tool access,
guards, expiry, and invocation limits. Existing server names remain the identifiers
used in policy grants and receipts. Importing does not infer or widen permissions.
A policy that grants no matching access will deny tool invocations.

On first launch, each server creates its own `session.sqlite.kernel.pub` public
key and private signing seed inside its state directory. Keep the directory
private and do not commit it: configuration and receipts can contain credentials,
tool arguments, and output. Default admission covers side-effecting operations;
a Chio YAML policy can select `kernel.durable_admission_mode: all` for every
invocation. Policies that disable durable admission are rejected by the importer.

## Check configuration and recent activity

Compare your client configuration with the adopted launch entries:

```bash
chio mcp status \
  --adoption /absolute/path/to/chio-state \
  --config .cursor/mcp.json \
  --admin-all
```

This reads the files and existing receipt databases without launching tools or
editing configuration, policy, or receipt rows. Missing, disabled, or changed
client entries, unavailable kernel executables, invalid policies, and failed
receipt verification produce a nonzero exit code. Other client servers are
listed as outside this adoption. Environment values and tool arguments are not
printed. Use `--format json` before `mcp` for a structured report.

`--admin-all` explicitly permits reading receipts from these local databases,
matching the operator boundary of `receipt list`. Without it, the command checks
configuration and policy and reports receipts as `not_inspected`.

The default sample contains the ten most recent receipts per server. Use
`--limit 1` through `--limit 100` to change it. Each sampled receipt must have a
valid content-derived ID, signature, argument hash, matching server identity,
and preventive kernel decision. Its signing key must match the operator-owned
`session.sqlite.kernel.pub` file. The summary shows allow, deny, cancelled, and
incomplete decisions and whether each receipt used the current policy hash.
A valid policy update is reported as a change since adoption; older receipts
retain their original policy identity.

`matches_adoption` means the selected configuration entries match the generated
ones. `verified_sample` means the sampled signed decisions passed verification.
These observations do not establish that an editor is connected now, that a tool
succeeded after admission, or that the whole receipt log is complete. A store
without recorded receipts reports `no_recorded_activity`. For complete store
health and checkpoint inspection, use the existing `receipt health` and
`receipt checkpoint status` commands.

## Inspect a denied call

Use the `receipt_db` path from the report:

```bash
chio --receipt-db /absolute/path/from/report/receipts.sqlite \
  receipt list --admin-all --outcome deny

chio --receipt-db /absolute/path/from/report/receipts.sqlite \
  receipt explain RECEIPT_ID --admin-all
```

A reconnect creates new session capabilities under the current policy. The signer
and receipt history persist. Invocation ceilings apply to each issued grant, so a
new session can receive a fresh allowance. This command does not introduce an
aggregate lifetime budget or automatically retry an interrupted effect. Chio
mediates the configured MCP connection; OS isolation and tools available through
other agent connections remain separate concerns.

To return to the previous connection, restore the `original.json` backup to your
client configuration location and restart the client. The report identifies it as
`backup_config_path`. Keep the Chio state directory if you need its audit history.

## Verify the complete path from source

```bash
cargo build -p chio-cli --bin chio
uv run --locked --project sdks/python/chio-py --extra mcp \
  python examples/mcp-adoption/check.py --chio "$PWD/target/debug/chio"
```

The check imports a real MCP server, executes two authorized writes, verifies a
third-call denial, restarts the generated process, and verifies that its signing
key and all six receipts survive. It independently checks the journal and confirms
that environment values reach the server. No model API key or editor installation
is required. Add `--state-dir /tmp/chio-adoption-evidence` to keep the evidence in a
new private directory.
