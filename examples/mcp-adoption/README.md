# Adopt an existing MCP server

Run the config importer against an ordinary Python MCP server, then execute the
generated configuration through the actual Chio kernel. The server gets its journal
path and label from environment variables in the original configuration.

From the repository root:

```bash
cargo build -p chio-cli --bin chio
uv run --locked --project sdks/python/chio-py --extra mcp \
  python examples/mcp-adoption/check.py --chio "$PWD/target/debug/chio"
```

The check runs two sessions with a two-invocation grant in each. It verifies four
actual journal writes, two signed denials, six persisted receipts, a stable kernel
signer across process restart, activation into the client configuration, and
restoration of the original server entry while preserving a later client setting.
The exact original backup remains unchanged.
A new session receives a fresh grant; this is not an aggregate lifetime quota.

Use `--state-dir /tmp/chio-adoption-evidence` to keep the original and generated
configs, private kernel state, journal, and verified receipts in a new directory.
The example prescribes tool requests and needs no language model credentials.

## Strict TypeScript client

Keep a run with `--state-dir /tmp/chio-adoption-evidence`, then exercise the same
configuration using the published TypeScript MCP SDK:

```bash
npm ci --ignore-scripts --prefix examples/mcp-adoption/typescript
npm --prefix examples/mcp-adoption/typescript run check -- \
  /tmp/chio-adoption-evidence/adopted/mcp.json
```

This validates all five paginated listing responses over real stdio. In
particular, exhausted pages must omit `nextCursor`; emitting JSON `null` is
rejected by this client. The check makes no tool invocations.

## Actual Claude Code client

With Claude Code already authenticated, run this opt-in check:

```bash
uv run --locked --project sdks/python/chio-py --extra mcp \
  python examples/mcp-adoption/claude_check.py \
  --chio "$PWD/target/debug/chio" --state-dir /tmp/chio-claude-acceptance
```

It uses a fresh private fixture, the ordinary deferred MCP tool-discovery path,
and a two-invocation kernel grant. Only tool search and the journal tool are
available. It succeeds only when the transcript contains the three requested
calls, the journal contains exactly two writes, and Chio verifies two allow
receipts plus a denial. The client's final answer does not determine success.

The model budget defaults to $0.50 (`--max-budget-usd` changes it). The client is
terminated after 180 seconds. Existing client configuration is not edited.
`acceptance.json` records the CLI version, binary hash, receipt IDs, and reported
model cost. The state directory also contains private signing material.

The profile was exercised with Claude Code 2.1.261 on Linux. It uses
[`--restricted`, `--strict-mcp-config`, and `--tools`](https://code.claude.com/docs/en/cli-reference)
to keep the fixture independent of user/project customizations. It requires a
version supporting these flags and existing Claude authentication, so normal CI
uses the credential-free Python and TypeScript checks above.

See [the adoption guide](../../docs/guides/ADOPT-EXISTING-MCP.md) for installing the
generated configuration in an existing client and inspecting denied calls.
