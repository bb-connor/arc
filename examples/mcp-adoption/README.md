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
signer across process restart, and preservation of the original configuration.
A new session receives a fresh grant; this is not an aggregate lifetime quota.

Use `--state-dir /tmp/chio-adoption-evidence` to keep the original and generated
configs, private kernel state, journal, and verified receipts in a new directory.
The example prescribes tool requests and needs no language model credentials.

See [the adoption guide](../../docs/guides/ADOPT-EXISTING-MCP.md) for installing the
generated configuration in an existing client and inspecting denied calls.
