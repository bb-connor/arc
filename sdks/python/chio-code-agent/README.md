# chio-code-agent

Chio-governed tool wrappers for coding agents. One package install,
zero-config default policy, works with Claude Code, Cursor, or any
MCP-based coding agent.

## Install

```bash
pip install chio-code-agent
```

## 10-line quickstart

```python
import asyncio
from chio_code_agent import CodeAgent
from chio_sdk import ChioClient  # or `chio_sdk.testing.MockChioClient` in tests

async def main() -> None:
    async with ChioClient("http://127.0.0.1:9090") as client:
        agent = CodeAgent(chio_client=client, capability_id="cap-123")
        result = await agent.files.read_file("README.md")      # allowed
        print(result.result)
        await agent.files.write_file(".env", "BAD=value")      # denied by policy

asyncio.run(main())
```

`.env` writes, `.git/**` reads, `rm -rf /`, and `git push --force` are
all denied by the bundled default policy before the call reaches the
sidecar.

## What the default policy does

- **Allows:** reading files under the cwd, writing files under
  `src/`, `tests/`, `docs/`, safe shell commands, read-only `git`
  subcommands (`status`, `diff`, `log`), plus `git add` / `git
  commit`.
- **Denies:** `.env` / `.env.*`, `.git/**`, `.ssh/**`, `.aws/credentials`,
  `*.pem`, `*.key`, `id_rsa`, `id_ed25519`.
- **Denies outright:** `rm -rf /`, `chmod 777`, `curl | sh`,
  `sudo ...`, `git push --force`, `git reset --hard origin`, `mkfs.*`,
  `dd if=... of=/dev/...`.
- **Requires approval:** `rm -rf <subdir>`, `mv`, `cp -r`,
  `git reset --hard`, `git clean -fd`. Pass `approved=True` to
  `shell.run_command(...)` once the user has confirmed.

## Custom policies

The bundled policy is YAML-driven and identical to the one embedded by
the Rust `chio mcp serve --preset code-agent` flag. To customize,
compile your own policy and pass it in:

```python
from chio_code_agent import CodeAgent, compile_policy

policy = compile_policy(open("my-policy.yaml").read())
agent = CodeAgent(chio_client=client, capability_id="cap-1", policy=policy)
```

See the bundled `default_policy.yaml` for the schema.

## Relation to `chio mcp serve --preset code-agent`

`chio-code-agent` is the Python-embedded flavour; `chio mcp serve
--preset code-agent` is the same policy wrapping an MCP server over
stdio. Pick whichever fits your integration surface -- they deny the
same set of operations.
