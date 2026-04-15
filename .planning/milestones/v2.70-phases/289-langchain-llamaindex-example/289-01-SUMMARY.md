# Summary 289-01

Phase `289` added a local LangChain tool-wrapping example at
[examples/langchain](/Users/connor/Medica/backbay/standalone/arc/examples/langchain/README.md).

## Delivered

- [pyproject.toml](/Users/connor/Medica/backbay/standalone/arc/examples/langchain/pyproject.toml)
  provides a minimal Python package definition.
- [run.py](/Users/connor/Medica/backbay/standalone/arc/examples/langchain/run.py)
  starts `arc mcp serve`, initializes the ARC MCP edge over stdio, wraps the
  governed `echo_text` tool as a LangChain `StructuredTool`, and invokes it
  locally.
- [README.md](/Users/connor/Medica/backbay/standalone/arc/examples/langchain/README.md)
  documents environment setup and execution.

## Verification

- `python3 -m venv /tmp/arc-langchain-venv`
- `. /tmp/arc-langchain-venv/bin/activate`
- `pip install -e examples/langchain`
- `python examples/langchain/run.py`

The example printed the upstream ARC tool inventory and returned a governed
LangChain tool result for `hello from LangChain`.
