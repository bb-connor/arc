---
phase: 307
plan: 02
created: 2026-04-13
status: complete
---

# Summary 307-02

`arc init` now scaffolds a runnable starter project. The CLI writes embedded
templates for a standalone Cargo manifest, a minimal MCP hello-world server, a
governed demo runner, a starter policy, and a README with build/run steps.

The scaffolded demo deliberately uses the real governance path instead of a
mock: it launches `arc mcp serve`, wraps the generated `hello_server` binary,
executes one MCP tool call, and then reads back the newest receipt from the
local SQLite store. The new `crates/arc-cli/tests/init.rs` integration test
proves that flow end to end.
