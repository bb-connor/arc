// ARC CLI -- command-line interface for the ARC runtime kernel.
//
// Provides commands for:
//
// - `arc run --policy <path> -- <command> [args...]`
//   Spawn an agent subprocess, set up the length-prefixed transport over
//   stdin/stdout pipes, and run the kernel message loop.
//
// - `arc check --policy <path> --tool <name> --params <json>`
//   Load a policy, create a kernel, and evaluate a single tool call.
//
// - `arc mcp serve --policy <path> --server-id <id> -- <command> [args...]`
//   Wrap an MCP server subprocess with the ARC kernel and expose an
//   MCP-compatible edge over stdio for stock MCP clients.

mod admin;
mod did;
mod passport;

include!("cli/types.rs");
include!("cli/dispatch.rs");
include!("cli/runtime.rs");
include!("cli/trust_commands.rs");
include!("cli/session.rs");
