---
phase: 307-identity-resolution-and-scaffolding
milestone: v2.81
created: 2026-04-13
status: complete
---

# Phase 307 Context

## Goal

Finish the ARC rename at the user-facing boundary and add an `arc init`
scaffold that gives a new developer a runnable governed hello-world project
without depending on unpublished ARC crates.

## Current Reality

- `README.md` and the review-remediation docs still exposed the old `CHIO`
  name, which meant the roadmap's literal rename gate still failed.
- The CLI had no `arc init` command and no built-in templates for a first
  project.
- Existing examples already proved the minimal governance path: a tiny MCP tool
  server behind `arc mcp serve`, a simple MCP client flow, and a local receipt
  store.

## Boundaries

- Preserve the user's existing in-flight edits in `README.md` and avoid
  touching unrelated dirty files like `crates/arc-cli/src/admin.rs`.
- Keep the scaffold self-contained so it can compile as a normal standalone
  Cargo project.
- Reuse the established MCP stdio path instead of inventing a new onboarding
  runtime lane.

## Key Risks

- A repo-wide rename could easily trample unrelated dirty docs if it were not
  scoped to the exact files covered by the success criterion.
- A scaffold that depended on unpublished ARC crates would satisfy the command
  surface but still fail the onboarding goal.
- The generated demo needed to prove governance, not just print a local hello
  string, so it had to run through `arc mcp serve` and show receipt output.

## Decision

Implement `arc init` as a template writer that creates a tiny standalone Rust
MCP server, a smoke-runner binary that launches `arc mcp serve`, performs one
governed tool call, and then prints the newest local receipt line.
