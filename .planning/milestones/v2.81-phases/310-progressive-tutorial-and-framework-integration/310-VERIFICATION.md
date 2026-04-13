---
phase: 310-progressive-tutorial-and-framework-integration
created: 2026-04-13
status: complete
---

# Phase 310 Verification

## Commands

- `./scripts/check-framework-integration-examples.sh`
- `cargo check -p arc-cli`
- `git diff --check -- .gitignore docs/PROGRESSIVE_TUTORIAL.md examples/anthropic-sdk examples/langchain examples/openai-compatible scripts/check-framework-integration-examples.sh .planning/phases/310-progressive-tutorial-and-framework-integration`

## Evidence

- The verification script booted a local `arc trust serve` plus
  `arc mcp serve-http` stack, then ran:
  - `node examples/anthropic-sdk/run.mjs --dry-run`
  - `python examples/langchain/run.py`
  - `node examples/openai-compatible/run.mjs --dry-run`
- All three examples reported non-empty `capabilityId`, `receiptId`, and
  echoed governed output.
- The tutorial document contains the required walkthrough sections:
  `ARC Concepts`, `Write A Policy`, `Wrap A Tool`, `Execute A Governed Call`,
  `Read A Receipt`, and `Delegate A Capability`.
- `cargo check -p arc-cli` passed against the phase write set.
