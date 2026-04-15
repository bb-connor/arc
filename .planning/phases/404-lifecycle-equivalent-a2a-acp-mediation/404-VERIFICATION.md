# Phase 404 Verification

## Commands

- `cargo test -p arc-a2a-edge -p arc-acp-edge`

## Result

Passed locally on 2026-04-14 after adding deferred-task lifecycle regressions
for:

- A2A `message/stream` -> `task/get`
- A2A `message/stream` -> `task/cancel`
- ACP `tool/stream` -> `tool/resume`
- ACP `tool/stream` -> `tool/cancel`
