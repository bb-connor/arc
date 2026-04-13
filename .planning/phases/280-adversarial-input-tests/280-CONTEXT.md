# Phase 280 Context

## Goal

Prove the real ARC transport and message parser do not crash on malformed,
truncated, or wrong-type input.

## Existing Coverage

`crates/arc-kernel/src/transport.rs` already tests:

- empty-read connection closure
- oversized frame rejection
- frame sequencing

But the milestone still lacks dedicated adversarial cases for:

- malformed canonical JSON bodies
- zero-length or half-sent frame bodies
- schema errors such as missing required fields or wrong field types on
  `AgentMessage::ToolCallRequest`

## Code Surface

- `crates/arc-kernel/src/transport.rs` for framing behavior
- `crates/arc-kernel/tests/` for black-box adversarial transport tests that do
  not add more panic assertions to kernel source
- `crates/arc-core/src/message.rs` as the serialized `AgentMessage` schema

## Execution Direction

- add a dedicated integration test file for adversarial transport inputs
- prove malformed and schema-invalid frames return typed errors without panic
- prove truncated body reads fail with `TransportError::ConnectionClosed`
- keep the tests at the real boundary: bytes on the wire into `ArcTransport`
