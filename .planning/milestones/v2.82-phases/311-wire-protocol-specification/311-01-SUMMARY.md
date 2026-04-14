---
phase: 311
plan: 01
created: 2026-04-13
status: complete
---

# Summary 311-01

Phase `311` now has a focused normative wire specification in
[spec/WIRE_PROTOCOL.md](/Users/connor/Medica/backbay/standalone/arc/spec/WIRE_PROTOCOL.md).
That document defines the shipped surface split explicitly instead of folding
hosted initialization and trust-control lifecycle behavior into the much
smaller native framed transport.

The new spec names the exact native framing contract from the implementation:
4-byte big-endian length prefix, canonical JSON payload bytes, `16 MiB`
maximum frame size, and terminal recovery behavior for truncated, oversized,
and invalid frames. It also documents every `AgentMessage`, `KernelMessage`,
`ToolCallResult`, and `ToolCallError` variant with the required fields and
discriminators an independent implementer needs to interoperate with the
current Rust surface.
