---
phase: 308
plan: 03
created: 2026-04-13
status: complete
---

# Summary 308-03

Publication verification is now stronger on both package lanes. The npm release
check now proves that the packed artifact exports both `ArcClient` and
`ReceiptQueryClient`, while the PyPI release check proves the wheel and sdist
install cleanly as `arc-sdk` and expose the same stable client surface.

Phase 308 also added one cross-language example harness:
`scripts/check-sdk-publication-examples.sh`. It boots a local `arc trust serve`
plus `arc mcp serve-http --control-url ...` stack, runs the official
TypeScript and Python examples against it, and asserts that both produce a
capability id, an echoed governed tool result, and a receipt id.
