---
phase: 308
plan: 02
created: 2026-04-13
status: complete
---

# Summary 308-02

Both SDK README files now read like stable package entry points instead of
internal beta notes. Each one documents installation, a quickstart snippet,
the public API surface, and the official governed example path.

The package-local examples now exercise the real ARC hosted-edge topology
instead of ad hoc client code. The TypeScript and Python scripts both
initialize an authenticated session, read the capability issued for that
session from `/admin/sessions/{session_id}/trust`, invoke `echo_text`, and then
read the resulting receipt back through the receipt-query API.
