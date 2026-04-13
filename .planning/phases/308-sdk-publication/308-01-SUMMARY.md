---
phase: 308
plan: 01
created: 2026-04-13
status: complete
---

# Summary 308-01

The Python SDK is now published locally as stable `arc-sdk` `1.0.0` while
keeping the import package name `arc`. The package metadata, version module,
release notes, and both release-check scripts all now agree on that public
identity.

Phase 308 also closed the biggest functional parity gap on the Python side:
`ReceiptQueryClient` is now part of the root package surface, backed by typed
query parameters, pagination helpers, and explicit `ArcQueryError` /
`ArcTransportError` behavior. The new `test_receipt_query.py` coverage verifies
query construction, auth headers, paging, and failure handling.
