# Phase 218 Context

After removing ARC-side product packaging, ARC generic receipt-query and
trust-control surfaces still named Mercury-specific filters directly. This
phase cleans those generic interfaces so product-specific retrieval concerns do
not leak into ARC kernel or generic CLI contracts.

Non-goals:
- do not remove generic receipt filtering or pagination behavior
- do not add a new replacement product-specific query layer inside ARC
- do not mutate Mercury app-owned query semantics in this phase
