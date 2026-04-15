# Phase 407 Context

## Goal

Remove implicit authoritative `Native` fallback and make claim-eligible target
resolution explicit or registry-derived through one shared executor registry.

## Why This Exists

`v3.15` proved ARC's bounded protocol-aware fabric, but the full
control-plane thesis is still blocked because unannotated bindings can still
default to `Native` and the executor seam is not yet universalized.

## Must Become True

- claim-eligible authoritative bindings never silently fall back to `Native`
- shared registry logic resolves target executors instead of edge-local branch
  tables
- at least one additional target family beyond the current `Native` / `Mcp`
  assumptions is plumbed through the shared registry contract
