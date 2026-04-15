# Phase 408 Context

## Goal

Qualify real multi-hop authoritative protocol routes with continuous ARC
receipt lineage.

## Why This Exists

The current orchestrator is real, but the strongest claim still fails because
the fabric is bounded rather than broadly multi-hop. The next proof step is
real route execution across more than one protocol boundary without bespoke
edge-local glue.

## Must Become True

- at least two qualified authoritative flows traverse more than one protocol
  boundary
- route-selection evidence and receipt lineage survive the full path
- the implementation uses the shared fabric rather than a special-case helper
