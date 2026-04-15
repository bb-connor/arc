---
phase: 394-http-authority-and-evidence-convergence
milestone: v3.13
created: 2026-04-14
status: in_progress
requirements: [HTTP-01, HTTP-02, HTTP-03, HTTP-04]
---

# Phase 394 Context

## Why This Phase Exists

The cross-protocol substrate is now real, but the HTTP lane still weakens the
strongest production-ready ARC claim in four concrete ways:

1. `HttpReceipt.response_status` reads like downstream response evidence even
   though allow-path evaluators can sign `200` before the real upstream or
   inner response exists.
2. `arc-api-protect` still defaults to method-based policy when explicit
   OpenAPI override metadata exists.
3. The reverse proxy forwards only a narrow demo-grade header subset instead
   of a truthful operator-grade protected proxy surface.
4. `arc-tower` still tells a similar story to the sidecar while using a
   separate embedded evaluator path.

## Phase Boundary

This phase must close the HTTP authority/evidence gap without broadening back
into protocol-lifecycle or claim-upgrade work.

It must:

- make receipt status semantics truthful and operator-legible
- honor explicit OpenAPI policy overrides in the live sidecar path
- make header forwarding fit real reverse-proxy usage, with exclusions made
  deliberate and documented
- converge `arc-tower` onto the shared authority/evidence model or narrow its
  story explicitly

It must not:

- absorb A2A/ACP lifecycle truth work from phase `395`
- absorb claim-upgrade qualification or end-to-end marketing gates from
  phase `396`
