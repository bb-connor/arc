---
phase: 313
plan: 01
created: 2026-04-13
status: complete
---

# Summary 313-01

Phase `313` now has a standalone security specification instead of relying on
scattered remediation memos.

- `spec/SECURITY.md` defines the ARC agent-kernel-tool trust boundary,
  protected assets, and the minimum threat set required by the roadmap.
- The document now enumerates the six mandatory threats directly:
  capability token theft, kernel impersonation, tool server escape,
  native-channel replay, resource-exhaustion denial of service, and
  delegation-chain abuse.
- Each threat entry records the currently shipped controls, the additional
  mitigations operators or later phases should rely on, and an explicit
  residual-risk statement where ARC is not yet a complete end-state defense.

The result is intentionally honest about ARC's current posture. The doc does
not claim universal sender constraint or fully recursive delegated-authority
validation where the shipped runtime does not yet enforce those properties in
every path.
