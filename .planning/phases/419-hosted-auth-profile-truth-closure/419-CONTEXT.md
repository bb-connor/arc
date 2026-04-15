# Phase 419 Context: Hosted/Auth Profile Truth Closure

## Why This Phase Exists

ARC's hosted/auth surfaces are real and useful, but the current docs can still
read as if sender-constrained identity continuity and shared-host isolation are
stronger or more universal than the runtime actually guarantees today.

Phase `419` defines one recommended bounded hosted/auth profile and demotes the
compatibility-only paths accordingly.

## Required Outcomes

1. Publish one recommended bounded hosted/auth security profile for ship.
2. Mark `shared_hosted_owner`, non-DPoP flows, and privilege-shrink-sensitive
   reuse behavior explicitly as compatibility-bounded where applicable.
3. Remove or qualify stolen-capability and strong multi-tenant isolation
   language that outruns the runtime profile.

## Existing Assets

- `docs/review/06-authentication-dpop-remediation.md`
- `docs/review/09-session-isolation-remediation.md`
- `crates/arc-cli/src/remote_mcp/oauth.rs`
- `crates/arc-cli/src/remote_mcp/http_service.rs`
- `crates/arc-kernel/src/dpop.rs`
- existing hello examples and hosted docs

## Gaps To Close

- no one authoritative bounded hosted/auth profile is published yet
- compatibility-only paths are not clearly demoted across all ship surfaces
- docs still risk overstating the consequences of optional DPoP and narrow
  session continuity checks

## Requirements Mapped

- `HOST5-01`
- `HOST5-02`

## Exit Criteria

This phase is complete only when hosted/auth claims, examples, and
qualification docs all point at the same bounded profile.
