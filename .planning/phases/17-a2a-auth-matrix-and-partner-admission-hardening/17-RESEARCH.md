# Phase 17: A2A Auth Matrix and Partner Admission Hardening - Research

**Researched:** 2026-03-25
**Domain:** Rust A2A adapter auth negotiation, partner admission, and operator
configuration
**Confidence:** HIGH

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| A2A-01 | Operator can configure remaining A2A peer auth schemes, including provider-specific or non-header credential delivery, through explicit adapter/admin surfaces | `A2aAdapterConfig` can safely expose request headers, query params, and cookies for both discovery and invoke flows |
| A2A-02 | A2A auth negotiation fails closed with clear diagnostics when peer requirements cannot be satisfied | Discovery and invoke paths already share enough context to emit partner, interface, skill, and tenant-aware denial messages |

</phase_requirements>

## Summary

The right implementation seam is adapter configuration, not a new protocol
layer. The alpha adapter already knew how to negotiate most peer-advertised
auth schemes; the missing work was operator-visible configuration for
provider-specific request shaping plus an explicit partner-admission contract
that prevents accidental trust widening.

Partner admission belongs at discovery time because the operator needs a
truthful failure before any mediated tool call is attempted. The policy should
be narrow and concrete: partner identity, expected tenant, expected skill or
security scheme, and optional allowed interface origins.

## Recommended Architecture

### Adapter Config
- add request header, query-param, and cookie setters to `A2aAdapterConfig`
- apply them to agent-card discovery and subsequent tool invocations
- keep them orthogonal to negotiated bearer/basic/api-key/oauth/mtls handling

### Partner Admission
- add a compact `A2aPartnerPolicy`
- validate it against the fetched agent card and selected interface
- reject discovery when tenant, skill, origin, or security metadata do not
  match

### Diagnostics
- keep auth failures fail closed
- include the peer context that caused rejection so the operator can remediate
  config without packet inspection

## Validation Strategy

- `cargo test -p arc-a2a-adapter --lib -- --nocapture`

## Conclusion

Phase 17 can close its requirements without changing the protocol shape: the
missing product surface is explicit operator configuration plus admission
validation around the already shipped auth matrix.
