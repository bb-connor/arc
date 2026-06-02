# chio-egress-contract Architecture

## Boundary

`chio-egress-contract` owns the typed HTTP egress policy boundary for substrate
adapters. It does not know Chio capabilities, kernel receipts, tool manifests,
or adapter protocols. Its job is to decide whether an outbound HTTP target,
redirect hop, DNS answer, and response byte count satisfy a declared tenant
egress contract.

The crate stays dependency-light by default. The optional `reqwest-egress`
feature adds a dispatch wrapper and resolver, but the core contract remains
usable without `reqwest` or `tokio`.

## Module Boundaries

- `HttpEgressContract` is the raw configured policy shape.
- `ValidatedHttpEgressTarget` is the URL authority result after enforcement.
- `HttpEgressError` is the fail-closed reason surface for config, URL, DNS,
  redirect, address-class, and byte-limit denials.
- Core enforcement validates schemes, userinfo, normalized authority, address
  classes, DNS answers, redirect depth, and response size.
- The optional `reqwest_helper` module turns those checks into a dispatch path
  that validates every hop, disables ambient proxy/redirect behavior, pins DNS
  through a contract-backed resolver, strips sensitive redirect headers, and
  caps streamed response bytes.

## Pain Points

- The raw contract is both configuration data and the enforcement object.
- Each enforcement method validates the raw contract again, which blurs the
  boundary between deployment config admission and per-request checks.
- The reqwest helper currently receives a raw contract and re-enters validation
  across the request loop, redirect loop, DNS resolver, and response byte
  checks.

## Security And API Constraints

- Missing contracts must fail closed.
- Existing public methods on `HttpEgressContract` must remain compatible.
- Allowed authorities stay exact normalized host or host:port entries.
- DNS enforcement must check every resolved IP before a socket is opened.
- Private/special-use IPv4 and IPv6 addresses must remain denied even when an
  authority entry was configured.
- Redirect limits, response byte ceilings, proxy disabling, and redirect
  self-management must remain enforced.
- The default feature set must stay free of optional `reqwest`/`tokio`
  dependencies.

## Affected Dependents

Direct dependents include `chio-http-core`, `chio-api-protect`,
`chio-mcp-remote`, `chio-openapi-mcp-bridge`, and `chio-a2a-adapter`. This
slice is additive for callers: existing raw-contract APIs remain available.
The optional reqwest helper can use the prepared boundary internally without
requiring downstream source changes.

## Planned Improvement

Add `PreparedHttpEgressContract`, an immutable pre-validated contract handle.
It separates config admission from per-attempt enforcement and lets dispatch
helpers avoid repeatedly validating raw policy shape while preserving the same
fail-closed URL, DNS, redirect, and byte checks.

The change is architectural because it introduces a distinct contract lifecycle:
raw config -> prepared contract -> per-hop enforcement.
