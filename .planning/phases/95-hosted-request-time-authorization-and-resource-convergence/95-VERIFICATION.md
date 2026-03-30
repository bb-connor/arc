# Phase 95 Verification

Phase 95 is complete locally.

## What Changed

- extended the ARC OAuth authorization profile with explicit request-time
  contract, resource-binding, and artifact-boundary semantics
- enforced hosted request-time validation for `authorization_details`,
  `arc_transaction_context`, and protected-resource `resource` matching
- preserved bounded request-time ARC auth fields through issued and exchanged
  access tokens
- added negative-path coverage for wrong-resource requests and artifact
  confusion at the hosted edge
- updated standards, protocol, release, and economic-interop docs to describe
  the live hosted contract honestly

## Validation

Passed:

- `cargo fmt --all`
- `cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_metadata_and_review_pack_surfaces -- --exact --nocapture`
- direct hosted-flow repro against a local `arc mcp serve-http` instance,
  including request-time `authorization_details`, `arc_transaction_context`,
  wrong-resource rejection, token replay rejection, and token-exchange
  preservation

## Outcome

ARC's hosted OAuth-family edge now matches the standards-facing contract it
advertises: governed request scope is representable at request time, protected
resource binding is explicit, and review or approval artifacts do not become a
second runtime authorization channel.
