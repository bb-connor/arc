# chio-mcp-remote

Remote hosted MCP runtime surface for Chio.

## What it does

`chio-mcp-remote` runs the Chio-governed MCP server that remote clients reach
over HTTP. It handles:

- MCP session lifecycle (session creation, message dispatch, teardown) via
  an Axum HTTP service with SSE delivery.
- OAuth 2.0 and DPoP token flows: authorization code exchange, token endpoint,
  token introspection, and resource-indicator binding. Supported JWT signature
  algorithms include RS256/RS384/RS512, PS256/PS384, ES256/ES384, and Ed25519.
- Enterprise federation: pluggable identity providers (OIDC, SAML-like, custom)
  resolved through `EnterpriseProviderRegistry`.
- Per-client rate limiting (600 requests per 60-second window, 4096 tracked
  keys) enforced before session work begins.
- Admin routes (`/admin/health`, `/admin/authority`, `/admin/rotate`) for
  operator keypair management.
- Receipt-bearing kernel dispatch: every tool invocation passes through
  `chio-kernel` and produces a signed `ChioReceipt`.

The public surface re-exports `CliError` and `JwtProviderProfile` from
`chio-control-plane` and exposes the HTTP service entrypoint via
`serve_http(RemoteServeHttpConfig)`.

## Durable resume integrity

`--session-db` requires `--resume-hmac-keyring`. The keyring is dedicated to
active resume records, terminal tombstones, and terminal generation fences. It
must not reuse an authority seed, control token, edge bearer, or admin bearer.
The file must be a regular non-symlink file with no group or world permissions.
It is opened without following links, must be owned by the effective user or
root, and must have exactly one hard link. It is parsed as strict I-JSON with
duplicate fields, unknown fields, trailing values, non-UTF-8 text, and
out-of-range integers rejected. Object member order and insignificant JSON
whitespace are not part of the contract. Decoded key material and the parsed
file buffer are zeroized on drop.

```json
{
  "schema": "chio.remote-mcp.resume-hmac-keyring.v1",
  "current": {
    "keyId": "edge-resume-2026-07",
    "version": 2,
    "keyBase64": "<unpadded-base64url-encoding-of-32-random-bytes>"
  },
  "previous": [
    {
      "keyId": "edge-resume-2026-06",
      "version": 1,
      "keyBase64": "<unpadded-base64url-encoding-of-32-random-bytes>",
      "verifyUntilMillis": 1784246400000
    }
  ]
}
```

The current version must be positive and greater than every previous version.
At most four previous keys are accepted, and each verification deadline must
be no more than seven days in the future when the process starts. After the
deadline, records signed by that key fail closed. A typical launch includes:

```bash
chmod 600 /etc/chio/edge-resume-hmac-keyring.json
chio --session-db /var/lib/chio/edge-sessions.sqlite3 \
  --resume-hmac-keyring /etc/chio/edge-resume-hmac-keyring.json \
  mcp serve-http ...
```

## Position in the system

```
Remote MCP client (browser / CLI / agent)
        |  (HTTP + SSE, OAuth 2.0 + DPoP)
  [chio-mcp-remote]
        |
  chio-kernel  ->  signed ChioReceipts
```

`chio-mcp-remote` depends on `chio-mcp-adapter` (MCP protocol types and
transport), `chio-kernel` (policy enforcement and receipts),
`chio-control-plane` (authority keypair management, policy loading, budget and
revocation stores), and `chio-egress-contract` (outbound HTTP safety).

## Crate layout

```
crates/protocol/chio-mcp-remote/
  Cargo.toml
  src/
    lib.rs              re-exports; includes remote MCP runtime files
    remote_mcp/
      admin.rs          admin REST routes (health, authority, rotate)
      http_service.rs   Axum service entry, rate limiter, SSE delivery
      oauth.rs          OAuth token endpoint, DPoP proof validation, JWT verify
      session_core.rs   session lifecycle, kernel dispatch, receipt signing
      session_identity.rs
                        OIDC/JWKS discovery and federated identity helpers
      session_resume.rs resumable-session fingerprints, keyring, and HMACs
      session_shared_upstream.rs
                        shared hosted upstream notification ownership
      session_forms.rs  admin query structs and OAuth request forms
      session_store.rs  atomic active, tombstone, and terminal-fence storage
      tests.rs          integration tests
```

## Building

```bash
cargo build -p chio-mcp-remote
cargo test -p chio-mcp-remote
```

## House rules

- No em dashes (U+2014) anywhere in code, comments, or documentation.
- Workspace clippy lints `unwrap_used = "deny"` and `expect_used = "deny"` apply.
- Fail-closed: sessions without a valid OAuth bearer or DPoP proof are rejected
  before the MCP session is created.
