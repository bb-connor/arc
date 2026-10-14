# MCP edge authorization audit

This audit maps each authorization requirement of the MCP specification,
revision `2026-07-28`, to the Chio code that implements it and to the test
that proves it. Requirement text comes from
[Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization),
[Authorization Server Discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery)
and
[Security Considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations).

## Scope

- **Resource server.** `chio mcp serve-http` is the protected MCP server. The
  HTTP edge, bearer verification and metadata live in
  `crates/protocol/chio-mcp-remote/src/remote_mcp/`. `chio-hosted-mcp`
  re-exports `serve_http` and `RemoteServeHttpConfig` and adds no
  authorization logic.
- **Local authorization server.** `--auth-server-seed-file` enables the embedded
  OAuth authorization server in `remote_mcp/oauth/local_server.rs` and
  `remote_mcp/oauth/request_validation.rs`. Requirements that bind
  authorization servers apply only to this mode. It has no end-user
  authentication: every token names the fixed `--auth-subject`, and anyone who
  can reach the authorize endpoint can approve a request. It is for local or
  operator-controlled deployments only. The consent nonce (AS-11) proves page
  provenance, not who approved. With `--auth-server`,
  `--auth-jwt-*` or `--auth-introspection-url`, an external authorization
  server owns them.
- **Upstream side.** `chio-mcp-adapter` launches the wrapped MCP server over
  stdio. `chio-mcp-edge` runs the JSON-RPC session behind the kernel. Neither
  receives the inbound access token.
- **Out of scope.** Client-only requirements (client registration, AS metadata
  discovery order, RFC 9207 issuer validation, step-up retry logic, refresh
  token storage) bind MCP clients. Chio's `chio mcp` client commands are not
  covered here.
- **Static bearer mode.** `--auth-token` is a shared-secret deployment
  outside the OAuth profile. It publishes no protected-resource metadata and
  answers `401` with a bare `Bearer` challenge. Rows below describe the OAuth
  modes (JWT, OIDC discovery, introspection, local authorization server)
  unless they name static bearer.

## Status legend

- **PASS**: the named test asserts the control and passes on `main` at the
  commit in [Verification](#verification).
- **GAP**: the control has no asserting test, or the code does not meet the
  requirement.
- **N/A**: the requirement does not bind any Chio component; the row says why.

Test identifiers use `<package> <target> <test path>`. `lib` is the
package's unit-test target.

## Resource server controls

### Protected resource metadata and challenge

| ID | Requirement | Implementation | Test | Status |
| --- | --- | --- | --- | --- |
| RS-01 | MCP servers MUST implement RFC 9728 protected resource metadata, and the document MUST list at least one authorization server. | `http_service.rs` `handle_protected_resource_metadata`; `http_service_auth.rs` `build_protected_resource_metadata` | `chio-cli mcp_serve_http mcp_serve_http_rejects_jwt_with_wrong_audience` asserts `resource`, `authorization_servers[0]` and `scopes_supported` | PASS |
| RS-02 | An OAuth edge without an authorization server to advertise does not start. | `build_protected_resource_metadata` returns an error when no `--auth-server`, local issuer, discovered issuer or `--auth-jwt-issuer` is set | `chio-mcp-remote lib hosted_tests::auth_config::oauth_edge_without_authorization_server_refuses_to_start` | PASS |
| RS-03 | Metadata is served at the path-suffixed well-known URI. | `PROTECTED_RESOURCE_METADATA_MCP_PATH` route | `chio-cli mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange` fetches `/.well-known/oauth-protected-resource/mcp` | PASS |
| RS-04 | Metadata is served at the root well-known URI. | `PROTECTED_RESOURCE_METADATA_ROOT_PATH` route | `chio-mcp-remote lib hosted_tests::auth_flows::hosted_mcp_serves_protected_resource_metadata_at_root_well_known_uri` | PASS |
| RS-05 | `401` responses MUST carry `WWW-Authenticate` with `resource_metadata`. | `oauth/bearer_auth.rs` `unauthorized_bearer_response`, `ProtectedResourceMetadata::bearer_challenge` | `chio-cli mcp_serve_http mcp_serve_http_rejects_jwt_with_wrong_audience` asserts `resource_metadata=` | PASS |
| RS-06 | A request with no `Authorization` header receives the same `401` challenge. | `extract_bearer_token` | `chio-mcp-remote lib hosted_tests::auth_flows::hosted_mcp_oauth_edge_challenges_missing_token_with_resource_metadata`; static bearer by `chio-cli mcp_serve_http mcp_serve_http_requires_auth_reuses_sessions_and_supports_delete` | PASS |
| RS-07 | The challenge SHOULD carry `scope`. | `bearer_challenge` appends `scope` when `--auth-scope` is set | `chio-cli mcp_serve_http mcp_serve_http_rejects_jwt_with_wrong_audience` asserts `scope="mcp:invoke"` | PASS |
| RS-08 | Protected resource metadata and `401` challenges SHOULD NOT name `offline_access`. | `http_service_auth.rs` `build_remote_auth_mode` refuses `--auth-scope offline_access` at startup | `chio-mcp-remote lib hosted_tests::auth_config::remote_auth_config_rejects_offline_access_scope` | PASS |
| RS-09 | Published authorization-server metadata agrees with the protected resource metadata (profile and issuer). | `http_service_auth.rs` `validate_chio_oauth_discovery_metadata_pair` | `chio-mcp-remote lib tests::chio_oauth_discovery_validation_rejects_profile_mismatch`; `chio-mcp-remote lib tests::chio_oauth_discovery_validation_rejects_unadvertised_issuer` | PASS |

### Token validation

| ID | Requirement | Implementation | Test | Status |
| --- | --- | --- | --- | --- |
| RS-10 | Servers MUST validate that tokens were issued for them (RFC 8707 audience). JWT path. | `JwtBearerVerifier::authenticate_token`: `aud` or `resource` must equal `--auth-jwt-audience`, else the metadata `resource` | `chio-cli mcp_serve_http mcp_serve_http_rejects_jwt_with_wrong_audience`; `chio-mcp-remote lib hosted_tests::auth_flows::hosted_mcp_accepts_jwt_and_rejects_wrong_audience` | PASS |
| RS-11 | Audience validation, introspection path. | `IntrospectionBearerVerifier::session_auth_context_from_introspection` | `chio-mcp-remote lib tests::bearer_verifier::introspection_bearer_verifier_accepts_active_token_with_resource_claim`; `chio-mcp-remote lib tests::bearer_verifier::introspection_bearer_verifier_rejects_audience_mismatch` | PASS |
| RS-12 | Token signature MUST verify. | `JwtVerificationKeySource::verify` | `chio-mcp-remote lib tests::bearer_verifier::inbound_authority_jwt_rejects_weak_key_forgery` | PASS |
| RS-13 | Expired tokens MUST receive `401`. | `exp` check in both verifiers | `chio-mcp-remote lib hosted_tests::error_contract::hosted_mcp_rejects_expired_or_mismatched_auth_during_session_reuse_without_panicking` | PASS |
| RS-14 | A token without `exp` is refused. | `JwtBearerVerifier::authenticate_token` and `IntrospectionBearerVerifier::session_auth_context_from_introspection` refuse a missing `exp` with `401`; local token exchange refuses a subject token without `exp` | `chio-mcp-remote lib tests::bearer_verifier::jwt_bearer_verifier_rejects_token_without_exp`; `chio-mcp-remote lib tests::bearer_verifier::introspection_bearer_verifier_rejects_token_without_exp`; `chio-mcp-remote lib tests::bearer_verifier::local_authorization_server_rejects_subject_token_without_exp` | PASS |
| RS-15 | Invalid or inactive tokens MUST receive `401`. | `unauthorized_bearer_response` on every verifier refusal | `chio-mcp-remote lib hosted_tests::auth_flows::hosted_mcp_accepts_static_bearer_and_rejects_invalid_token`; `chio-mcp-remote lib tests::bearer_verifier::introspection_bearer_verifier_rejects_inactive_token`; `chio-mcp-remote lib tests::bearer_verifier::inbound_authority_jwt_unknown_empty_or_null_confirmation_never_becomes_bearer` | PASS |
| RS-16 | Issuer mismatch is refused. | `http_service_auth.rs` `expected_bearer_issuer` resolves the issuer when the edge starts; both verifiers refuse a token whose `iss` is absent or differs from it | `chio-mcp-remote lib tests::bearer_verifier::jwt_bearer_verifier_rejects_issuer_mismatch`; `chio-mcp-remote lib tests::bearer_verifier::introspection_bearer_verifier_rejects_missing_or_mismatched_issuer` | PASS |
| RS-17 | `401` challenges for a rejected token carry `error="invalid_token"` (OAuth 2.1 section 5.3, RFC 6750 section 3.1). | `bearer_auth.rs` `unauthorized_bearer_response` emits `error="invalid_token"` in OAuth modes; a request without a token gets the challenge without `error` | `chio-mcp-remote lib tests::bearer_verifier::invalid_token_challenge_carries_error_invalid_token` | PASS |
| RS-18 | Tokens MUST be sent in the `Authorization` header and never in the URI query. | `extract_bearer_token` reads only `Authorization: Bearer`; metadata publishes `bearer_methods_supported: ["header"]` | `chio-mcp-remote lib hosted_tests::auth_flows::hosted_mcp_rejects_access_token_in_query_string` | PASS |

### Scope

| ID | Requirement | Implementation | Test | Status |
| --- | --- | --- | --- | --- |
| RS-19 | A token lacking a required scope is refused. Runtime insufficient scope SHOULD be `403` with `error="insufficient_scope"`, `scope` and `resource_metadata`. | `bearer_auth.rs` `insufficient_scope_response` answers `403` with `error="insufficient_scope"`, the required `scope` and `resource_metadata` in both verifiers | `chio-mcp-remote lib tests::bearer_verifier::missing_required_scope_answers_403_insufficient_scope_challenge` | PASS |
| RS-20 | Servers MUST account for scope hierarchies. | `--auth-scope` values are flat and matched exactly; Chio defines no scope that implies another | not applicable | N/A |

### No token passthrough and token handling

| ID | Requirement | Implementation | Test | Status |
| --- | --- | --- | --- | --- |
| RS-21 | The MCP server MUST NOT pass through the token it received; it MUST NOT accept or transit other tokens. | The verified token becomes a `SessionAuthContext` holding claims and a SHA-256 fingerprint. Tool calls reach the wrapped server as kernel-mediated JSON-RPC over stdio; no code path forwards `Authorization`. | `chio-cli mcp_serve_http token_passthrough::mcp_serve_http_wrapped_server_never_observes_inbound_bearer` (the wrapped server records its environment, argv and every received message; neither the token, its signature nor its fingerprint appears); `chio-mcp-remote lib tests::bearer_verifier::jwt_bearer_verifier_builds_oauth_session_auth_context` | PASS |
| RS-22 | Edge credentials do not reach the wrapped MCP server process. | `chio-mcp-adapter` `transport/utils.rs` `remove_chio_auth_env` strips `CHIO_AUTH_ENV_VARS` from the child environment | `chio-mcp-adapter lib transport::tests::stdio_transport_child_env_removes_chio_auth_tokens` | PASS |
| RS-23 | Servers MUST store tokens securely (OAuth 2.1 section 7.1). | Session records and resume records keep `token_fingerprint`, never the token | `chio-mcp-remote lib tests::remote_session_auth_context_uses_static_bearer_fingerprint_and_origin`; `chio-mcp-remote lib tests::bearer_verifier::jwt_bearer_verifier_builds_oauth_session_auth_context` | PASS |
| RS-24 | Token theft resistance: sender-constrained tokens are bound to the presenting key, and replayed proofs are refused. | `sender_constraint.rs` `SenderConstraintVerifier`; `cnf` binding in both verifiers | `chio-cli mcp_auth_server mcp_serve_http_local_auth_server_enforces_dpop_sender_constraint_across_token_and_mcp_runtime`; `chio-cli mcp_auth_server mcp_serve_http_local_auth_server_enforces_mtls_and_attestation_bound_sender_constraint`; `chio-cli mcp_auth_server mcp_serve_http_local_auth_server_rejects_attestation_bound_sender_without_dpop_or_mtls` | PASS |
| RS-25 | A session accepts only the authenticated context that created it; a different principal on the same session is `403`. | `bearer_auth.rs` `validate_session_auth_context` | `chio-mcp-remote lib hosted_tests::error_contract::hosted_mcp_rejects_expired_or_mismatched_auth_during_session_reuse_without_panicking`; `chio-cli mcp_serve_http mcp_serve_http_rejects_session_reuse_when_authenticated_principal_changes`; `chio-cli mcp_serve_http mcp_serve_http_dedicated_jwt_sessions_require_exact_bearer_continuity_and_separate_admin_token` | PASS |
| RS-26 | The session credential and the administrative credential are distinct. | `admin_bearer_token`, `build_remote_auth_mode` | `chio-mcp-remote lib tests::jwt_remote_auth_requires_separate_admin_token`; `chio-mcp-remote lib tests::bearer_edge_requires_a_dedicated_admin_token`; `chio-mcp-remote lib hosted_tests::auth_flows::hosted_mcp_accepts_static_bearer_and_rejects_invalid_token` | PASS |
| RS-27 | Error responses do not echo token or request input. | `oauth_error.rs` `OAuthRejection` keeps detail in a response extension; the wire body carries a registered code | `chio-mcp-remote lib tests::oauth_error_extensions_preserve_domain_context_with_redacted_wire_body` | PASS |

### Communication security

| ID | Requirement | Implementation | Test | Status |
| --- | --- | --- | --- | --- |
| RS-28 | Endpoints are served over HTTPS (OAuth 2.1 section 1.5). | The shared listener refuses a non-loopback plaintext bind unless `--allow-plaintext` names a protected proxy network | `chio-mcp-remote lib tests::revocation_transport::mcp_transport_denies_public_plaintext_before_policy_or_store_work` | PASS |
| RS-29 | Advertised URLs (`resource`, `resource_metadata`, issuer, endpoints) use `https` unless the host is loopback. | `normalize_public_base_url` refuses a base URL that is not `https` unless its host is `localhost` or a loopback address | `chio-mcp-remote lib hosted_tests::auth_config::public_base_url_rejects_non_https_non_loopback_scheme` | PASS |

## Local authorization server controls

These apply when `--auth-server-seed-file` is set.

| ID | Requirement | Implementation | Test | Status |
| --- | --- | --- | --- | --- |
| AS-01 | PKCE is required with `S256`; the metadata advertises `code_challenge_methods_supported`. | `validate_authorization_request` refuses a missing or empty `code_challenge` and any method other than `S256`; metadata publishes `["S256"]` | `chio-mcp-remote lib tests::local_authorization::local_authorization_server_rejects_missing_or_plain_code_challenge` (also asserts `code_challenge_methods_supported == ["S256"]`); `chio-cli mcp_serve_http mcp_serve_http_serves_oauth_authorization_server_metadata_for_local_issuer` | PASS |
| AS-02 | The code verifier MUST match the challenge at the token endpoint. | `exchange_authorization_code` | `chio-mcp-remote lib hosted_tests::auth_flows::hosted_mcp_accepts_local_oauth_pkce_and_rejects_invalid_verifier` | PASS |
| AS-03 | The `resource` parameter is required at authorization and MUST name this server. | `validate_authorization_request` returns `invalid_target` | `chio-cli mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange` (foreign resource); `chio-mcp-remote lib tests::local_authorization::local_authorization_server_rejects_missing_resource` | PASS |
| AS-04 | The token-endpoint `resource`, when present, matches the grant. | `exchange_authorization_code` returns `invalid_target` | `chio-mcp-remote lib tests::local_authorization::local_authorization_server_rejects_token_resource_mismatch` | PASS |
| AS-05 | Issued tokens carry the requested resource as `aud`. | `sign_access_token` | `chio-cli mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange`; `chio-mcp-remote lib hosted_tests::auth_flows::hosted_mcp_accepts_local_oauth_pkce_and_rejects_invalid_verifier` | PASS |
| AS-06 | An authorization code is not a bearer token at the resource server. | Codes are opaque and never verify as JWTs | `chio-cli mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange` asserts `401` for the code as a bearer | PASS |
| AS-07 | Codes are single use, short lived, and bound to `client_id` and `redirect_uri`. | `exchange_authorization_code` removes the code, checks the deadline and both bindings | `chio-mcp-remote lib tests::local_authorization::local_authorization_server_codes_are_single_use_expiring_and_bound` | PASS |
| AS-08 | Redirect URIs MUST be `https` or loopback. | `http_service_auth.rs` `build_client_registry` refuses at startup an `--auth-client` redirect URI that is not `https` or `http` on a loopback host, or that is not canonical, carries a fragment or contains a wildcard; the authorize endpoint accepts only registered URIs | `chio-mcp-remote lib hosted_tests::auth_config::local_authorization_server_refuses_invalid_client_registrations` | PASS |
| AS-09 | Authorization servers MUST validate exact redirect URIs against pre-registered values. | Clients and their exact redirect URIs are declared at startup with `--auth-client CLIENT_ID=REDIRECT_URI`; the embedded server refuses to start without one. `validate_authorization_request` answers an unknown `client_id` or an unregistered `redirect_uri` with `400 invalid_request` and never redirects. There is no dynamic client registration | `chio-mcp-remote lib hosted_tests::auth_flows::local_authorization_server_rejects_unregistered_redirect_uri`; `chio-mcp-remote lib hosted_tests::auth_config::local_authorization_server_refuses_invalid_client_registrations` | PASS |
| AS-10 | Consent: the user sees client, resource, subject and scopes and can approve or deny; denial redirects with `access_denied`. | `authorization_page`, `approve_authorization` | approval covered by `chio-cli mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange`; denial by `chio-mcp-remote lib tests::local_authorization::local_authorization_server_denial_redirects_access_denied_without_code` | PASS |
| AS-11 | Approval is accepted only from the consent page the server rendered. | `authorization_page` stores the validated request under a single-use `consent_nonce` that the page carries; `approve_authorization` accepts only that nonce and the decision, consumes it on the first answer and approves the stored request. A missing, unknown, answered or expired nonce is `400 invalid_request` with no redirect. The nonce proves page provenance only: the embedded server has no end-user authentication | `chio-mcp-remote lib hosted_tests::auth_flows::local_authorization_server_rejects_approval_without_consent_nonce`; `chio-mcp-remote lib tests::clock_custody::local_authorization_server_consent_nonce_is_single_use_and_expiring` | PASS |
| AS-12 | Authorization responses SHOULD include `iss` and advertise `authorization_response_iss_parameter_supported` (RFC 9207). | `approve_authorization` and `redirect_oauth_error` append `iss`; the local server metadata publishes `authorization_response_iss_parameter_supported: true` | `chio-mcp-remote lib tests::local_authorization::local_authorization_server_redirect_carries_iss` | PASS |
| AS-13 | Access tokens SHOULD be short lived. | `sign_access_token` sets `exp = iat + access_token_ttl_secs` | `chio-mcp-remote lib tests::local_authorization::local_authorization_server_access_token_lifetime_is_bounded` | PASS |
| AS-14 | Unsupported scopes are refused with `invalid_scope`; token exchange cannot widen the subject token's scopes. | `resolve_requested_scopes`, `resolve_exchange_scopes` | `chio-mcp-remote lib tests::local_authorization::local_authorization_server_rejects_unsupported_and_widened_scopes` | PASS |
| AS-15 | Token exchange issues a new token for this resource and never returns the subject token. | `exchange_subject_token` checks `resource` and re-signs | `chio-cli mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange` asserts a distinct token that authenticates; the resource-mismatch refusal has no test | PASS |
| AS-16 | Public-client refresh tokens MUST rotate. | The server issues no refresh tokens | not applicable | N/A |

## Per-client consent for proxies

The specification requires MCP proxy servers that use a static client ID to
obtain user consent for each dynamically registered client before forwarding
to a third-party authorization server. Chio never forwards an authorization
request to a third-party authorization server. With an external authorization
server, clients go to it directly from the protected resource metadata. With
the local server, each authorization request renders its own consent page
(AS-10, AS-11). The proxy requirement therefore binds no Chio component, and
per-request consent at the local server is the consent control.

## Verification

Every PASS row ran on Linux x86_64 with the full suites of the named
packages, on `main` at `52e44d78b9` plus the tests added with this revision:

```sh
cargo test -p chio-mcp-remote -p chio-mcp-adapter
cargo test --locked -p chio-cli --features real-linux-enforcement \
  --test mcp_serve_http --test mcp_auth_server
```

- `chio-mcp-remote`: 257 passed. `chio-mcp-adapter`: 137 passed.
- `chio-cli` `mcp_serve_http` and `mcp_auth_server`: 44 and 5 passed. These
  tests launch the wrapped server inside the native cage and run only with
  the enforced native fixture (`CHIO_CAGE_INIT`, read grants, runtime files
  and an independent receipt anchor) that
  `.github/actions/enforced-native-fixture` provisions. Without it they
  panic before the edge starts.
- The conformance runner in `--auth-mode oauth-local` with the auth
  scenarios passes 5 of 5 against the Python peer, which exercises client
  registration, the consent nonce, PKCE and token exchange end to end.
