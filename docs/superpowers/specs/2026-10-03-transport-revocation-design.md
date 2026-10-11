# Transport confidentiality and truthful revocation

Execute the approved AP7 and AP8 review findings in the existing security worktree.

## Intended behavior

Three production HTTP surfaces (trust-control, remote MCP, API-protect) share a
rustls server profile. Non-loopback plaintext binds fail before store opening,
policy discovery, upstream launch or listener publication. An explicit
`--allow-plaintext` escape hatch supports protected proxy networks and is not a
claim of confidentiality. Loopback development remains supported. `--tls-cert`
and `--tls-key` must be paired and cannot silently fall back to plaintext.

Use the existing `chio-http-serve` crate for immutable prepared TLS configuration,
connection IO and bind validation. Use control-plane's bounded private-file custody
loader for private keys because all three compositions already depend on it;
never add a control-plane dependency to the transport crate. Certificate files
are bounded public input; private files remain owner-only, regular, singly linked,
no-follow and zeroized. rustls verifies key/certificate consistency at startup.
The certificate's trust, name and validity are verified by connecting clients.

TLS handshakes happen in accepted connection IO, under the existing connection
permit. They have a fixed deadline and do not serialize the accept loop. Preserve
socket peer addresses for MCP proxy authentication and rate limiting. TLS does not
turn untrusted certificate headers into identity: the AP6 authenticated proxy
boundary remains required for header-derived client certificate evidence. Server
TLS uses rustls safe versions with an explicit workspace AWS-LC provider. No FIPS,
client-certificate authentication, certificate automation or deployed proxy claim.
Reference: https://docs.rs/rustls/0.23.35/rustls/struct.ConfigBuilder.html

Control clients accept HTTPS or literal loopback HTTP. Reject credentials, query,
fragment and non-loopback HTTP without rendering rejected URLs. Disable all HTTP
redirects so a trusted endpoint cannot forward a service credential to plaintext
or a different authority. Existing explicit cluster leader selection remains.

Session-wide revocation reports success only after every capability's write and
readback succeed and confirm revoked. Return a non-2xx JSON result for partial
progress, preserving each capability's status and safe failure phase. Retain typed
local causes without exposing upstream bodies, paths or credentials. Reuse one
backend instance for the batch. Already-revoked capabilities and retry after
partial progress are idempotent. Backend initialization failure is an error.

## Acceptance

Actual TLS connections succeed with a trusted certificate; plaintext, wrong name,
untrusted certificate, malformed/mismatched identity and unsafe private key refuse.
Idle handshakes time out, do not block honest clients, count against the connection
cap and release their permits. All three production starts reject unsafe binds and
accept the configured TLS profile. Native CLI arguments reach the profile.

Control clients refuse non-loopback HTTP before networking and never follow a
redirect. Session revocation tests include remote 500, local write failure,
readback failure, partial success, false readback, already revoked and retry.
Retain failed attempts, focused owner tests, lint/source gates and one independent
integrated review. Publish branch changes only; hosted/native-platform and release
qualification remain separate.
