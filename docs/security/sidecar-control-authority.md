# Sidecar control authority

`chio-api-protect` treats network location as transport metadata, not authority.
An untrusted agent may share the sidecar's IPv4 or IPv6 loopback interface,
container network namespace, or reverse proxy. None grants operator privileges.

## Required credentials

Every control request requires a nonempty configured
`ProtectConfig::sidecar_control_token` and exactly one matching
`Authorization: Bearer <token>` header. The CLI reads
`CHIO_SIDECAR_CONTROL_TOKEN`, falling back to `CHIO_API_PROTECT_CONTROL_TOKEN`
when the first variable is absent. Configuration retains its existing outer
whitespace normalization. Presented credentials are not trimmed. Bearer scheme
casing is insensitive; complete token bytes use the constant-time comparator.

Missing or blank configuration disables control access, even on loopback. Wrong,
missing, malformed, comma-combined, and duplicate credentials deny. Duplicate
headers deny in either order, including two identical valid values. Peer address
extensions and forwarded-address headers cannot satisfy the gate. An authenticated
operator does not need peer-address metadata.

The gate covers all `/approvals` routes, both capability mint paths, capability
release, validation and attenuation, operator receipt submission, reconciliation,
and metrics. It runs before body decoding or store mutation. Reconciliation and
the other control routes use the same gate. Denials retain HTTP 403 and
`chio_control_forbidden`, with no credential values in the response or gate log.

Public liveness, readiness and signature-verification routes remain separate.
Proxy and mediated evaluation still enforce their own capability and kernel
checks; this change does not turn a control credential into an agent capability.
The attenuation endpoint still refuses to act as the parent subject's signer.

## Migration and limits

Previously, an absent control token admitted a loopback caller. Deployments and
clients relying on that behavior must configure the dedicated token and attach
the bearer header. Do not restore access with a locality exception. When no token
is configured, the proxy may still start with its independently authorized data
path and public health checks; privileged control requests remain unavailable.

Distribute the token only to trusted operator/controller and reconciliation
components. Do not give it to agents or untrusted tool subprocesses, reuse an
agent credential, or forward it upstream. Protect nonlocal transport with the
deployment's authenticated TLS boundary. The shared credential grants broad
sidecar control access. It is not per-user identity, tenant isolation, scoped
operator RBAC, DPoP, or the enterprise broker's request proof.

Threshold collection still requires a separately configured authenticated request
source that revalidates current policy, capability, route, intent and submitter.
Neither control authentication nor a signed proposal supplies that context. The
default sidecar's mediated threshold execution remains disabled.

## Regression boundary

`proxy::tests::control_auth` exercises the production Axum router across 18
control routes. It covers IPv4 and IPv6 loopback, unknown and remote peers,
configuration failure, malformed and duplicate headers, forwarded-localhost
spoofing, denial before decoding, unchanged pending/resolved approval state,
unchanged capability revocation state, authenticated access without peer metadata,
and public liveness. Existing authenticated approval, minting, receipt, revocation,
and reconciliation tests exercise the successful flows.

These are local router and store-boundary regressions, not a native confinement,
cross-tenant authorization, or hosted deployment qualification.
