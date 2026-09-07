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

Nonempty configured values must use the
[RFC 6750 section 2.1 token alphabet](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1):
letters, digits, the permitted punctuation, and optional trailing padding. The
sidecar adds a local maximum of 512 bytes after normalization. Embedded whitespace,
commas, quotes, non-ASCII text, misplaced padding, and oversized values reject
before spec discovery, durable-store creation or listener startup. The borrowed
validated credential view is shared by authentication and containment and has no
secret-revealing debug representation. Syntax and size checks do not establish
credential entropy.

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

## Control credential containment

The upstream proxy rejects a request when any original header value contains the
configured control token's complete byte sequence. It returns HTTP 403 with
`chio_control_credential_wrong_route` before projecting caller identity, reading
the body, entering kernel admission or contacting the upstream. Unknown operator
paths that fall through to the upstream proxy receive this same check.

Containment uses raw bytes from every value, including duplicate fields and
non-UTF-8 values. It does not rely on a single-value map, valid Bearer syntax,
header names, or UTF-8 conversion to recognize the credential. Padded, quoted,
comma-combined and prefix/suffix-wrapped copies also reject. It does not strip the
credential and continue under a different upstream identity.

The total header scan budget is 64 KiB, measured as the sum of each name and value
length, counting names again for duplicate values. Larger requests return HTTP
431 with `chio_proxy_headers_too_large` before secret comparison. Equal-length
candidate windows use the constant-time comparator and accumulate all matches
without prefix-dependent search or early return. No request-sized allocation is
needed; comparison work is bounded by the header and token limits.

Requests that pass this preflight retain their original headers and independently
run the existing kernel and egress checks. Ordinary upstream Bearer, Basic and
Digest credentials remain unchanged, as do unrelated duplicate and binary values.
Disabled control configuration has no reserved credential to scan for. These
transport-preflight denials do not enter kernel receipt or budget processing.

This is containment for the current unencoded token in request-supplied header
values, not general secret detection. It does not inspect bodies, URLs, derived
encodings, historical credentials or secrets introduced by downstream components.
A caller already holding the control token remains a privileged operator. This
check does not replace credential custody or prevent a privileged caller from
deliberately disclosing it. Short tokens can collide with ordinary header data;
syntax validation alone does not make them suitable operator credentials.

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

The 17-test `proxy::tests::control_containment` inventory adds actual upstream
header observations, configuration rejection before I/O, exact inclusive bounds,
duplicate-value accounting, every-offset and near-match controls, and a serving
proxy test that withholds the advertised request body. The proxy must answer the
header rejection without waiting for that body. TCP bind failures fail these
tests rather than selecting an implicit skip.

These are local router, network and store-boundary regressions, not native
confinement, cross-tenant authorization, throughput, or hosted qualification.
