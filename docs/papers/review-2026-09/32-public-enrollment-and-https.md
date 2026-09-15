# Public enrollment and locally activated HTTPS

The checked-work example now has a deployment interface for separately
provisioned participants. Its Rust provider serves TLS 1.3, and its Python
buyer activates a signed enrollment against an operator-selected provider key
and origin. The enrollment binds that application identity to TLS trust material
and a buyer-specific negotiation capability. Neither application signing seed
nor a shared bearer secret needs to cross between the parties.

This advances the chosen goal of work between companies, but the judgment
remains that a breakthrough is unproven. TLS, signed configuration and
proof-of-possession credentials are established mechanisms. The strongest
objection is still that this is careful, application-specific integration under
one project and operator. Useful work between independently operated participants,
with demonstrably less bespoke security and recovery logic than a matched
alternative, would provide stronger evidence of the protocol's value.

## The boundary that changed

The preceding example required loopback HTTP and a common launcher to place
the provider's bearer credential in the buyer's state. The new
[operator interface](../../../examples/federated-work/HTTPS.md) allows each side
to initialize its own identity, exchange public application keys, configure its
peer locally, and transfer a provider-signed public enrollment artifact. The
provider checks the buyer against its configured relationship before issuance.

The existing `SignedExportEnvelope` carries the enrollment. Its body binds the
supported work profile, provider and buyer keys, exact HTTPS origin, public TLS
certificates and provider-signed negotiation capability. That capability permits
only quote, acceptance, status and delivery retrieval, with a 256 KiB argument
bound. Every grant requires proof of possession of the buyer's application key.
The paid review capability is still negotiated separately and limited to one
review and 100 provider-local test units.

The buyer's `enroll` command receives the expected provider key and endpoint
from the operator. It verifies the enrollment and capability signatures, exact
identity and origin bindings, validity, scope and TLS trust parsing, then
atomically activates `connection.json`. Existing state cannot change application
peers. Certificate or endpoint changes under the same peer require another
explicit local activation. Agent discovery cannot add roots or select a new
credential destination.

The HTTPS harness removes the buyer's legacy `peers.json` and `session.json`
after activation. All subsequent requests use the buyer's own signing key and
the locally activated public enrollment. Request proofs bind the capability,
server, tool, arguments, nonce and timestamp. The kernel denies absent or
incorrect proofs before dispatch. These are native Chio sender proofs; no
OAuth DPoP wire compatibility or mutual TLS is claimed.

## Transport implementation

The Rust example uses the repository's Rustls/Tokio stack, permits TLS 1.3
only, and advertises HTTP/1.1. The existing A2A HTTP edge sits behind a private
Unix socket in the provider's private state. The TLS adapter connects to that
socket only after a successful handshake; there is no plaintext TCP backend.
It bounds concurrent connections to 32, handshakes to five seconds and each
connection to 30 seconds. Socket reuse permits recovery on the same fixed
origin after a process kill.

The Python client uses an explicit TLS client context with only the activated
certificate roots, hostname verification, no common-name fallback and TLS 1.3
minimum. It uses neither proxy environment variables nor environment-driven
TLS key logging. An activated HTTPS relationship cannot fall back to the
legacy HTTP path. The advertised A2A interface must match the active origin's
`/rpc` exactly. Certificate and hostname verification use
[Python's documented SSL context](https://docs.python.org/3.12/library/ssl.html#ssl.SSLContext).

The signed enrollment authenticates the selected trust material; it does not
replace the TLS handshake. A correctly signed packet containing the wrong CA
still fails at connection time. Similarly, valid trust roots do not waive
certificate hostname checks. This separates the provider's application key,
the TLS server key and the buyer's local activation decision.

During implementation review, the initial CA-file path could copy unrelated
contents from a combined PEM file into the public enrollment. Issuance now
parses and validates certificates, rejects non-certificate PEM blocks, and
re-encodes only the public certificates. A regression supplies a real combined
certificate/private-key file and verifies that issuance fails with no artifact.
Another supplies an unrelated comment and verifies that it is not exported.

## Executed evidence

All 17 HTTPS process scenarios pass. Sixteen are the complete previous
Python-to-Rust negotiation, work, rejection, process-kill, Unicode and concurrent
accounting scenarios, now using TLS and public enrollment. The added scenario
executes 13 denials:

| Boundary | Rejected cases |
| --- | --- |
| Public artifact issuance | Combined certificate and private-key file |
| Local activation | Wrong expected provider key, wrong selected origin, substituted trust material, substituted buyer |
| Destination selection | HTTP downgrade and an unselected HTTPS origin |
| Actual TLS handshake | Untrusted serving certificate, hostname mismatch, TLS 1.2 downgrade, plaintext HTTP sent to the TLS listener |
| Negotiation authorization | Public enrollment with no sender proof, and with a proof signed by the wrong key |

The last two callers run in a namespace containing only public enrollment and
a signed quote, without either participant's signing seed or the provider TLS
key. They receive verifiable signed denials. Across all 13 denials, the provider
creates no job or acceptance event, and the buyer retains zero reservations,
reviews, captures and expenses. Restoring the correct local configuration then
completes exactly one review, capture and expense.

The complete legacy HTTP regression suite also passes all 16 scenarios. The
Rust example passes six unit tests, including origin validation and rejection
of private-key or malformed certificate material. All 16 Python unit tests
pass, covering the prior public work verifier and the new activation, scoped
credentials, expired authorization, trust-store selection, discovery substitution
and origin cases. Clippy denies warnings; Rust formatting and whitespace checks
pass. The paper builds at 12 pages and 4,999 body words, with its opening updated
to name locally activated HTTPS without claiming independent operation.

The changes are confined to the example, its dependency manifest and lock,
the participant and harness code, and documentation. Production kernel, market,
store and A2A crate sources remain unchanged from the preceding qualification.
Their earlier native test results are historical evidence, not newly rerun
kernel qualification. The added Rustls PEM dependency is recorded in the example
lock; the Python dependency lock remains unchanged.

The [evidence manifest](evidence/32-public-enrollment-and-https/manifest.json)
records public enrollment and work artifacts, peer pins, local activation
observations, source snapshots, dependency inventory, binary hash and test logs.
Exports exclude application seeds, TLS private keys and legacy bearer credentials.
Public work packages still disclose the public review fixture. Account and
process observations are unsigned harness evidence, distinct from signed
receipts and enrollment.

## What this still does not establish

Every executed scenario uses one host, one project author and one trusted
launcher. The interfaces permit separate provisioning and non-loopback HTTPS
endpoints, but no independent company deployment or wide-area run occurred in
this phase. The launcher can access both participants' state. Certificate fixtures
are generated inside the provider namespace for testing, not by a qualified
deployment PKI. The service limits do not establish internet-facing availability.

The provider-local ledger remains the selected settlement authority. A valid
report is captured before the buyer's independent verification; the buyer's check
is not an external escrow release condition. Signatures do not prove honest
private accounting, real funds, collateral or public non-equivocation. The
profile still admits one configured buyer per provider state and checks bounded
OpenAPI declarations rather than arbitrary security-review quality. Uncertain
post-dispatch work still requires authorized resolution rather than a timeout
refund or automatic replay.

The next material evidence should combine independent operation with a useful
non-fixture job and a deliberately selected settlement authority. The operator
instructions and signed public enrollment make that experiment executable,
while leaving its outcome unclaimed.

All work remains local and uncommitted on the checkout based on
`2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`. No release, remote CI qualification,
public traffic, external payment, independent adoption or breakthrough is claimed.
