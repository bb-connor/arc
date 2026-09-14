# Verifiable unresolved work

The Python buyer can retrieve and retain a native incident after a provider
crash leaves dispatch committed but no durable kernel tool return. Both the
Python and Rust verifiers check the public artifact. This extends the existing
version 3 agreement without changing its payment terms.

`work STATE URL` returns a JSON status with `outcome` equal to
`outcome_unknown_after_dispatch`, `incidentVerified: true`, `workExecuted: null`,
`buyerVerified: false`, `localCreditSettled: false` and
`paymentResolution: "required"`. Command success means that the incident was
retrieved and verified. The review has not been verified or settled. The buyer
retains its 100-unit reservation and records no expense or restoration.

An ordinary timeout, an absent provider job, and an attempted send without a
matching committed incident still return an error and retain the reservation.
Neither elapsed time nor an empty response permits another paid work request.

## Wire profile

The existing `delivery` tool returns an incident when a unique matching native
unknown terminal exists. No new negotiation grant is required. The outer object
has exactly `schema`, `agreementSha256`, `acceptedBidSha256` and `projection`.
Its schema is `chio.example.review-incident.v1`. The projection is the existing
`chio.signed-admission-terminal-projection.v1` envelope. There is no report,
Finding, paid receipt, zero-charge receipt or receipt-log inclusion claim.

The native envelope signs its canonical body with the domain bytes
`chio.signed-admission-terminal-projection.v1` followed by a NUL byte. Its
source and terminal operations retain the capability digest, request binding,
dispatch attempt, budget hold, payment participant and store fences. The
canonical projection contains the exact incident binding; the manifest commits
that projection and its one incident record.

The provider's qualified SQLite export reads and validates the retained rows,
reconstructs the deterministic predecessor and requires exact replay of the
stored projection before signing. It neither reopens the terminal nor changes
the payment journal. Its bounded example locator checks at most 4,097 operation
rows and rejects stores exceeding the 4,096-operation profile.

Both verifiers require the operator-configured provider key, the accepted work
capability and the hash of the buyer's exact retained request. Native incident
record contents, projection contents and terminal replay reference must agree.
The Python profile independently recomputes the namespace, request-binding,
operation, incident and manifest hashes. It accepts only the example's paid
review participant set and deterministic kernel incident form.

## Local retention and offline verification

One buyer transaction binds an incident to an existing attempted work request
and reservation, enforces a unique operation id, and excludes an already
settled delivery. Identical retrieval is idempotent. Later ordinary delivery
processing cannot replace a retained incident with a different terminal.
Repeated `work` calls can return the retained incident with the provider offline.
`snapshot` reports `incidentCount`; local balances are unsigned observations.

With locally selected public peer pins and an exported status file:

```sh
python client.py verify-incident PEERS_JSON PUBLIC_JSON
chio-federated-work verify-incident PEERS_JSON PUBLIC_JSON
```

These commands require no participant signing seeds. The original Rust buyer's
`work` command continues to reject unresolved work; it does not maintain the
Python buyer's incident journal. Its public `verify-incident` command checks the
same native evidence independently.

## Meaning and limits

The evidence says that this provider signed this retained unknown outcome for
this exact work request. It does not prove an honest provider, prove that the
tool did nothing, or authorize payment release. The same terminal can follow a
crash before the tool's write or a crash after that write but before kernel
return capture. Both cases preserve a consumed invocation and an authorized
hold. The peer does not gain a new authority root from an incident.

Resolving that hold needs a separate settlement authority and durable operation.
The current store forbids recovery claims on terminal operations and binds an
unknown terminal to an unmoved authorization. Directly releasing the rail or
rewriting the journal would violate that contract. No mutual-consent release,
arbitration, external payment, timeout refund or power-loss qualification is
implemented here.
