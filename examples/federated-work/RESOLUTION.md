# Mutually releasing an unresolved payment hold

An unknown work incident cannot prove that a tool did nothing. Two configured
parties can nevertheless agree to release the associated payment claim. This
example implements that separate decision for the existing 100 TST local-credit
review contract. It transfers no external funds and makes no legal-enforcement
claim across jurisdictions.

The Python buyer must already have retained a verified incident. Its operator
can then run:

```sh
python python_buyer/client.py resolve BUYER_STATE https://SELECTED_PROVIDER:PORT
```

The provider must use the updated binary and the buyer must have activated its
signed HTTPS enrollment v2, with a proof-of-possession grant for `resolve`.
Existing v1 enrollments remain verifiable but grant no resolution permission.
A request never activates a key, payment rail or trust root.

The command obtains a receiver-signed proposal, verifies it against the buyer's
retained work and incident, countersigns it, saves the exact consent before
sending it, and checks the provider's completed release receipt. Only that
receipt can restore the buyer's reserved credit. Repeated or concurrent calls
reuse the retained consent and restore the reservation once.

After completion, both `resolve` and `work` return the original incident with:

```json
{
  "paymentResolution": "released_by_agreement",
  "workExecuted": null,
  "buyerVerified": false,
  "incidentVerified": true,
  "localCreditSettled": true,
  "available": 1000,
  "reserved": 0,
  "spent": 0,
  "externalFundsTransferred": false
}
```

The response's `release` field contains the public verification package. Save
that field as `release.json`, without the surrounding account summary. Either
implementation can verify it offline against independently configured peer keys:

```sh
python python_buyer/client.py verify-release peers.json release.json
chio-federated-work verify-release peers.json release.json
```

## Wire contract

The A2A `resolve` tool accepts a closed object with `action: "offer"` and the
original `work`, or `action: "accept"`, the original `work` and `consent`.
The accepted work agreement stays at v3. Resolution is a separately signed
amendment, not a changed work outcome or replacement acceptance.

`chio.unknown-payment-release.v1` terms contain the locally selected policy
hash, original operation id, terminal projection digest, full native signed
incident, original capability, exact authorized payment journal, issue time and
expiry. The issue time follows the incident and the admission window is at most
24 hours. This example offers one hour.

Both Ed25519 signatures cover the same RFC 8785 canonical terms with distinct
prefixes: `chio.unknown-payment-release.v1`, a zero byte, `receiver` or
`counterparty`, another zero byte, then the canonical terms. A signature copied
between roles fails. The host supplies policy pins for both parties, rail and
currency; a policy carried in an incoming request has no activation authority.

The native completed receipt uses `SignedExportEnvelope` with schema
`chio.unknown-payment-release-receipt.v1`. Its record binds the exact co-signed
request and original unknown operation, acceptance time and serving fence, rail
transaction id, completion time and serving fence. The Python implementation
checks these fields independently, without Rust bindings or a verifier process.

## Recovery and storage

The qualified SQLite store keeps two immutable resolution rows per original
operation: accepted intent and completed release. The global authority chain
commits to each exact row, with exact coverage and serving-fence checks. The
accepted intent atomically reconciles monetary budget exposure to zero while
preserving the consumed invocation. The buyer's reservation stays held until
it verifies completion.

The native mediator calls the locally configured reversible adapter only after
the intent is durable, using the original authorization and operation reference.
Only the rail's `Released` result permits a completed record and signed receipt.
Startup retries this same accepted economic intent, including after its offer
expires. It never redispatches the original work. Adapter idempotency at the
original reference is required; this example uses the native SQLite operator
ledger.

The original admission terminal, projection and physical authorization journal
remain unchanged. Normal qualified payment reads return the effective successor
journal (`settling` or `settled`, release action). Historical unknown verification
reads the original journal. A completed release is new authority to stop charging;
it is not newly discovered evidence of no execution.

The current buyer retains one consent choice per incident. It does not silently
replace an expired consent that the provider never accepted. That case requires
a future explicit renewal procedure. It also cannot resolve a buyer's ambiguous
send when the provider has no matching signed incident. Disputes without mutual
consent, unilateral refunds, external rails, and independent operator deployment
remain outside this demonstration.

Run the isolated HTTPS fault suite from the repository root:

```sh
python3 examples/federated-work/resolution_smoke.py \
  --binary target/debug/chio-federated-work \
  --python-env /ABSOLUTE/LOCKED/PYTHON/ENV \
  --output /ABSOLUTE/NEW/RESULTS
```

It exercises both unknown-work crash positions, three provider release crash
positions, two buyer crash positions, four concurrent recovery clients per case,
provider restart, offline replay, unchanged historical evidence and one-time
accounting. Public negative vectors are tested in both implementations.
