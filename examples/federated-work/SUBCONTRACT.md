# Bounded work across three organizations

This example connects a buyer A, a provider B and a specialist C. A Python buyer
hires a Rust provider. B's native tool dispatch runs a separate Python procurement
worker against C's Rust kernel over TLS 1.3 and A2A. Each receiver issues its own
capabilities. Existing market bids, asks, reservations, accepted bids, Findings,
receipts and durable payment recovery supply both work exchanges.

The harness simulates three organizations in isolated processes on one Linux
host. One operator creates their keys and configurations. It transfers local
TST credits, not external funds, and establishes no independent administration,
geographic deployment, legal effect or general API security assessment.

## Contract and authority

| Role | Private key | Permitted role in this profile |
| --- | --- | --- |
| A buyer | Agent key | Sign the parent bid, reservation and acceptance |
| B kernel | Receiver key | Issue A's work capability; sign the exact child procurement permit and parent evidence |
| B worker | Separate delegated agent key | Buy the one permitted child job from C |
| C kernel | Receiver key | Issue the child's capability; enforce the permit, execute and attest to child work |

All four keys must differ. The worker never receives B's kernel signing seed.
C's locally selected B promisor key checks procurement evidence only. It does
not become a trusted capability issuer. An incoming agreement, permit or report
cannot add an issuer root or choose a network endpoint.

Parent profile `chio.example.security-review-agreement.v4` requires
`subcontracting: true` and this closed `subcontract` object:

```json
{
  "specialist": "C_KERNEL_PUBLIC_KEY_HEX",
  "delegate": "B_AGENT_PUBLIC_KEY_HEX",
  "paths": ["/accounts", "/refunds"],
  "inputSha256": "SHA256_OF_EXACT_PROJECTED_UTF8_INPUT",
  "priceCeiling": 100
}
```

The 1 to 16 paths are sorted, unique, absolute and at most 256 UTF-8 bytes each.
Only their effective authentication declarations and referenced inline HTTP or
API-key scheme fields enter the child input. Descriptions, responses, parameters,
examples, extensions and unselected paths are omitted, including fields nested
under an approved operation. Rust and Python independently reconstruct and
canonicalize that document. Its exact digest must match A's signed contract.
This is an explicit disclosure profile; it cannot decide whether selected path
names or authentication scheme names are appropriate to disclose.

The child uses existing v3 work terms. Its job id is `child-` followed by the
canonical parent agreement's SHA-256, its buyer is B's delegated agent, its
provider is C, its ceiling is exactly 100 TST, and its deadline is the parent's.
It cannot subcontract onward. The ceiling cannot exceed the parent ceiling.
These are per-job limits, not a shared organization wallet or solvency proof.

B's trusted dispatch shim signs a `chio.example.subcontract-permit.v1` envelope.
It binds both parent agreement and complete parent work-request hashes, the
child agreement hash, delegated agent, specialist, 100 TST ceiling and expiry.
C requires it for that locally configured delegate before quotation, acceptance
and paid dispatch. Missing permits, altered jobs or prices, and signatures by
the agent or an unselected promisor deny. Repeating a valid quote returns the
same single-use capability; it cannot create another purchase.

## Operator configuration

Each party keeps its own state directory and private keys. C configures
`peers.json` with B's delegated agent as buyer and C's kernel as provider.
C's private state also contains `delegation.json`:

```json
{"promisor":"B_KERNEL_PUBLIC_KEY_HEX","delegate":"B_AGENT_PUBLIC_KEY_HEX"}
```

C's signed HTTPS enrollment v3 advertises that selected promisor, its own
receiver-issued proof-of-possession session and supported work profiles.
An ordinary receiver advertises a null promisor. Historical enrollment v1 and
v2 remain verifiable. The five v3 session grants are quote, accept, status,
delivery and resolve; they contain no paid review or issuer delegation grant.

B configures `subcontract.json` in its private provider state:

```json
{
  "specialist":"C_KERNEL_PUBLIC_KEY_HEX",
  "delegateState":"/absolute/private/B-delegate",
  "origin":"https://specialist.example",
  "enrollment":{},
  "pythonEnvironment":"/absolute/locked-python-environment",
  "buyerCode":"/absolute/federated-work/python_buyer"
}
```

Replace the empty enrollment with C's complete signed public enrollment. The
origin and C identity are selected locally, then checked against that artifact.
B also checks that C activated B's actual kernel as the promisor. The input
cannot override these settings. B advertises v4 only when this configuration
loads successfully. A selects the same specialist and delegated agent in its
own agreement; receipt verification uses those already selected identities.

The worker runs in a nested bubblewrap mount and network namespace. Its mounts
contain readonly code, interpreter, delegated key, exact agreement, disclosure,
permit and connection, plus its writable child journal. An AF_UNIX tunnel
connects only to the configured C endpoint; the Python client still verifies
TLS certificates and hostname over it. The worker cannot open a direct TCP
connection. Locks and staging files remain outside its writable mount. Host
diagnostics replace directory entries atomically, without following
worker-created symlinks. Host kernel, runtime configuration, disclosure code and
receiver implementations remain trusted.

## Delivery and recovery

B's v2 signed review report includes C's complete public request and delivery.
B's native output guard and both public verifiers require the exact derived
child agreement and input, B's parent-bound permit, C's signed market artifacts,
checked report, Finding, native receipt and inclusion proof. A valid B signature
cannot replace C's evidence. Missing or invalid child evidence produces B's
existing durable checked-output rejection with zero parent charge.

The payments remain separate. If C completed and captured 100 TST before B
failed, B can still owe C 100 while A is charged zero. Unknown execution stays
unknown even when the parties separately agree to release its payment.

B's operator can recover an existing child journal using the parent agreement
digest recorded under `STATE/subcontracts/`:

```bash
chio-federated-work subcontract-recover STATE PARENT_AGREEMENT_SHA256
```

This checks the retained B-signed permit and current local relationship, then
runs the isolated buyer's recovery against C. It issues no new permit and does
not rerun the parent call. Retained buyer attempts prevent automatic child
redispatch. A previously unseen response can record an already completed child
expense once, or retain C's signed unknown incident without inventing success.

When B elects the existing mutually agreed release policy for an unknown child,
the local operator can request:

```bash
chio-federated-work subcontract-recover STATE PARENT_AGREEMENT_SHA256 --release-unknown
```

The child remains unknown. Native co-signed release and verified accounting
restore the child reservation once. The command is local; no public recovery
endpoint grants access to B's worker state. A's corresponding parent release
uses the existing Python `resolve` command described in [RESOLUTION.md](RESOLUTION.md).

## Reproduction

Use the locked Python environment documented in [python_buyer/README.md](python_buyer/README.md).
On a Linux host with bubblewrap and user namespaces:

```bash
CARGO_TARGET_DIR=target cargo build --manifest-path examples/federated-work/Cargo.toml --locked
/path/to/venv/bin/python examples/federated-work/subcontract_smoke.py \
  --binary target/debug/chio-federated-work \
  --python-env /path/to/venv \
  --output /tmp/chio-subcontract-run
```

Use a fresh output directory. `--normal-only` runs the successful exchange and
its receiver spending attacks. The full suite also kills B and C, recovers
accounts concurrently, rejects invalid child evidence, exercises a malicious
sandbox worker, and denies unauthorized disclosure before child state exists.
Only explicitly exported public artifacts are suitable for sharing. The role
directories contain private keys, credentials and databases.
