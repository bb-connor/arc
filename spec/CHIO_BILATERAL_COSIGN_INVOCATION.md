# Chio Bilateral Co-Signed Invocation: An in-toto Predicate Proposal

**Status:** v1 (Chio-owned pre-release spec carrying an in-toto WG proposal) | **Date:** 2026-05-04
**Intended audience:** in-toto Attestation WG; OpenSSF AI/ML Security
WG; CoSAI Workstream 4. **Editors:** chio maintainers.

This document specifies the shipped Chio-owned predicate type
`chio.bilateral-cosign-invocation.v1` for **bilateral co-signed runtime
invocations** between two distinct organisational kernels, and carries
the matching in-toto WG proposal that mirrors it. The intent is either
to land chio's bilateral-co-signed invocation semantics in the
in-toto vocabulary or to confirm in writing the structural gap that
motivates the chio-namespaced predicate.

The keywords MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY are to
be interpreted as described in RFC 2119. Canonical JSON serialisation
follows RFC 8785 (JCS). DSSE follows the Secure Systems Lab spec
(`secure-systems-lab/dsse`, envelope and PAE).

---

## 1. Status

- **Version:** v1 (Chio-owned pre-release spec carrying an in-toto WG
  proposal); **Date:** 2026-05-04.
- **Intended audience:** in-toto Attestation WG (primary), OpenSSF AI/ML
  Security WG (secondary), CoSAI Workstream 4 (secondary).
- **Disposition:** Chio ships the Chio-owned predicate type
  `chio.bilateral-cosign-invocation.v1` (section 3) today and proposes
  the matching in-toto canonical URI for adoption by the in-toto WG.
  Implementations switch to the in-toto vocabulary once (or if) it is
  accepted.
- **Engagement contacts named:** Aditya Sirish A Yelgundhalli (in-toto),
  Tom Hennen (SLSA). See section 12.
- **Changelog:** 2026-09: aligned to the shipped verifier.

---

## 2. Motivation

Current in-toto predicates are **artifact-centric**. The SLSA Provenance
predicate (`https://slsa.dev/provenance/v1`) is build-provenance-shaped:
who built which artifact under what configuration. The Runtime Trace
predicate (`https://in-toto.io/attestation/runtime-trace/v0.1`) extends
in-toto into runtime by capturing process, network, and file events
under a single monitor, but its scope is the **builder's own runtime
observability** of a build. Sigstore Rekor anchors single-party DSSE
entries against Fulcio-issued identities and gives a public
transparency log; multi-signature DSSE envelopes are mechanically
permitted (`secure-systems-lab/dsse` protocol allows `(t,n)` thresholds)
but no predicate vocabulary in-toto ships today says "this DSSE envelope
verifies if and only if these two specific organisational identities
both signed the same Statement, each having independently evaluated
their local policy on the underlying invocation."

That is the gap chio addresses. It is not a transparency-log gap and
it is not a build-provenance gap. It is the gap between two parties
**signing the same canonical body** (a statistical accident) and two
parties **independently committing to the same canonical action under
their separate policies** (a verifiable, mechanically-checkable joint
intent). That is the vocabulary this predicate makes expressible;
section 4.4 states exactly which part of it the shipped co-signing
protocol enforces and which part a deployment must add for itself. The existing chio primitive is
[../crates/trust/chio-federation/src/bilateral.rs](../crates/trust/chio-federation/src/bilateral.rs).
The composition unit is the workflow receipt
([../crates/platform/chio-workflow/src/lib.rs](../crates/platform/chio-workflow/src/lib.rs)),
and capability scoping rides on agent passports
([../crates/trust/chio-credentials/src/lib.rs](../crates/trust/chio-credentials/src/lib.rs)).
The cross-vendor agent action attestation use case needs all three properties
at once: bilateral intent, per-action capability scoping, and workflow-receipt
composition.

---

## 3. Predicate Type URI

Two URIs are reserved:

- **Proposed in-toto canonical:**
  `https://in-toto.io/attestation/bilateral-cosign-invocation/v1`
- **Chio-namespaced, the only accepted type:**
  `chio.bilateral-cosign-invocation.v1`

Until the in-toto WG accepts the canonical URI, producers MUST emit the
Chio-namespaced type and verifiers MUST accept only it. A verifier MUST
NOT accept the proposed canonical URI, MUST NOT treat the two as
equivalent, and MUST NOT rewrite one into the other (the predicate type
is part of the signed Statement, so rewriting would break signature
verification). The shipped verifier compares `predicateType` against
the single constant `PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION` in
[../crates/trust/chio-federation/src/bilateral_dsse/types.rs](../crates/trust/chio-federation/src/bilateral_dsse/types.rs)
and rejects every other value with `predicate.type_unrecognised`. If the
WG accepts the canonical URI, this section will name the version at
which producers and verifiers switch together.

Implementation status: `crates/trust/chio-federation` emits and verifies
only the strict predicate type `chio.bilateral-cosign-invocation.v1` for
Chio proof packages. The older `chio.bilateral-signature-slice.v1`
profile remains available as a compatibility artifact for local receipt
binding, but strict Chio verification rejects it as conformance
evidence.

Chio offline package verification is verifier-owned. The proof package
MUST NOT define its own peer pins, accepted ladder refs, action-class
policy, workflow-intersection acceptance hash, revocation checkpoint, BBS
issuer trust, authority lifecycle, or disclosure policy. Those values are
supplied by `chio.federation.verifier-trust-bundle.v1` plus the required
`chio.federation.verification-context.v1`. A verifier MUST reject packages
whose embedded hints disagree with the trust bundle or whose BBS proof
nonce is not bound to the verifier context.

---

## 4. Subject Definition and Normative Data Flow

The in-toto Statement v1 envelope binds a predicate to one or more
ResourceDescriptor subjects. For bilateral co-signed invocations, the
subject is the **content-addressable invocation event itself**, not an
on-disk artifact.

Recommendation: the subject's `digest` MUST be the SHA-256 of the
canonical-JSON (RFC 8785) serialisation of the underlying
`chio_core_types::ChioReceipt` body. The `name` SHOULD be the receipt's
internal identifier (UUID or hash-derived string). Concretely:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "chio-receipt:<receipt_id>",
      "digest": {
        "sha256": "<hex SHA-256 of canonical-JSON ChioReceipt body>"
      }
    }
  ],
  "predicateType": "chio.bilateral-cosign-invocation.v1",
  "predicate": { ... }
}
```

Rationale: anchoring to the receipt body's content hash makes the
predicate refer to a precise invocation event independent of where the
receipt is stored. A verifier resolving the receipt out of a kernel's
audit log can re-hash the body and confirm subject membership without
needing to dereference any external pointer. This mirrors the chio
internal pattern in
[../crates/trust/chio-federation/src/bilateral.rs](../crates/trust/chio-federation/src/bilateral.rs)
where both kernels sign over the canonical bytes of `CoSigningBody`.

### 4.1 Normative Data Flow

This subsection traces one complete cross-organization call, one numbered step
per object, naming who produces it, which store holds it, and the moment it
enters the receiving kernel's state. It is normative: an implementation that
orders these objects differently is not conforming.

**Roles.** Org A is the **origin**: the organization whose agent authored the
call. Org B is the **receiver**: the organization whose kernel admits and
dispatches the tool. In the predicate, `tool_server_a` is always Org A and
`tool_server_b` is always Org B. The receiver is therefore the second party
throughout, which is what section 7 step 17 means when it requires the resolved
receipt's kernel key to be the pinned `tool_server_b` key: the subject of an
inbound statement is a receipt the receiver itself signed.

**Keys.** Each kernel holds two key roles. The **kernel signing key** signs
`ChioReceipt` bodies; its public half is the receipt's `kernel_key`. The
**passport key** signs DSSE pre-authentication bytes; its SHA-256 is both the
envelope `keyid` and the predicate's `passport_key_fingerprint`. For Org B the
two MUST be the same key, because step 17 compares the resolved receipt's
`kernel_key` against the pinned `tool_server_b` passport key and rejects any
difference with `peer.unpinned_or_keyid_mismatch`. For Org A this
specification relates the two in no way, because no Org A receipt is resolved
on this path.

**D1. Pins (out of band, before any call).** Each organization records the
other's kernel identifier, passport public key, and rotation deadline.
Producer: the two operators. Store: each kernel's own pin set. Enters the
receiver's state at pinning time, before any agreement exists.

**D2. Agreement (activation).** A `chio.federation.treaty-scope.v1` record
naming exactly two kernel identifiers, their passport public keys, the digest
of each side's ladder manifest, the action classes in scope, a validity window,
a revocation epoch digest, and a trust bundle digest. Producer: the two
organizations jointly, out of band. Store: each side activates its **own** copy
under evidence kind `treaty_scope`. Enters the receiver's state at activation,
before any call.

**D3. Ladder intersection.** Producer: the receiver, which intersects the two
activated manifests itself, per action class. Store: the receiver, under
evidence kind `ladder_intersection`. Enters at activation. The intersection is
never transferred; each side computes its own.

**D4. Admission bundle.** The receiver's record of the call it is about to
admit: an admission identifier, the request binding (request identifier,
capability identifier, server identifier, tool name, argument digest, origin
kernel identifier, host kernel identifier), the workflow and grant identifiers,
the step index, the destructive flag, the lease identifier, the governance
receipt identifier, and the trust bundle and verification context digests.
Producer: the receiver. Store: the receiver. Enters before the hook runs; the
request carries only the admission identifier and the bundle digest.

**D5. Continuation.** A `chio.federation.cross-kernel-continuation.v1` record
binding the parent receipt digest, the parent session anchor digest, the
capability, the action class, the audience tool, a nonce, the two kernel
identifiers, and a validity window. It carries **no signature**. Producer: the
receiver, on behalf of the source kernel the record names. Store: the receiver,
under evidence kind `cross_kernel_continuation`. Enters before the request.

An implementation MAY mint the continuation in the origin kernel and transfer
it. A receiver MUST NOT accept a continuation that is not already resident in
its own store at the identifier and digest the request presents, and a
continuation is therefore authenticated by residency and digest rather than by
a signature. The shipped reference path mints it in the receiver.

**D6. Subject receipt.** A `ChioReceipt` signed by the receiver's kernel key,
whose `id` equals the predicate's `invocation_id`, whose `tool_name` equals the
predicate's, and whose action parameter hash equals `tool_args_hash.value`.
Producer: the receiver. Store: the receiver's receipt store. Enters **before**
the statement exists, because the statement's subject digest is the SHA-256 of
this receipt's canonical body. This is the receipt this section names as the
subject, and it is not the receipt the receiver writes for this call at the end
of admission (D13).

The subject receipt is a receipt the receiver has already signed, and this
specification requires nothing more of it than the three equalities above. The
shipped reference path signs one such receipt per receiver process and names it
for every call that process serves, so its subject carries no per-call
information: `invocation_id` and the subject digest are the same value on every
call, and the per-call binding is carried entirely by the binding reference of
D9. A deployment that wants the subject to identify the call MUST mint a
distinct subject receipt per call; nothing in section 7 forces that.

**D7. Invocation record.** Section 4.2. Producer: the receiver. Store: the
receiver, under evidence kind `bilateral_invocation`. Enters before the
request.

**D8. Lineage bundle.** Section 4.3. Producer: the receiver. Store: the
receiver, under evidence kind `receipt_lineage_bundle`. Enters before the
request.

**D9. Statement, first signature.** The receiver builds the in-toto Statement:
the single subject of D6, the predicate of section 5, and the treaty binding
reference whose fields commit to D2, D3, D5, D6, D7, D8 and the request digest.
It canonicalises the Statement (RFC 8785), computes the DSSE pre-authentication
encoding, and signs those bytes with its own passport key.

**D10. Co-signature.** The receiver sends the origin the tuple (origin kernel
identifier, receiver kernel identifier, pre-authentication bytes, receiver
signature). The origin MUST check that the transport-authenticated peer
resolves, through its own verified directory, to the declared receiver kernel
identifier, and MUST verify the receiver's signature over those exact bytes
before signing. It then returns its own signature over the same bytes. The
origin signs the bytes it was handed and does not re-derive or parse them. The
receiver verifies the origin's signature and assembles the two-signature
envelope. Store: the receiver, under evidence kind `bilateral_dsse_envelope`.
Enters before the request. See section 4.4 for what this second signature
establishes and what it does not.

**D11. Request.** The origin's agent sends the tool call. Its agreement context
carries identifiers and digests only: the agreement identifier and digest, the
intersection identifier and digest, the action class identifier, and for each
of the continuation, the lineage bundle, the invocation record and the envelope
an identifier and a digest. Nothing else about the agreement crosses. A context
carrying any of the eleven refused key names is denied before anything is
resolved, with `request_smuggled_trust_root` or
`request_smuggled_dynamic_trust`.

**D12. Pre-dispatch hook.** The receiver resolves each named artifact out of
its own store by evidence kind and identifier, denies any whose stored digest
differs from the presented one, checks the continuation binds this request and
is inside its window, checks the lineage bundle binds the continuation, checks
the invocation record binds the agreement, intersection, continuation, class,
capability, request digest and lineage statement, verifies the envelope's two
signatures against the public keys the **agreement** carries, and compares the
binding reference against its own admission bundle and its own resolved
artifacts. It then consumes the continuation: an `INSERT OR IGNORE` into one table keyed
by the continuation identifier, where an insert that changed no row is the
replay denial `chio_treaty_continuation_replay`. A later pre-dispatch denial
releases that row, scoped to the admission that took it, so a rejected call
does not burn a continuation the origin will retry. Once dispatch commits, the
row stays.

**D13. The receiver's receipt for this call.** Built from the admitted inputs
after output checks, rechecked against them, signed with the receiver's kernel
key, and persisted before the caller sees a result. Producer: the receiver.
Store: the receiver. It is a different object from D6 and no admission path
resolves it.

**What the pre-dispatch hook verifies** is the statement of D9 and D10. Its
subject is the receiver's own receipt (D6), not the peer's. It is never carried
on the wire: the request names it by identifier and digest, and the receiver
resolves it out of a store the receiver itself wrote.

**The outbound co-signature.** After persisting D13, the receiver asks the peer
to co-sign a statement whose subject is D13's digest. This is not optional in
the shipped reference kernel: it runs on every federated request, immediately
after the step-7 receipt is durable, and a co-sign it cannot complete fails the
response. A federated request with no cosigner installed, an admitted peer
snapshot that does not match the origin, and a non-deny federated receipt with
no verified treaty material are each an error that aborts the caller's response
path rather than shipping a receipt without the remote signature. A federated
request denied before treaty admission ran is recorded single-signed, because
it dispatched no cross-organization outcome to co-sign.

That object is nevertheless an after-the-fact acknowledgement. It is minted
after the dispatch it describes, no admission path resolves it, and a
conforming implementation MUST NOT treat its presence or absence as an
admission input. It gates the response, never the dispatch. It is the inbound
statement of D9 and D10, never the outbound one, that any property about what a
receiver dispatched can quantify over.

### 4.2 The Invocation Record

The **invocation record** is the receiver-owned object the pre-dispatch hook
resolves by identifier and against which it compares the binding reference's
`consistency_model`, `outcome_sha256`, `local_receipt_sha256`,
`remote_receipt_sha256` and signer order. It is distinct from the subject
receipt that section 7 steps 17 to 19 resolve: the record is what the receiver
stores about the invocation, the receipt is what the receiver signed about it.
The record's type is `chio.federation.bilateral-invocation.v1` and its fields
are:

| Field | Meaning |
| --- | --- |
| `schema` | `chio.federation.bilateral-invocation.v1`. |
| `invocation_id` | Identifier under which the receiver stores the record. |
| `treaty_id` | The agreement (D2) this call runs under. |
| `ladder_intersection_sha256` | Digest of the intersection (D3) the receiver computed. |
| `continuation_sha256` | Digest of the continuation (D5). |
| `lineage_statement_sha256` | Digest of the one lineage statement (D8) that binds this call. |
| `action_class_id` | The action class in the intersection. |
| `consistency_model` | The class's consistency model. |
| `capability_id` | The capability the call exercises. |
| `request_sha256` | Digest of the canonical tool arguments. |
| `outcome_sha256` | The subject receipt's `content_hash`. |
| `local_receipt_sha256` | The parent receipt the continuation names, which is the lineage bundle's root. |
| `remote_receipt_sha256` | The subject receipt (D6), which is the lineage bundle's leaf. |
| `signer_kernel_ids` | Exactly the two agreement participants, in agreement order. |

Producer: the receiver. Store: the receiver, under evidence kind
`bilateral_invocation`. It enters the receiver's store at D7, before the
request.

The record's digest is taken over the canonical JSON of every field above
**except** `lineage_statement_sha256`. The exclusion is deliberate and not an
omission: the lineage statement carries the record's digest, so covering the
statement's digest in the record's would be circular. The excluded field is
bound instead through the bundle: the hook accepts the record only when some
statement in the resolved lineage bundle carries this record's digest **and**
itself hashes to the value `lineage_statement_sha256` names. A verifier MUST
perform that mutual check; a verifier that resolves the record without it has
left one field unbound.

An action class whose co-signing mode requires two signatures forces the
invocation record into its required-evidence set, so for such a class the record
is mandatory. There is no first-contact case: a call cannot name an invocation
record the receiver has not already minted, and a request naming one that does
not resolve is denied with `chio_treaty_missing_bilateral_evidence` before any
signature is checked.

### 4.3 The Lineage Bundle

The **lineage bundle** is the receiver-owned record chaining this call to the
receipts behind it. Its type is
`chio.federation.receipt-lineage-bundle.v1`, and it carries a bundle
identifier, a root receipt digest, a leaf receipt digest, and a non-empty list
of lineage statements. Each statement carries a statement identifier, a parent
receipt digest, a child receipt digest, the continuation digest, the invocation
record digest, an evidence class, and the source and target kernel identifiers.

The receiver walks the statements for the one whose continuation digest, source
and target kernel identifiers, and parent receipt digest all bind the resolved
continuation; the digest of that statement is what the invocation record's
`lineage_statement_sha256` must equal. If no statement binds, the call is
denied with `chio_treaty_lineage_mismatch`.

Neither decider resolves the root or leaf receipt digest to a receipt. The hook
compares them against the invocation record and the binding reference, and the
conforming verifier never sees the bundle at all. What the bundle establishes
is therefore that the receiver's own records agree on which digests this call
chains to, and nothing about any parent receipt existing: in the reference path
the root digest is the SHA-256 of a per-continuation label rather than of a
receipt. A deployment that needs the parent receipt to exist MUST resolve it
separately.

The walk is the only part of admission linear in the size of an artifact rather
than constant. It is bounded structurally rather than by a declared cap: the
bundle must already be resident in the receiver's own store at the digest the
request presents, so its size is whatever the receiver itself wrote, and a
request cannot enlarge it. A receiver SHOULD nevertheless cap the statement
count it will accept into that store, because a bundle it writes once is walked
on every call that names it.

### 4.4 What the Second Signature Establishes

Section 2 describes the gap this predicate fills as two parties independently
committing to the same canonical action under their separate policies. That is
the vocabulary the predicate makes expressible. What the co-signing protocol of
D9 and D10 establishes is narrower, and this subsection states it exactly,
because a verifier that assumes more than this is assuming something no shipped
check enforces.

The receiver authors the bytes and the peer signs them. It follows that:

1. **Against an adversary holding the peer's passport key, the second signature
   constrains nothing about what the receiver dispatches.** Every field the
   receiver compares at D12 is compared against a record the receiver itself
   wrote. Removing the peer's signature from an otherwise identical envelope
   changes no receiver-side comparison except the envelope signature check,
   which the adversary can satisfy. What the design delivers against a
   compromised peer is attribution, not prevention.

2. **The signature is a liveness and consent gate.** The peer must be reachable
   and willing at D10. A peer that declines to co-sign leaves the receiver with
   no statement to resolve, and a class that requires bilateral evidence then
   denies. This is a stop the peer can exercise without waiting for revocation
   to propagate.

3. **The signature is a durable non-repudiable record** that the peer's
   passport key endorsed these exact pre-authentication bytes, which the
   receiver persists. Conditional on the peer's key custody, the peer cannot
   later deny the endorsement.

4. **Under key compromise, (3) degrades from prevention to evidence.** The
   adversary must exercise the key, and the exercised signature is persisted by
   the receiver over bytes that name the agreement, the class, the capability,
   the request digest and the continuation. That converts a silent abuse into
   one that names a key and a moment, which is what makes detection and
   revocation actionable. It does not stop the call.

5. **The signature is not evidence that the peer evaluated its own policy.**
   The predicate's `policy_evaluation_summary.server_a_verdict` is written by
   the receiver and signed by the peer over bytes the peer does not parse. The
   co-signing protocol transfers pre-authentication bytes and a signature and
   defines no payload parse on the responder. A verifier MUST NOT read
   `server_a_verdict` as evidence of an independent evaluation by Org A. A
   deployment that wants that property MUST specify a responder profile in
   which Org A decodes the Statement and evaluates the named policy before
   signing; no such profile is specified here.

---

## 5. Predicate Body Schema

The predicate is a JSON object with the following JSON Schema (Draft
2020-12). Implementations MUST validate the predicate against this
schema before signature verification.

This schema is the strict CHIO target, not the currently emitted
`chio.bilateral-signature-slice.v1` compatibility profile. A signature
slice MUST NOT be described as conforming to this section unless its
predicate validates against the schema below.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://in-toto.io/attestation/bilateral-cosign-invocation/v1",
  "title": "Chio Bilateral Co-Signed Invocation",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "invocation_id",
    "tool_server_a",
    "tool_server_b",
    "tool_name",
    "tool_args_hash",
    "capability_lease_ref",
    "policy_evaluation_summary",
    "consistency_model",
    "cross_org_visibility",
    "co_sign",
    "timestamp_unix_ms"
  ],
  "properties": {
    "invocation_id": {
      "type": "string",
      "description": "UUIDv4 or canonical-JSON SHA-256 of the underlying invocation event. MUST be globally unique within the federation graph.",
      "pattern": "^[A-Za-z0-9._:-]{1,128}$"
    },
    "tool_server_a": { "$ref": "#/$defs/kernelIdentity" },
    "tool_server_b": { "$ref": "#/$defs/kernelIdentity" },
    "tool_name": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256,
      "description": "Logical tool identifier as known to both kernels. Inclusion here ensures the joint commit is bound to a specific named tool surface."
    },
    "tool_args_hash": {
      "type": "object",
      "additionalProperties": false,
      "required": ["alg", "value"],
      "properties": {
        "alg": { "type": "string", "enum": ["sha256"] },
        "value": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
      },
      "description": "SHA-256 over the canonical-JSON of the tool arguments. The arguments themselves are off-chain; only the hash binds to the predicate."
    },
    "capability_lease_ref": {
      "type": "object",
      "additionalProperties": false,
      "required": ["lease_id", "issuer", "expires_at_unix_ms"],
      "properties": {
        "lease_id": { "type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$" },
        "issuer": { "type": "string", "description": "did:chio of the kernel that minted the lease." },
        "expires_at_unix_ms": { "type": "integer", "minimum": 0 },
        "scope_digest": {
          "type": "object",
          "additionalProperties": false,
          "required": ["alg", "value"],
          "properties": {
            "alg": { "type": "string", "enum": ["sha256"] },
            "value": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
          }
        }
      },
      "description": "Reference to the chio capability under which the action ran. Verifier MUST resolve and confirm non-expiry at the pinned epoch."
    },
    "policy_evaluation_summary": {
      "type": "object",
      "additionalProperties": false,
      "required": ["server_a_verdict", "server_b_verdict"],
      "properties": {
        "server_a_verdict": { "$ref": "#/$defs/policyVerdict" },
        "server_b_verdict": { "$ref": "#/$defs/policyVerdict" },
        "joint_disposition": {
          "type": "string",
          "enum": ["allow", "deny"],
          "description": "Derived joint outcome. MUST equal `allow` only when both kernel verdicts are `allow`."
        }
      }
    },
    "governance_receipt_ref": {
      "type": "object",
      "additionalProperties": false,
      "required": ["receipt_id", "kernel_id", "digest"],
      "properties": {
        "receipt_id": { "type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$" },
        "kernel_id": { "type": "string" },
        "digest": {
          "type": "object",
          "additionalProperties": false,
          "required": ["alg", "value"],
          "properties": {
            "alg": { "type": "string", "enum": ["sha256"] },
            "value": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
          }
        }
      },
      "description": "REQUIRED iff the action class is declared `receipt-backed` in the chio governance ladder manifest (see CHIO_LADDER.md section 3.3). Otherwise OPTIONAL."
    },
    "consistency_model": {
      "type": "string",
      "enum": ["crdt-commutative", "totally-ordered", "quorum-required"],
      "description": "Mirrors CHIO_LADDER.md section 4. The chosen model MUST match the action class declaration in both kernels' ladder manifests."
    },
    "consistency_anchor": {
      "type": "string",
      "enum": ["chio-anchor", "hash-chain", "frost-quorum"],
      "description": "REQUIRED for `totally-ordered` and `quorum-required` consistency models."
    },
    "cross_org_visibility": {
      "type": "string",
      "enum": ["private", "treaty_only", "federated", "public"],
      "description": "Mirrors the ladder. Drives downstream gossip and BBS+ disclosure decisions."
    },
    "co_sign": {
      "type": "string",
      "enum": ["bilateral_required", "bilateral_if_cross_org", "n_of_m"],
      "description": "Restricted to co-sign modes that produce a multi-signature DSSE envelope. `none` MUST NOT appear in this predicate."
    },
    "timestamp_unix_ms": {
      "type": "integer",
      "minimum": 0,
      "description": "Tool-server B's wall-clock timestamp at the moment the joint body was canonicalised."
    }
  },
  "allOf": [
    {
      "if": { "properties": { "consistency_model": { "const": "totally-ordered" } } },
      "then": { "required": ["consistency_anchor"] }
    },
    {
      "if": { "properties": { "consistency_model": { "const": "quorum-required" } } },
      "then": { "required": ["consistency_anchor"] }
    }
  ],
  "$defs": {
    "kernelIdentity": {
      "type": "object",
      "additionalProperties": false,
      "required": ["kernel_id", "passport_key_fingerprint", "alg"],
      "properties": {
        "kernel_id": {
          "type": "string",
          "description": "did:chio identifier of the participating kernel."
        },
        "passport_key_fingerprint": {
          "type": "string",
          "pattern": "^[0-9a-f]{64}$",
          "description": "SHA-256 of the kernel's passport public key, hex-encoded."
        },
        "alg": {
          "type": "string",
          "enum": ["ed25519", "hybrid:ed25519:mldsa65"]
        }
      }
    },
    "policyVerdict": {
      "type": "object",
      "additionalProperties": false,
      "required": ["verdict", "policy_id", "policy_version"],
      "properties": {
        "verdict": { "type": "string", "enum": ["allow", "deny"] },
        "policy_id": { "type": "string" },
        "policy_version": { "type": "string" },
        "rationale_code": { "type": "string", "maxLength": 64 }
      }
    }
  }
}
```

A predicate that fails this schema MUST be rejected before any
signature verification is attempted.

The shipped verifier (`validate_chio_predicate` in
[../crates/trust/chio-federation/src/bilateral_dsse/verify.rs](../crates/trust/chio-federation/src/bilateral_dsse/verify.rs))
enforces this schema with three strict additions: `schema` and
`receipt_canonical_json` MUST be absent (both belong to the compatibility
profile); an OPTIONAL `treaty_binding_ref` object is accepted, with the
fields and cross-checks of section 7 step 23; and `co_sign: n_of_m` is
accepted only when the verifier was handed a verified FROST
authorization (section 6).

---

## 6. DSSE Envelope Shape

This predicate uses the standard DSSE envelope
(`secure-systems-lab/dsse`) with **exactly two signatures** in every
co-sign mode. The verifier rejects any other count with `dsse.malformed`
(section 7 step 8; an empty array is rejected at step 1). In the
`n_of_m` mode the envelope still carries the two kernel signatures; the
quorum is a FROST authorization
(`VerifiedFrostAuthorization` in
[../crates/trust/chio-federation/src/frost/verify.rs](../crates/trust/chio-federation/src/frost/verify.rs))
verified outside the envelope and bound to the predicate by the verifier
(section 7 step 25). DSSE's `(t,n)` threshold semantics are not used.

The serialised envelope:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<Base64(canonical-JSON Statement)>",
  "signatures": [
    {
      "keyid": "<sha256 of tool_server_a passport public key, hex>",
      "sig": "<Base64(Ed25519 signature over PAE)>"
    },
    {
      "keyid": "<sha256 of tool_server_b passport public key, hex>",
      "sig": "<Base64(Ed25519 signature over PAE)>"
    }
  ]
}
```

Signing uses the standard DSSE Pre-Authentication Encoding:

```
PAE("application/vnd.in-toto+json", canonical-JSON Statement bytes)
  = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
```

Both kernels sign the same PAE bytes. Each `keyid` MUST equal the
SHA-256 of the corresponding kernel's Ed25519 passport public key bytes,
hex-encoded (`Keyid::from_public_key`), and MUST equal the
`passport_key_fingerprint` declared for that kernel in the predicate's
`tool_server_a` or `tool_server_b` field. Signatures are matched by
`keyid`; the array order is not significant. Duplicate `keyid` values
are rejected with `dsse.malformed`, and the two pinned keys MUST be
distinct (section 7 step 13). The predicate body names which two keys
MUST appear in the envelope, and the envelope is invalid if either is
absent. The verification contract is therefore a **named set of two
signers**, stricter than DSSE's default "any t-of-n succeed".

---

## 7. Verification Algorithm

Two verifier entry points ship in `crates/trust/chio-federation`:

- `verify_chio_bilateral_dsse_envelope(envelope, key_a, key_b)` in
  [../crates/trust/chio-federation/src/bilateral_dsse/verify.rs](../crates/trust/chio-federation/src/bilateral_dsse/verify.rs)
  is the envelope layer. It takes the two public keys as arguments,
  holds no state, returns `BilateralCoSigningError`, and performs steps
  8 to 14 below.
- `verify_chio_bilateral_invocation(envelope, config)` in
  [../crates/trust/chio-federation/src/bilateral_verifier/cosign.rs](../crates/trust/chio-federation/src/bilateral_verifier/cosign.rs)
  is the conforming verifier. `config` supplies the verifier-owned
  state: the peer pin set, the pinned epoch (`now_unix_ms`,
  `epoch_height`), the revocation oracle, the receipt store, the
  capability lease registry, the action-class table with its
  unknown-class policy, and the governance receipt store. It performs
  steps 1 to 7, calls the envelope layer with the pinned keys, and
  continues with steps 15 to 26. It returns `VerifierError`;
  envelope-layer errors are mapped into it by `map_bilateral_error`
  (section 7.1). `verify_chio_bilateral_invocation_with_frost` is the
  same function with a verified FROST authorization supplied for
  `n_of_m`.

A conforming verifier MUST execute the steps in this order and MUST
abort at the first failure with the code shown. This is the shipped
order: verifier-owned peer pins are consulted before any byte-level
check, and the two Ed25519 signatures are verified after every
structural check on the envelope. The verifier accepts a unanimous
`deny` for audit and dispute review; admission paths additionally
require `allow` (`require_policy_evaluation_allow_admission`).

```text
verify_chio_bilateral_invocation(envelope, config, frost_authorization?):

  -- structural prefix
   1. envelope.payloadType == "application/vnd.in-toto+json"
      and signatures is non-empty                    -> dsse.malformed
   2. Base64-decode envelope.payload; parse the Statement
                                                     -> dsse.malformed (base64)
                                                        statement.malformed (JSON)
   3. predicateType == "chio.bilateral-cosign-invocation.v1"
                                                     -> predicate.type_unrecognised
   4. _type == "https://in-toto.io/Statement/v1"     -> statement.schema_invalid
   5. exactly one subject                            -> statement.schema_invalid

  -- peer pins
   6. pinned_a = peer_pin_set.lookup(pred.tool_server_a.kernel_id);
      keyid(pinned_a.key) == pred.tool_server_a.passport_key_fingerprint
                                                     -> peer.unpinned_or_keyid_mismatch
   7. the same for tool_server_b                     -> peer.unpinned_or_keyid_mismatch

  -- envelope layer:
  -- verify_chio_bilateral_dsse_envelope(envelope, pinned_a.key, pinned_b.key)
   8. payloadType as in step 1; exactly two signatures
                                                     -> dsse.malformed
   9. decode; canonical_json(statement) == payload bytes
                                                     -> statement.malformed
  10. _type and predicateType as in steps 4 and 3    -> statement.schema_invalid
                                                        predicate.type_unrecognised
  11. predicate schema (section 5 and its strict rules); co_sign in
      {bilateral_required, bilateral_if_cross_org}, or n_of_m only when
      a FROST authorization was supplied            -> predicate.schema_invalid
      tool_server_a.alg / tool_server_b.alg != "ed25519"
                                                     -> signature.server_a_invalid / _b_
      a verdict outside {allow, deny}, an empty policy_id or
      policy_version, disagreeing verdicts, or an inconsistent
      joint_disposition                              -> policy.verdict_disagreement
  12. exactly one subject (already checked in step 5), and
      subject[0].name == "chio-receipt:" + pred.invocation_id
                                                     -> subject.digest_mismatch
                                                        (statement.malformed at the
                                                        envelope layer)
  13. key distinctness: pinned_a.key != pinned_b.key and
      keyid(pinned_a.key) != keyid(pinned_b.key)      -> dsse.malformed
                                                        (signer.independence_required
                                                        at the envelope layer)
      no duplicate keyid across signatures           -> dsse.malformed
      pred.tool_server_a.passport_key_fingerprint == keyid(pinned_a.key)
                                                     -> signature.server_a_invalid
      pred.tool_server_b.passport_key_fingerprint == keyid(pinned_b.key)
                                                     -> signature.server_b_invalid
  14. pae = PAE(payloadType, payload bytes);
      a signature with keyid(pinned_a.key) exists    -> signature.server_a_invalid
      then a signature with keyid(pinned_b.key) exists
                                                     -> signature.server_b_invalid
      sig_a decodes to 64 bytes                      -> signature.server_a_invalid
      then sig_b decodes to 64 bytes                 -> signature.server_b_invalid
      sig_a verifies under pinned_a.key over pae     -> signature.server_a_invalid
      then sig_b verifies under pinned_b.key over pae
                                                     -> signature.server_b_invalid

  -- verifier-owned state
  15. for tool_server_a, then tool_server_b: the pinned peer carries a
      ladder manifest reference                      -> ladder.manifest_missing
      and that reference is fresh at pinned_epoch.now_unix_ms
                                                     -> ladder.manifest_stale
  16. revocation_oracle.is_active_at_epoch(fingerprint, pinned_epoch.epoch_height)
      for tool_server_a, then tool_server_b          -> peer.revoked_at_epoch
  17. receipt = receipt_store.resolve(pred.invocation_id); the receipt
      exists, its signature verifies, and receipt.tool_name == pred.tool_name
                                                     -> subject.digest_mismatch
      receipt.kernel_key == pinned_b.key             -> peer.unpinned_or_keyid_mismatch
      pred.receipt_canonical_json absent; pred.tool_args_hash present
      with alg sha256 and a 64-char lowercase hex value
                                                     -> predicate.schema_invalid
  18. receipt.action's parameter hash re-verifies and
      pred.tool_args_hash.value == receipt.action.parameter_hash
                                                     -> subject.digest_mismatch
  19. subject[0].name == "chio-receipt:" + receipt.id and
      subject[0].digest.sha256 == sha256_hex(canonical_json(receipt.body()))
                                                     -> subject.digest_mismatch
  20. pred.policy_evaluation_summary present; server_a_verdict and
      server_b_verdict each in {allow, deny} with non-empty policy_id
      and policy_version; the two verdicts equal; joint_disposition,
      if present, equals them                        -> policy.verdict_disagreement
  21. pred.capability_lease_ref present; lease = lease_registry.resolve(lease_id);
      lease.issuer and lease.expires_at_unix_ms equal the predicate's;
      expires_at_unix_ms > pinned_epoch.now_unix_ms; scope_digest present
      and equal on both sides, or absent on both     -> capability.lease_expired_or_unknown
  22. class = action_classes[pred.tool_name]         -> governance.unknown_action_class
      if class is receipt-backed: pred.governance_receipt_ref present,
      its digest well-formed, the receipt resolves in the governance
      receipt store with the same kernel_id and
      sha256_hex(canonical_json) == digest           -> governance.receipt_required_missing
  23. if pred.treaty_binding_ref present (its shape was already checked
      at step 11, where empty refs are rejected): treaty_id,
      action_class_id, and consistency_model non-empty; every *_sha256
      field 64-char lowercase hex; signer_kernel_ids exactly two
      non-empty distinct ids; lease_refs non-empty;
      request_sha256 == tool_args_hash.value;
      signer_kernel_ids == [tool_server_a.kernel_id, tool_server_b.kernel_id];
      lease_refs == [capability_lease_ref.lease_id];
      governance_refs == [governance_receipt_ref.receipt_id], or empty
      when that ref is absent;
      outcome_sha256 == receipt.content_hash;
      remote_receipt_sha256 == sha256_hex(canonical_json(receipt));
      governance_refs == [resolved governance receipt id] when one
      resolved; lease_refs == [lease.lease_id]       -> predicate.schema_invalid
  24. if pred.consistency_model != "crdt-commutative": treaty_binding_ref
      present with an equal consistency_model; the model is one of
      crdt-commutative, totally-ordered, single-kernel, quorum-required;
      totally-ordered and quorum-required carry a non-empty
      consistency_anchor                             -> predicate.schema_invalid
      reserved: reconciling the anchor against a verifier view and
      checking quorum population are not performed
  25. co_sign binding: bilateral_required and bilateral_if_cross_org
      require that no FROST authorization was supplied; n_of_m requires
      one, a treaty_binding_ref, consistency_model "quorum-required"
      with consistency_anchor "frost-quorum", and an authorization whose
      action class == treaty_binding_ref.action_class_id, scope ==
      treaty_binding_ref.treaty_id, resource == pred.invocation_id, and
      which is current at pinned_epoch.now_unix_ms / 1000; any other
      co_sign value                                  -> predicate.schema_invalid
  26. return VerifiedBilateralCoSignInvocation { statement,
      resolved_receipt, resolved_lease, resolved_governance_receipt,
      joint_verdict, frost_authorization }
```

### 7.1 Error Codes

The stable code is `VerifierError::code()` in
[../crates/trust/chio-federation/src/bilateral_verifier/error.rs](../crates/trust/chio-federation/src/bilateral_verifier/error.rs).
`Display` renders `code: detail`; the detail is diagnostic and not part
of the protocol surface. The following sixteen codes MUST be surfaced
verbatim. Each may be recorded as a `GenericGovernanceCaseKind::Dispute`
finding
([../crates/trust/chio-governance/src/generic.rs](../crates/trust/chio-governance/src/generic.rs)).

| Code | Meaning |
| --- | --- |
| `dsse.malformed` | Wrong `payloadType`; empty or not exactly two signatures; undecodable base64 payload; duplicate signature `keyid`; or, through the operational verifier, two pinned keys that are not distinct. |
| `statement.malformed` | Payload is not parseable JSON or is not canonical JSON (RFC 8785). |
| `statement.schema_invalid` | `_type` is not the in-toto Statement v1 type, or the subject count is not one. |
| `predicate.type_unrecognised` | `predicateType` is not `chio.bilateral-cosign-invocation.v1`. |
| `predicate.schema_invalid` | The predicate fails section 5 or a strict rule of steps 11, 17, 23, 24, or 25. |
| `subject.digest_mismatch` | The receipt is not resolvable or its signature is invalid; `tool_name` or the request hash disagrees with it; or the subject name or digest does not match the resolved receipt body. |
| `peer.unpinned_or_keyid_mismatch` | A kernel id is not pinned, its declared fingerprint disagrees with the pin, or the resolved receipt's kernel key is not the pinned `tool_server_b` key. |
| `peer.revoked_at_epoch` | A pinned passport is not active at the pinned epoch height. |
| `signature.server_a_invalid` | `tool_server_a`'s signature is absent, undecodable, or does not verify; or its `alg` is not `ed25519`; or its declared fingerprint is not the pinned key's keyid. |
| `signature.server_b_invalid` | The same for `tool_server_b`. |
| `policy.verdict_disagreement` | Missing summary, a verdict outside {allow, deny}, an empty `policy_id` or `policy_version`, disagreeing verdicts, or an inconsistent `joint_disposition`. |
| `capability.lease_expired_or_unknown` | Missing `capability_lease_ref`; lease not in the registry; issuer, expiry, or scope digest disagreeing with the registry; or expiry at or before `now_unix_ms`. |
| `governance.receipt_required_missing` | A receipt-backed class lacks `governance_receipt_ref`, or the ref does not resolve, names another kernel, or carries a wrong digest. |
| `ladder.manifest_missing` | A pinned peer has no ladder manifest reference. |
| `ladder.manifest_stale` | A pinned peer's ladder manifest reference is not fresh at `now_unix_ms`. |
| `governance.unknown_action_class` | `tool_name` is not in the verifier's action-class table; the only unknown-class policy is reject. |

**Reserved, not emitted.** `consistency.anchor_unverified` and
`consistency.quorum_underpopulated` are reserved for the anchor
reconciliation and quorum-population checks of step 24. No shipped
verifier emits them: an ordered or quorum predicate without an anchor
fails step 24 with `predicate.schema_invalid`, and quorum membership is
established by the FROST authorization of step 25.

**Envelope-layer codes.** `BilateralCoSigningError::code()` in
[../crates/trust/chio-federation/src/bilateral.rs](../crates/trust/chio-federation/src/bilateral.rs)
is the code surface of the envelope layer and of the co-signing
protocol. It shares `dsse.malformed`, `statement.malformed`,
`statement.schema_invalid`, `predicate.type_unrecognised`,
`predicate.schema_invalid`, `subject.digest_mismatch`,
`signature.server_a_invalid`, and `signature.server_b_invalid` with the
table above and adds:

| Code | Meaning |
| --- | --- |
| `signer.independence_required` | The two signer keys or keyids are identical (step 13). Through the operational verifier this surfaces as `dsse.malformed`. |
| `canonical_json.invalid` | Canonical-JSON encoding failed for a reason no more specific code covers. |
| `peer.unknown` | The co-signing peer is not a trusted federation peer. |
| `peer.expired` | The co-signing peer's rotation window has lapsed; it must re-handshake. |
| `transport.failed` | The co-signing transport failed. |
| `peer.rejected` | The co-signing peer rejected the request. |
| `schema.unsupported` | The co-signing request schema is unsupported. |
| `peer.identity_mismatch` | The bilateral receipt's peer identity does not match the pinned peers. |

`map_bilateral_error` (`bilateral_verifier/error.rs`) converts
envelope-layer errors into `VerifierError` by message prefix: the
subject-name mismatch becomes `subject.digest_mismatch`, verdict
failures become `policy.verdict_disagreement`, and any error without a
recognised prefix, including the signer-independence message and the
protocol codes above, becomes `dsse.malformed`.

### 7.2 Code-Only Rejection Surface

The code of section 7.1 is the whole of the rejection that is part of
this protocol. It is a value of the closed set that `RejectionCode`
([../crates/trust/chio-federation/src/bilateral.rs](../crates/trust/chio-federation/src/bilateral.rs))
enumerates, reachable as `VerifierError::redacted` and
`BilateralCoSigningError::redacted`; the dotted string it renders is what
the two `code()` accessors return, and it names the check that failed and
nothing else.

Everything else a rejection carries is local diagnostic. The `Display`
of either error renders `code: detail`, and the detail names the values
that were compared: presented and expected digests, key fingerprints,
kernel ids, keyids, epoch heights, and policy verdicts. That detail is
written for the operator reading the verifier's own log, on the host that
holds the material already. It is not versioned, not stable across
releases, and not part of the wire contract; an implementation MAY change
any of it without notice, and a peer MUST NOT parse it.

A verifier therefore MUST NOT copy the rendered message, or any value the
message names, into an artifact that leaves the host: a signed receipt, a
co-signed envelope, a governance finding, or an exported verification
report. Such an artifact carries the code and, where its schema requires a
human-readable field, a fixed phrase that does not vary with the material
under verification. This includes the reply frame of the co-signing
protocol itself: a peer that refuses to co-sign returns the code, or a
fixed phrase, and never the rendered message. A rejection that echoed
presented values back to the presenter would make the verifier an oracle
over the material it holds: the sender learns which of its guesses matched
a pinned fingerprint, a receipt digest, or a lease scope, one rejection at
a time. The code alone answers only which check failed, which the sender
already knows it provoked.

The offline buyer verifier is the reference for this rule. Its exported
report
([../crates/trust/chio-attest-buyer-core/src/report.rs](../crates/trust/chio-attest-buyer-core/src/report.rs))
is hashed into the buyer attestation packet, so it is an artifact that
leaves the host: `VerifierFailure::from_error` reduces every failure to
its code, the stage that owns it, and the fixed phrase
`WITHHELD_FAILURE_DETAIL`, and the rendered diagnostic stays with the
local error.

### 7.3 Conformance Relation With the Pre-Dispatch Hook

Two implementations answer whether a cross-organization call may proceed, in
two disjoint code families.

- The **conforming verifier** of this section,
  `verify_chio_bilateral_invocation`, answers offline from verifier-owned
  state: a pin set, a receipt store, a lease registry, a governance receipt
  store, a revocation oracle, an action-class table, and a pinned epoch. It
  returns the dotted codes of section 7.1. It is normative for what an envelope
  means, and it is the implementation a second implementer conforms to.
- The **pre-dispatch hook** answers inline during admission, from the
  receiving kernel's own runtime store, and it is the implementation that
  decides a live call. It answers from the kernel's runtime failure-code set
  and maps every envelope-layer failure to
  `chio_treaty_unverified_required_evidence`.

The relation between them is not identity, and this subsection states it, so
that neither an implementer nor a reader has to infer it. It is held by the
differential corpus at
[../crates/trust/chio-federation/tests/verifier_hook_conformance.rs](../crates/trust/chio-federation/tests/verifier_hook_conformance.rs),
which builds one cross-organization call per input, projects it into both
deciders, and asserts which of four relations holds. The set of divergences the
corpus contains is asserted whole, so a check that moves between the two, in
either direction, on any input the corpus holds, fails it.

**They agree on everything the envelope alone determines.** Media type,
signature count, canonicalisation, predicate type, statement type, subject
count, declared fingerprints against pinned keys, verdict well-formedness and
agreement, and every binding-reference field that is compared against another
field of the same envelope. On each of these an accept is an accept on both
sides and a reject is a reject on both sides; only the code differs, because
the two code families differ.

**Among the inputs the corpus covers, the conforming verifier rejects and the
hook admits in these cases.** Each is a resolution the hook does not perform.

| Case | Verifier code | Why the hook admits |
| --- | --- | --- |
| Subject digest does not match the receipt body | `subject.digest_mismatch` | The hook reads no subject and resolves no receipt. |
| Subject receipt not in the receiver's receipt store | `subject.digest_mismatch` | The hook has no receipt store on this path. |
| Capability lease not in the registry | `capability.lease_expired_or_unknown` | The hook compares `lease_refs` against the lease identifier its own admission bundle names and does not resolve the lease record, so issuer and expiry are not checked here. |
| Governance record not in the store | `governance.receipt_required_missing` | The hook compares `governance_refs` against its own admission bundle and does not re-derive the record's digest. |
| Tool name not in the verifier's action-class table | `governance.unknown_action_class` | The table is verifier-owned and its unknown-class policy is reject. The hook reads the class out of the ladder intersection it computed itself. |
| Peer passport revoked at the pinned epoch | `peer.revoked_at_epoch` | Revocation reaches the kernel through its revocation view, not through this hook. |
| Pinned peer carries no ladder manifest reference | `ladder.manifest_missing` | The hook activates both manifests itself and checks the intersection it stored, not a per-peer manifest reference. |
| Pinned peer's ladder manifest reference is stale | `ladder.manifest_stale` | Freshness is measured against the verifier's pinned epoch, which the hook does not hold; the hook bounds the same material through the validity window of the intersection it stored. |
| Origin's passport key rotated in the agreement but not in the pin set | `peer.unpinned_or_keyid_mismatch` | The hook verifies the envelope under the keys the **agreement** carries, so it admits under the rotated key the pin set has not received. |

The first two are the consequential ones. **The receipt resolution of steps 17
to 19 has no counterpart on the dispatch path**: the hook never resolves the
subject receipt and never reads the statement's subject. A property of the form
"the subject of the admitted statement is the digest of a receipt the receiver
resolved from its own store" is therefore a property of the conforming
verifier, not of the hook. What the hook establishes instead is that every
identifier and digest the request presented resolved, in the receiver's own
store, to the artifact the co-signed binding reference names. A deployment that
needs the full section 7 result on the dispatch path MUST run the conforming
verifier in addition to the hook.

The last row is a divergence of a different kind, and it is the one an operator
has to act on. **The two deciders resolve the participants' public keys from
two different receiver-owned stores.** The conforming verifier takes both from
its pin set, at steps 6 and 7, and compares each declared fingerprint against
the pin. The hook takes both from the activated agreement, by the position of
the kernel identifier in the agreement's participant list, and verifies the two
signatures under those. Both stores belong to the receiver and either can be
ahead of the other: a rotation carried into one and not the other is admitted
by whichever decider holds the key the envelope names, and rejected by the
other. A deployment MUST keep its pin set and its activated agreements in
agreement about every participant's key, or run both deciders on every call.

**Among the inputs the corpus covers, the hook rejects and the conforming
verifier admits in these cases.** Each is over receiver-owned runtime state that
no envelope carries.

| Case | Hook code | Why the verifier admits |
| --- | --- | --- |
| Consistency model below what the action class requires | `chio_treaty_dsse_binding_mismatch` | The verifier has no ladder intersection, so it accepts any model the predicate and its binding reference agree on. |
| Unanimous `deny` | `chio_treaty_policy_denied` | A unanimous deny is a valid statement; the verifier returns it verified for audit and dispute review. Admission is the stricter caller. |
| Agreement not in the store | `chio_treaty_missing_scope` | No agreement record reaches the verifier. |
| Presented agreement digest differs from the store | `chio_treaty_scope_hash_mismatch` | No agreement record reaches the verifier. |
| Action class outside the agreement's allowed classes | `chio_treaty_action_class_not_allowed` | Which classes are in scope is a field of the agreement the receiver activated; the envelope names a class and nothing that decides whether this receiver admits it. |
| Ladder intersection not in the store | `chio_treaty_missing_intersection` | The intersection is computed by the receiver and never transferred. |
| Presented intersection digest differs from the store | `chio_treaty_intersection_mismatch` | The intersection is computed by the receiver and never transferred. |
| Continuation not in the store | `chio_treaty_missing_continuation` | The continuation is authenticated by residency in the receiver's store; the statement names it only by digest. |
| Presented continuation digest differs from the store | `chio_treaty_continuation_hash_mismatch` | The verifier resolves no continuation. |
| Continuation already spent | `chio_treaty_continuation_replay` | Single use is a property of one table in the receiver's store; nothing in the envelope records it. |
| Continuation outside its window | `chio_treaty_continuation_stale` | The continuation is a receiver-owned record the statement names only by digest. |
| Presented action class does not bind the stored continuation | `chio_treaty_continuation_mismatch` | The envelope carries the class identifier and nothing that would let an offline verifier decide whether this receiver admits it. |
| Presented lineage bundle digest differs from the store | `chio_treaty_lineage_hash_mismatch` | No bundle crosses; the verifier never sees one. |
| No lineage statement binds the stored continuation | `chio_treaty_lineage_mismatch` | The walk is over records the receiver wrote. |
| Invocation record not in the store | `chio_treaty_missing_bilateral_evidence` | The record lives only in the receiver's store. |
| Presented invocation record digest differs from the store | `chio_treaty_bilateral_hash_mismatch` | The record is never carried on the wire. |
| Invocation record does not bind the requested dispatch | `chio_treaty_bilateral_mismatch` | The record is compared against the receiver's own admission bundle, which the verifier does not hold. |
| Envelope reference omitted for a class that requires it | `chio_treaty_missing_required_evidence` | Which evidence classes a call must carry comes from the action class in the intersection the receiver stored. A verifier handed an envelope is never in a position to observe that one was not presented. |
| Request carries a refused key name | `request_smuggled_trust_root` | The refusal is over the request's agreement context, which no envelope verifier sees. |

**One binding field is compared by neither.** `admission_report_sha256` is
checked for hex shape and never compared against anything: the receiver
recomputes the digest of its own report and overwrites the field before
signing, because a peer-supplied hash must not sit inside a locally signed
receipt as though the receiver had computed it. A conforming verifier MUST NOT
reject an envelope on this field's value, and an implementer MUST NOT enforce
it. The corpus asserts that both deciders admit when it is substituted, so the
field's non-normative status cannot silently change.

**What the corpus does and does not establish.** It is a set of inputs, not a
proof. Over its forty-five inputs it exercises the accept path, every one of
the sixteen codes section 7.1 requires a conforming verifier to surface, and
nineteen of the twenty-four `chio_treaty_` codes the runtime registry defines
for agreement admission. Both figures are asserted mechanically against the two
code registries, and the five runtime codes no input reaches are named in the
corpus with the reason each is out of its range. The corpus therefore states
how the two deciders relate on the inputs it contains, and states nothing about
inputs it does not contain: it is not a proof that no other input diverges. A
check added to either decider MUST be added to the corpus, and a divergence
discovered outside it MUST be added to the tables above.

---

## 8. Composition With Workflow Receipts

A chio workflow receipt
([../crates/platform/chio-workflow/src/receipt.rs](../crates/platform/chio-workflow/src/receipt.rs))
captures an N-step skill execution as a single signed artifact. When
the steps cross trust boundaries, each step is itself a
bilateral-cosign-invocation predicate. The composition rule:

1. Each step MAY produce one bilateral-cosign-invocation Statement
   (DSSE-enveloped). The Statement's subject is the step's
   `tool_receipt_id`.
2. The workflow receipt's body lists per-step records, each carrying
   the SHA-256 of the corresponding step's bilateral-cosign-invocation
   Statement payload (not just the underlying tool receipt).
3. The workflow receipt is itself a Statement under a separate
   predicate type (provisionally
   `https://in-toto.io/attestation/chio-workflow-receipt/v1`, to be
   specified in a sibling proposal). Its `subject` is the
   canonical-JSON SHA-256 of the
   [`WorkflowReceiptBody`](../crates/platform/chio-workflow/src/receipt.rs).
4. A verifier of the workflow receipt SHOULD verify each referenced
   bilateral-cosign-invocation predicate independently. Failure of any
   one step's predicate verification MUST be surfaced; the workflow
   receipt itself MAY still verify its own signature, but the
   composite assertion "every cross-org step jointly committed" is
   only true when every step-level predicate verifies.

This separation lets verifiers walk the DAG bottom-up: confirm each
joint commit at the leaves, then confirm the workflow receipt's roll-up
signature at the root. The bilateral-cosign-invocation predicate is
the leaf primitive; the workflow-receipt predicate is the composition
primitive.

---

## 9. Composition With Rekor

The DSSE envelope MAY be additionally submitted to a Sigstore Rekor v2
instance for transparency-log evidence. Recommended Rekor entry kind:
`dsse` (Rekor v2's native DSSE entry). The envelope is anchored
verbatim; no chio-specific transformation is required.

This composition is a **free property**. The verification contract in
section 7 does not depend on Rekor inclusion. A Rekor-anchored envelope
gains:

- Public, append-only proof that the envelope existed at the inclusion
  time, defending against retroactive forgery if both kernels' audit
  stores are later compromised.
- A discoverable index for third-party auditors who do not have direct
  access to either kernel's receipt store.

A Rekor inclusion proof MAY be carried alongside the envelope in a
Sigstore Bundle. Verifiers SHOULD treat Rekor inclusion as **additional
evidence**, not as a substitute for the bilateral verification
contract: a Rekor-anchored envelope that fails section 7 is invalid;
a non-Rekor-anchored envelope that satisfies section 7 is valid. Chio
already integrates with Sigstore at
[../crates/trust/chio-attest-verify/src/lib.rs](../crates/trust/chio-attest-verify/src/lib.rs);
the inverse (writing chio receipts into Rekor) is a small extension.

---

## 10. Comparison Table

| Property | bilateral-cosign-invocation/v1 (this proposal) | runtime-trace/v0.1 | slsa-provenance/v1 | single-party DSSE on Rekor |
| --- | --- | --- | --- | --- |
| Subject | content-hash of a runtime invocation event | one or more built artifacts | one or more built artifacts | arbitrary payload |
| Number of signers | exactly two in every mode (`n_of_m` adds a FROST authorization outside the envelope) | one (the monitor's identity) | one (the builder's identity) | one (the signer's identity) |
| Cross-org semantics | yes; two named signers from two distinct kernels | no; monitor is single party | no; builder is single party | no; one signer per envelope |
| Per-action capability binding | yes (`capability_lease_ref`) | no | no (build-config rather than per-action) | no |
| Policy-verdict agreement contract | yes (`policy_evaluation_summary` MUST agree) | no | no | no |
| Workflow composition primitive | yes (sibling workflow-receipt predicate) | no | no (build, not workflow) | no |
| Consistency-model declaration | yes (CRDT / totally-ordered / quorum) | no | no | no |
| Transparency-log anchoring | optional (Rekor v2) | optional | optional | required (by the Rekor model) |
| What it proves | both kernels independently evaluated and jointly committed to the same canonical action under named capabilities | a monitor observed these events during a build | this artifact was produced by this builder under this configuration | this signer signed this payload |
| What it does NOT prove | that any third party observed the action; that the action's effects are durable beyond the kernels' audit stores | cross-org consent; per-action capability scoping | runtime invocation; multi-party intent | multi-party intent; capability scoping; workflow context |

The structural slice that bilateral-cosign-invocation occupies is the
**joint-commit-at-action-time** slice. Sigstore + in-toto + SLSA in
their current form do not occupy it. A multi-signer DSSE envelope on
Rekor is mechanically possible today but lacks the predicate vocabulary
to express what the multi-signing means: a verifier sees two
signatures and has no in-toto-supplied way to know whether they are
two independent assertions or a single joint commit.

---

## 11. Open Questions for the WG

1. **Predicate adoption vs sibling envelope.** Does in-toto want to
   absorb a multi-signer predicate type into its core vocabulary, or
   prefer a sibling envelope that **wraps** Statement and carries the
   multi-signer semantics out-of-band? The former keeps tooling simple;
   the latter keeps the Statement layer minimal.
2. **DSSE threshold vs named-set semantics.** DSSE permits `(t,n)`
   thresholds. This proposal narrows that to a **named set of two
   signers** (signatures matched by the passport fingerprints declared
   in the predicate body; array order is not significant). Should
   in-toto define a recommended "named multi-signer" pattern other
   predicates can reuse?
3. **Subject as event-hash vs file-hash.** This proposal points
   `subject.digest` at the canonical-JSON SHA-256 of a runtime
   `ChioReceipt`. Is a content-hash of an in-memory event a legitimate
   subject, or should runtime predicates declare a side-channel event
   identifier field instead?
4. **Capability-lease referencing.** Is there appetite for an in-toto
   standard "capability reference" sub-type that other runtime
   predicates (and a future runtime-trace v1) could share?
5. **Composition with workflow / DAG predicates.** Does the WG have a
   preferred shape for "Statement that references other Statements as
   composite parts" (Bundle, Manifest, or a new Composition predicate)
   that this proposal should align with?

---

## 12. Engagement Plan

The chio maintainers intend the following next steps:

1. **In-toto attestation issues.** File this proposal as an issue
   against `in-toto/attestation` referencing the canonical URI
   `https://in-toto.io/attestation/bilateral-cosign-invocation/v1` and
   inviting review by Aditya Sirish A Yelgundhalli and the broader WG.
2. **OpenSSF AI/ML Security WG.** Present at the next WG call as a
   "predicate-shape proposal that arose from cross-vendor agent
   action attestation" and solicit cross-pollination with the
   AI/ML-specific predicates the WG is sketching.
3. **CoSAI Workstream 4.** Share with the Secure AI Software Supply
   Chain workstream as adjacent prior art relevant to their runtime
   invocation receipt discussions.
4. **ITE drafting.** If the in-toto WG indicates appetite, draft an
   in-toto Enhancement (ITE) using this document as the seed text,
   carrying it through the standard ITE review process.
5. **Reference implementation.** Keep the chio-namespaced strict predicate
   implementation covered by production tests, then switch emission to the
   canonical URI if the in-toto WG accepts it. The existing
   `chio.bilateral-signature-slice.v1` helper remains compatibility-only and
   must not be treated as strict Chio predicate evidence.

If the WG declines or the discussion stalls, this document remains the written
record of the structural gap that motivates the chio-namespaced predicate.
