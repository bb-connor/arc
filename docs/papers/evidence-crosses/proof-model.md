# Execution model, games, and proofs for receiver-owned admission

This document is the formal companion to the paper. It replaces the informal
property statements of the security section with an execution model, an
adversary oracle interface, an accept predicate written as the conjunction of
the checks the shipped receiver actually runs, four properties stated as games,
and proofs. Where a proof needs a fact the implementation does not give, the
fact is stated as a premise and labelled, not assumed silently.

Three things carry the argument and each is a different kind of object.

1. The **accept predicate** (Section 3) is read off the code. Its definition
   names the functions it comes from, so a reader can check it against the
   implementation rather than against prose.
2. The **completeness of the comparison set** (Section 4) is discharged inside
   the proof, by an enumeration of every leaf the crossing object can carry
   together with a classification that is total by construction. It is a
   classification of what the receiver compares each leaf against, not a claim
   that the leaves it does not compare are unconstrained. The enumeration is
   mechanized in Lean
   (`formal/lean4/Chio/Chio/Treaty/AdmissionBinding.lean`) and executed in Rust
   (`crates/kernel/chio-runtime-core/tests/runtime_treaty_predicate_substitution.rs`).
3. The **reductions** (Section 6) construct the reducing adversary and account
   for the advantage.

Section 8 states, without hedging, the places where this model is weaker than
the paper's current text, and what the paper must say instead.

## 1. Syntax

### 1.1 Primitives and notation

- `H` is SHA-256. `|H| = 256`.
- `J` is the RFC 8785 canonical JSON encoder. `J(x)` is a byte string.
- `D(x) = H(J(x))`, written as a 64-character lowercase hex string when it
  appears in a wire field.
- `Sig`, `Vf` are Ed25519 signing and verification. A key pair is `(sk, pk)`.
- `PAE(t, p) = "DSSEv1" ‖ SP ‖ |t| ‖ SP ‖ t ‖ SP ‖ |p| ‖ SP ‖ p`, the DSSE
  pre-authentication encoding, with lengths in decimal ASCII and `SP` one
  space. In this protocol `t` is always `application/vnd.in-toto+json`.
- `kid(pk) = H(raw(pk))` in hex, the DSSE key identifier.

### 1.2 Receipts

Three preimages of one receipt occur in this protocol, and they are nested
rather than equal. Name them.

- `b_id`, the **identity projection**: the receipt's fields minus `id`, minus
  the signature, and minus the BBS signature
  (`crates/core/chio-core-types/src/receipt/body.rs`, `ChioReceiptIdInput`).
- `b_subj`, which is `b_id` together with `id`, and is what `receipt.body()`
  serializes (same file, `ChioReceipt::body`).
- `r`, which is `b_subj` together with the signature, the optional BBS
  signature, and the optional algorithm tag: the receipt as it travels.

The quantities the protocol carries are then

```
id  = H(J(b_id))
sig = Sig(sk, J({id: id, body: b_id, bbs_signature?}))
```

and three digests appear on the wire, one per preimage:

- `id = D(b_id)`, the receipt identifier;
- `D(b_subj)`, which is what a statement's subject digest carries and what the
  conforming verifier recomputes (`bilateral_verifier/cosign.rs`, and
  `receipt_body_digest_hex` in `bilateral_dsse/verify.rs`);
- `D(r)`, which is what the binding reference's `remote_receipt_sha256` carries
  (`receipt_canonical_digest_hex`).

They are distinct because their preimages are distinct: `b_subj` contains `id`
and `b_id` does not, and `r` contains the signature and `b_subj` does not. In
particular `D(b_subj)` is not `id`, which is the confusion a reader of the
paper's Table 1 can fall into and which Section 8 item 11 asks the paper to
close.

Two further facts about the signing preimage matter later. It is neither
`J(b_subj)` nor `J(r)`: it is the canonical encoding of a three-field object
carrying the identifier, the identity projection, and the optional BBS
signature (`receipt/signing.rs`, `ChioReceiptSigningBody`). And `bbs_signature`
sits inside that preimage while sitting outside `b_id`, so it is covered by the
receipt signature and not by the receipt identifier: two receipts differing
only there share an `id`, and differ in `sig` and in `D(r)`.

### 1.3 Statements

A statement is an in-toto Statement v1 whose predicate type is
`chio.bilateral-cosign-invocation.v1`. Write a statement as a finite map from
leaf paths to values, `S : F -> V`, where `F` is the finite set of leaf paths
that the wire type admits. `F` is enumerated in Section 4; it has 55 elements.
The strict profile refuses two of them outright, so 53 may occur in a strict
statement. The statement studied here carries 49; the other four are leaves the
wire type marks optional and this call omits, and Section 4.3 records what the
receiver does when they are added.

An envelope is `E = (t, p, [(kid_1, s_1), (kid_2, s_2)])` with `p = J(S)`
base64-encoded. The two signatures cover `PAE(t, J(S))`.

### 1.4 Receiver state

The receiving kernel's state at the moment a request arrives is

```
Σ = (sk_R, pk_R, P, A, I, K, C, L, G, X, clock)
```

- `sk_R, pk_R`: the receiver's own passport key pair. `sk_R` is in the trusted
  base.
- `P`: the pin set, a partial map from kernel identifier to public key and
  rotation deadline, established out of band.
- `A`: activated agreements, keyed by agreement identifier. An agreement fixes
  exactly two participant kernel identifiers, their public keys, the allowed
  action classes, a validity window, and a revocation epoch.
- `I`: ladder intersections, keyed by identifier, each carrying per action
  class the mode, the destructive flag, the consistency model, the co-signing
  mode, and the required evidence set.
- `K`: admission bundles, keyed by admission identifier. A bundle carries the
  request binding (request identifier, capability, server, tool, canonical
  argument hash, origin and host kernel identifiers), the lease identifier, the
  governance receipt identifier, and two trust digests.
- `C`: continuations, keyed by continuation identifier.
- `L`: receipt lineage bundles, keyed by identifier.
- `G`: bilateral invocation records, keyed by identifier.
- `X`: co-signed envelopes, keyed by identifier.
- `clock`: the injected clock, subject to ASSUME-OS-CLOCK.

Every one of `P, A, I, K, C, L, G, X` is receiver-owned: the adversary reaches
them only through the delivery oracle of Section 2.3, never by direct write.

### 1.5 Requests

A request `q` carries the tool call (server, tool, arguments, capability,
agent, federated origin kernel identifier) and a governed intent whose context
object carries two sub-objects: `chioAdmission` (admission identifier, bundle
digest) and `chioTreaty`. The extraction function

```
ref(q) = (scopeId, scopeDigest, intersectionId, intersectionDigest,
          actionClassId, contRef?, lineageRef?, invocationRef?, dsseRef?)
```

reads exactly those names from `chioTreaty` and ignores every other key, after
refusing eleven names outright (`trustRoot`, `trustRoots`, `trustBundle`,
`treatyScope`, `ladderManifest`, `signingKey`, `peerDirectory` with
`request_smuggled_trust_root`; `dynamicTrust`, `dynamicTrustBundle`,
`runtimeTrustInput`, `peerDiscovery` with `request_smuggled_dynamic_trust`).
Source: `admission_hook/treaty_ref.rs`, `treaty_ref_from_request`.

## 2. Execution model

### 2.1 Instances

An execution is a single receiving kernel `R` with state `Σ`, one pinned peer
`Q` with key pair `(sk_Q, pk_Q)`, and one activated agreement naming `Q` and
`R`. Concurrency is modelled as interleaved oracle calls against one `Σ`; the
single-store premise this requires is P5 in Section 7.

### 2.2 What the adversary holds

Per the paper's threat model: everything outside the receiving kernel. In this
model that is made precise as possession of `sk_Q`, full control of the
network, full control of every request field, and the ability to present any
artifact it has ever seen. It does not hold `sk_R` and cannot write to `Σ`.

One point deserves to be stated rather than left implicit, and the obvious
argument for it is not the argument that works. The two signatures on an
inbound statement are one from `Q` and one from `R` itself. The comparison that
looks like it establishes this does not: the hook passes
`statement.predicate.tool_server_b.kernel_id` as both the statement's second
participant and as `local_kernel_id`
(`admission_hook/treaty_evidence.rs`, `verified_federation_treaty_material`),
so `verified_treaty.rs`'s `participant_kernel_ids[1] = local_kernel_id` is a
comparison of a value with itself on this path. What does establish it is a
chain of three links, all of them receiver-held.

1. The request binding is built from the live request together with the
   receiver's own `local_kernel_id`, so `binding.host_kernel_id` is the
   receiver by construction.
2. Stage C3 requires `continuation.target_kernel_id = binding.host_kernel_id`
   and requires both of the continuation's kernels to be participants of the
   agreement `R` resolved. The receiver is therefore one of the two
   participants.
3. Stage M1 pins `tool_server_a` to the request's federated origin, which is
   the other participant, and the agreement fixes exactly two. Hence
   `tool_server_b` is the receiver.

The second signature is then verified under the public key the agreement pins
for that participant. That is a statement about which key `R`'s own activated
agreement names for `R`, not about `R` comparing its live signing key against
the statement. The adversary cannot produce a valid inbound envelope on its
own. What it can do is ask `R` to co-sign, which is the co-signing oracle
below. The consequence is Section 6.3: the second signature is a statement
about what `R` has seen, not about what `Q` is entitled to.

### 2.3 Oracle interface

The adversary `A` is a probabilistic polynomial-time algorithm with access to:

- `O_peerSign(m) -> Sig(sk_Q, m)`. Unrestricted. This is the paper's "controls
  the peer kernel and can make it sign anything".
- `O_coSign(S) -> Sig(sk_R, PAE(t, J(S)))` if `Q_cosign(S, Σ)` holds, and
  `bot` otherwise. `Q_cosign` is the receiver's own co-signing guard. The
  implementation reached by this document does not fix `Q_cosign`; it is
  premise P6.
- `O_deliver(kind, id, obj)`. Offers an artifact for storage. `R` stores it
  only if its ingest validation `V_ingest(kind, obj, Σ)` accepts. `V_ingest` is
  premise P7.
- `O_admit(q, E) -> (allow | deny(code), Σ')`. The main oracle: it runs the
  accept predicate of Section 3 against `Σ`, and on allow it consumes the
  continuation and hands verified material to dispatch.
- `O_replay(q, E)`. Sugar for calling `O_admit` again on a previously submitted
  pair. Not a separate power; listed because the single-use game refers to it.
- `O_tick(d)`. Advances `clock` by `d`, subject to ASSUME-OS-CLOCK.

`A` chooses every field of `q`, including `actionClassId`, and every leaf of
`S`. It sees every decision and every failure code.

### 2.4 What "dispatch" means

`O_admit` returns allow together with verified federation material only if the
accept predicate holds. The kernel then dispatches. The games below are stated
over `O_admit` returning allow, which is the last receiver-side event before
the tool runs.

## 3. The accept predicate

`Accept(q, E, Σ)` is the conjunction of the following, in the order the
implementation evaluates them: 47 numbered conjuncts across nine stages. Each
line names the function it is read from. Failure at any line denies with the
code given; the hook maps every envelope-layer failure to
`chio_treaty_unverified_required_evidence`. Stage L is the one an account of
the statement's binding is likely to omit, because it reads no leaf of the
statement, and omitting it is what makes the ordering claim below come out
wrong.

**Stage R, request extraction** (`treaty_ref_from_request`)

- R1. `chioTreaty` is an object and carries none of the eleven refused names.
- R2. The five required identifiers are present, non-empty, and the two
  digests are 64 lowercase hex characters.
- R3. Each evidence reference that is present carries both an identifier and a
  64-hex digest.

**Stage S, store resolution** (`verify_treaty_reference_from_store`)

- S1. `K[admissionId]` exists.
- S2. `A[scopeId]` exists and the digest the receiver recorded beside it when
  it stored it equals `scopeDigest`. This is a stored column, not a
  recomputation; that the column matches the artifact is premise P7. The
  recomputation happens later, at D4, which compares the statement's
  `treaty_scope_sha256` against `treaty_scope_sha256(A[scopeId])` computed on
  the spot (`admission_hook/dsse.rs`).
- S3. `A[scopeId].trust_bundle_sha256 = K[admissionId].trust_bundle_sha256`.
- S4. `I[intersectionId]` exists and `D(I[intersectionId]) = intersectionDigest`.
- S5. Each present evidence reference resolves and its stored digest equals the
  digest the request named.
- S6. If the action class requires lineage or a bilateral record, or if any
  evidence reference is present, then a continuation reference is present.

**Stage C, continuation** (`verify_continuation_evidence`)

- C1. The continuation validates against its schema.
- C2. `issued_at <= clock < expires_at`.
- C3. `capability_id`, `action_class_id`, `target_kernel_id`, `source_kernel_id`
  and `audience_tool` all equal the corresponding receiver-held values from
  `K[admissionId].binding` and `ref(q).actionClassId`, and both kernel
  identifiers are participants of `A[scopeId]`.

**Stage G, lineage and record** (`verify_lineage_bundle_evidence`,
`verify_bilateral_invocation_evidence`)

- G1. If a lineage bundle resolved, some statement in it binds the resolved
  continuation by digest, source, target, and parent receipt digest.
- G2. If an invocation record resolved, it validates, names the same agreement,
  intersection digest, continuation digest, action class, consistency model,
  capability and argument hash as the receiver holds, and its signer set equals
  the agreement's participant set.
- G3. If both resolved, the record's receipt digests equal the bundle's root
  and leaf, and the bundle contains a statement binding the record.

**Stage D, statement** (`verify_treaty_dsse_evidence`, then
`verify_chio_bilateral_dsse_envelope`)

- D1. The payload decodes and parses, and the predicate type is the strict one.
- D2. A policy evaluation summary is present, both verdicts are in
  `{allow, deny}` and equal, any joint disposition agrees with them, and the
  origin verdict is `allow`.
- D3. A binding reference is present.
- D4. The seven always-compared binding leaves equal the receiver-held values
  they name (agreement identifier, agreement digest, intersection digest,
  continuation digest, action class, consistency model, argument hash).
- D5. `tool_args_hash.value` equals the binding reference's `request_sha256`.
- D6. `lease_refs` equals the singleton list of `K[admissionId].lease_id`, and
  `governance_refs` equals the singleton list of its governance receipt
  identifier.
- D7. There are exactly two participants and two signers and the two sets are
  equal.
- D8. The two pinned public keys resolved from the agreement in the order the
  statement's signer list gives are distinct.
- D9. Strict envelope verification: media type; exactly two signatures;
  re-canonicalization reproduces the payload bytes; Statement v1; strict
  predicate type; predicate schema rules (no `schema`, no
  `receipt_canonical_json`, non-empty identifiers, `alg` is `ed25519`,
  fingerprints are 64 hex, `tool_args_hash` is a well-formed sha256 record,
  lease and policy summary present, co-signing mode in the allowed set,
  visibility in the allowed set, binding reference well formed, lease and
  governance and signer lists agree with the predicate's own copies); exactly
  one subject whose name is `chio-receipt:` followed by the invocation
  identifier; both declared fingerprints equal `kid` of the two pinned keys;
  duplicate key identifiers refused; **then** `PAE` is computed, each signature
  is selected by the pinned key's identifier, and both verify.
- D10. If a lineage bundle resolved: the binding reference's
  `lineage_bundle_sha256`, `local_receipt_sha256` and `remote_receipt_sha256`
  equal the bundle's digest, root, and leaf.
- D11. If an invocation record resolved: the binding reference's consistency
  model, `outcome_sha256`, `local_receipt_sha256`, `remote_receipt_sha256` and
  ordered signer list equal the record's.

**Stage A, admission report** (`evaluate_cross_boundary_admission`)

- A1. The agreement and intersection validate and are inside their validity
  windows at `clock`.
- A2. Agreement and intersection agree on agreement identifier, manifest digest
  list, and participant list.
- A3. The named intersection digest equals the recomputed one.
- A4. The action class is allowed by the agreement and present in the
  intersection.
- A5. Every required evidence class is present and verified. A class in
  `bilateral_required` co-signing mode has `bilateral_invocation` forced into
  its required set.

**Stage M, verified material** (`VerifiedFederationTreatyMaterial::verify`)

- M1. The request carries a federated origin, and the first of the two kernel
  identifiers handed to this stage equals it. The second is compared against
  `local_kernel_id`, which on this path the hook supplies from the statement's
  own `tool_server_b` (Section 2.2), so that conjunct does not by itself bind
  the receiver; the predicate's two identity blocks must then equal the two
  identifiers, the two must differ, and their public keys, resolved from the
  agreement, must differ.
- M2. Strict envelope verification runs again on the same envelope and the same
  two keys.
- M3. `tool_name` equals the request's tool name.
- M4. `tool_args_hash.value` and the binding reference's `request_sha256` both
  equal the canonical parameter hash recomputed from the live request
  arguments.
- M5. The policy summary admits (both verdicts `allow`).
- M6. The lease has not expired at `clock` and its issuer is one of the two
  participants.
- M7. The report is accepted, its digest is 64 hex, the co-signing mode is in
  `{bilateral_required, bilateral_if_cross_org}` and equals the predicate's,
  and the binding reference's agreement identifier, agreement digest,
  intersection digest, action class and consistency model, and the predicate's
  own top-level consistency model, equal the report's.
- M8. The peer-supplied `admission_report_sha256` is discarded and replaced
  with the digest of the receiver's own report before anything is signed.

**Stage K, continuation consumption** (`admission_hook.rs`, `evaluate`)

- K1. `consume(continuationId, admissionId)` inserts a row and reports one
  affected row. Zero rows denies with `chio_treaty_continuation_replay`.

**Stage L, local admission report**
(`admission.rs`, `evaluate_runtime_admission_tracked`)

This stage runs **after** K1, and it can deny. It is the part of the decision
that does not read the statement at all, which is why it is easy to leave out
of an account of the statement's binding and why leaving it out makes the
ordering claim false.

- L1. The admission profile carries the supported schema and
  `profile.issued_at <= clock < profile.expires_at`.
- L2. `K[admissionId]` resolves and carries the supported bundle schema.
- L3. If a signed runtime trust input is present it names the profile's
  verifier, validates against the trusted verifier keys, and its floor entry
  records against the receiver's own chain; if trusted verifier keys are
  configured and no trust input is present, the report rejects.
- L4. `K[admissionId].binding.host_kernel_id = profile.local_kernel_id`.
- L5. `K[admissionId].binding` equals the binding rebuilt from the live
  request, field for field: request identifier, capability, server, tool,
  canonical argument hash, origin and host kernel identifiers
  (`admission.rs`, `bundle.binding != input.request`). This is the conjunct
  that makes the tool name and the argument hash receiver-held quantities
  rather than request-held ones, and it is what stages M3 and M4 lean on.
- L6. Where a pheromone policy is configured, its decision is neither deny nor
  escalate.
- L7. If the bundle is destructive it names a lease and a governance receipt,
  and the destructive lease reserves.

On a deny at any of L1 through L7 the hook releases what it reserved, including
the continuation K1 took (`admission_hook.rs`, `release_reservations`). A
release that fails is not retried, and the denial carries
`reservation_release_failed`, which is an ambiguous state rather than a clean
one.

The position of K1 is load-bearing and the paper does not state it. The precise
statement is: **consumption runs strictly after every statement-level
comparison and after both signature verifications (stages R through M), and
before the local admission report (stage L)**. Two consequences follow, and
only the first is the good one.

- A statement that fails any comparison returns before K1 and therefore cannot
  burn a continuation. Garbage cannot deny service to a legitimate call. The
  executed corpus asserts this for all 245 cases: every denial leaves the
  unsubstituted statement admissible afterwards, and every admission makes it
  a replay.
- A valid statement on a request that then fails the local admission report
  does consume, and depends on the compensating release above. Where that
  release fails the continuation's state is ambiguous, and the decision records
  it as such rather than resolving it. The corpus cannot see this, because its
  fixture passes stage L on every case.

## 4. The comparison set, enumerated

`Accept` reads the statement only through the leaves listed below. This is the
step the paper previously discharged with a twenty-case table; here it is an
enumeration with a total classification, and the completeness of the comparison
set is a consequence of the enumeration rather than of the corpus.

### 4.1 The enumeration

`F` is derived from the Rust wire type, not from a hand list and not from a
schema. The repository has no machine-readable schema for the strict predicate:
the only in-tree schema for this predicate family,
`spec/schemas/chio-wire/v1/federation/bilateral-signature-slice.schema.json`,
describes the compatibility profile, enumerates 37 leaves, and carries neither
`tool_args_hash` nor `treaty_binding_ref`. Nothing in this document is
schema-generated, and the paper should not say it is.

What the enumeration is generated from is the type. In Rust it is obtained by
serializing a maximally populated statement built with exhaustive struct
literals and walking it to its scalar leaves, so a field added to the predicate
stops the corpus compiling. In Lean it is the constructor list of an inductive
type, and the classification is a match on that type, so a field added there
stops the classification elaborating until it is classified. The two are not
merely asserted to be the same enumeration: the Rust corpus reads the Lean
module, parses its path and classification matches, and requires them to equal
its own table leaf for leaf, so a leaf added or reclassified on one side fails
the corpus rather than leaving the two silently disagreeing.

`|F| = 55`. The classification assigns each leaf exactly one of seven kinds:

| Kind | Count | Meaning |
| --- | --- | --- |
| `receiverState` | 23 | compared for equality against a named receiver-held value |
| `receiverDomain` | 2 | required to lie in a named receiver-held set that is not a singleton |
| `selfConsistent` | 7 | compared only against another leaf of the same statement |
| `shape` | 6 | constrained to a constant or a fixed domain the receiver holds as code |
| `uncompared` | 11 | compared against nothing the receiver holds |
| `absentRequired` | 2 | refused outright by the strict profile |
| `absentOptional` | 4 | marked optional by the wire type, and not carried by this call |

The 49 leaves this call's statement carries are the first five rows; adding the
four optional leaves gives the 53 a strict statement may carry. Write
`BoundEq = receiverState` (23 leaves), `BoundDom = receiverDomain` (2 leaves),
`Bound = BoundEq ∪ BoundDom` (25 leaves), and `Free = uncompared` (11 leaves).
The split between `BoundEq` and `BoundDom` is load-bearing and Section 4.2 says
why. These counts are mechanized as
`Chio.Treaty.AdmissionBinding.classification_census`.

### 4.2 The bound leaves and what they are compared against

Two kinds of binding live here and conflating them overstates the claim. A
leaf in `BoundEq` must **equal** a value the receiver holds, so an accepted
statement pins it exactly. A leaf in `BoundDom` must lie **inside** a set the
receiver holds, and the set is not a singleton, so an accepted statement pins
it only to the set. There are two of the second kind, and no statement of the
binding property may quantify over them as if they were equalities.

Receiver-state leaves, with the value each must equal:

| Leaf | Receiver-held value |
| --- | --- |
| `predicate/tool_server_a/kernel_id` | the origin kernel identifier of the request (M1), and the agreement's participant set |
| `predicate/tool_server_a/passport_key_fingerprint` | `kid` of the key the resolved agreement pins for that participant |
| `predicate/tool_server_b/kernel_id` | the agreement's participant set; that this participant is the receiver follows from C3 and M1, not from a direct comparison (Section 2.2) |
| `predicate/tool_server_b/passport_key_fingerprint` | `kid` of the key the resolved agreement pins for that participant |
| `predicate/tool_name` | the tool name of the request |
| `predicate/co_sign` | the co-signing mode of the resolved action class |
| `predicate/consistency_model` | the consistency model of the resolved action class |
| `predicate/tool_args_hash/value` | the canonical argument hash of the request |
| `predicate/treaty_binding_ref/treaty_id` | the resolved agreement's identifier |
| `predicate/treaty_binding_ref/treaty_scope_sha256` | `D` of the resolved agreement |
| `predicate/treaty_binding_ref/ladder_intersection_sha256` | `D` of the resolved intersection |
| `predicate/treaty_binding_ref/continuation_sha256` | `D` of the resolved continuation |
| `predicate/treaty_binding_ref/lineage_bundle_sha256` | `D` of the resolved lineage bundle |
| `predicate/treaty_binding_ref/action_class_id` | the resolved action class |
| `predicate/treaty_binding_ref/consistency_model` | the resolved action class's model |
| `predicate/treaty_binding_ref/request_sha256` | the bundle's canonical argument hash |
| `predicate/treaty_binding_ref/outcome_sha256` | the record's outcome digest |
| `predicate/treaty_binding_ref/local_receipt_sha256` | the bundle's root and the record's local digest |
| `predicate/treaty_binding_ref/remote_receipt_sha256` | the bundle's leaf and the record's remote digest |
| `predicate/treaty_binding_ref/lease_refs/0` | the bundle's lease identifier |
| `predicate/treaty_binding_ref/governance_refs/0` | the bundle's governance receipt identifier |
| `predicate/treaty_binding_ref/signer_kernel_ids/0` | the agreement's participant set, and the record's order |
| `predicate/treaty_binding_ref/signer_kernel_ids/1` | the agreement's participant set, and the record's order |

The two `receiverDomain` leaves, with the set each must lie in:

| Leaf | Receiver-held set |
| --- | --- |
| `predicate/capability_lease_ref/expires_at_unix_ms` | the instants strictly later than `clock` (`verified_treaty.rs` denies on `expires_at_unix_ms <= now`) |
| `predicate/capability_lease_ref/issuer` | the agreement's two participant kernel identifiers, as a membership test (`verified_treaty.rs`, `participant_kernel_ids.contains`) |

Both are exercised in both directions. Substituting the lease expiry with a
later instant is admitted and substituting it with an instant in the past is
denied; substituting the issuer with the other participant is admitted and
substituting it with a third identifier is denied. An accepted statement
therefore says of these two leaves only that they fell inside the set, and
`accept_implies_domain_membership` is the form the mechanized claim takes for
them. Reading them as equalities would assert something impossible in the first
case, since a lease expiry equal to the receiver's clock is expired.

Four of the receiver-state leaves are compared only when the admission resolves
the artifact they name: `lineage_bundle_sha256` when a lineage bundle resolved,
and `outcome_sha256`, `local_receipt_sha256`, `remote_receipt_sha256` when a
lineage bundle or an invocation record resolved. A class in
`bilateral_required` co-signing mode has the invocation record forced into its
required evidence (A5), so under that mode the last three are compared on every
admission. The conditionality of `lineage_bundle_sha256` is real and is
exercised: under an action class that resolves no lineage bundle, substituting
it is admitted.

### 4.3 The residual: leaves the receiver compares against nothing

Eleven leaves are compared against nothing the receiver holds. That is not the
same as unconstrained. Each carries a declared shape that the statement-level
gate still enforces, and the residual an adversary who can obtain both
signatures actually chooses is the shape, not the type. The shape column is
therefore part of the claim, not decoration.

| Leaf | Declared shape | Why it is not compared |
| --- | --- | --- |
| `subject/0/digest/sha256` | any JSON string | the receipts are bound through `local_receipt_sha256` and `remote_receipt_sha256`; the admission path never compares the subject digest |
| `predicate/timestamp_unix_ms` | any unsigned integer | the presentation window comes from the lease, the governance record, and the continuation, all receiver-held |
| `predicate/policy_evaluation_summary/server_a_verdict/policy_id` | a non-empty string | the receiver resolves neither party's policy identity |
| `predicate/policy_evaluation_summary/server_a_verdict/policy_version` | a non-empty string | as above |
| `predicate/policy_evaluation_summary/server_b_verdict/policy_id` | a non-empty string | as above |
| `predicate/policy_evaluation_summary/server_b_verdict/policy_version` | a non-empty string | as above |
| `predicate/governance_receipt_ref/kernel_id` | any JSON string | the governance record the receiver acts on is the one its own bundle names |
| `predicate/governance_receipt_ref/digest/alg` | any JSON string | the governance digest is never resolved during admission |
| `predicate/governance_receipt_ref/digest/value` | any JSON string | as above |
| `predicate/consistency_anchor` | any JSON string | the anchor is carried for the peer's own reconciliation |
| `predicate/treaty_binding_ref/admission_report_sha256` | 64 lowercase hex characters | checked for that shape and then overwritten with the digest of the receiver's own report before signing |

Every shape narrower than the leaf's JSON type is exercised in both directions:
a value inside it is admitted, and a declared value outside it is denied. The
empty policy identity and the non-hexadecimal admission report digest are the
two that bite, and they are the reason Corollary 3 below is stated over shapes
rather than over arbitrary replacements.

One further leaf belongs in this accounting although the classification places
it elsewhere. `predicate/cross_org_visibility` is classified `shape` because it
is confined to four declared labels, but inside those four the receiver
compares it against nothing: substituting `federated` for the fixture's value
is admitted. Its residual is a four-value domain rather than a string space,
which is why it is not in the table above, but an adversary chooses it too.

Finally, the residual has an additive half. The four leaves the wire type marks
optional and this call omits are `capability_lease_ref/scope_digest/alg`,
`capability_lease_ref/scope_digest/value`, and the two
`policy_evaluation_summary/*/rationale_code` fields. The strict predicate
validator refuses only `predicate/schema` and
`predicate/receipt_canonical_json` (`bilateral_dsse/verify.rs`,
`validate_chio_predicate`); these four it permits and never reads. Adding each
of them to a doubly signed statement, and adding all four at once, is admitted.
The scope digest is worth naming separately, because its own contract says that
when it is present a lease registry record's scope digest must match it, and
the pre-dispatch hook resolves no lease registry record, so the requirement is
documented and unenforced. The residual an adversary chooses is therefore the
eleven leaves' shapes, the visibility label's four values, and the presence and
content of four leaves nothing validates.

### 4.4 Lemma 1 (comparison-set completeness)

**Lemma 1.** For every `f ∈ F` that a strict statement of this call carries,
exactly one of the following holds: `f` is compared against something the
receiver holds, either for equality or for membership in a receiver-held set;
`f` is constrained only against the statement itself or against a constant;
`f` is compared against nothing the receiver holds. For every `f ∈ F` the
statement does not carry, exactly one of the following holds: the strict
profile refuses `f`; the wire type marks `f` optional and this call omits it.
The classification is total.

*Proof.* Totality is structural. In the Lean development the classification is
a function `classify : Field -> Comparison` defined by a match on an inductive
type whose constructors are exactly `F`, so it is total by exhaustiveness
checking; the trichotomy over the carried leaves and the dichotomy over the
absent ones are then decided by case analysis over the 55 constructors
(`Chio.Treaty.AdmissionBinding.classification_trichotomy` and
`absent_leaves_are_refused_or_merely_optional`, neither of which depends on any
axiom). In the Rust corpus the same enumeration is derived from the wire type
by serializing an exhaustively constructed value, and the classification is
asserted equal to that leaf set in both directions; the Lean enumeration and
the Rust one are asserted equal to each other by the same corpus. QED

Read the third branch as it is stated. It says the receiver compares the leaf
against nothing, not that nothing constrains the leaf. Section 4.3 gives the
shape that does.

**Lemma 2 (accept-set decomposition).** For the shipped predicate of Section 3:
if `Accept(q, E, Σ)` holds then every leaf in `BoundEq` equals the
receiver-held value it names and every leaf in `BoundDom` lies in the
receiver-held set it names. The converse does not hold for the shipped
predicate, and this document does not claim it: D9 requires both signatures to
verify, S1 through S5 require the named artifacts to resolve from `Σ`, C2
requires the continuation to be live, K1 requires it unconsumed, and stage L
must accept, and none of those is a leaf comparison.

The biconditional does hold in the Lean model, where signatures, store
resolution and the local admission report are abstracted away and the statement
gate is named explicitly:
`accept = statementGate ∧ ⋀_{f ∈ F} comparison(f)`, so
`accept` is true exactly when the gate holds and every bound leaf agrees
(`Chio.Treaty.AdmissionBinding.accept_iff_gate_and_comparisons_hold`).

*Proof.* The forward direction over the shipped predicate is by inspection of
Section 3: each conjunct listed there under D4 through D11, M1 through M7 and
C3 is exactly one of the comparisons the classification names, so `Accept`
implies each of them. This is the only direction Theorem 1 clause (i) uses. The
model's biconditional is proved in Lean, from which `accept_implies_binding`,
`accept_implies_domain_membership`, `disagreement_denies` and
`value_outside_domain_denies` follow. That the shipped receiver realizes the
modelled predicate is not proved; it is checked, leaf by leaf, by the executed
corpus of Section 5. That split is deliberate: the biconditional is a theorem
about the model, and the corpus is the evidence that the model is the right
one. QED

**Corollary 3 (residual).** Substituting any leaf in `Free` with a value of its
declared shape leaves the decision unchanged. In the model this is
`residual_substitution_preserves_acceptance`, whose hypothesis is exactly that
the statement gate's verdict does not move; the gate is where the declared
shape lives. The qualification is not a formality: a non-hexadecimal
`admission_report_sha256` and an empty `policy_id` are both denied, and a
statement of this corollary quantifying over arbitrary replacements would be
false of the shipped receiver.

The corpus exhibits the corollary concretely in three ways: substituting at
once every leaf whose single substitution is admitted, which is the eleven free
leaves plus the lease expiry moved further into the future, still admits and
dispatches; adding all four optional leaves at once still admits; and each
declared value outside a leaf's shape is denied.

## 5. The executed corpus

`crates/kernel/chio-runtime-core/tests/runtime_treaty_predicate_substitution.rs`
runs 245 cases against one complete, admissible fixture, which is 490 admission
decisions because each case also re-drives the unsubstituted bundle against the
same store. Each case substitutes one or more leaves with a well-formed value
of the same JSON type generated from the value it replaces, or with a value the
classification declares, or adds a leaf the statement does not carry; it then
re-signs the statement with both participant keys over its own
pre-authentication bytes, asserts both signatures verify over the rewritten
bytes, and drives the pre-dispatch hook. Every denial additionally asserts that
no verified material reached dispatch and that the continuation the statement
named is still unconsumed; every admission asserts the opposite.

| Group | Cases | What it establishes |
| --- | --- | --- |
| Single leaf, lineage and record resolved | 49 generated plus 12 declared probes | each leaf's classification, including the twelve leaves where one value cannot separate a domain constraint, a shape, or a bound from a comparison |
| Single leaf, no lineage bundle | 49 | the conditional comparisons, and that only `lineage_bundle_sha256` differs |
| Every pair inside the binding reference | 120 | no comparison masks another: all 120 pairs over the reference's 16 leaves are denied without dispatch |
| Duplicated leaves rewritten consistently | 8 | the statement's internal agreement checks do not stand in for a comparison against receiver state |
| Optional leaves added to the signed statement | 4 | the additive half of the residual, for the four leaves substitution cannot reach |
| Every admitted leaf at once | 1 | the residual of Corollary 3, twelve leaves in one statement |
| Control | 2 | the unsubstituted statement admits under both evidence profiles |

The twelve declared probes are the cases where the generated value would not
separate two hypotheses. Two of them sit outside a receiver-held domain (a
lease expiry in the past, denied) or inside it at a second point (the other
participant as lease issuer, admitted), which is what distinguishes a domain
from an equality. Five sit outside a leaf's declared shape (a non-hexadecimal
admission report digest, and each of the four empty policy identities and
versions, all denied), which is what distinguishes a shape from no constraint
at all. The remainder pin a second value inside a fixed domain.

The duplicated-leaf group is the one that a single-fault corpus cannot reach.
Six of its eight cases rewrite both copies of a value that appears twice
(consistency model, request digest, lease identifier, governance receipt
identifier, and each signer identifier), so the internal cross-check passes and
only a comparison against receiver state can deny. All six deny. The remaining
two admit, and both are reported in Section 8.

The addition group is the one a substitution corpus cannot reach at all: a leaf
the fixture omits has no value to replace. All four additions are admitted, so
the corpus records what the classification says about them rather than
inferring it from silence.

The corpus also fails closed on drift: the classification must equal the leaf
set of the wire type exactly, in both directions, so a field added to the
predicate fails the corpus until someone classifies it.

## 6. The properties, as games

Throughout, `A` is PPT with the oracle interface of Section 2.3, making at most
`q_a` admission queries, `q_c` co-signing queries, and `q_s` peer-signing
queries.

### 6.1 Game AB (admission binding)

```
Game AB(A):
  (sk_R, pk_R) <- KeyGen; (sk_Q, pk_Q) <- KeyGen
  Σ <- Setup(pin {Q: pk_Q}, activate agreement T over {Q, R})
  A runs with O_peerSign, O_coSign, O_deliver, O_admit, O_tick, and halts
  with a witness w which is either bot or a pair (f, x').
  A wins if some O_admit(q, E) returned allow and, writing S for the
  statement in E,
    (i)  some leaf f in BoundEq has S(f) != val_Σ(f, q), or some leaf f in
         BoundDom has S(f) outside the receiver-held set dom_Σ(f, q), or
    (ii) w = (f, x') with f a digest-valued leaf in BoundEq, x' an object A
         obtained from O_deliver or produced itself, x' != x_f where x_f is
         the object the receiver resolved for f, and S(f) = D(x'), or
    (iii) PAE(t, J(S)) was never signed under pk_R, or
    (iv) the continuation named by S had already been consumed when the
         admission began.
Adv_AB(A) = Pr[A wins].
```

Clause (i) is leaf agreement, and it is stated over the two bound kinds
separately because they are different claims: equality for `BoundEq`,
membership for `BoundDom`. Clause (ii) is artifact identity, and it requires
`A` to **exhibit** the colliding object rather than to have intended one; that
is what makes the reduction below a construction. Clause (iii) is statement
authenticity, and (iv) is freshness of the continuation.

**Theorem 1.** For every such `A`,

```
Adv_AB(A) <= Adv_CR(B_h) + Adv_INJ(B_e) + 2 * Adv_EUF-CMA(B_sig) + Adv_ATOM
```

where `B_h`, `B_e` and `B_sig` are the adversaries constructed below, each
running in time `t_A + O(q_a * |Σ|)`, and `Adv_ATOM` is the probability that
ASSUME-SQLITE-ATOMICITY fails.

*Proof.* By clauses.

**(i) Leaf agreement.** Unconditional. By Lemma 2's forward direction,
`Accept` holds only if every leaf in `BoundEq` equals the receiver-held value
it names and every leaf in `BoundDom` lies in the receiver-held set it names,
so clause (i) has probability zero. This step needs no assumption and no
reduction; what it needs is Lemma 1, which is why the completeness of the
comparison set is discharged inside the proof rather than by a table. It says
nothing about the two `BoundDom` leaves beyond membership, and the game's
clause (i) is stated so that it cannot be read as saying more.

**(ii) Artifact identity.** Construct `B_h`, a collision finder for SHA-256.
`B_h` runs `A`, simulating every oracle honestly (it holds both key pairs it
generated and the whole of `Σ`), and records every object `A` offers through
`O_deliver`. When `A` halts with a witness `w = (f, x')` and wins by clause
(ii), `B_h` reads `x'` from the witness and takes `x = x_f`, the object its own
simulated `Σ` resolved for `f`, so both objects are in `B_h`'s hands rather
than in `A`'s intent. Acceptance gives `S(f) = D(x)`, because `f` is in
`BoundEq` and the receiver-held value it names is the digest of the object the
receiver resolved; the win condition gives `S(f) = D(x')` and `x != x'`. Hence
`D(x) = D(x')` with `x != x'`.
If `J(x) != J(x')` then `(J(x), J(x'))` is a SHA-256 collision and
`B_h` outputs it. If `J(x) = J(x')` with `x != x'` then the canonical encoder
is not injective on that pair, and `B_e` outputs it; ASSUME-CANONICAL-JSON is
the premise that this cannot happen inside its stated domain, and premise P1 in
Section 7 is the part of that domain the implementation does not enforce.
`B_h` and `B_e` succeed exactly when `A` wins by clause (ii), so that clause
contributes `Adv_CR(B_h) + Adv_INJ(B_e)`.

Requiring the witness is what makes this a reduction rather than a gesture. An
adversary that merely believed `S(f)` denoted some other object, without being
able to produce it, would leave `B_h` with nothing to output, and the `Adv_CR`
term would be unearned.

**(iii) Statement authenticity.** Construct `B_sig`, an EUF-CMA adversary.
`B_sig` receives a challenge public key `pk*` and a signing oracle. It flips a
bit `c` and plants `pk*` as `pk_R` if `c = 0` and as `pk_Q` if `c = 1`,
generating the other key pair itself. It simulates `A`'s oracles: `O_coSign`
and `O_peerSign` are answered with its own signing oracle when the key in
question is `pk*`, and with the generated key otherwise. If `A` wins by clause
(iii), then the accepted envelope carries a valid signature under `pk_R` on
`PAE(t, J(S))`, and by assumption that message was never queried to
`O_coSign`; in the branch `c = 0` that message and signature are a valid
EUF-CMA forgery. The branch is correct with probability `1/2`, so
`Pr[clause (iii)] <= 2 * Adv_EUF-CMA(B_sig)`. The same reduction covers a
forgery under `pk_Q` in the branch `c = 1`, which is why the bound is stated
with the factor 2 over a single challenge key rather than as a sum over two
independent games.

Two caveats travel with this step and neither is cosmetic. First, `A` holds
`sk_Q` by hypothesis, so no forgery under `pk_Q` is ever needed: the origin
signature is not an unforgeability claim in this threat model, and the term
above is vacuous for `c = 1`. Second, the `pk_R` term is only as strong as
`Q_cosign`: what it establishes is that the receiver signed these exact bytes
at some earlier time, not that the receiver intended this dispatch. Section 6.3
states what remains.

**(iv) Continuation freshness.** Stage K1 inserts on a primary key and reads
the affected row count. Under ASSUME-SQLITE-ATOMICITY exactly one of any set of
concurrent inserts creates the row and every other reports zero and denies, so
clause (iv) requires that assumption to fail. Its contribution is `Adv_ATOM`,
which is not a cryptographic term and is not reducible here. Premise P5 records
that this argument is about one store.

Summing the four clauses gives the bound. QED

**What Theorem 1 does not say.** It does not say that the statement's subject
is the digest of a receipt the receiver holds. The admission path does not
compare the subject digest; see Section 8. It does not say anything about
leaves in `Free`, nor about the four optional leaves an adversary may add. For
the two leaves in `BoundDom` it says only that they fell inside a receiver-held
set. It does not say the peer authorized anything. And it is a statement about
stages R through M and K: a request that clears all of them can still be denied
at stage L, after the continuation has been consumed.

### 6.2 Game RL (receiver locality)

```
Game RL(A):
  A outputs two requests q0, q1 with ref(q0) = ref(q1) and the same
  chioAdmission sub-object, differing arbitrarily elsewhere in chioTreaty.
  A wins if O_admit(q0, E) and O_admit(q1, E) resolve different artifacts
  from Σ.
```

**Theorem 2.** `Adv_RL(A) = 0`.

*Proof.* Structural, and stronger than the paper's argument. `ref` reads a
fixed finite set of names from the `chioTreaty` object and ignores every other
key (`treaty_ref_from_request`). Store resolution is a sequence of total
lookups keyed by the identifiers in `ref(q)` together with the admission
identifier the request carries in `chioAdmission`, which is the key for S1,
against `Σ`, followed by digest equality against `Σ`'s own content. The game
fixes both, which is why it requires the two requests to carry the same
`chioAdmission` sub-object as well as the same `ref`. Hence the resolved
artifacts are a function of `(Σ, ref(q), admissionId(q))` alone, and the two
requests give the same artifacts. The
eleven refused names are therefore not what makes locality true; they make a
request that attempts to carry trust fail loudly rather than be silently
ignored, which is a different and weaker claim than the paper makes. QED

The premise this needs is P8: no other component reads the same context object
during admission. This document verified it only for the treaty path.

### 6.3 Game ACC (peer accountability), and what the second signature buys

The paper's threat model gives the adversary `sk_Q`, and the paper declines to
assume the two keys are independently held. Under those two statements no
property about `Q`'s intent is available, and the second signature contributes
nothing to Game AB beyond what `R`'s own state already gives. That is worth
stating as a definition rather than leaving as an absence.

```
Game ACC(A), honest-peer variant:
  As Game AB, except A does not hold sk_Q and instead has an oracle
  O_peerSignHonest(S) that signs only statements S for which the peer's own
  guard Q_peer(S) holds.
  A wins if O_admit(q, E) returns allow for a statement S with
  Q_peer(S) = false.
```

**Theorem 3.** In the honest-peer variant, `Adv_ACC(A) <= Adv_EUF-CMA(B_sig)`
with `B_sig` as in Theorem 1 restricted to the `c = 1` branch.

*Proof.* Acceptance requires a valid signature under `pk_Q` on
`PAE(t, J(S))`, and by hypothesis `O_peerSignHonest` never produced one for a
statement failing `Q_peer`. A win therefore yields a forgery. QED

Theorem 3 is the property that makes the second signature worth carrying, and
it holds only under an assumption the paper currently declines to make. The
honest formulation is: in the paper's threat model, the second signature is a
non-repudiable record that the peer's key was used on these bytes, which is an
audit property, not an authorization property. Section 8 says how the paper
should phrase this.

### 6.4 Game SU (single use)

```
Game SU(A):
  A wins if two distinct O_admit queries both return allow with the same
  continuation identifier bound.
```

**Theorem 4.** `Adv_SU(A) <= Adv_ATOM`, under premise P5 (one store, one
coordinator).

*Proof.* Stage K1 inserts a row keyed by the continuation identifier and
denies on zero affected rows. Release deletes only a row keyed by both the
continuation identifier and the admission identifier that took it, and runs
only when a later pre-dispatch step denies, so no admission frees another's row
and no post-dispatch path frees one. Two allows with the same identifier
therefore require two successful creating inserts on one primary key. Note that
this argument does not need K1 to be last: it needs the insert to be on a
primary key and the release to be keyed by the taker. QED

The ordering of K1 answers a different question, and only half of it. Because
consumption runs after all of stages R through M, a statement that fails any
comparison cannot burn a continuation, so an adversary cannot deny service to a
legitimate call by presenting garbage that names its continuation. Because
consumption runs before stage L, a valid statement on a request that then fails
the local admission report does burn one, and gets it back only through the
compensating release; where that release fails the continuation is left in a
state the decision records as ambiguous. Two further gaps stay open: an
adversary may guess or learn a continuation identifier and present a **fully
valid** statement for it, which is premise P2, and an adversary that can drive
a request to a stage L denial repeatedly is exercising the compensating release
repeatedly.

### 6.5 Game AUD (audience binding)

```
Game AUD(A):
  Σ_R and Σ_R' are two receivers. A obtains a statement S that Σ_R admits.
  A wins if Σ_R' also admits S for some request of A's choosing.
```

**Theorem 5.** `Adv_AUD(A) <= Adv_AB(A restricted to Σ_R')`, and the win
requires `Σ_R'` to have pinned the same two keys, activated an agreement with
the same identifier and the same canonical content, resolved the same
intersection, hold the same continuation unconsumed, and hold the same
invocation record.

*Proof.* Each conjunct is a bound leaf compared against `Σ_R'`'s own state,
with one link that has to be drawn carefully. `treaty_id` and
`treaty_scope_sha256` are compared against the agreement `Σ_R'` resolved,
`ladder_intersection_sha256` against the intersection, and
`continuation_sha256` against the continuation. Any difference contradicts
Lemma 2's forward direction.

The identity of the receiver enters by the chain of Section 2.2 rather than by
a direct comparison of `tool_server_b` against `Σ_R'`'s own identity. Stage C3
forces the continuation's target to be `Σ_R'`'s own `host_kernel_id` and forces
both of its kernels to be participants of the agreement `Σ_R'` resolved; stage
M1 pins `tool_server_a` to the request's federated origin; the agreement fixes
exactly two participants. So `Σ_R'` admits only if it is itself the second
participant of the agreement it resolved, and the second signature verifies
under the key **that agreement** pins for that participant. Audience binding is
therefore a consequence of agreement activation at `Σ_R'`, not of `Σ_R'`
comparing its live key against the statement, and a deployment that activates
an agreement naming a key it does not hold weakens this theorem accordingly.

The case the paper's argument does not cover is a single receiver holding
several agreements over the same pair of kernels: that case is covered here,
because `treaty_id` and `treaty_scope_sha256` are both bound, and the agreement
is resolved from the request's identifier and then digest-checked against `Σ`,
so two agreements over the same pair are separated whenever their canonical
content differs. QED

### 6.6 Cross-protocol separation

A lemma the paper needs and does not state. The receiving kernel signs receipts
with the same Ed25519 key it co-signs statements with: the signature-slice
profile requires the embedded receipt's `kernel_key` to equal Org B's passport
key, and the strict path resolves the second signer to the receiving kernel.
A first-byte argument separating receipts from DSSE is not enough on its own,
because that key signs at least three preimage families and two of them are
JSON objects.

The three families this document traced are:

- **RSIGN**, the receipt signing preimage, `J({id, body, bbs_signature?})`
  (`receipt/signing.rs`, `ChioReceiptSigningBody`);
- **COSIGN**, the dual-signed receipt body,
  `J({schema, receiptCanonicalJson, orgAKernelId, orgBKernelId})`
  (`bilateral.rs`, `CoSigningBody`);
- **PAE**, the DSSE pre-authentication encoding of a statement.

**Lemma 6.** No byte string is a preimage of two of RSIGN, COSIGN and PAE.

*Proof.* Two steps, and each is a property of the encodings rather than of a
domain separation tag.

PAE against the other two: a canonical JSON object encoding begins with the
byte `{`, and a DSSE pre-authentication encoding begins with the literal
`DSSEv1`. The languages are disjoint in their first byte.

RSIGN against COSIGN: both are canonical encodings of JSON objects, so if their
byte strings were equal their key sets would be equal, because RFC 8785 emits
every member key of the object in codepoint order and emits no key the object
does not have. RSIGN's key set is `{id, body}` or
`{bbs_signature, id, body}`; COSIGN's is
`{schema, receiptCanonicalJson, orgAKernelId, orgBKernelId}`. The two are
disjoint, so the key sets differ, so the byte strings differ. Concretely they
diverge at the first key: RSIGN's first key in codepoint order is
`bbs_signature` or `body`, and COSIGN's is `orgAKernelId`. QED

Lemma 6 is what rules out reinterpreting one signed object as another. It
covers the three families this document traced; premise P10 records that the
full set of preimage families a kernel passport key signs across the workspace
was not enumerated here, and that the lemma's method, not its instance list, is
what a deployment must re-run when a fourth family is added.

## 7. Premises

These are facts the proofs use that the implementation reached by this document
does not establish. Each is stated so that a reader can check it against a
deployment.

- **P1 (canonical domain over tool arguments).** ASSUME-CANONICAL-JSON's stated
  domain is strings, bounded integers, finite arrays, and ordered objects, and
  excludes floats. A receipt body carries `action.parameters`, which is
  arbitrary tool arguments chosen by the adversary. Theorem 1's step (ii) needs
  the encoder to be injective on the objects actually hashed. Either the
  parameter object must be restricted to the assumption's domain before
  hashing, and the restriction enforced at a named point, or the assumption
  must be widened and the wider claim proved. This document does not resolve
  it; it records that the injectivity step has this precondition.
- **P2 (continuation unpredictability).** The continuation is minted by the
  origin, which the adversary controls. Single use is a property of the table,
  not of the identifier. If identifiers are predictable, an adversary that can
  produce a valid statement can pre-consume a future identifier. The protocol
  needs an explicit unpredictability assumption on continuation identifiers, or
  an argument that pre-consumption is not reachable.
- **P3 (continuation distribution).** The receiver resolves the continuation by
  identifier against its own store, so a continuation minted by the origin must
  reach the receiver's store by some path. That path is the delivery oracle and
  its validation `V_ingest` (P7). Receiver locality in the form of Theorem 2 is
  about the admission path and says nothing about the ingest path.
- **P4 (federated origin classification).** ASSUME-FEDERATED-ORIGIN-CLASSIFICATION
  places a classifier at the receiving edge. A request misclassified as local
  never reaches any check in this document. The classifier is therefore inside
  the trusted base, and the model above assumes it correct.
- **P5 (one store, one coordinator).** Single use and the atomicity term in
  Theorem 1 are properties of one primary-key table under one coordinator. A
  replicated or failed-over receiver is outside this model.
- **P6 (co-signing guard).** `Q_cosign`, the condition under which the receiver
  will co-sign a statement, is not fixed by the material read for this
  document. Theorem 1 step (iii) is only as strong as that guard.
- **P7 (ingest validation).** `V_ingest`, the validation the receiver applies
  before storing a delivered artifact, is likewise not fixed here. Every store
  lookup in stage S assumes the stored artifact is one the receiver accepted.
- **P8 (sole reader of the context object).** Theorem 2 assumes no other
  component reads the `chioTreaty` object during admission.
- **P9 (clock tolerance).** ASSUME-OS-CLOCK is parameterized by an operator
  tolerance that is never instantiated. Stages C2, A1, L1 and M6 are windows
  evaluated against that clock.
- **P10 (signing-preimage families).** Lemma 6 separates the three preimage
  families this document traced. The complete set of families signed under one
  kernel passport key was not enumerated: the workspace has many callers of the
  canonical signing API, most of them under other keys. A deployment that adds
  a fourth family signed under the passport key must re-run Lemma 6's argument
  for it, which for a JSON-object family means exhibiting a required key the
  other families do not have.

## 8. Where this model is weaker than the paper's current text

The following are differences between what the artifact establishes and what
the paper says. Each is stated as the correction the paper should make.

1. **The subject digest is not compared.** The paper's admission binding
   property says "the subject of `S` is the digest of a receipt the receiver
   resolved from its own store". The pre-dispatch hook does not check this. The
   strict verification path checks the subject's *name* against the invocation
   identifier and never compares the subject's digest against anything; the
   receipt binding is carried by `local_receipt_sha256` and
   `remote_receipt_sha256`, which are compared against the lineage bundle and
   the invocation record. The corpus confirms it: substituting
   `subject/0/digest/sha256` is admitted and dispatches. The conforming
   verifier does resolve the receipt and compare the subject digest at its
   steps 17 to 19, but the paper itself says the hook is what decides a live
   call. The property must either drop that clause for the hook, or the hook
   must compare the subject digest.

   The second option is not a one-line change and should not be offered as
   one. `RuntimeAdmissionStore` (`chio-runtime-core/src/store/traits.rs`) has
   no receipt lookup at all, and the binding reference cannot stand in for one:
   `local_receipt_sha256` is `D(r)`, a digest of the whole canonical receipt,
   while the subject digest is `D(b_subj)`, over `receipt.body()`. They are
   digests of different preimages and comparing one against the other is not a
   check, it is a type error in disguise. Closing the gap means giving the
   admission hook a receipt-by-identifier capability, which widens a store
   trait that was made narrow on purpose. The honest choice is between paying
   that cost and dropping the subject clause from the property for the hook,
   saying instead that the receipt binding is carried by
   `local_receipt_sha256` and `remote_receipt_sha256` through the lineage
   bundle and the invocation record.
2. **The invocation identity is not bound to the receiver's record either.**
   In the hook, the predicate's `invocation_id` is checked only against the
   subject name, which is derived from it. Rewriting both consistently is
   admitted. So a statement the hook accepts for this call may name any
   invocation identifier. Nothing in the decision depends on it, but the
   archived statement is then an audit record whose own identifier the receiver
   never checked.

   Items 1 and 2 have one cause, and naming it is the useful form of both.
   The conforming verifier does what the property describes: it resolves the
   receipt by invocation identifier from its own receipt store, checks that
   receipt's signature and kernel key, and then compares the subject name and
   the subject digest against the receipt it resolved
   (`bilateral_verifier/cosign.rs`). The hook never resolves a receipt by
   invocation identifier at all. That single missing step is the whole of the
   divergence between the two decision families on this point, and it is what
   the paper's admission binding property assumes has happened.
3. **Ten leaves outside `admission_report_sha256` are also uncompared, and
   four more can be added.** The paper names one uncompared field. There are
   eleven. The nine that are not the admission report digest or the subject
   digest are the two policy identities, the two policy versions, the
   governance kernel identifier, the governance digest and its algorithm, the
   consistency anchor, and the statement timestamp. None is used in the
   decision; all are doubly signed and archived. Beyond them, four leaves the
   wire type marks optional are permitted, never validated, and never read: the
   two halves of the lease scope digest and the two policy rationale codes.
   Adding them to a doubly signed statement is admitted. The paper should
   enumerate all of these with their declared shapes and say what an auditor
   may conclude from them, which is: nothing, unless the auditor independently
   trusts both signers. It should also say that
   `capability_lease_ref.scope_digest` carries a normative requirement of its
   own, that a lease registry record's scope digest must match it, which no
   pre-dispatch check enforces because the hook resolves no registry record.
4. **The completeness claim's scope.** The corpus previously covered fifteen
   fields of one sub-object, one at a time. The predicate type carries 55
   leaves; the strict profile refuses two, so 53 may occur in a strict
   statement, and the statement under study carries 49. The paper should say 49
   carried out of 53 possible and cite the enumeration, not 15 and cite a
   table, and it should say the enumeration is derived from the Rust wire type
   rather than from a schema, because the only in-tree schema for this
   predicate family covers the compatibility profile and enumerates 37 leaves.
   The binding-reference corpus the paper cites is now 22 cases rather than 20,
   so the derived case-count macro moves with it; its own arithmetic is 16
   substitutions, two of the new kind, three conditional cases, and one
   control.
5. **Receiver locality is stronger than the paper's argument and weaker than
   its statement.** The denylist of eleven names does not establish
   independence from request content. What establishes it is that extraction
   reads a fixed set of names and ignores the rest (Theorem 2). The paper
   should make that the argument and demote the denylist to what it is, a loud
   failure for requests that try to carry trust.
6. **What the second signature buys.** In the paper's own threat model the
   origin signature is not an unforgeability claim, because the adversary holds
   the origin key. The property the second signature gives is Theorem 3, which
   needs an honest-peer premise the paper declines to make. The paper should
   either state that premise and the accountability property it buys, or say
   plainly that the origin signature is an audit record rather than an
   authorization input. The rejection code named for signer independence should
   be renamed after what it checks, which is key distinctness.
7. **The position of consume.** The paper does not state where continuation
   consumption sits. The statement it should make is the one the code supports
   and no more: consumption runs after every statement-level comparison and
   after both signature verifications, and before the local admission report.
   The first half is what rules out burning a legitimate continuation with a
   statement that would later fail a comparison, and it should be stated. The
   second half is the part that must not be omitted: a valid statement on a
   request that fails the local admission report does consume, and gets the
   continuation back only through a compensating release, whose failure the
   decision records as ambiguous rather than resolving. Saying "consumption
   runs after every other gate" is false.
8. **Cross-protocol separation.** The receipt signature and the DSSE signature
   can be made under the same key, and the profile in fact requires the
   receipt's kernel key to equal the second signer's passport key. That key
   signs at least three preimage families, not two: the receipt signing body,
   the dual-signed `CoSigningBody`, and the DSSE pre-authentication encoding.
   A first-byte argument separates the DSSE family from the other two and says
   nothing about the pair a reader asks about next. Separation rests on
   Lemma 6, which adds the RFC 8785 argument that two canonical JSON objects
   with equal encodings have equal key sets, and these two have disjoint
   required keys. The paper should state the lemma in that form, and should
   carry premise P10, which is that the full set of families under this key was
   not enumerated.
9. **The conditional comparisons and the action class.** Four comparisons run
   only when the admission resolves the artifact they bind, and the action
   class is named in the request. The downgrade this invites is closed, but not
   by anything the paper says: the class must be in the agreement's allowed
   set (A4) and present in the intersection, the intersection is the receiver's
   own computation over two manifests it activated, a destructive class below
   `receipt_backed` is refused at intersection time, and the class named in the
   statement is compared against the class the receiver resolved (D4). The
   paper should give that chain rather than leave the conditionality open.
10. **What the mechanization covers.** The Lean development proves properties
    of the modelled accept predicate and of the field classification. It does
    not prove that the shipped Rust hook realizes that predicate. The corpus is
    what links them, leaf by leaf, on one configuration. The paper should state
    the split in those words. It may also say that the mechanized enumeration
    and the executed one are checked against each other rather than asserted
    to be the same, because the corpus reads the Lean module and compares both
    the leaf paths and the classification.
11. **Receipt identity has three preimages and the paper's Table 1 names one.**
    The identifier is `D(b_id)` over a projection that excludes `id`, the
    signature and the BBS signature; the subject digest is `D(b_subj)` over
    `receipt.body()`, which includes `id`; the binding reference's
    `remote_receipt_sha256` is `D(r)` over the whole receipt. The signature
    covers none of those three: it covers a three-field object carrying the
    identifier, the identity projection, and the optional BBS signature. The
    paper should give the three preimages names and say which digest each wire
    field carries, because two of its own claims (the subject clause of
    admission binding, and the receipt binding through the binding reference)
    are about different preimages and read as though they were about the same
    one. It should also say that `bbs_signature` is covered by the receipt
    signature and not by the receipt identifier.
12. **The two bound leaves that are not equalities.** The lease expiry is
    compared as a strict lower bound against the receiver's clock and the lease
    issuer as membership in the agreement's two participants. A binding claim
    quantified over "every compared leaf equals the receiver-held value" is
    false of both, and impossible for the first, since an expiry equal to the
    receiver's clock is expired. The paper should state the binding property
    over the equality-bound leaves and state the membership property separately
    for these two.

## 9. Artifact index

| Object | Where |
| --- | --- |
| Leaf enumeration and classification, mechanized | `formal/lean4/Chio/Chio/Treaty/AdmissionBinding.lean` |
| Comparison-set completeness theorem | `Chio.Treaty.AdmissionBinding.classification_trichotomy` |
| The two kinds of absence | `Chio.Treaty.AdmissionBinding.absent_leaves_are_refused_or_merely_optional` |
| The counts of Section 4.1 | `Chio.Treaty.AdmissionBinding.classification_census` |
| Accept-set decomposition | `Chio.Treaty.AdmissionBinding.accept_iff_gate_and_comparisons_hold` |
| Admission binding, equality-bound leaves | `Chio.Treaty.AdmissionBinding.accept_implies_binding` |
| Admission binding, domain-bound leaves | `Chio.Treaty.AdmissionBinding.accept_implies_domain_membership` |
| Fail-closed contrapositive, equality | `Chio.Treaty.AdmissionBinding.disagreement_denies` |
| Fail-closed contrapositive, domain | `Chio.Treaty.AdmissionBinding.value_outside_domain_denies` |
| Acceptance depends only on the gate and the compared leaves | `Chio.Treaty.AdmissionBinding.accept_determined_by_gate_and_compared_leaves` |
| The residual | `Chio.Treaty.AdmissionBinding.residual_substitution_preserves_acceptance` |
| Exhaustive substitution and addition corpus, 245 cases | `crates/kernel/chio-runtime-core/tests/runtime_treaty_predicate_substitution.rs` |
| Agreement of the mechanized and executed enumerations | same file, `the_lean_model_and_the_executed_classification_are_the_same_enumeration` |
| Binding-reference corpus, 22 cases | `crates/kernel/chio-runtime-core/tests/runtime_treaty_binding_substitution.rs` |
| Accept predicate, stages R and S and C and G | `crates/kernel/chio-runtime-core/src/admission_hook/treaty_ref.rs`, `treaty_evidence.rs` |
| Accept predicate, stage D | `crates/kernel/chio-runtime-core/src/admission_hook/dsse.rs`, `crates/trust/chio-federation/src/bilateral_dsse/verify.rs` |
| Accept predicate, stage A | `crates/kernel/chio-runtime-core/src/treaty.rs`, `evaluate_cross_boundary_admission` |
| Accept predicate, stage M | `crates/kernel/chio-kernel/src/kernel/verified_treaty.rs` |
| Accept predicate, stage K | `crates/kernel/chio-runtime-core/src/admission_hook.rs`, `evaluate` |
| Accept predicate, stage L | `crates/kernel/chio-runtime-core/src/admission.rs`, `evaluate_runtime_admission_tracked` |

None of the Lean theorems above depends on the collision-resistance axiom or on
any other project axiom: each depends on at most `propext` and `Quot.sound`,
and the five decided by case analysis or computation over the enumeration
depend on no axiom at all. They sit below the cryptographic layer, where they
belong.
