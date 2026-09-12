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
   together with a classification that is total by construction. The
   enumeration is mechanized in Lean
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

A receipt body `b` is a JSON object over the fields of Table 1 of the paper.
A receipt is

```
r = (b, id, sig)      id = H(J(b))      sig = Sig(sk, J({body: b, id: id}))
```

Three digests of the same receipt occur in the protocol and they are distinct
byte strings: `id` is the identity, `D(b)` is what the statement's subject
carries, and `D(r)` is the whole-object digest that the binding reference's
`remote_receipt_sha256` carries. Section 8 records that the paper's Section 3
is ambiguous about which fields `b` excludes; the model here takes `id` and
`sig` to be excluded and treats the exclusion set as fixed.

### 1.3 Statements

A statement is an in-toto Statement v1 whose predicate type is
`chio.bilateral-cosign-invocation.v1`. Write a statement as a finite map from
leaf paths to values, `S : F -> V`, where `F` is the finite set of leaf paths
that the wire type admits. `F` is enumerated in Section 4; it has 55 elements,
of which 49 occur in a strict statement and 6 are required absent by the strict
profile.

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

One point deserves to be stated rather than left implicit. The two signatures
on an inbound statement are one from `Q` and one from `R` itself: the strict
verifier resolves `tool_server_b` to the receiving kernel and requires its
`passport_key_fingerprint` to equal `kid(pk_R)`
(`bilateral_dsse/verify.rs`, and `verified_treaty.rs` requires
`participant_kernel_ids[1] = local_kernel_id`). The adversary therefore cannot
produce a valid inbound envelope on its own. What it can do is ask `R` to
co-sign, which is the co-signing oracle below. The consequence is Section 6.3:
the second signature is a statement about what `R` has seen, not about what `Q`
is entitled to.

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
implementation evaluates them. Each line names the function it is read from.
Failure at any line denies with the code given; the hook maps every
envelope-layer failure to `chio_treaty_unverified_required_evidence`.

**Stage R, request extraction** (`treaty_ref_from_request`)

- R1. `chioTreaty` is an object and carries none of the eleven refused names.
- R2. The five required identifiers are present, non-empty, and the two
  digests are 64 lowercase hex characters.
- R3. Each evidence reference that is present carries both an identifier and a
  64-hex digest.

**Stage S, store resolution** (`verify_treaty_reference_from_store`)

- S1. `K[admissionId]` exists.
- S2. `A[scopeId]` exists and `D(A[scopeId]) = scopeDigest`.
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

- M1. The request carries a federated origin, the statement's two kernel
  identifiers are that origin and the receiving kernel in that order, and they
  differ; their public keys differ.
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

The position of K1 is load-bearing and is stated here because the paper does
not state it: **consumption runs strictly after every check in stages R through
M**. A statement that fails any comparison returns before K1 and therefore
cannot burn a continuation. The executed corpus asserts this for all 220 cases:
every denial leaves the unsubstituted statement admissible afterwards, and
every admission makes it a replay.

## 4. The comparison set, enumerated

`Accept` reads the statement only through the leaves listed below. This is the
step the paper previously discharged with a twenty-case table; here it is an
enumeration with a total classification, and the completeness of the comparison
set is a consequence of the enumeration rather than of the corpus.

### 4.1 The enumeration

`F` is derived from the wire type, not from a hand list. In Rust it is obtained
by serializing a maximally populated statement built with exhaustive struct
literals and walking it to its scalar leaves, so a field added to the predicate
stops the corpus compiling. In Lean it is the constructor list of an inductive
type, and the classification is a match on that type, so a field added there
stops the classification elaborating until it is classified.

`|F| = 55`. The classification assigns each leaf exactly one of six kinds:

| Kind | Count | Meaning |
| --- | --- | --- |
| `receiverState` | 24 | compared for equality against a named receiver-held value |
| `receiverBound` | 1 | compared against a receiver-held value as an inequality |
| `selfConsistent` | 7 | compared only against another leaf of the same statement |
| `shape` | 6 | constrained to a constant or a fixed domain the receiver holds as code |
| `uncompared` | 11 | not compared at all |
| `absentByProfile` | 6 | required absent from a strict statement |

The 49 leaves a strict statement carries are the first five rows. Write
`Bound = receiverState ∪ receiverBound` (25 leaves) and
`Free = uncompared` (11 leaves).

### 4.2 The bound leaves and what they are compared against

Receiver-state leaves, with the value each must equal:

| Leaf | Receiver-held value |
| --- | --- |
| `predicate/tool_server_a/kernel_id` | the origin kernel identifier of the request |
| `predicate/tool_server_a/passport_key_fingerprint` | `kid` of the pinned origin key |
| `predicate/tool_server_b/kernel_id` | the receiving kernel's own identifier |
| `predicate/tool_server_b/passport_key_fingerprint` | `kid` of the pinned local key |
| `predicate/tool_name` | the tool name of the request |
| `predicate/co_sign` | the co-signing mode of the resolved action class |
| `predicate/consistency_model` | the consistency model of the resolved action class |
| `predicate/tool_args_hash/value` | the canonical argument hash of the request |
| `predicate/capability_lease_ref/issuer` | one of the agreement's two participants |
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

The single `receiverBound` leaf is
`predicate/capability_lease_ref/expires_at_unix_ms`, compared against `clock`
as a strict lower bound.

Four of the receiver-state leaves are compared only when the admission resolves
the artifact they name: `lineage_bundle_sha256` when a lineage bundle resolved,
and `outcome_sha256`, `local_receipt_sha256`, `remote_receipt_sha256` when a
lineage bundle or an invocation record resolved. A class in
`bilateral_required` co-signing mode has the invocation record forced into its
required evidence (A5), so under that mode the last three are compared on every
admission. The conditionality of `lineage_bundle_sha256` is real and is
exercised: under an action class that resolves no lineage bundle, substituting
it is admitted.

### 4.3 The free leaves, and why each is free

Eleven leaves are compared against nothing. This is the residual of the
comparison set and the honest statement of what an adversary who can obtain
both signatures may choose.

| Leaf | Why it is not compared |
| --- | --- |
| `subject/0/digest/sha256` | the receipts are bound through `local_receipt_sha256` and `remote_receipt_sha256`; the admission path never compares the subject digest |
| `predicate/timestamp_unix_ms` | the presentation window comes from the lease, the governance record, and the continuation, all receiver-held |
| `predicate/policy_evaluation_summary/server_a_verdict/policy_id` | the receiver resolves neither party's policy identity |
| `predicate/policy_evaluation_summary/server_a_verdict/policy_version` | as above |
| `predicate/policy_evaluation_summary/server_b_verdict/policy_id` | as above |
| `predicate/policy_evaluation_summary/server_b_verdict/policy_version` | as above |
| `predicate/governance_receipt_ref/kernel_id` | the governance record the receiver acts on is the one its own bundle names |
| `predicate/governance_receipt_ref/digest/alg` | the governance digest is never resolved during admission |
| `predicate/governance_receipt_ref/digest/value` | as above |
| `predicate/consistency_anchor` | the anchor is carried for the peer's own reconciliation |
| `predicate/treaty_binding_ref/admission_report_sha256` | checked only for hex shape, then overwritten with the digest of the receiver's own report before signing |

Only the last of these is discussed in the paper. The other ten are new to this
document and two of them change what the paper may claim (Section 8).

### 4.4 Lemma 1 (comparison-set completeness)

**Lemma 1.** For every `f ∈ F`, exactly one of the following holds: `f` is
bound to a named receiver-held value; `f` is constrained only against the
statement itself or against a constant; `f` is constrained by nothing. The
classification is total.

*Proof.* Totality is structural. In the Lean development the classification is
a function `classify : Field -> Comparison` defined by a match on an inductive
type whose constructors are exactly `F`, so it is total by exhaustiveness
checking; the trichotomy is then decided by case analysis over the 55
constructors
(`Chio.Treaty.AdmissionBinding.classification_trichotomy`, which depends on no
axioms). In the Rust corpus the same enumeration is derived from the wire type
by serializing an exhaustively constructed value, and the classification is
asserted equal to that leaf set in both directions. QED

**Lemma 2 (accept-set decomposition).** `Accept` is the conjunction over `F` of
the per-leaf comparisons the classification names, and no other gate reads a
leaf of `S`. Hence `Accept(q, E, Σ) = true` if and only if every leaf in
`Bound` equals the receiver-held value it names.

*Proof.* The "if and only if" is proved in Lean over the modelled accept
predicate
(`Chio.Treaty.AdmissionBinding.accept_iff_bound_fields_agree`), from which
`accept_implies_binding` and `disagreement_denies` follow. That the shipped
receiver realizes this predicate is not proved; it is checked, leaf by leaf, by
the executed corpus of Section 5. That split is deliberate: Lemma 2 is a
theorem about the model, and the corpus is the evidence that the model is the
right one. QED

**Corollary 3 (residual).** Substituting any leaf in `Free` leaves the decision
unchanged (`unbound_substitution_preserves_acceptance`). The corpus exhibits
this concretely: substituting at once every leaf whose single substitution is
admitted, which is the eleven free leaves plus the lease expiry moved further
into the future, still admits and dispatches.

## 5. The executed corpus

`crates/kernel/chio-runtime-core/tests/runtime_treaty_predicate_substitution.rs`
runs 220 admission decisions against one complete, admissible fixture. Each
case substitutes one or more leaves with a well-formed value of the same JSON
type generated from the value it replaces, re-signs the statement with both
participant keys over its own pre-authentication bytes, asserts both signatures
verify over the substituted bytes, and drives the pre-dispatch hook. Every
denial additionally asserts that no verified material reached dispatch and that
the continuation the statement named is still unconsumed; every admission
asserts the opposite.

| Group | Cases | What it establishes |
| --- | --- | --- |
| Single leaf, lineage and record resolved | 49 generated plus 6 declared probes | each leaf's classification, including six leaves where one value cannot separate a domain constraint from a comparison |
| Single leaf, no lineage bundle | 49 | the conditional comparisons, and that only `lineage_bundle_sha256` differs |
| Every pair inside the binding reference | 105 | no comparison masks another: all 105 pairs are denied without dispatch |
| Duplicated leaves rewritten consistently | 8 | the statement's internal agreement checks do not stand in for a comparison against receiver state |
| Every admitted leaf at once | 1 | the residual of Corollary 3, twelve leaves in one statement |
| Control | 2 | the unsubstituted statement admits under both evidence profiles |

The duplicated-leaf group is the one that a single-fault corpus cannot reach.
Six of its eight cases rewrite both copies of a value that appears twice
(consistency model, request digest, lease identifier, governance receipt
identifier, and each signer identifier), so the internal cross-check passes and
only a comparison against receiver state can deny. All six deny. The remaining
two admit, and both are reported in Section 8.

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
  A runs with O_peerSign, O_coSign, O_deliver, O_admit, O_tick
  A wins if some O_admit(q, E) returned allow and, writing S for the
  statement in E,
    (i)  some leaf f in Bound has S(f) != val_Σ(f, q), or
    (ii) some digest-valued leaf f in Bound has S(f) = D(x) for an object x
         that is not the object the receiver resolved for f, or
    (iii) PAE(t, J(S)) was never signed under pk_R, or
    (iv) the continuation named by S had already been consumed when the
         admission began.
Adv_AB(A) = Pr[A wins].
```

Clause (i) is field agreement, (ii) is artifact identity, (iii) is statement
authenticity, (iv) is freshness of the continuation.

**Theorem 1.** For every such `A`,

```
Adv_AB(A) <= Adv_CR(B_h) + Adv_INJ(B_e) + 2 * Adv_EUF-CMA(B_sig) + Adv_ATOM
```

where `B_h`, `B_e` and `B_sig` are the adversaries constructed below, each
running in time `t_A + O(q_a * |Σ|)`, and `Adv_ATOM` is the probability that
ASSUME-SQLITE-ATOMICITY fails.

*Proof.* By clauses.

**(i) Field agreement.** Unconditional. By Lemma 2, `Accept` holds only if
every leaf in `Bound` equals the receiver-held value it names, so clause (i)
has probability zero. This step needs no assumption and no reduction; what it
needs is Lemma 1, which is why the completeness of the comparison set is
discharged inside the proof rather than by a table.

**(ii) Artifact identity.** Construct `B_h`, a collision finder for SHA-256.
`B_h` runs `A`, simulating every oracle honestly (it holds both key pairs it
generated and the whole of `Σ`). When `A` wins by clause (ii) on a leaf `f`,
`B_h` holds the receiver-resolved object `x` and the object `x'` that `A`
intended `S(f)` to denote, with `D(x) = S(f) = D(x')` and `x != x'`. If
`J(x) != J(x')` then `(J(x), J(x'))` is a SHA-256 collision and `B_h` outputs
it. If `J(x) = J(x')` with `x != x'` then the canonical encoder is not
injective on that pair, and `B_e` outputs it; ASSUME-CANONICAL-JSON is the
premise that this cannot happen inside its stated domain, and premise P1 in
Section 7 is the part of that domain the implementation does not enforce.
`B_h` and `B_e` succeed exactly when `A` wins by clause (ii), so that clause
contributes `Adv_CR(B_h) + Adv_INJ(B_e)`.

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
leaves in `Free`. It does not say the peer authorized anything.

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
lookups keyed by the identifiers in `ref(q)` against `Σ`, followed by digest
equality against `Σ`'s own content. Hence the resolved artifacts are a function
of `(Σ, ref(q))` alone, and `ref(q0) = ref(q1)` gives the same artifacts. The
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

*Proof.* Stage K1 runs after every other gate and before the decision is
returned. It inserts a row keyed by the continuation identifier and denies on
zero affected rows. Release deletes only a row keyed by both the continuation
identifier and the admission identifier that took it, and runs only when a
later pre-dispatch step denies, so no admission frees another's row and no
post-dispatch path frees one. Two allows with the same identifier therefore
require two successful creating inserts on one primary key. QED

The ordering of K1 also answers a question the paper leaves open: because
consumption runs after all of stages R through M, a statement that fails any
comparison cannot burn a continuation, so an adversary cannot deny service to a
legitimate call by presenting garbage that names its continuation. What it can
do is guess or learn a continuation identifier and present a **fully valid**
statement for it, which is premise P2.

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

*Proof.* Each conjunct is a bound leaf compared against `Σ_R'`'s own state:
`tool_server_b/kernel_id` and its fingerprint against `Σ_R'`'s own identity and
pin, `treaty_id` and `treaty_scope_sha256` against the agreement `Σ_R'`
resolved, `ladder_intersection_sha256` against the intersection, and
`continuation_sha256` against the continuation. Any difference contradicts
Lemma 2. The case the paper's argument does not cover is a single receiver
holding several agreements over the same pair of kernels: that case is covered
here, because `treaty_id` and `treaty_scope_sha256` are both bound, and the
agreement is resolved from the request's identifier and then digest-checked
against `Σ`, so two agreements over the same pair are separated whenever their
canonical content differs. QED

### 6.6 Cross-protocol separation

A lemma the paper needs and does not state. The receiving kernel signs receipts
with the same Ed25519 key it co-signs statements with: the signature-slice
profile requires the embedded receipt's `kernel_key` to equal Org B's passport
key, and the strict path resolves the second signer to the receiving kernel.

**Lemma 6.** No receipt-signing preimage is a DSSE pre-authentication preimage.

*Proof.* A receipt signature covers `J({body: ..., id: ...})`, which is the
canonical encoding of a JSON object and therefore begins with the byte `{`. A
DSSE pre-authentication encoding begins with the literal `DSSEv1`. The two
languages are disjoint in their first byte, so no string is both. QED

Lemma 6 is what rules out reinterpreting one signed object as the other. It is
a property of the encodings, not a domain separation tag, and the paper should
say so rather than leave the question open.

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
  tolerance that is never instantiated. Stages C2, A1 and M6 are windows
  evaluated against that clock.

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
   must compare the subject digest. The latter is a one-line change and is the
   better fix.
2. **The invocation identity is not bound to the receiver's record either.**
   In the hook, the predicate's `invocation_id` is checked only against the
   subject name, which is derived from it. Rewriting both consistently is
   admitted. So a statement the hook accepts for this call may name any
   invocation identifier. Nothing in the decision depends on it, but the
   archived statement is then an audit record whose own identifier the receiver
   never checked.

   Findings 1 and 2 have one cause, and naming it is the useful form of both.
   The conforming verifier does what the property describes: it resolves the
   receipt by invocation identifier from its own receipt store, checks that
   receipt's signature and kernel key, and then compares the subject name and
   the subject digest against the receipt it resolved
   (`bilateral_verifier/cosign.rs`). The hook never resolves a receipt by
   invocation identifier at all. That single missing step is the whole of the
   divergence between the two decision families on this point, and it is what
   the paper's admission binding property assumes has happened.
3. **Ten leaves outside `admission_report_sha256` are also uncompared.** The
   paper names one uncompared field. There are eleven. The nine that are not
   the admission report digest or the subject digest are the two policy
   identities, the two policy versions, the governance kernel identifier, the
   governance digest and its algorithm, the consistency anchor, and the
   statement timestamp. None is used in the decision; all are doubly signed and
   archived. The paper should enumerate them and say what an auditor may
   conclude from them, which is: nothing, unless the auditor independently
   trusts both signers.
4. **The completeness claim's scope.** The corpus previously covered fifteen
   fields of one sub-object, one at a time. The predicate carries 49 leaves that
   a strict statement populates. The paper should say 49 and cite the
   enumeration, not 15 and cite a table. The binding-reference corpus the paper
   cites is now 22 cases rather than 20, so the derived case-count macro moves
   with it; its own arithmetic is 16 substitutions, two of the new kind, three
   conditional cases, and one control.
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
   consumption sits. It sits after every comparison and after both signature
   verifications. That is the good ordering and it should be stated, because it
   is what rules out burning a legitimate continuation with a statement that
   would later fail.
8. **Cross-protocol separation.** The receipt signature and the DSSE signature
   can be made under the same key, and the profile in fact requires the
   receipt's kernel key to equal the second signer's passport key. Separation
   rests on Lemma 6, a disjointness of encodings, not on a domain separation
   tag. The paper should state the lemma.
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
    the split in those words.

## 9. Artifact index

| Object | Where |
| --- | --- |
| Field enumeration and classification, mechanized | `formal/lean4/Chio/Chio/Treaty/AdmissionBinding.lean` |
| Comparison-set completeness theorem | `Chio.Treaty.AdmissionBinding.classification_trichotomy` |
| Accept-set decomposition | `Chio.Treaty.AdmissionBinding.accept_iff_bound_fields_agree` |
| Admission binding, field agreement | `Chio.Treaty.AdmissionBinding.accept_implies_binding` |
| Fail-closed contrapositive | `Chio.Treaty.AdmissionBinding.disagreement_denies` |
| Acceptance depends only on bound leaves | `Chio.Treaty.AdmissionBinding.accept_determined_by_bound_fields` |
| The residual | `Chio.Treaty.AdmissionBinding.unbound_substitution_preserves_acceptance` |
| Exhaustive substitution corpus, 220 cases | `crates/kernel/chio-runtime-core/tests/runtime_treaty_predicate_substitution.rs` |
| Binding-reference corpus, 22 cases | `crates/kernel/chio-runtime-core/tests/runtime_treaty_binding_substitution.rs` |
| Accept predicate, stages R and S and C and G | `crates/kernel/chio-runtime-core/src/admission_hook/treaty_ref.rs`, `treaty_evidence.rs` |
| Accept predicate, stage D | `crates/kernel/chio-runtime-core/src/admission_hook/dsse.rs`, `crates/trust/chio-federation/src/bilateral_dsse/verify.rs` |
| Accept predicate, stage A | `crates/kernel/chio-runtime-core/src/treaty.rs`, `evaluate_cross_boundary_admission` |
| Accept predicate, stage M | `crates/kernel/chio-kernel/src/kernel/verified_treaty.rs` |
| Accept predicate, stage K | `crates/kernel/chio-runtime-core/src/admission_hook.rs`, `evaluate` |

None of the Lean theorems above depends on the collision-resistance axiom or on
any other project axiom: each depends only on `propext` and `Quot.sound`, which
is to say they sit below the cryptographic layer, where they belong.
