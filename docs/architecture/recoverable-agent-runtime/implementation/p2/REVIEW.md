# P2 code review

Reviewer: Codex. Scope: every handwritten P2 change relative to the retained P1
source baseline, the closed schemas and generated model boundaries, CLI/SDK
adapters, generator schema closure, portable dependency/feature manifests,
acceptance fixtures and requirement evidence. This is a complete local source
review, not independent human approval or hosted production qualification.

## Review findings and resolutions

1. A signature alone could bless a different result or basis. Verification now
   requires the separately selected advisory key, domain, issuer, deployment,
   policy, contract, intent, scope and limits, then recomputes the normalized
   snapshot/registry, full evaluation and recipient projection. The tampering
   corpus correctly re-signs changed commitments and bindings; all are refused.
2. Full graph digests/signatures could reveal low-entropy private membership.
   The full report and all transitive commitments remain classified. A separate
   signed view carries authorized candidate facts, recipient and random reference,
   without protected digests or private totals. Hidden-world cases produce the
   same view bytes and signature for the same public time/reference.
3. Hidden candidates could change public ranking or cause public search
   exhaustion. Filtering now precedes evaluation. Both candidate classification
   and disclosure constraints must flow to the audience. A newly tested secret
   disclosure constraint with an otherwise public candidate label cannot change
   public ranking. The full classification joins those constraints as well.
4. Hidden evidence expiry could shorten a restricted view's public deadline.
   Restricted views use the fixed public window and control authority ceiling;
   classified report deadlines remain dependent on their classified evidence.
5. Separate view construction followed by full report construction could repeat
   projected evaluation beyond the declared allowance. The paired preparation
   API uses one projected and one full evaluation, each receiving half the fixed
   allowance. Returning the native view compares fresh audience/source state
   without running a second planner.
6. Native provenance could be mistaken for integrity endorsement. An integrity
   requirement remains `NeedsFreshEvidence`; P2 cannot infer P3 endorsement
   authority from an attester or classifier.
7. Original capability expiry, source generation changes, closure or cancellation
   could leave misleading native advice. Current original-token validation uses
   the kernel's existing cryptographic/time/revocation/delegation verifier.
   Source mismatch and expired requirements remain explicit gaps. Policy
   eligibility incorporates workflow control and closure. Live resume continues
   to reject stale authority independently of advice.
8. The TypeScript public validator closure omitted the new signed view even
   though type generation included it. The pinned finite generator closure now
   includes the view and its exact local references. Unknown schemas still
   refuse; the client does not return full reports or leaking extra fields.
9. The existing P1 protected-read port requires retained-source clearance.
   That boundary is preserved. A limited native audience receives the same
   generic forbidden category without a protected graph. The explicit-data
   projector supplies separately signed restricted views for mediated inputs;
   no new low-clearance raw-workflow read or authority bypass was added.

## Boundary audit

The pure crate resolves only explicit bounded data, canonical hashing and
signature verification. It imports no kernel, process, store, effect ports,
ambient time, filesystem, network, RNG or signer. Its alloc-only and additive std
feature closures compile independently at MSRV 1.93 and current toolchain,
including WASM. Mutation checks reject effect dependencies, inherited defaults,
ambient reads and signing/authority interfaces.

The host dry service needs only explicit facts and an advisory signer. Native
composition refuses the disclosure signer. The network endpoint accepts only a
capability and workflow ID and returns a signed safe view. The protected inspector
rechecks current audience and the full joined classification. No lock spans
signing or await, no process reservation/admission/capture/budget write is added,
and no provider submit or reconciliation is initiated by explaining.

All arithmetic, time windows, list/dependency bounds, closed variants and scope
bindings were reviewed. Missing, unverified and expired facts stay uncertain;
negative capability or policy facts cannot become feasible. Mandatory dependency
kinds bind their exact intent, destination, authority scope or semantic template.
Incomparable audience changes survive the partial order; unspecified latency
never supplies a dominance claim. Exhaustion remains explicit.

Advisory types have no conversion to grants or native ownership. Wire and
compile-fail tests reject report substitution. Native tests reject injection,
revoked control, rotated selected policy/recipient and stale equal-label source
generations, without extra effects or replacement identity. Reports do not renew
cancelled control or a frozen original action.

Schema IDs for the new family use chio.computer. Legacy domain and schema
meanings remain byte-stable. All three pinned generators reproduce their outputs.
The CLI and both SDKs transport the same Rust-owned protocol, with bounded
responses, no redirects/retries and structural validation only. No dependency
pin, source-size exception, production deadline or lint was relaxed.

The retained evidence records earlier unsuccessful broad/concurrent runs and
sandbox listener failures as well as successful focused acceptance. Local tests
are not a claim of hosted CI, live provider delivery, lock-exact JavaScript
installation, deployment or scale qualification. P1's historical verification
bytes and source baseline are preserved.

There are **zero open P0 or P1 severity findings in the reviewed P2 changes and
supported local profile**. Severity is distinct from the numbered roadmap
phases. The final source and evidence hashes are in `verification.json`.

The package auditor was reviewed and executed against the retained artifacts.
It checks source/archive content, gate evidence, coverage and pin preservation;
it does not rerun tests or create a new security qualification claim.
