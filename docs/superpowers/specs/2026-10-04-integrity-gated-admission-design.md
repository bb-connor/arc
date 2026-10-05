# Design: integrity-gated admission

- Status: PROPOSED (revision 3, 2026-10-05, after the independent review and Codex review on PR #1174; revision 1 baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5)
- Date: 2026-10-04
- Scope: make "unbounded or unknown external influence cannot authorize a consequential tool call, except through an exact endorsement" a property the kernel enforces for any agent framework (the precise property is in section 11). It is built from the shipped and implemented knowledge (P4), semantic (P3) and confinement (P5) surfaces:
  - grants declare a required integrity;
  - the kernel records the influence of every output it delivers into a mediated context;
  - an early deny-only guard checks the calling context's influence, and the authoritative check runs inside the intent commit;
  - refusals become a classified, anti-oracle fault whose remedies run through recovery.

  It adds no interpreter, no taint tracking inside model reasoning, and no reduction of influence history.
- Owners:
  - `chio-core-types`: the `RequiredIntegrity` constraint and the integrity requirement vocabulary.
  - `chio-security-types`: the influence state, origin classes and typed return contracts.
  - `chio-kernel`: `IntegrityGuard`, crossing check 4, and fault classification.
  - `chio-store-sqlite`: output influence joins and the influence summary row.
  - `chio-control-plane`: operator origin bindings and confined typed returns.
  - `chio-process` and the SDKs: initial context influence from the worker profile.
- Related:
  - W: `docs/architecture/recoverable-agent-runtime/01-security-model.md` (the proposed `InfluenceState`, SEC-05), `05-semantic-contracts.md` (P3), `06-artifacts-memory.md` (P4), `07-confined-returns.md` (P5).
  - M: `docs/security/active-defense-rollout.md` (isolation-epoch successors), `crates/kernel/chio-process/MAILBOXES.md`.
  - `spec/PROTOCOL.md` sections 5, 6 and 8.
- Citation convention:
  - M: = `origin/integration/process-security-m4` at `19df31ad9`.
  - V: = `origin/work/verifiable-work-session-20261003` at `14477aaac`.
  - R: = `origin/research/openappa-recovery-20261001` at `de84fc306`.
  - W: = the uncommitted recovery working tree at `standalone/arc-worktrees/recoverable-agent-runtime-20261002`. Its line references reflect 2026-10-04 and may drift.
  - P: = `feat/process-command-experience-20260924`.
  - B: = `origin/wip/bench-results-2026-09-13`.
  - W1-W4 and doc-only R: names are contract anchors.
- Origin: `docs/research/2026-10-04-chio-kernel-north-star.md`, bet 3.
- Siblings:
  - the umbrella `2026-10-04-ftl-lessons-program-design.md`;
  - the program specs: `closed-kernel-abi`, `authority-faults`, `typed-reservations`, `authority-space-teardown`, `unified-event-queue`, `opaque-adapter-context`, `microkernel-isolation-backend`, `durable-stop-epoch`;
  - the north-star specs `2026-10-04-pure-admission-machine-design.md` (A) and `2026-10-04-crossing-primitive-design.md` (B).

## Revision 3 changes

From the independent review on PR #1174:
- **Endorsement is part of the authoritative predicate (R-11-01).** Revision 2 required `satisfies(state, requirement)` unconditionally at the intent commit, so the I21 endorsement it promised could never pass. The check now admits when the context satisfies the requirement **or** when a verified exact endorsement applies. The endorsement must be bound to the exact action, to the current influence commitment, to the current deployment, and to a single-use continuation. It is carried in the crossing plan and consumed in the same transaction. The early guard defers a presented endorsement to that check and never accepts it on its own (I13, I15a).
- **The guarantee is stated precisely (R-11-02).** `BoundedExternal` admits a bounded channel that attacker-controlled content can influence. A one-bit return can choose between publish and delete. The spec no longer claims that external content cannot steer a bounded context. Section 11 states the enforceable property. A new optional requirement, `BoundedSelection`, binds a bounded requirement to an operator-signed action-selection contract, for deployments that need zero unauthorized action selection (I22a).
- **Deny receipts no longer disclose the commitment (R-11-03).** Allow and deny receipts have separate disclosure rules. A caller-visible deny carries neither the commitment nor `satisfied_by`. Allow receipts carry a blinded, per-receipt commitment reference. The raw audit basis goes to an operator-audience record (I25, I25a).

## Revision 2 changes

- **The join is a real lattice join.** Revision 1's join summed `bounded_bits_total` and chained `H(s1.commitment, s2.commitment)`. So `join(s, s)` doubled the bits, the ordered hash was neither commutative nor associative, and replaying or rebuilding one delivery could push a context over its bound. A context's state is now a canonical, deduplicated set of observations with stable ids. Every field, the commitment included, is a function of that set, and join is set union (section 4, rule I4a).
- **Summary rows stay exact under the new join.** Per-key heads are maintained for the seven key subsets, so crossing check 4 computes the union over principal, lineage and session by inclusion-exclusion, counting each observation once (I16).
- **Observation ids name their destination (round 2).** An id hashes the delivery record and the destination context's key values. Two contexts that read one artifact version each record an observation, and retries of one delivery stay stable (I4a).
- **Tracked contexts are not check-only (round 2).** A call in a context with integrity tracking takes the durable path, so its output join commits before delivery. Gating requires tracking (I4b).
- **The integrity fault has its own block (round 2).** It is `IntegrityFaultV1` (`chio.integrity-fault.v1`), a sibling of spec 2's `AuthorityFaultV2` under a tagged classifier output. It is not a fifth `AuthorityFaultClass` (I18, I19).
- **The worker profile is consumed as a verified fact.** Spec 7 rule 6.3.5 defines its qualification and fail-closed behavior. I7 uses only the verified fact and commits the initial influence once, as an observation, when the context's scope is created.

## 1. Decision summary

The research consensus is that prompt injection is contained outside the model:
- In-model defenses fall to adaptive attacks, all eight evaluated, consistently above 50 percent success ([arXiv 2503.00061](https://arxiv.org/abs/2503.00061)).
- Systems that hold up enforce a deterministic dataflow rule: once untrusted content has entered a context, it cannot trigger a consequential action ([Design Patterns, arXiv 2506.08837](https://arxiv.org/abs/2506.08837)).
- CaMeL enforces this in a custom Python interpreter ([arXiv 2503.18813](https://arxiv.org/abs/2503.18813)), and FIDES in one planner ([arXiv 2505.23643](https://arxiv.org/abs/2505.23643)).

Chio already has the primitives at the operating-system layer:
- **P4** keeps a monotone knowledge join per principal, lineage and session in the serving writer.
- **P5** cages a zero-authority reader that returns a typed value.
- **P3** binds endorsements to one exact action.

The recovery security model already specifies the integrity contract (W: `01-security-model.md:23`):
- an `InfluenceState` retaining the union of observed origin classes plus `Unknown`;
- tool contracts declaring acceptable influence sets;
- a scoped endorsement that authorizes an exact action "despite those influences; it does not rewrite global influence history".

Three things are missing:
1. **Admission does not consult influence.** Integrity gating today exists only inside P3 semantic contracts.
2. **Tool output delivered to a worker records no influence.** The `CapturedOutput` release kind is defined but never produced (W: `chio-security-types/src/knowledge/release.rs:58-61`).
3. **Every published artifact is marked externally influenced unconditionally** (W: `.../knowledge/traversal.rs:67`). Nothing can be trusted, so a gate built on today's state would deny everything.

This design closes all three:

1. **The lattice.** An integrity lattice taken from W:'s implemented influence record and the proposed origin classes (section 4). It adds a bounded-capacity class for typed confined returns.
2. **Output influence joins.** Every output the kernel delivers into a mediated context joins its influence, and origin classes are assigned by operator bindings (section 5).
3. **`Constraint::RequiredIntegrity`.** It follows the `MinimumRuntimeAssurance` precedent and is preserved monotonically under delegation (section 6).
4. **Two checks.** A deny-only `IntegrityGuard` runs early (section 7). The authoritative check is crossing check 4 inside spec B's intent commit, in the same writer as the joins (section 8).
5. **The fault.** `InsufficientIntegrity` is a sibling fault kind in spec 2's tagged classifier, with its own block (section 9). Its remedies are:
   - an exact endorsement, through the existing but unused `AuthorityObligationV1::IntegrityEndorsement`;
   - a quarantined continuation in an isolated successor fed by typed P5 returns.

## 2. Verified current state

| Fact | Evidence |
|---|---|
| Confidentiality labels are owner-to-reader policies plus compartments, with `Top`, and support `join_restrictions` and `flows_to` | W: `crates/security/chio-security-types/src/flow.rs:44-51`, `:362`, `:401` |
| Influence is recorded as `ArtifactInfluenceV1 { commitment, externally_influenced, unknown }` on every artifact version, release and checkpoint | W: `chio-security-types/src/knowledge/artifact.rs:15-19`, `:65`; `knowledge/release.rs:72`; `knowledge/checkpoint.rs:16` |
| A context's influence is the OR over knowledge-join records in the same tenant and isolation epoch whose principal, lineage *or* session matches. It is computed inside a writer transaction | W: `crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/knowledge.rs:52-87` |
| Published artifacts are always marked `externally_influenced: true` | W: `.../admission_operation_store/knowledge/traversal.rs:43-73`, `:67` |
| `ArtifactReleaseKindV1::CapturedOutput` has no producer, so ordinary tool output records no join | W: `knowledge/release.rs:58-61`; no constructor in W: crates |
| Capture and knowledge join serialize through one writer. "Knowledge committed first refuses stale native preparation"; "a later dispatch check may refuse changed knowledge" | W: `docs/.../implementation/p4/OPERATIONS.md:107-113` |
| The proposed `InfluenceState`: origin classes plus `Unknown`; tool contracts declare acceptable sets; a scoped endorsement authorizes exact actions without rewriting history | W: `docs/.../01-security-model.md:23` |
| SEC-05: "Disclosure/endorsement MUST NOT reduce retained confidentiality or influence history" | W: `01-security-model.md:55` |
| P3 operations declare `external_influence`, and verification ORs it into the action's influence | W: `chio-security-types/src/semantic/package.rs:84`; `chio-semantic-contracts/src/verification.rs:156`, `:199` |
| P3 `ScopedEndorsementV1` binds an exact action digest, the influence digest, destination and purpose, and supplies the contract's required assertions. "Integrity endorsements cannot change this confidentiality comparison" | W: `semantic/evidence.rs:84-101`; `verification.rs:205`, `:237-282` |
| P5 `ReturnContractV1` admits only one 8-byte value on the `Value` channel, with `require_integrity`. The host recomputes a canonical boolean projection | W: `chio-security-types/src/confinement.rs:51-82`; `chio-core-types/src/recovery/confinement.rs:58-73` |
| P5 return admission requires an independently rooted endorsement when `require_integrity` is set, but copies the observation's influence into the parent release | W: `.../knowledge/confinement/returns.rs:356-372`, `:383` |
| `AuthorityObligationV1::IntegrityEndorsement { principal }` exists with no consumer. `AuthorizationRequirementsV1` binds an `influence_basis` | W: `chio-security-types/src/recovery/authorization.rs:39-44`, `:47-62` |
| Planner vocabulary: facts `Capability`, `Policy`, `DestinationAcl`, `AuthorityCoverage`, `Transformation`, `Prerequisite`; remedy kinds `ExistingDestination`, `ExactApproval`, `Transformation`, `Prerequisite` | W: `chio-security-types/src/recovery/explanation/snapshot.rs:5-12`; `registry.rs:6-11` |
| `ToolGrant` has constraints and caps, and `Constraint::MinimumRuntimeAssurance` is a tier constraint. Constraint preservation under delegation defaults to equality | M: `crates/core/chio-core-types/src/capability/scope.rs:95-118`, `:331`, `:359`, `:602` |
| KG4: issuance is exhaustive over `Constraint` | M: `crates/kernel/chio-kernel/src/authority.rs:102-137` |
| `Guard` with opt-in dispatch revalidation | M: `crates/kernel/chio-kernel/src/kernel/mod.rs:870-899` |
| The confidentiality flow guard `FlowPreInvocationGuard` takes a `MissingContextPolicy { Allow, Deny }`. No integrity guard exists | M: `crates/security/chio-security-kernel/src/pre_invocation.rs:62`; `lib.rs:49-59`; chio-flow modules are classification, declassification, engine and lattice |
| The tool manifest carries a publisher-authenticated `flow` (confidentiality only) and annotations `read_only` and `destructive` | M: `crates/core/chio-core-types/src/manifest.rs:143`, `:186`, `:188`; W: `flow.rs:269-277` |
| The security context comes only from a trusted runtime boundary. Process calls set session to the runtime id and lineage to the process lineage | M: `kernel/mod.rs:225-241`; `crates/kernel/chio-process/src/security.rs:28-46` |
| "Messages and tool outputs are untrusted data". `attest_senders` records the kernel-selected sender | M: `crates/kernel/chio-process/MAILBOXES.md:33`, `:61` |
| "Only a verified isolation-epoch transition starts an isolated successor"; taint survives session closure | M: `docs/security/active-defense-rollout.md:19`; W: `ports_parts/part_01.rs:813` (`IsolationEpochTransition`) |

## 3. Goals and non-goals

Goals:
- A grant can require that its call come from a context with no unendorsed external influence, and the kernel enforces it for every framework running as a mediated process.
- Influence tracks what actually entered a context: tool outputs, mailbox messages, artifact reads, model-context restores and confined returns.
- Refusals are recoverable through endorsement or quarantine without weakening the property of section 11. A quarantined continuation is admitted only under the bounded allowance its requirement names.
- The guarantee is measured under adaptive attack, and published.

Non-goals:
- Taint inside model reasoning or per token. NeuroTaint argues string-level taint fails ([arXiv 2604.23374](https://arxiv.org/abs/2604.23374)). This design is sound at context granularity and does not claim more.
- Clearing a context's influence. SEC-05 forbids it.
- Certifying integrity for contexts the kernel does not mediate completely (section 12).
- Replacing confidentiality flow control. This design is orthogonal to `InformationLabel` and never changes a confidentiality comparison.

## 4. Integrity lattice

The lattice is W:'s implemented influence record, read as a three-point order, plus the proposed origin classes as one refinement step.

```rust
// chio-security-types::knowledge (extends the proposed InfluenceState, W: 01-security-model.md:23)
pub enum InfluenceOriginV1 {
    External,                                // tool output, provider fetch, mailbox from an unattested sender
    ExternalBounded { max_bits: u16 },       // typed P5 return; capacity bound by its contract (section 10)
    ModelProvider { provider: ProviderId },  // operator-bound provider responses
}

/// One joined observation. Its id names one delivery into one destination context, and is stable
/// across retries, replays and rebuilds of that delivery (I4a).
pub struct InfluenceObservationV1 {
    pub observation_id: CanonicalPayloadDigest,
    pub origin: Option<InfluenceOriginV1>,           // None: a trusted observation
    pub unknown: bool,                               // provenance unknown for this observation
}

/// Derived entirely from the canonical deduplicated observation set O of a context.
pub struct InfluenceStateV1 {
    pub origins: BoundedSet<InfluenceOriginClass, 32>, // { class(o.origin) : o in O }; empty means trusted
    pub bounded_bits_total: u32,                       // sum of max_bits over distinct ExternalBounded
                                                       //   observations in O, saturated after exact sum
    pub unknown: bool,                                 // some o in O has unknown
    pub observation_count: u64,                        // |O|
    pub commitment: CanonicalPayloadDigest,            // SetHash over { o.observation_id : o in O }
}

/// `class` drops `max_bits`: bits are tracked by `bounded_bits_total`.
pub enum InfluenceOriginClass { External, ExternalBounded, ModelProvider { provider: ProviderId } }
```

`SetHash` is an additive homomorphic set hash, such as LtHash or MuHash, over `SHA-256("chio.influence-set.v1\0" || observation_id)`. Its value depends only on the set, not on insertion order. The origin-class space is bounded by the deployment binding (I5): an `IntegrityDeploymentBindingV1` naming more than 30 providers is refused at configuration time, so `origins` never overflows at runtime.

Projection from the implemented record:
- `unknown` maps to `unknown`;
- `externally_influenced` maps to `External` in `origins`;
- otherwise the state is trusted, with empty origins.

The proposed refinement adds `ExternalBounded` and `ModelProvider`. It is additive, as W: requires ("requires new native participant evidence before deployment").

Order and join. The abstract state of a context is its observation set `O`, keyed by `observation_id`, and `state(O)` derives every field above:

```text
state(O1) <= state(O2)       iff  O1 subset-of O2
join(state(O1), state(O2))    =   state(O1 union O2)
bottom = state({})                (trusted: empty origins, 0 bits, known)
```

Join is set union, and every field (the commitment included) is a function of the set. So join is idempotent (`join(s, s) = s`: replaying or rebuilding a delivery adds nothing), commutative and associative. The order implies the field orders: `origins` only grows, `bounded_bits_total` only grows (a sum of non-negative terms over a superset, saturated after the exact sum), and `unknown` only moves from false to true. Two distinct deliveries of the same bounded return are two observations, and both count. One delivery replayed counts once.

The requirement a grant declares:

```rust
pub enum IntegrityRequirementV1 {
    Trusted,                                      // no external origin, known provenance
    BoundedExternal { max_bits: u16 },            // only ExternalBounded origins, total <= max_bits
    ProviderOnly { providers: BoundedSet<ProviderId, 8> }, // Trusted plus listed providers
    BoundedSelection {                            // BoundedExternal, plus an action-selection contract (I22a)
        max_bits: u16,
        contract: ActionSelectionContractDigest,
    },
}
```

Normative rules:

1. **I1. Satisfaction.** `satisfies(state, req)` is false whenever `state.unknown`.
   - `Trusted` requires empty origins.
   - `BoundedExternal { n }` requires every origin to be `ExternalBounded` and `bounded_bits_total <= n`.
   - `ProviderOnly(ps)` requires every origin to be `ModelProvider { p }` with `p` in `ps`.
   - `BoundedSelection { n, c }` requires what `BoundedExternal { n }` requires. Its action condition is checked by crossing check 4 (I22a), because `satisfies` reads state only.
2. **I2. Monotone.** Joins only move up the order, and nothing in this design moves a context down, so `satisfies` can only go from true to false within one context.
3. **I3. Requirement order.** For attenuation: `Trusted` is stronger than `BoundedExternal { n }`, which is stronger than `BoundedExternal { m }` when `n < m`. `ProviderOnly(ps)` is stronger than `ProviderOnly(qs)` when `ps` is a subset of `qs`. `Trusted` is stronger than every `ProviderOnly`. `BoundedSelection { n, c }` is stronger than `BoundedExternal { m }` when `n <= m`, and stronger than `BoundedSelection { m, d }` when `n <= m` and `c`'s authorized action set is a subset of `d`'s. `Trusted` is stronger than every `BoundedSelection`.

## 5. Output influence joins

Today the influence of a context reflects only P4 artifact traffic. The main injection vector is a tool output entering a worker's model context, and it is untracked.

4. **I4. Join on delivery.** Every output the kernel delivers into a mediated context joins its influence into that context's knowledge flow rows. The join happens in the serving writer, in the same transaction as the outcome commit or release (spec B). Delivered outputs are:
   - process `invoke` results;
   - kernel-session tool results;
   - mailbox `receive` payloads;
   - artifact reads;
   - model-context restores;
   - confined returns.

   The previously unproduced `ArtifactReleaseKindV1::CapturedOutput` becomes the release record for invoke results under enforced knowledge.

   **I4a. Observation identity and dedupe.**
   - The id names one delivery into one destination context:

     ```text
     observation_id = SHA-256("chio.influence-observation.v1\0" || source_kind
                              || "\0" || delivery_record_digest
                              || "\0" || destination_digest)
     ```

   - `destination_digest` is the canonical digest of the destination context's key values: tenant, isolation epoch, principal, lineage, and session or process id. These are the values its flow row carries and its heads are keyed by (I16).
   - `delivery_record_digest` identifies one delivery or read, never the delivered bytes or the source object alone:
     - the output release record (operation id plus output digest), for invoke results and session tool results. One operation has exactly one destination;
     - the message id plus the receiver's claim (mailbox id and receiver), for mailbox receives;
     - the read's release record, for artifact reads. That is the P4 `ReleaseIntent` of that read, which binds the artifact version digest; the version digest alone is never the source record;
     - the restore record, for model-context restores;
     - the confined-return record, which binds the child's influence `commitment` (I8), for confined returns;
     - the context-creation record under `source_kind = initial`, for the initial-influence observation (I7). It is the knowledge-scope creation row written in the same transaction: scope id, context key values, creation attempt, and the worker-profile outcome, which is the verified launch record digest when `Verified`, or the `Unverified` reason (absent, mismatched, unverifiable, lookup failed, predicate false) otherwise. Every context therefore has a stable initial id, including when verification fails, and the fail-closed `unknown` start commits idempotently.
   - **Distinct destinations are distinct observations.** Two contexts that read the same artifact version produce two observations, one per destination. Each context's heads therefore receive the artifact's influence, and neither context can stay trusted because another context read the version first.
   - **Retries are stable.** A retry, replay or rebuild of one delivery (same record, same destination) yields the same id and changes nothing. Two deliveries of identical bytes yield two ids.
   - **A retry that cannot reuse its record over-taints and never under-taints.** If a host cannot reuse the delivery record when it retries, the retry adds a second observation. That only adds influence (I2). It never double-counts bits, because `ExternalBounded` observations are keyed by the confined-return record, which is unique per return.
   - Knowledge flow rows are unique on `(tenant, isolation_epoch, observation_id)`. The id binds the destination, so a row's principal, lineage and session or process values are a function of its id.
   - A join whose row key values disagree with the id's `destination_digest` is refused. The join fails closed, so the delivery it belongs to is withheld (I4).
   - A join inserts with insert-or-ignore semantics. Only a newly inserted row changes the summary heads (I16), so a duplicate join changes nothing.

   **I4b. Tracked contexts are not check-only or non-durable.**
   - When integrity tracking is enabled for the calling context, the call is neither check-only eligible nor `NonDurable`, under spec 9's eligibility rule (`2026-10-04-pure-admission-machine-design.md` section 4.4) and spec 10's read-only and non-durable paths (`2026-10-04-crossing-primitive-design.md` section 6.2, X13 and X13c).
   - It takes the durable path, whose `OutcomeCommit` writes the output-influence join (I4) in the same writer transaction, before the bytes are delivered. A check-only release only appends to `receipts.db`, so it has no authority write that could carry the join.
   - Gating requires tracking. A gated grant evaluated for a context without tracking is denied, because untracked deliveries would leave its influence head stale.
5. **I5. Origin assignment.** Origins come from an operator-signed `IntegrityDeploymentBindingV1`, never from the output and never solely from the tool publisher:
   - **Default.** Every route's output origin is `External`. An unbound route is `External`, never trusted (fail closed).
   - **Operator trust.** An operator may bind a route as `Trusted`, for an internal deterministic tool over operator-controlled data, or as `ModelProvider { provider }`. The binding names the server, the tool and the tool server's manifest digest. A manifest change voids it.
   - **Publisher declarations.** A publisher's `ToolFlowDeclaration` may only add influence, through a new optional `output_influence: External` field. It can never assert trust, matching P3's "publisher signatures confer no tenant authority".
   - **Replaces the unconditional marking.** The unconditional `externally_influenced: true` at W: `traversal.rs:67` becomes the join of the published inputs' actual influence states.
6. **I6. Mailboxes.**
   - A `receive` payload inherits the sender's influence state, recorded at `send` in the same transaction, when the channel has `attest_senders` (M: `MAILBOXES.md:33`).
   - Without sender attestation, its origin is `External`.
7. **I7. Initial influence of a context.** It comes from the **verified** worker-profile fact (`2026-10-04-microkernel-isolation-backend-design.md` rule 6.3.5), never from the raw attribution.
   - **Qualification.** The fact is `Verified(kind)` only when the host attribution equals the runner's per-attempt record, the referenced launch record verifies (pinned signer, digest, enforcement state), the record's attempt equals spec 7's runner-bound `worker_profile.launch_attempt` for this context (spec 7 rule 5.2.8), and the kind's own predicate holds (spec 7 rule 6.3.5).
   - **Failure behavior.** Any failure (absent, mismatched, unverifiable, lookup failed, predicate false) is `Unverified` and is treated as `direct` below. A failure can only make the start less trusted.
   - **Committed once.** The host verifies the fact when the context's knowledge scope is created. In the same writer transaction, it writes the context-creation record and inserts the initial observation keyed by it (`source_kind = initial`, I4a), whether the outcome is `Verified` or `Unverified`. A scope cannot exist without its initial observation. Crossings read the committed state and never re-derive it, and a later attribution can only add influence (I2).

   Starting states by verified kind:
   - **`direct`, or `Unverified`,** starts at `unknown = true`. The worker can ingest anything outside mediation.
   - **`container`** starts at trusted only when the run plan pins every input, the image digest, task input and seeds. Otherwise it starts at unknown.
   - **`split_domain`** starts the controller domain at trusted. Execution-domain results arrive as ordinary tool outputs, `External` unless bound otherwise.
   - **`confined_reader`** is not applicable: it has no tools.

   Kernel sessions (MCP edges) start at unknown (section 12).
8. **I8. Confined returns are bounded, not cleared.** A P5 return joins `ExternalBounded { max_bits }` into the parent, where `max_bits` is the capacity of its return contract (section 10). It does not copy the observation's full influence as `External`, which is today's `returns.rs:383` behavior. The original influence is retained, because the return's observation id binds the child's influence `commitment` (I4a), so the parent's set hash covers it. History is not reduced (SEC-05).
   - This is the one place where the class of a join differs from its source. It is justified because the parent receives only a host-recomputed value of at most `max_bits` bits, and every other channel is withheld (W: `confinement.rs:15-25`).
   - When the contract sets `require_integrity`, the return additionally needs its independently rooted endorsement, as today.

## 6. Declaring the requirement

`Constraint::RequiredIntegrity(IntegrityRequirementV1)` is a new constraint variant. A constraint, rather than a `ToolGrant` field, gives:
- conjunctive composition with other constraints;
- KG4's exhaustive enforcement decision;
- the portable core's fail-closed handling;
- the existing tier-constraint precedent (`MinimumRuntimeAssurance`, M: `scope.rs:359`).

9. **I9. Preserved monotonically.** `is_preserved_by` gains an explicit arm, so the default equality rule does not apply (M: `scope.rs:602`):

   ```text
   (RequiredIntegrity(p), RequiredIntegrity(c)) => stronger_or_equal(c, p)
   ```

   A delegation may raise the requirement, keep it, or add it, and never weaken or drop it (`is_subset_of` requires every parent constraint to be preserved).
10. **I10. KG4.** `ensure_capability_issuance_supported` (M: `authority.rs:102`) lists `RequiredIntegrity` as supported only when the receiving kernel has durable knowledge enforcement and the integrity crossing check installed. Otherwise issuance rejects it with the existing "grant-specific enforcement is unavailable" error.
11. **I11. Portable core.** `chio-kernel-core` has no knowledge store. It treats the constraint as unevaluable and fails closed with a `ConstraintError`, so browser, mobile and C FFI kernels deny integrity-gated grants.
12. **I12. Deployment floor.** An operator may set `integrity_floor` per effect class, from the tool annotations `destructive` and not-`read_only` (M: `manifest.rs:186-188`) and the monetary effect class.
    - The floor applies as if the constraint were present on every matching grant.
    - It may only raise requirements, and it is recorded in receipts (section 13).
    - The default floor is none, so v1 is opt-in per grant (open decision 1).

## 7. `IntegrityGuard` (early)

13. **I13. The guard.** `IntegrityGuard` is a deny-only `Guard`:
    - **Inputs.** For each matched grant carrying `RequiredIntegrity` (or a floor), it reads the calling context's influence through a read-only `IntegrityStatePort`, keyed by the trusted `SecurityInvocationContextV1` (M: `kernel/mod.rs:234`).
    - **Missing context.** It always denies. Unlike `FlowPreInvocationGuard`, there is no `MissingContextPolicy::Allow`, because the requirement is signed into the grant.
    - **Unavailable port.** It denies.
    - **Revalidation.** It sets `requires_dispatch_revalidation() = true` and repeats the read before dispatch (M: `kernel/mod.rs:882`).
    - **Presented endorsement.** When the request carries an `EndorsementRef` (I15a) and the context does not satisfy the requirement, the guard does not deny on influence alone. It checks only structure: the reference names a recovery workflow continuation for this request's scope. If that check passes, it defers the decision to crossing check 4. It never treats a reference as satisfying the requirement, and it denies when the structure check fails.
14. **I14. Advisory only.** The early read and the revalidation are best-effort latency savers. Neither decides an effect (section 8).

## 8. Authoritative check: crossing check 4

A join and a capture can race. A tool output can be delivered into the same context, and commit its join, between the guard's read and the dispatch. P4 already resolves the analogous confidentiality race by serializing capture and join in one writer (W: `p4/OPERATIONS.md:107-113`). Integrity uses the same point.

15. **I15. Inside the intent commit.** Spec B's crossing primitive evaluates `CrossingCheck::KnowledgeIntegrity { key, requirement }` inside the intent commit's writer transaction, before `DispatchCommitted`. A gated call always runs in a tracked context (I4b), so it is never check-only or `NonDurable`. It takes spec B's durable read path and is checked in that path's intent commit. Spec B's check-only dispatch crossing still carries the check, reading the committed influence head in the writer without writing, but under I4b it never meets a gated grant in a tracked context. `satisfies` is computed from the influence state as committed in that same transaction.
    - **Join first:** a join that commits first makes the intent commit fail with `InsufficientIntegrity`, unless a verified endorsement over the post-join commitment applies (I15a).
    - **Intent first:** the effect proceeds, and the later join affects only later calls.

    **I15a. Endorsed admission.** Crossing check 4 admits when either condition holds inside the crossing's writer transaction:
    - **By context.** `satisfies(state, requirement)` holds for the committed state of the call's key. For `BoundedSelection`, I22a's action condition also holds. The receipt records `satisfied_by = context`, or `bounded` when the satisfying origins are `ExternalBounded`.
    - **By endorsement.** The crossing plan carries `EndorsementRef { workflow_id, continuation_id }`, and every check below passes in this transaction. The receipt records `satisfied_by = endorsement`.
      - **Recorded and verified.** The approval is recorded on that recovery workflow record in the same writer. Its signatures and coverage were verified when it was submitted (W: `admission_operation_store/recovery/validation.rs:274-286`, `validate_approval`).
      - **Fresh deployment.** `fresh_basis` holds now: deployment, policy and contract digests unchanged (W: `validation.rs:287-300`).
      - **Integrity authority.** Its `obligations` include `IntegrityEndorsement { principal }`, and `principal` is on the deployment's integrity roster (W: `recovery/authorization.rs:40-45`).
      - **Exact action.** Its `ActionIntentV1` names this call's request id, request namespace and semantic request digest (W: `authorization.rs:69-90`). An endorsement for another action never applies.
      - **Current influence.** Its `influence_basis` equals the commitment of the call's key state as committed in this transaction, not the state when the approval was made. Any join after approval makes it stale.
      - **Single use.** The continuation has not been consumed by another operation. W: binds each recovery workflow to exactly one native operation, through `native_link`, set in the same writer when the continuation's operation begins (W: `admission_operation_store/recovery/native.rs:49-86`, which also re-runs `fresh_basis`). The crossing that carries the call (`RecoveryCapture`, or `SemanticCapture` for P3 connectors) sets or verifies that link in this same transaction. A different operation naming the same continuation fails the check, and a replay of the same operation returns its bound terminal result.
    - **Otherwise** the check refuses with `InsufficientIntegrity`. A refused endorsement is not a new fault (I18). The recovery actor learns the reason at resolution: `stale`, `consumed`, `wrong_action`, `deployment_changed` or `unrecorded`.
16. **I16. Summary rows.** W:'s `observed_influence` scans up to 4,096 join records per call (W: `security_participant_state/knowledge.rs:64-75`). This design adds `knowledge_influence_heads(tenant, isolation_epoch, key_subset, key_values) -> InfluenceHeadV1`. `key_subset` is one of the seven non-empty subsets of {principal, lineage, session}. Each head holds exact counters over the observations whose key values match on that subset: a `u64` bit sum, a count per origin class, an unknown count, an observation count and the additive set-hash value.
    - **Update.** A newly inserted observation (I4a) adds its terms to the seven heads of its key triple, in the same transaction. A duplicate insert changes nothing.
    - **Read.** Crossing check 4 computes the state of `P union L union S` (I17) exactly, by inclusion-exclusion over the seven heads of the call's triple, for every counter and for the set hash. That is seven row reads, which is O(1), and an observation reachable through several keys counts once. A class is in `origins` when its resulting count is positive. `bounded_bits_total` saturates only after the exact sum. The resulting set hash is the receipt `commitment` (I25).
    - **Rebuild.** A startup check recomputes every head from the flow rows and refuses readiness on mismatch. Each head is a function of the row set, so a rebuild reproduces it exactly.
    - **Fallback.** If a deployment ever makes a key kind multi-valued per observation, the check sums the per-key heads instead. That is an upper bound, and it is sound because `satisfies` is antitone: it can only deny more, never less.
17. **I17. Key semantics unchanged.** The check uses W:'s key semantics: the union of rows matching principal, lineage or session within tenant and isolation epoch. Narrowing is a later decision (section 11).

```text
committed(join(ctx, s)) before intent_commit(op) and key(op) = ctx and not satisfies(s', req(op))
  -> not DispatchCommitted(op)                     (s' = state after the join)
DispatchCommitted(op) -> satisfies(state_at(intent_commit(op)), req(op)) and action_ok(op)
                         or endorsed(op, intent_commit(op))                       (I15a)
endorsed(op, t)        -> exact_action(approval(op), op)
                          and influence_basis(approval(op)) = commitment(state_at(t))
                          and fresh_deployment(approval(op), t)
                          and consumed_exactly_once(continuation(op), t)
action_ok(op)          -> req(op) is not BoundedSelection, or action(op) in authorized(contract(op))   (I22a)
forall ctx: state(ctx) only increases              (I2; SEC-05)
```

## 9. Refusal, fault and remedies

18. **I18. A sibling fault kind, not a fifth class.**
    - Spec 2's classifier output is tagged: `FaultKind = Authority(AuthorityFaultClass) | Integrity` (`2026-10-04-authority-faults-design.md` section 4, rule R1). Each kind has its own block.
    - `AuthorityFaultClass` stays closed at four variants, and `AuthorityFaultV2` is unchanged. No integrity denial has to fill its capability, subject, tool, parameter or principal-path fields, and the `Capability` projection never sees an integrity denial.
    - The integrity kind is classified from the typed refusal `KernelError::InsufficientIntegrity { surface }`, which `IntegrityGuard` (I13) and crossing check 4 (I15) return. It is never classified from `GuardDenied`, which stays never-resolvable.
    - A request that presents an integrity endorsement (I21) never yields this fault, even when I15a refuses the endorsement. That avoids fault-on-fault loops (spec 2 R5).
19. **I19. The integrity fault block and its anti-oracle rule.** The block is written under receipt metadata key `integrity_fault`, and MCP carries it as `_meta["chio/integrityFault"]`:

    ```rust
    // crates/core/chio-core-types/src/capability/integrity_fault.rs (no_std + alloc)
    pub const INTEGRITY_FAULT_SCHEMA: &str = "chio.integrity-fault.v1";

    pub enum IntegrityFaultSurface { Guard, Crossing }
    pub enum IntegrityRemedyClass { IntegrityEndorsement, QuarantinedContinuation }

    #[serde(deny_unknown_fields)]
    pub struct IntegrityFaultV1 {
        pub schema: String,                            // the schema names the kind; no class field
        pub request_id: String,                        // the caller's own request
        pub requirement: IntegrityRequirementV1,       // the caller's own grant requirement
        pub surface: IntegrityFaultSurface,
        pub remedy_classes: Vec<IntegrityRemedyClass>, // closed, ordered, at most 2
    }
    ```

    - **Configuration-blind remedies.** `remedy_classes` is a function of the caller's own requirement, never of deployment configuration (spec 2 A5):
      - `Trusted` and `ProviderOnly` list `[IntegrityEndorsement]`;
      - `BoundedExternal` and `BoundedSelection` list `[IntegrityEndorsement, QuarantinedContinuation]`, because a quarantined successor can satisfy only a bounded requirement (I22).

      Whether a remedy is actually available is disclosed only to the recovery actor at resolution.
    - **Never carried.** The block never carries origin classes, bit totals, the commitment, or which delivery caused the taint. With session-wide keys (I17), the cause may be another process's delivery in the same runtime, so revealing it would leak cross-process activity.
    - **Spec 2's rules apply.** A1-A5 apply to this block, with A1's caller-held set equal to the fields above. A deny receipt carries at most one fault block, either `authority_fault` or `integrity_fault`. `ExplainIntent`-equivalent projections follow P2's stricter rules.
20. **I20. Planner fact.** Where a recovery deployment covers the request, the kernel exposes a new `ExplanationFactKind::Integrity` with value `false`. This is spec 2's projection for `FaultKind::Integrity`; `FaultKind::Authority` keeps projecting to `Capability`. W:'s fact enum is closed, so this is a schema change. Only two remedy paths may address it:
    - `ExactApproval` with obligation `IntegrityEndorsement` (I21);
    - `Prerequisite` with the `QuarantinedContinuation` template (I22).

    No other remedy kind may address it, and the planner returns `NoRegisteredRemedy` otherwise.
21. **I21. Endorsement.** An approver on the deployment's integrity roster signs an exact approval whose `AuthorizationRequirementsV1.obligations` contains `IntegrityEndorsement { principal }`. Its `influence_basis` equals the context's committed influence digest (W: `authorization.rs:44`, `:55`). The approval authorizes exactly one continuation despite the influence.
    - **Admission.** Crossing check 4 accepts it under I15a. The approval binds the exact action, the current commitment, the deployment and one continuation, and it is consumed in the same transaction.
    - **History.** The context's state is unchanged (SEC-05). The next consequential call needs its own endorsement.
    - **Semantic connectors.** For P3 connectors, the existing `ScopedEndorsementV1` over `ExactAction` (W: `semantic/evidence.rs:84-87`) is the same rule, already implemented, and satisfies the crossing check for that action.
22. **I22. Quarantined continuation.** The remedy that recovers utility without a human:
    1. A verified isolation-epoch transition starts an isolated successor whose influence starts trusted (M: `active-defense-rollout.md:19`).
    2. The tainted parent hands its untrusted artifacts only to P5 confined readers.
    3. The readers' typed returns join the successor as `ExternalBounded` (I8).
    4. The successor performs the consequential call under a `BoundedExternal { n }` requirement.

    This follows the Design Patterns paper's dual-LLM and action-selector patterns, enforced by the kernel rather than by framework discipline.

    **What it does not guarantee.** The successor's call is admitted on a bounded channel that external content influences. The readers saw untrusted artifacts, and their returned values pass to the successor. A one-bit boolean that a framework uses to choose between publishing and deleting is admitted under `BoundedExternal { n: 1 }` with no endorsement. `BoundedExternal` is therefore an explicit policy allowance of up to `n` attacker-influenced bits. It is not a guarantee that external content cannot select the action.

    **I22a. Action-selection contract (optional).** A deployment that needs zero unauthorized action selection uses `BoundedSelection { max_bits, contract }`. The contract is operator-signed:

    ```rust
    pub struct ActionSelectionContractV1 {
        pub schema: String,                                               // "chio.action-selection-contract.v1"
        pub return_contracts: BoundedList<ReturnContractDigest, 8>,       // typed returns allowed to select
        pub selector: SelectorTableV1,                                    // typed return values -> action template
        pub authorized_actions: BoundedSet<ActionTemplateDigest, 64>,     // every action the selector can produce
    }
    ```

    - An action template fixes the tool, the server and every argument, except arguments the selector fills from trusted inputs.
    - Crossing check 4 computes the expected action from the committed typed return values, through the selector. It uses the host's canonical projections (I23), never model text.
    - It admits the call only when the call's exact action equals that expected action and is in `authorized_actions`. Otherwise it refuses with `InsufficientIntegrity`.
    - A value outside the selector's domain is already refused at projection (I23).
    - **The property.** External content can choose only among `authorized_actions`; it can never reach an unauthorized action. Which authorized action it chooses remains influenced, and the operator accepts that when signing the set.

## 10. Typed return contracts (generalizing P5)

`ReturnContractV1` admits only an 8-byte boolean today (W: `confinement.rs:67-79`). This design adds a closed return-type library, recomputed by the host exactly as the boolean projection is (W: `chio-core-types/src/recovery/confinement.rs:58-73`):

```rust
pub enum ConfinedReturnTypeV1 {
    Boolean,                                                   // 1 bit
    Enum { variants: BoundedList<ProtectedText<64>, 256> },    // ceil(log2(n)) bits
    Integer { min: i64, max: i64 },                            // ceil(log2(max - min + 1)) bits
    Identifier { max_len: u8, charset: IdentifierCharsetV1 },  // max_len * log2(|charset|) bits, max_len <= 64
}
```

23. **I23. Capacity.** Each type has a fixed capacity in bits, which becomes `ExternalBounded { max_bits }`.
    - `Identifier` uses a restricted charset (ASCII letters, digits, `.`, `_`, `-`), with no spaces and no punctuation that can form instructions. Free text is not a return type.
    - The host projection rejects any value outside the type. There is no fallback.
24. **I24. Return discipline unchanged.** One value, on the `Value` channel only, with every other channel withheld. `max_bytes` is derived from the type, up to 64.

## 11. Granularity and utility

- **The enforceable property.** It holds at context granularity, over Chio-mediated channels. For a gated call that crossing check 4 admits:
  - **By context, under `Trusted`.** No external or unknown influence reached the context.
  - **By context, under `ProviderOnly`.** Only the listed providers did.
  - **By context, under `BoundedExternal { n }`.** At most `n` bits of external influence reached the context, each through a typed confined return. Those bits may select the action: this is a policy allowance, not a no-steering guarantee.
  - **By context, under `BoundedSelection`.** The same bit bound holds, and the action is one of the contract's authorized actions (I22a).
  - **By endorsement.** A roster principal approved this exact action against the context's current commitment, once (I15a).

  Unbounded or unknown influence can therefore authorize a gated call only through an exact endorsement. Influence at finer grain than a context is heuristic and out of scope.
- **Over-taint.** W:'s keys join principal, lineage and session, and process calls use the runtime id as session (M: `chio-process/src/security.rs:28-46`). One process's untrusted delivery therefore taints every process in that runtime.
  - This is conservative, and correct while processes can exchange data through mailboxes, blobs and spawn inputs.
  - Narrowing to lineage requires every inter-process channel to carry influence (I6 does so for attested mailboxes). Open decision 2.
- **Expected utility.** CaMeL solves 77 percent of AgentDojo tasks with provable security, against 84 percent undefended ([arXiv 2503.18813](https://arxiv.org/abs/2503.18813)). Expect a similar gap with `Trusted` requirements, narrowed by quarantined continuations (I22) and operator-bound trusted routes (I5).
- **What to report.** Utility, false-deny rate, and the endorsement rate, which measures human burden (section 14).

## 12. Surfaces and framework independence

- **Process workers.** These are any framework running as a Chio process (LangGraph, AI SDK, mini-SWE, coding-agent plugins). They get the full guarantee when the verified worker profile is `container` with pinned inputs, or `split_domain` (I7; spec 7 rule 6.3.5). The guarantee does not depend on the framework's language or interpreter.
- **Kernel sessions through MCP edges or the sidecar.** These start at `unknown`, because the client's model context includes inputs the kernel never saw.
  - Integrity-gated grants deny there, with `InsufficientIntegrity` and remedy class "run as a mediated process".
  - Grants without the constraint behave as today.
  - A deployment cannot declare an MCP client "trusted", because the kernel cannot verify complete mediation (open decision 3).
- **Hosted sessions** follow the kernel-session rule.

## 13. Receipts and evidence

25. **I25. Receipt metadata.** Every receipt for a grant with a requirement or floor carries `chio_runtime.integrity`. Allow and deny receipts disclose different fields, because with session-wide keys (I17) the commitment changes when another context in the same runtime receives a delivery.
    - **Allow receipts** carry:
      - `required`;
      - `satisfied_by`: `context`, `bounded` or `endorsement`;
      - the action contract digest under `BoundedSelection`;
      - `commitment_ref = HMAC(audit_key, commitment || request_id)`. The ref is blinded per receipt, so two receipts cannot be compared for equality without the audit key;
      - the floor source, when a floor applied.
    - **Caller-visible deny receipts** carry only `required`, `outcome: denied` and the floor source, plus the `integrity_fault` block (I19). They carry no `commitment`, `commitment_ref`, `context_generation` or `satisfied_by`.

    **I25a. Audit basis.** The raw `commitment`, the `context_generation` and the head digests used by crossing check 4 are written to `integrity_admission_audit(request_id, decision, commitment, context_generation, heads_digest)`, in the admission writer, in the decision's transaction (for a guard-only deny, in the deny receipt's transaction). The table is operator audience: it is exported only through operator-authenticated audit and SIEM paths, never to the caller. An auditor joins any consequential effect to the commitment that admitted it by recomputing `commitment_ref` with the audit key.

## 14. Evaluation plan

- **Benchmarks.**
  - AgentDojo: 97 tasks and 629 security cases ([leaderboard](https://agentdojo.spylab.ai)).
  - AgentDyn: dynamic, open-ended tasks.
  - PIArena ([arXiv 2604.08499](https://arxiv.org/abs/2604.08499)).
- **Attackers.** Adaptive attackers in the method of Zhan et al. ([arXiv 2503.00061](https://arxiv.org/abs/2503.00061)): attacks optimized against the deployed system, not static injection strings.
- **Configurations.**
  - Undefended.
  - Integrity gating with `Trusted` requirements.
  - Gating plus quarantined continuations.
  - Gating plus endorsement.

  Each runs across at least three frameworks running as Chio processes.
- **Metrics.**
  - Attack success rate on consequential actions.
  - Utility, as task success.
  - False-deny rate.
  - Endorsements per task.
  - Mediation overhead.
- **Success criteria.**
  - Zero gated consequential calls admitted from unbounded or unknown influence without an exact endorsement. This holds by construction (section 11), and the evaluation confirms the implementation.
  - Calls admitted under `BoundedExternal` are reported separately, with their attack success rate. A bounded channel is an allowance, so injections that succeed through it are counted, not excluded.
  - Under `BoundedSelection`, zero admitted calls outside the contract's authorized actions.
  - Utility within 10 points of undefended with quarantine templates.
  - The methodology, seeds and traces are published.
- **Honesty.** Static-benchmark "0 percent" claims are not reported.

## 15. Failure modes

| Failure | Behavior |
|---|---|
| No security context for a gated grant | Deny (I13) |
| Influence port or summary row unavailable | Deny |
| Summary row mismatch at startup | Not ready (I16) |
| The same delivery is joined twice (retry, replay, rebuild) | Insert ignored; state unchanged (I4a) |
| Two contexts read the same artifact version | One observation per destination; both contexts gain the artifact's influence (I4a) |
| A flow row's key values disagree with its id's destination | Join refused; the delivery is withheld (I4a) |
| Gated grant in a context without integrity tracking | Deny (I4b) |
| Worker-profile fact unverified | Context starts at `unknown`; gated calls deny (I7) |
| Unbound route output | Joins `External` (I5) |
| Manifest digest changed under an operator binding | The binding is void; output joins `External` |
| Join commits before the intent commit | Intent commit fails `InsufficientIntegrity` (I15) |
| Endorsement `influence_basis` stale (context gained influence since) | The endorsement does not apply; deny (I15a) |
| Endorsement's continuation already consumed (reuse) | Deny; the first admission's consumption stands (I15a) |
| Endorsement for a different action, request or namespace | Deny (I15a) |
| Endorsement after a deployment, policy or contract change | Deny (I15a) |
| `BoundedSelection` call whose action is not the selector's output, or not authorized | Deny (I22a) |
| Portable core receives the constraint | `ConstraintError` deny (I11) |
| Typed return outside its type | Return refused; no fallback (I23) |

## 16. Protocol, schema and wire impact

- `spec/PROTOCOL.md` section 5: the `required_integrity` constraint (vocabulary, ordering, preservation rule I9, KG4 support condition).
- Section 6: `chio_runtime.integrity` receipt metadata, and the `chio.integrity-fault.v1` block under `integrity_fault`, a sibling of spec 2's `authority_fault` (I18, I19).
- Section 8: deployment integrity bindings and floors.
- New schemas:
  - `chio.integrity-requirement.v1`;
  - `chio.integrity-fault.v1`;
  - `chio.influence-state.v1`;
  - `chio.integrity-deployment-binding.v1`;
  - `chio.confined-return-type.v1`;
  - `chio.action-selection-contract.v1`.
- Changes to W: closed enums: `ExplanationFactKind::Integrity`, the `QuarantinedContinuation` template, and `InfluenceOriginV1`. These are additive.
- Process ABI: no new op. Influence travels in existing invoke and receive outcomes.

## 17. Rollout

1. **Output joins (I4-I8)** behind `integrity-tracking`, recording influence without gating. This also replaces the unconditional external marking.
2. **The constraint, the guard, and crossing check 4 (I9-I17)** behind `integrity-gating`. Grants opt in.
3. **The fault, endorsement and quarantined continuation (I18-I22)**, with typed returns (I23-I24).
4. **Evaluation publication**, then optional deployment floors (I12).

GT1 applies: no guarantee is claimed until the conformance scenarios run in hosted CI.

## 18. Tests and conformance evidence

- **Proptest.**
  - Lattice laws over generated observation sets that include duplicates and replays: join is commutative, associative and idempotent, and monotone (I2). The bit total and commitment of `join(s, s)` equal those of `s`.
  - Fan-out identity: generated deliveries of one artifact version to several destinations give one observation per destination. Each destination's state includes that observation, and replaying any one delivery changes no state (I4a).
  - Head maintenance: incremental heads equal heads rebuilt from rows. Inclusion-exclusion over the seven heads equals a direct scan of `P union L union S`.
  - `satisfies` is antitone in state.
  - Attenuation never weakens a requirement (I9).
- **Loom.** A join racing an intent commit on the same context gives exactly one order. A post-join intent fails (I15). A join racing an endorsed intent makes the endorsement stale exactly when the join commits first (I15a).
- **Kani.** `satisfies` is total, and `unknown` always fails.
- **Unit.**
  - Unbound routes join `External`.
  - The operator binding is voided by a manifest change.
  - Attested mailbox inheritance.
  - Initial influence per verified worker profile. Each qualification failure starts at `unknown`.
  - Typed return capacity and projection rejection.
  - `InsufficientIntegrity` yields the `integrity_fault` block, never an `authority_fault` block. Its field set equals I19's, and `remedy_classes` depends only on the caller's requirement (I18, I19).
- **Conformance.**
  - An injected tool output followed by a consequential call is denied.
  - The quarantined continuation succeeds under `BoundedExternal`.
  - A same-principal endorsement replayed after new influence is refused.
  - Endorsement cases (I15a):
    - **fresh:** an exact endorsement over the current commitment admits the call once, with `satisfied_by = endorsement`;
    - **stale:** a join committed after approval makes the same endorsement fail;
    - **reused:** a second call naming the consumed continuation is refused;
    - **wrong action:** an endorsement for a different request, namespace or semantic digest is refused.

    The early guard defers each case to the crossing and never admits on the reference alone.
  - **Adversarial one-bit action selector.** An attacker-controlled document flips a boolean return that the framework uses to choose publish or delete.
    - Under `BoundedExternal { n: 1 }`, the delete is admitted with `satisfied_by = bounded`, and the evaluation counts it as an attack success through the allowance.
    - Under `BoundedSelection` with only publish authorized, the delete is refused (I22a).
  - **Whole-response anti-oracle differential.** Two runs differ only in which other context in the runtime received a tainting delivery, and when. Their caller-visible deny responses are byte-identical, including the body, `_meta` and all receipt metadata, except request id, timestamps and signatures (I19, I25).
  - MCP-edge gated grants deny.
  - A cross-process taint in one runtime denies, with no cause disclosed.
  - Two contexts in one tenant and isolation epoch read the same artifact version. The second context's gated call is denied (I4a).
  - A gated read-only call in a tracked context takes the durable path, and its output join commits before delivery (I4b).
- **Adversarial suite.** Adaptive injection cases from section 14 are added to `chio-adversarial-suite`.

## 19. Residual risks and open decisions

Residual risks:
- Channels outside mediation (a `direct` worker reading the network) are the reason such contexts start at `unknown`. A misdeclared worker profile would break the premise, so I7 consumes only the verified fact, and an unverified profile starts at `unknown` (spec 7 rule 6.3.5).
- Operator-bound `Trusted` routes are a trust decision. A wrong binding admits injection through that route.
- Bounded returns still carry information, up to `max_bits`, and that information can select the action (section 11). `Identifier` returns of 64 characters can encode short strings, so grants choose `n`. Only `BoundedSelection` limits which actions can be selected (I22a).
- Session-wide keys over-taint (section 11).

Open decisions:
1. **The default floor.** Opt-in per grant (proposed), or a default floor for `destructive` and monetary effects once evaluation numbers exist?
2. **Lineage-scoped keys.** Narrow to lineage once every inter-process channel carries influence?
3. **MCP clients.** Allow an attested-client profile (a client attests complete mediation inside a TEE) to start trusted, or never?
4. **Provider origins.** `ModelProvider` as a separate class, or always `External`?
5. **P5 change.** I8 replaces the copied `External` with `ExternalBounded` on returns. The P5 owners must confirm this matches SEC-05 as intended, since history is retained in `commitment` but the class differs.

## Review disposition

### Codex review (PR #1174, round 1)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180435333 | Define an idempotent integrity join | Fixed now. The state is a canonical deduplicated observation set with stable ids, and every field (an additive set hash for the commitment) derives from it, so join is set union. Heads use inclusion-exclusion for exact unions. The lattice-law tests now cover duplicates and replays | Section 4; I4a; I16; section 18 |
| 4180731791 (with spec 7) | Treat worker profile as an authorization fact | Fixed now. I7 consumes only the verified fact defined by spec 7 rule 6.3.5, commits it once as an initial observation, and starts any unverified context at `unknown` | I7; section 15; section 19 |

### Codex review (PR #1174, round 2)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180839009 | Include the artifact delivery in the observation ID | Fixed now. The id hashes the delivery record (for artifact reads, that read's P4 `ReleaseIntent`, never the version digest alone) and the destination context's key values. Two contexts that read one version each record an observation; retries of one delivery stay stable; a row whose key values disagree with its id is refused | I4a; section 15; section 18 proptest and conformance |
| 4180839016 (with spec 2) | Define an integrity-specific fault payload | Fixed now. Spec 2's classifier output is tagged (`FaultKind::Authority(class)` or `FaultKind::Integrity`). The integrity kind has its own `IntegrityFaultV1` block with only the request id, the caller's requirement, the surface and configuration-blind remedy classes, and it projects to `ExplanationFactKind::Integrity`. `AuthorityFaultClass` stays at four | I18; I19; I20; sections 13 and 16; spec 2 sections 4, 5, 8 and 10 |
| 4180839013 (spec 10 side handled there) | Persist influence joins before check-only output release | Fixed here for spec 11. A call in a tracked context is not check-only eligible, so its `OutcomeCommit` writes the join before delivery. Gating requires tracking | I4b; I15; section 15 |

### Codex review (PR #1174, round 4)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180933157 | Define an ID for unverified initial observations | Fixed now. The initial observation is keyed by the durable context-creation record, which records the worker-profile outcome (the verified launch record digest, or the `Unverified` reason). Every context gets a stable initial id, including on verification failure, and scope creation commits it in the same transaction | I4a; I7 |

### Independent review (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-11-01 | The integrity check rejects the endorsement remedy it promises to accept | Fixed. Crossing check 4 admits by context **or** by a verified exact endorsement, checked in the crossing's transaction. The endorsement must be recorded and verified on the workflow record, `fresh_basis` must hold, it must carry the `IntegrityEndorsement` obligation from a roster principal, its action intent must match this call's request id, namespace and semantic digest, and its `influence_basis` must equal the commitment as committed now. Its continuation is bound once, through W:'s one-operation `native_link`, in that transaction. The guard defers a presented reference without accepting it. Predicates and tests updated (fresh, stale, reused, wrong action) | I13; I15a; I15; section 8 predicates; I18; I21; section 15; section 18 |
| R-11-02 | A bounded return does not establish the claimed zero-injection guarantee | Fixed. Section 11 states the enforceable property per requirement. `BoundedExternal` is named an explicit allowance of attacker-influenced bits that may select the action. New optional `BoundedSelection` with an operator-signed `ActionSelectionContractV1` (selector plus authorized action set) gives zero unauthorized action selection. Success criteria count bounded-channel successes. A one-bit action-selector adversarial test is added. Appendix A no longer imports CaMeL's or FIDES's guarantees | scope line; section 4 (requirement, I1, I3); I22; I22a; section 11; section 14; section 18; section 19; Appendix A |
| R-11-03 | Deny receipts expose the commitment that the anti-oracle rule withholds | Fixed. Allow and deny receipts have separate disclosure rules. Caller-visible denies carry no commitment, ref, generation or `satisfied_by`. Allow receipts carry a per-receipt blinded `commitment_ref`. The raw basis goes to the operator-audience `integrity_admission_audit` table. A whole-response differential anti-oracle test is added | I25; I25a; section 18 |

### Codex review (PR #1174, round 5)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180993951 | A verified exact endorsement must satisfy both checks | Fixed, together with R-11-01. The early guard no longer denies on influence alone when a request presents an `EndorsementRef` that passes its structure check: it defers to crossing check 4 and never admits on the reference itself. Crossing check 4 then validates, in one writer transaction, the recorded and verified approval, the roster principal's `IntegrityEndorsement` obligation, the exact action (request id, namespace, semantic digest), `influence_basis` equal to the current commitment, and a fresh deployment. It binds the continuation to exactly one operation through W:'s `native_link`, so the endorsement admits exactly one call | I13; I15a; I21; section 18 endorsement cases |

## Appendix A. CaMeL, FIDES and the FTL lesson

| | CaMeL | FIDES | Chio (this design) |
|---|---|---|---|
| Enforcement point | Custom Python interpreter | Planner | Kernel admission and the intent commit |
| Quarantine | Quarantined LLM without tools | Hidden variables; constrained queries | P5 confined reader in an OS cage with `FullyEnforced` evidence; typed returns |
| Label | Per-value capabilities | Confidentiality and integrity labels per message | P4 influence state per context, monotone, in the serving writer |
| Endorse | Policy functions | `reveal` and endorse | Exact endorsement (`IntegrityEndorsement`, `ScopedEndorsementV1`); never rewrites history |
| Framework scope | One interpreter | One planner | Any framework running as a mediated process |

**The FTL lesson.** FTL's `lx` enforces its policy in the same address space as the application it polices, so the policy is advisory (FTL `lx/src/thread.rs:58`, `lx/src/process.rs:81`). A framework-level injection defense has the same flaw: the agent and its injected content share the domain doing the enforcement. This design moves enforcement out of that domain:
- into the kernel's writer, for the check;
- into a cage, for the quarantine.

The analogy holds for where enforcement happens. It does not transfer guarantees. CaMeL's and FIDES's results come from their own dataflow models and evaluations. Chio's guarantee is only the property in section 11, argued from its own mechanisms. A quarantine return under `BoundedExternal` is an allowance that can still select an action.
