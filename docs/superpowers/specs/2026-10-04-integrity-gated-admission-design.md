# Design: integrity-gated admission

- Status: PROPOSED (revision 5, 2026-10-05, after Codex review rounds 7, 8 and 10 on PR #1174; revision 4 after the second independent review; revision 3 after the first independent review and Codex review; revision 1 baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5)
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

## Revision 5 changes

- **Independent review pass 4 and Codex round 17.**
  - Crossing check 4's endorsement branch reads one `VerifiedEndorsementFactV1`, built by a recovery-approval adapter or a P3 adapter. I21's automatic P3 claim is withdrawn (I15b, R-11-07).
  - New section 4.1 freezes the LtHash16 commitment and names the P4 journal as the canonical owner, with versioned projections, conservative legacy seeds and readiness gating (R-11-08).
  - `commitment_ref` and the audit rows bind the full replay identity (I25, I25a).

From Codex review round 10 on PR #1174 (head `f7242409b`):
- **The quarantined successor is the one exception to inheritance (4185993940).** I7a's lossless inheritance made the I22 successor inherit its tainted parent, so the remedy always denied. A verified isolation-epoch transition is now an explicit, fail-closed exception. It needs a verified remedy record, a fresh epoch and no parent channel other than P5 returns. When it applies, only P5 typed returns and the successor's own classified bootstrap contributions cross. Any failed condition falls back to full inheritance.
- **Return types are validated at load (4185993976).** Every return type is validated at load: an `Enum` is non-empty and distinct, an `Integer` has `min <= max`, and an `Identifier` has valid bounds and charset. `N >= 1` therefore always holds, and a malformed contract is rejected at policy load.

From Codex review round 7 on PR #1174 (head `3672dca3b`):
- **Lossless inheritance (4185260800).** A child no longer copies parent observation ids, which bind the parent's destination, and no longer uses one summarizing observation, which can carry only one origin and one bit bound. Each parent observation is re-keyed for the child (`source_kind = inherited`), with its origin class, provider, bit bound and `unknown` copied exactly. A parent state that cannot be enumerated and re-keyed within bounds denies scope creation (I7a).
- **Selector inputs are bound (4185260813).** An action contract now declares ordered input slots. The call binds the exact confined-return observations that fill them. Crossing check 4 computes the expected action only from those inputs, consumes each input once, and denies a missing, extra, duplicate, consumed or ambiguous input (I22a).

## Revision 4 changes

From the second independent review on PR #1174 (head `faec88fcd`):
- **Action restrictions are independent of input integrity (R-11-04).** Revision 3 put `BoundedSelection` below `Trusted` in one order, so a delegate could replace a parent's action-selection contract with `Trusted` and call an action the parent excluded. The requirement is now a pair: an integrity level and an optional action contract. Attenuation may raise the level, but it must keep the parent's contract, compared by digest. An endorsement never authorizes an action outside the contract (section 4, I1, I3, I9, I15a, I22a).
- **Launch qualification is not input trust (R-11-05).** Revision 3 started a verified `container` or `split_domain` context at trusted when its inputs were pinned. A digest proves which bytes were supplied, not where they came from. Every bootstrap contribution is now joined before the context is ready: inherited parent state, task input, seeds, checkpoint, spawn input, and control and selection metadata. Unclassified contributions start `unknown`, and pinned contributions start `External`. Only an explicit operator-signed `BootstrapTrustAssertionV1` makes a contribution trusted (I4, I4a, I7, I7a, section 11).
- **The denial invariant includes the endorsement exception (R-11-06).** The section 8 predicate, the failure table and the Loom plan now distinguish join, then fresh approval, then intent (admitted) from approval, then new join, then intent (refused).

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

`SetHash` is the frozen additive set hash of section 4.1, over the observation ids. Its value depends only on the set, not on insertion order. The origin-class space is bounded by the deployment binding (I5): an `IntegrityDeploymentBindingV1` naming more than 30 providers is refused at configuration time, so `origins` never overflows at runtime.

Projection from the implemented record:
- `unknown` maps to `unknown`;
- `externally_influenced` maps to `External` in `origins`;
- otherwise the state is trusted, with empty origins.

The proposed refinement adds `ExternalBounded` and `ModelProvider`. It is additive, as W: requires ("requires new native participant evidence before deployment"). The enum change is additive. The representation change it brings (a versioned projection, a frozen commitment and a migration of existing state) is specified in section 4.1.

Order and join. The abstract state of a context is its observation set `O`, keyed by `observation_id`, and `state(O)` derives every field above:

```text
state(O1) <= state(O2)       iff  O1 subset-of O2
join(state(O1), state(O2))    =   state(O1 union O2)
bottom = state({})                (trusted: empty origins, 0 bits, known)
```

Join is set union, and every field (the commitment included) is a function of the set. So join is idempotent (`join(s, s) = s`: replaying or rebuilding a delivery adds nothing), commutative and associative. The order implies the field orders: `origins` only grows, `bounded_bits_total` only grows (a sum of non-negative terms over a superset, saturated after the exact sum), and `unknown` only moves from false to true. Two distinct deliveries of the same bounded return are two observations, and both count. One delivery replayed counts once.

The requirement a grant declares is a pair of independent restrictions: what may have influenced the context (the level), and which actions it may select (the optional action contract).

```rust
pub struct IntegrityRequirementV1 {
    pub level: IntegrityLevelV1,                                 // input integrity (I1)
    pub action_contract: Option<ActionSelectionContractDigest>,  // action restriction (I22a), independent of level
}

pub enum IntegrityLevelV1 {
    Trusted,                                      // no external origin, known provenance
    BoundedExternal { max_bits: u16 },            // only ExternalBounded origins, total <= max_bits
    ProviderOnly { providers: BoundedSet<ProviderId, 8> }, // Trusted plus listed providers
}
```

Notation used in this spec:
- `Trusted`, `BoundedExternal { n }` and `ProviderOnly(ps)` alone mean that level with no action contract.
- `BoundedSelection { n, c }` means `{ level: BoundedExternal { n }, action_contract: Some(c) }`.
- Any level may carry a contract. For example, `{ level: Trusted, action_contract: Some(c) }` is a trusted context restricted to `c`'s actions.

Normative rules:

1. **I1. Satisfaction.** `satisfies(state, req)` reads `req.level` only, and is false whenever `state.unknown`.
   - `Trusted` requires empty origins.
   - `BoundedExternal { n }` requires every origin to be `ExternalBounded` and `bounded_bits_total <= n`.
   - `ProviderOnly(ps)` requires every origin to be `ModelProvider { p }` with `p` in `ps`.
   - The action contract is a separate condition, `action_ok`, which crossing check 4 evaluates whenever `req.action_contract` is set, whatever the level (I22a). `satisfies` reads state only.
2. **I2. Monotone.** Joins only move up the order, and nothing in this design moves a context down, so `satisfies` can only go from true to false within one context.
3. **I3. Requirement order.** The order is the product of two independent orders. `stronger_or_equal(c, p)` holds only when both of these hold:
   - **Level.** `level_ge(c.level, p.level)`:
     - `Trusted` is stronger than every `BoundedExternal` and every `ProviderOnly`;
     - `BoundedExternal { n }` is stronger than `BoundedExternal { m }` when `n <= m`;
     - `ProviderOnly(ps)` is stronger than `ProviderOnly(qs)` when `ps` is a subset of `qs`;
     - `BoundedExternal` and `ProviderOnly` are incomparable.
   - **Action contract.** `contract_preserved(c.action_contract, p.action_contract)`. A parent with no contract imposes none. A parent with `Some(d)` requires the child to carry exactly `Some(d)`, the same contract digest.

   Raising the level never removes an action restriction. `Trusted` alone is not stronger than `BoundedSelection { n, c }`; the stronger form is `{ level: Trusted, action_contract: Some(c) }`.
   - **Why digest equality.** Comparing authorized action sets is not enough. Two contracts with the same set can map the same typed return to different actions, so a set check would let a child change which action an influenced value selects.
   - **Future refinement.** A relation that admits a refined contract (the same selector over a subset of actions, with a checked proof) is a later decision. Version 1 requires equal digests and allows only a stricter bit bound.

### 4.1 Commitment algorithm, canonical owner and migration

**Frozen commitment algorithm.** The algorithm is fixed before anything is persisted or signed. Changing it requires a new domain version and a migration under the rules below.
- **Accumulator.** LtHash16: 1024 lanes of `u16`, 2048 bytes. Adding an element adds lane-wise modulo 2^16, and removing it subtracts. LtHash is chosen over MuHash because I16's inclusion-exclusion subtracts, and MuHash would need modular inversion.
- **Element map.** `E(id) = SHA-256("chio.influence-set.v1\0" || id || 0x00) || ... || SHA-256("chio.influence-set.v1\0" || id || 0x3f)`, which is 64 blocks giving 2048 bytes, read as 1024 little-endian `u16` lanes. It uses only SHA-256, which the workspace already ships.
- **Final digest.** `commitment = SHA-256("chio.influence-commitment.v1\0" || accumulator_le_bytes || u64_le(|O|))`, as a `CanonicalPayloadDigest` tagged with its domain. Heads store the accumulator and the count, and receipts carry only the final digest (blinded, I25).
- **Conformance vectors** ship with the schema: the empty set; one element; two elements added in both orders; add then remove; and an inclusion-exclusion example over overlapping principal, lineage and session keys. An implementation that fails a vector refuses readiness.

**One canonical owner.** The P4 knowledge journal (W: `security_participant_state/knowledge.rs`, flow rows) is the only writable truth about what influenced a context.
- Every consumer reads it through one versioned projection, `project(journal, projection_version) -> InfluenceStateV1`. The consumers are crossing check 4, the I16 heads, artifact and checkpoint influence, releases, archive import, semantic materialization and confined returns.
- I16 heads are derived caches. Only the journal-insert transaction and the startup rebuild write them, a rebuild reproduces them exactly, and they are never a second writable truth.

**Historical domains are immutable.** No existing signed byte or historical digest is rewritten or reinterpreted:
- `ArtifactInfluenceV1 { commitment, externally_influenced, unknown }` inside immutable artifact metadata (W: `knowledge/artifact.rs:13-19`), checkpoints (`knowledge/checkpoint.rs:16`) and releases (`knowledge/release.rs:72`);
- the journal's `chio.knowledge.observed-influence.v1` commitment (W: `security_participant_state/knowledge.rs:82`);
- traversal commitments (`knowledge/traversal.rs:43-73`);
- P3's `chio.knowledge.semantic-influence.v1` digests (W: `recovery/knowledge.rs`).

New records carry the new state in a separate, versioned field (`influence_state: chio.influence-state.v1`) beside the old one, never in place of it. The old reducers stay available as projections of the same journal under their own domains, so P3 materialization and P4 provenance keep producing exactly the digests they produce today.

**Legacy seed observations.** The migration that enables tracking turns every existing journal record into one seed observation:
- `observation_id = H("chio.influence-legacy-seed.v1\0" || journal_record_id || destination_digest)`, with the record's own key values and its record id as provenance, so the id is stable and a re-run inserts nothing new.
- The classification is conservative: `externally_influenced` gives `External`, and `unknown` gives `unknown = true`. **A record with both flags false projects `unknown = true`** unless the complete mediated history of the context that produced it is independently proven. That proof needs a producing context created under tracking, or a journal showing every input of that context. This covers pre-migration artifacts read by contexts created after migration: such an artifact may derive from the same unjournaled tool output, so reading it taints the reader as unknown.
- **Missing history is not trust.** Before tracking, tool output delivered to a worker was not journaled (N25, section 5). So every context that is live at migration also receives one seed observation with `unknown = true`, `H("chio.influence-legacy-context.v1\0" || destination_digest)`, whatever its legacy rows say, including when it has none.
  - The only exception is a context whose complete mediated history can be shown: one created after tracking was enabled, or one restarted in a fresh isolation epoch after migration.
  - A pre-tracking context can therefore never satisfy a `Trusted` requirement merely because nothing tainted it on record.
- Refinements cannot be recovered from legacy state, so a legacy external record stays `External`, never `ExternalBounded` or `ModelProvider`. That is more restrictive, never less.
- A record whose kind or influence cannot be classified seeds `unknown = true`. A record that cannot be read refuses readiness.

**Consistent projections for every consumer:**
- **Live heads** are built from seeds plus new observations in the migration transaction.
- **Artifacts, checkpoints and releases.** A read or restore of an artifact or checkpoint written before migration joins an observation whose origin is projected from its stored `ArtifactInfluenceV1` by the conservative rule above.
- **Archive import** projects imported influence the same way, and refuses an archive whose influence or projection version it does not support.
- **Semantic materialization** keeps its own domain, computed from the same journal state that the heads project (I15b recomputes it in the same writer).
- **Confined returns** record their `ExternalBounded` observation through the journal (I8).

**Readiness and downgrade:**
- The migration records `knowledge_projection_version` only after seeds and heads are complete and the startup rebuild matches.
- `integrity-gating` cannot be enabled, and a gated grant does not load, unless that version is current. A partial migration, or an unsupported commitment or projection version, refuses readiness.
- The admission schema version is bumped, so an older binary refuses to open the store instead of writing journal rows that bypass the heads. The new number is allocated in landing order under the schema ledger lock, with a symbolic name on the branch (owner decision UR-D3).

**Owner's open question 2, resolved.** The P4 knowledge journal is the canonical owner. `chio.influence-state.v1` is a versioned projection beside `ArtifactInfluenceV1`, which it extends rather than replaces. The commitment algorithm and old-state migration are frozen above, before any signed schema is published. The old artifact, approval and semantic domains are kept as history.

## 5. Output influence joins

Today the influence of a context reflects only P4 artifact traffic. The main injection vector is a tool output entering a worker's model context, and it is untracked.

4. **I4. Join on delivery.** Every output the kernel delivers into a mediated context joins its influence into that context's knowledge flow rows. The join happens in the serving writer, in the same transaction as the outcome commit or release (spec B). Delivered outputs are:
   - process `invoke` results;
   - kernel-session tool results;
   - mailbox `receive` payloads;
   - artifact reads;
   - model-context restores;
   - confined returns;
   - bootstrap contributions at scope creation (I7a).

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
     - for each bootstrap contribution under `source_kind = bootstrap` (I7a), the context-creation record digest plus the contribution kind and the contribution digest;
     - for each inherited parent observation under `source_kind = inherited` (I7a), the parent observation's own `observation_id`. The child's `destination_digest` completes the id, so the inherited row never collides with the parent's row under the `(tenant, isolation_epoch, observation_id)` key, and it passes the destination check below;
     - the context-creation record under `source_kind = initial`, for the initial-influence observation (I7). It is the knowledge-scope creation row written in the same transaction: scope id, context key values, creation attempt, and the worker-profile outcome, which is the verified launch record digest when `Verified`, or the `Unverified` reason allowed by spec 7 rule 6.3.5 (absent or unavailable evidence, lookup failed, qualification unavailable with no mismatch) otherwise. Every created context therefore has a stable initial id, including on an allowed unverified fallback, and the fail-closed `unknown` start commits idempotently. A profile mismatch or mandatory-claim rejection refuses context creation instead (I7).
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
   - **Failure behavior.** Apply spec 7 rule 6.3.5 in its stated order. Attribution or available-record mismatches and mandatory-claim failures deny before context creation, even for calls without an integrity requirement; they never produce a `direct` fallback. Only evidence unavailable or unqualified without such a rejection yields `Unverified`, treated as `direct` below. The knowledge owner consumes this result from spec 7's verifier rather than implementing another qualification path.
   - **Committed once.** The host verifies the fact when the context's knowledge scope is created. In the same writer transaction, it writes the context-creation record and inserts the initial observation keyed by it (`source_kind = initial`, I4a), whether the outcome is `Verified` or `Unverified`. A scope cannot exist without its initial observation. Crossings read the committed state and never re-derive it, and a later attribution can only add influence (I2).

   Launch qualification and input influence are two separate facts. The verified profile decides only whether the worker has channels outside mediation. It never decides that the worker's inputs are trusted. The initial observation by verified kind:
   - **`direct`, or `Unverified`:** `unknown = true`, because the worker can ingest anything outside mediation.
   - **`container`, or the controller domain of `split_domain`:** a trusted initial observation that asserts only "no channel outside mediation". The context's starting state is then that observation joined with every bootstrap contribution (I7a). A pinned run plan proves which bytes were supplied, which makes the run reproducible, not which bytes are trusted. A `split_domain` controller's execution-domain results arrive later as ordinary tool outputs, `External` unless bound otherwise.
   - **`confined_reader`:** not applicable, because it has no tools.

   Kernel sessions (MCP edges) start at unknown (section 12).

   **I7a. Bootstrap joins before readiness.** In the same writer transaction that writes the context-creation record, and before the context becomes ready or receives its first input byte, the host joins one observation per bootstrap contribution (`source_kind = bootstrap`, I4a). This follows P5's rule, which joins parent knowledge, control and selection metadata, seeds and sensitive observations before stdin delivery (W: `implementation/p5/OPERATIONS.md:70-71`). Bootstrap contributions are:
   - the inherited parent state, re-keyed observation by observation (below);
   - the task input and any spawn or bootstrap JSON delivered on stdin (M: `chio-process/src/registry.rs:23-45`; `chio-cli/src/cli/process_host/runner/child.rs:524-530`);
   - seeds;
   - a checkpoint or restored state;
   - control and selection metadata the host passes in.

   **Inherited parent state, re-keyed.** Inheritance is lossless and never summarized:
   - **Source set.** The parent's observation set is exactly what crossing check 4 would read for the parent at this transaction: the flow rows matching the parent's principal, lineage or session within tenant and isolation epoch (I17). It is read in the same writer transaction that creates the child.
   - **Re-keying.** For each parent observation `p` not already reachable through the child's own key union, the child inserts one inherited observation. Its id is

     ```text
     observation_id = SHA-256("chio.influence-observation.v1\0" || "inherited"
                              || "\0" || p.observation_id
                              || "\0" || child destination_digest)
     ```

     and its `origin` (class, provider id and `max_bits`) and `unknown` are copied from `p` exactly. A parent observation already reachable through the child's keys (a shared principal, lineage or session) already counts once in the child's union, so it is not re-keyed, and no bounded bits are counted twice.
   - **Exactness.** The inherited observations, together with the parent rows already reachable through the child's keys, reproduce the parent's `origins`, `bounded_bits_total` and `unknown` at that transaction exactly. The child's full starting state joins that with its own initial observation and other bootstrap contributions, so it is never less tainted than the parent. The commitment differs because the ids differ. The context-creation record keeps `inherited_from { parent scope, parent commitment, parent observation_count }` for audit.
   - **Idempotent.** Re-running inheritance for the same parent set and child destination yields the same ids. Inserts use insert-or-ignore (I4a), so a retried creation changes nothing.
   - **Unrepresentable means deny.** One `InfluenceObservationV1` carries one origin and one bit bound, so no single summarizing observation can stand for a parent with several origin classes, several providers or accumulated bounded bits. Scope creation is therefore refused, never under-tainted, in three cases:
     - the parent's rows are not in this writer;
     - the parent's set exceeds the per-context history bound of 4,096 rows (W: `security_participant_state/knowledge.rs:123-141`);
     - any parent row cannot be read.

   **The one exception: the quarantined successor (I22).** A child created by I22's verified isolation-epoch transition does not inherit the parent's observation set. This is the only exception to inheritance, and it fails closed.
   - **When it applies.** All three conditions hold in the creating transaction. Otherwise the child inherits in full, as above:
     1. **Verified transition.** A committed remedy record of the `QuarantinedContinuation` template (I19, I22) drives the creation. It names the parent scope, the parent's commitment when the remedy was recorded, and the new isolation epoch id. Its approval or remedy decision, deployment binding (I5) and freshness are verified in the same transaction.
     2. **Fresh epoch.** The new isolation epoch id has never been used in this tenant: no scope, flow row or summary head exists under it.
     3. **No other channel.** The successor's scope gives the parent no capability, delegation, mailbox route, shared session, shared process lineage or shared principal into the successor. Its run plan names no input source in the parent other than P5 confined returns. The host checks this against the successor's run plan and capability set before readiness, and a check that cannot be completed counts as a failure.
   - **What crosses.** The successor starts at the trusted bottom state of the new epoch, joined with:
     - its own initial observation (I7) and its bootstrap contributions, classified by the rules below and never as inherited. A task, seed or other contribution that the parent authored is parent influence, so it joins the parent's state exactly as inheritance would. The remedy therefore succeeds only when the successor's task and seeds come from the remedy record's template, or from the workflow request that predates the taint, under a `BootstrapTrustAssertionV1`;
     - each P5 typed confined return, joined as `ExternalBounded` through its confined-return record (I4a, I8). Under I17's key semantics this is the only influence that can reach the new epoch.
   - **What does not cross.** The parent's observation set, its commitment and its summary heads. The context-creation record keeps `quarantined_from { parent scope, parent commitment, remedy record id, new epoch }` for audit.
   - **Guarantee kept.** Every other child keeps the never-less-tainted guarantee above. The successor's property is I22's: under `BoundedExternal { n }`, at most `n` attacker-influenced bits reach it, each through a typed return.

   Each contribution is classified by the first rule that applies:
   - **Inherited.** It carries the parent's influence exactly, through the re-keyed observations above.
   - **Asserted trusted.** It is trusted only under a `BootstrapTrustAssertionV1` that covers it (below).
   - **Pinned, unasserted.** A contribution whose digest is pinned in the run plan, with no assertion, joins `External`.
   - **Unclassified.** Any other contribution, including any the host cannot attribute, joins with `unknown = true`.

   ```rust
   /// The assertable bootstrap contributions of I7a, closed. Inherited parent state is never asserted.
   #[serde(rename_all = "snake_case")]
   pub enum BootstrapKind { TaskInput, BootstrapJson, Seed, Checkpoint, ControlMetadata } // closed

   /// The signed body. A digest alone never confers trust, and the body alone is never accepted.
   #[serde(deny_unknown_fields)]
   pub struct BootstrapTrustAssertionV1 {
       pub schema: String,                                     // "chio.bootstrap-trust-assertion.v1"
       pub deployment_binding: Digest,                         // IntegrityDeploymentBindingV1 (I5)
       pub deployment_generation: DeploymentGeneration,        // roster and policy generation it was signed under (I15a)
       pub run_plan: Digest,                                   // the run plan the context launches under
       pub contributions: BoundedList<(BootstrapKind, Digest), 16>, // exactly which contributions, by kind and digest; non-empty, no repeated pair
       pub signer: IntegrityAuthorityId,                       // the integrity-roster entry that signs (I15a, I21)
       pub expires_at: UnixSeconds,
   }

   /// The only accepted form; recorded with the context-creation record.
   #[serde(deny_unknown_fields)]
   pub struct SignedBootstrapTrustAssertionV1 {
       pub body: BootstrapTrustAssertionV1,
       pub signer_key: PublicKey,   // the key the integrity roster binds to body.signer
       pub signature: Signature,    // over SHA-256("chio.bootstrap-trust-assertion.v1\0" || canonical_json(body))
   }
   ```

   - **Verification.** At scope creation, in the writer transaction that writes the context-creation record, an assertion is accepted only when every check passes:
     - it decodes as `SignedBootstrapTrustAssertionV1`, with no unknown field and a known `BootstrapKind` in every entry, and `schema` is exactly `chio.bootstrap-trust-assertion.v1`;
     - `body.signer` is on the deployment's integrity roster at the current deployment generation, and `body.deployment_generation` is that generation (I15a's roster rule; the roster is configured only through the P6 signed policy owner);
     - `signer_key` is the key the roster binds to `body.signer`, and `signature` verifies under it over the domain-separated canonical body;
     - `deployment_binding` and `run_plan` name this context's, each covered contribution's digest matches, and authority time is before `expires_at`.
   - **Rejection fails closed.** An unsigned, malformed, unverifiable or off-roster assertion is rejected and confers nothing. Each contribution it named is classified by the next rule below, as if no assertion existed: `External` when pinned, otherwise `unknown`. The rejection is recorded with the context-creation record. A fabricated assertion therefore never makes attacker-controlled bootstrap bytes `Trusted`.
   - An assertion applies only to the named deployment, the named run plan and the exact contribution digests, before `expires_at`. The accepted signed assertion is recorded with the context-creation record.
   - A context therefore starts trusted only when its profile is qualified and every bootstrap contribution is inherited from a trusted parent or covered by an assertion.
   - **Owner's question on bootstrap authority, answered.** Pinning is a reproducibility mechanism only. Trust in bootstrap material is an explicit decision: the authorizer is an integrity-roster principal, the scope is (deployment, run plan, contribution kind and digest), and the evidence is the signed assertion. Without it, pinned material is `External`.
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

   A delegation may raise the level, keep it, or add a requirement, and never weaken or drop one (`is_subset_of` requires every parent constraint to be preserved). `stronger_or_equal` is I3's product order, so a delegation can never drop or change a parent's action contract, even while raising the level to `Trusted`.
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
    - **Presented endorsement.** When the request carries an `EndorsementRef` (I15a) and the context does not satisfy the requirement, the guard does not deny on influence alone. It checks only structure: the reference names either a recovery workflow continuation, or (once the I15b P3 adapter ships) a P3 `ScopedEndorsementV1` evidence reference, for this request's scope. If that check passes, it defers the decision to crossing check 4. It never treats a reference as satisfying the requirement, and it denies when the structure check fails.
14. **I14. Advisory only.** The early read and the revalidation are best-effort latency savers. Neither decides an effect (section 8).

## 8. Authoritative check: crossing check 4

A join and a capture can race. A tool output can be delivered into the same context, and commit its join, between the guard's read and the dispatch. P4 already resolves the analogous confidentiality race by serializing capture and join in one writer (W: `p4/OPERATIONS.md:107-113`). Integrity uses the same point.

15. **I15. Inside the intent commit.** Spec B's crossing primitive evaluates `CrossingCheck::KnowledgeIntegrity { key, requirement }` inside the intent commit's writer transaction, before `DispatchCommitted`. A gated call always runs in a tracked context (I4b), so it is never check-only or `NonDurable`. It takes spec B's durable read path and is checked in that path's intent commit. Spec B's check-only dispatch crossing still carries the check, reading the committed influence head in the writer without writing, but under I4b it never meets a gated grant in a tracked context. `satisfies` is computed from the influence state as committed in that same transaction.
    - **Join first:** a join that commits first makes the intent commit fail with `InsufficientIntegrity`, unless a verified endorsement over the post-join commitment applies (I15a).
    - **Intent first:** the effect proceeds, and the later join affects only later calls.

    **I15a. Endorsed admission.** Crossing check 4 admits when either condition holds inside the crossing's writer transaction:
    - **By context.** `satisfies(state, requirement)` holds for the committed state of the call's key, and, when `requirement.action_contract` is set, I22a's action condition also holds, whatever the level. The receipt records `satisfied_by = context`, or `bounded` when the satisfying origins are `ExternalBounded`.
    - **By endorsement.** The crossing plan carries an `EndorsementRef`, and an adapter (I15b) builds a `VerifiedEndorsementFactV1` from it inside this transaction. The branch admits only on that fact, never on raw approval or evidence bytes. Every check below passes in this transaction, and the receipt records `satisfied_by = endorsement`.
      - **Integrity authority.** `fact.integrity_authority` is on the deployment's integrity roster at `fact.deployment_generation`. The roster and the other integrity deployment fields are configured only through the existing P6 signed policy owner, `apply_reviewed_semantic_deployment`, with explicit fields and validation (spec 1 section 6). There is no separate activation service. That generation must be the current one (`fresh_basis`: deployment, policy and contract digests unchanged; W: `validation.rs:287-300`).
      - **Exact action.** `fact.native_binding` names this call's request namespace, request id and semantic request digest. An endorsement for another action never applies.
      - **Action contract still applies.** When `requirement.action_contract` is set, I22a's full action condition `action_ok` holds in this transaction, exactly as on the context branch: the selector inputs are bound (cardinality, membership, distinctness, commit order, single consumption), the call's exact action equals the selector's output for those bound values, and that action is in `authorized_actions`. An endorsement replaces only the level condition `satisfies(state, requirement)`. A human approved this action despite the influence, but no endorsement overrides the selector or authorizes an action the contract excludes. An endorsed call whose action differs from the selector's output is refused.
      - **Current influence.** `fact.context_commitment` equals the I16 commitment of the call's key state as committed in this transaction, not the state when the endorsement was made. Any join after the endorsement makes it stale.
      - **Single use.** `fact.continuation` has not been consumed by another operation, and the crossing that carries the call consumes it in this transaction. For a recovery approval this is W:'s `native_link`, which binds each recovery workflow to exactly one native operation (W: `admission_operation_store/recovery/native.rs:49-86`, which also re-runs `fresh_basis`) and is set or verified by `RecoveryCapture`. For a P3 endorsement it is the semantic operation's own consumption record, set by `SemanticCapture` (I15b). A different operation naming the same continuation fails the check, and a replay of the same operation returns its bound terminal result.

    **I15b. The verified endorsement fact and its two adapters.** Crossing check 4 reads one narrow fact, whatever produced the endorsement:

    ```rust
    /// Built inside the crossing's writer transaction by one adapter below. Never deserialized
    /// from a caller, never persisted as an authority input, never compared across digest domains.
    pub struct VerifiedEndorsementFactV1 {
        pub source: EndorsementSourceV1,                 // RecoveryApproval | SemanticEndorsement
        pub integrity_authority: IntegrityAuthorityId,   // the roster entry that authorized it (principal or key)
        pub deployment_generation: DeploymentGeneration, // roster and policy generation it was checked against
        pub native_binding: NativeActionBindingV1,       // request_namespace_digest, request_id, semantic request digest
        pub context_commitment: CanonicalPayloadDigest,  // the I16 commitment (chio.influence-commitment.v1) checked in this transaction
        pub continuation: EndorsementContinuationV1,     // Recovery { workflow_id, continuation_id } | Semantic { operation_id }
    }
    ```

    - **Recovery approval adapter.** It reuses the existing recovery approval and custody owner, with no second approval workflow:
      - the approval is recorded on that workflow in the same writer, and its signatures and coverage were verified at submission (W: `admission_operation_store/recovery/validation.rs:274-286`, `validate_approval`);
      - its `obligations` include `IntegrityEndorsement { principal }` for a principal on the integrity roster (W: `recovery/authorization.rs:40-45`), which becomes `integrity_authority`;
      - its `ActionIntentV1` (W: `authorization.rs:69-90`) supplies `native_binding`;
      - for an `IntegrityEndorsement` obligation, its `influence_basis` is, by this spec, a tagged digest in the `chio.influence-commitment.v1` domain. An approval whose basis carries any other domain tag does not adapt. The adapter copies the basis into `context_commitment` only after checking it equals the current commitment.
    - **P3 semantic endorsement adapter.** It first runs P3's existing verification unchanged (W: `chio-semantic-contracts/src/verification.rs:237-282`): route `endorsement_key`, signature, `SemanticActionDigest`, `body.influence == action.influence`, destination, purpose, assertion coverage and validity time. That success alone is not the fact. The adapter then checks each binding P3 does not establish:
      - **Integrity authority.** The integrity roster names the endorser key, or the principal bound to it, as an integrity authority at the current deployment generation. A route key that is not on the integrity roster does not adapt, however valid its signature.
      - **Native binding.** The endorsed `SemanticActionDigest` belongs to this call's native operation: its request namespace, request id and semantic request digest equal the call's.
      - **Relation to the current context.** In this writer transaction, the adapter recomputes the semantic action influence from the current committed journal state, exactly as P3 materialization does (W: `semantic/materialization.rs:47-134`, then `knowledge_semantic_influence`, domain `chio.knowledge.semantic-influence.v1`). It requires equality with the endorsed `body.influence`. It then records, as `context_commitment`, the I16 commitment of the same committed state. The two digests stay in their own domains: equality is only ever checked within one domain, and a semantic-influence digest is never compared with a context commitment.
      - **Single use.** `SemanticCapture` consumes the semantic operation once in the same transaction.
    - **Until the P3 adapter ships,** I21's automatic P3 compatibility is withdrawn. A gated P3 call needs a recovery integrity approval (the first adapter), even when a valid P3 endorsement exists, and only when its denial is origin-eligible (I20a).
    - **Owner's open question 1, resolved.** P3 endorsements are adapted into the complete predicate through the adapter above. Signer selection is the integrity roster at the current deployment generation, not the P3 route alone. The action and context binding is the native binding plus a same-writer recomputation of the semantic influence. Consumption is one `SemanticCapture`. Until that adapter is implemented, the first gated release requires a separate recovery integrity approval.
    - **Otherwise** the check refuses with `InsufficientIntegrity`. A refused endorsement is not a new fault (I18). The recovery actor learns the reason at resolution: `stale`, `consumed`, `wrong_action`, `deployment_changed`, `unrecorded`, `not_integrity_authority` or `domain_mismatch`.
16. **I16. Summary rows.** W:'s `observed_influence` scans up to 4,096 join records per call (W: `security_participant_state/knowledge.rs:64-75`). This design adds `knowledge_influence_heads(tenant, isolation_epoch, key_subset, key_values) -> InfluenceHeadV1`. `key_subset` is one of the seven non-empty subsets of {principal, lineage, session}. Each head holds exact counters over the observations whose key values match on that subset: a `u64` bit sum, a count per origin class, an unknown count, an observation count and the additive set-hash value.
    - **Update.** A newly inserted observation (I4a) adds its terms to the seven heads of its key triple, in the same transaction. A duplicate insert changes nothing.
    - **Read.** Crossing check 4 computes the state of `P union L union S` (I17) exactly, by inclusion-exclusion over the seven heads of the call's triple, for every counter and for the set hash. That is seven row reads, which is O(1), and an observation reachable through several keys counts once. A class is in `origins` when its resulting count is positive. `bounded_bits_total` saturates only after the exact sum. The resulting set hash is the receipt `commitment` (I25).
    - **Rebuild.** A startup check recomputes every head from the flow rows and refuses readiness on mismatch. Each head is a function of the row set, so a rebuild reproduces it exactly.
    - **Fallback.** If a deployment ever makes a key kind multi-valued per observation, the check sums the per-key heads instead. That is an upper bound, and it is sound because `satisfies` is antitone: it can only deny more, never less.
17. **I17. Key semantics unchanged.** The check uses W:'s key semantics: the union of rows matching principal, lineage or session within tenant and isolation epoch. Narrowing is a later decision (section 11).

```text
committed(join(ctx, s)) before intent_commit(op) and key(op) = ctx and not satisfies(s', req(op))
  and not endorsed(op, intent_commit(op))
  -> not DispatchCommitted(op)                     (s' = state after the join; I15a exception)
DispatchCommitted(op) -> action_ok(op)
                         and (satisfies(state_at(intent_commit(op)), req(op))
                              or endorsed(op, intent_commit(op)))                 (I15a, I22a)
endorsed(op, t)        -> exists f = fact(op, t) built by an I15b adapter in the transaction at t:
                              on_integrity_roster(f.integrity_authority, f.deployment_generation)
                          and f.deployment_generation = current_generation(t)
                          and f.native_binding = native_binding(op)
                          and f.context_commitment = commitment(state_at(t))          (one domain: chio.influence-commitment.v1)
                          and consumed_exactly_once(f.continuation, t)
action_ok(op)          -> req(op).action_contract = None
                          or (inputs_bound(op)
                              and action(op) = selector(contract(op), values(selector_inputs(op)))
                              and action(op) in authorized(contract(op)))                     (I22a)
                          or (no_input_ok(op)
                              and action(op) = no_input_row(contract(op))
                              and action(op) in authorized(contract(op)))                     (I22a, no typed return)
no_input_ok(op)        -> no_input_row(contract(op)) is defined
                          and |selector_inputs(op)| = 0
                          and for each slot digest d: unconsumed(d, key(op)) = 0
inputs_bound(op)       -> |selector_inputs(op)| = slots(contract(op))
                          and each input is a committed, slot-matching ExternalBounded return in key(op)
                          and for each digest d: unconsumed(d, key(op)) = slots_d(contract(op)), filled in CrossingOrder (spec 10 X4)
                          and each input is consumed exactly once, by op, at intent_commit(op)
inherit(parent, child) -> quarantined(child)
                          or (state(child) at creation >= state(parent) at the same transaction,
                              with the inherited part exact on origins, bits and unknown, or creation is refused)   (I7a)
quarantined(child)     -> verified_remedy(child) and fresh_epoch(child) and no_parent_channel(child)
                          and state(child) at creation = initial(child) join classified_bootstrap(child)
                          and later influence(child) = typed_returns(child) join own deliveries(child)   (I7a exception, I22)
attenuate(p, c)        -> level_ge(c.level, p.level) and contract_preserved(c, p)             (I3, I9)
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
      - level `Trusted` or `ProviderOnly` lists `[IntegrityEndorsement]`;
      - level `BoundedExternal`, with or without an action contract, lists `[IntegrityEndorsement, QuarantinedContinuation]`, because a quarantined successor can satisfy only a bounded level (I22).

      Whether a remedy is actually available is disclosed only to the recovery actor at resolution.
    - **Never carried.** The block never carries origin classes, bit totals, the commitment, or which delivery caused the taint. With session-wide keys (I17), the cause may be another process's delivery in the same runtime, so revealing it would leak cross-process activity.
    - **Spec 2's rules apply.** A1-A5 apply to this block, with A1's caller-held set equal to the fields above. A deny receipt carries at most one fault block, either `authority_fault` or `integrity_fault`. `ExplainIntent`-equivalent projections follow P2's stricter rules.
20. **I20. Planner fact.** Where a recovery deployment covers the request, the kernel exposes a new `ExplanationFactKind::Integrity` with value `false`. This is spec 2's projection for `FaultKind::Integrity`; `FaultKind::Authority` keeps projecting to `Capability`. W:'s fact enum is closed, so this is a schema change. Only two remedy paths may address it:
    - `ExactApproval` with obligation `IntegrityEndorsement` (I21);
    - `Prerequisite` with the `QuarantinedContinuation` template (I22).

    No other remedy kind may address it, and the planner returns `NoRegisteredRemedy` otherwise.

    **I20a. Origin eligibility for every recovery-backed integrity remedy.** Both paths run in the recovery owner. Native `CreateWorkflow` resolves the denied request's original, and verifies the unchanged original process request, before any approval can be recorded on the workflow (W: `admission_operation_store/recovery/commands.rs:83-94`; `recovery/origins.rs:61-81`). The I15b recovery adapter starts from an approval on that workflow and supplies no creation authority of its own. So the `Integrity` fact carries spec 2's `origin_retained` planner input, derived from native flow state exactly as for `Capability` (spec 2 section 6.10 O8), and both paths require it:
    - **Eligible.** `origin_retained` holds when the refusal left a native original that `origins::resolve` verifies. Examples are a `Prepared` or slow-path refusal that compensated a begun operation, or a deny tombstone that retains the request material and security binding `resolve` reads. `ExactApproval` and `QuarantinedContinuation` are then available as specified.
    - **Ineligible.** Examples are a fused refusal from `Unbegun` whose spec 10 X15 tombstone retains no request material, or an original whose native or process evidence is stale or mismatched. No integrity template addresses the fact, and the planner returns `NoRegisteredRemedy`. The recovery actor learns `origin_unavailable` at resolution, before any approval is solicited. No approval is recorded, and neither a second approval path nor a weaker origin check is used.
    - **Configuration-blind block.** `remedy_classes` is unchanged (I19, spec 2 A5). Eligibility is disclosed only to the recovery actor.
    - **Rollout.** Until spec 2 O8's retained-denial profile ships, the recovery approval adapter (I15b) is qualified only for denials with a verified origin. The P3 fallback in I15b and I21 applies only to such denials. An ineligible gated P3 call is refused with no remedy until the P3 adapter ships, or until O8 supplies its origin.
21. **I21. Endorsement.** An approver on the deployment's integrity roster signs an exact approval whose `AuthorizationRequirementsV1.obligations` contains `IntegrityEndorsement { principal }`. Its `influence_basis` equals the context's committed influence digest (W: `authorization.rs:44`, `:55`). The approval authorizes exactly one continuation despite the influence.
    - **Admission.** Crossing check 4 accepts it under I15a. The approval binds the exact action, the current commitment, the deployment and one continuation, and it is consumed in the same transaction.
    - **History.** The context's state is unchanged (SEC-05). The next consequential call needs its own endorsement.
    - **Semantic connectors.** A P3 `ScopedEndorsementV1` over `ExactAction` (W: `semantic/evidence.rs:84-101`) is not the same rule. It binds a route key, a `SemanticActionDigest` and a semantic-influence digest, not an integrity-roster authority and the context commitment. It satisfies crossing check 4 only through the I15b P3 adapter, after every missing binding is checked. Until that adapter ships, a gated P3 call needs a recovery integrity approval, which is available only for an origin-eligible denial (I20a).
22. **I22. Quarantined continuation.** The remedy that recovers utility without a human:
    1. A verified isolation-epoch transition starts an isolated successor whose influence starts trusted (M: `active-defense-rollout.md:19`). This is I7a's single exception to parent inheritance. The parent's observation set does not cross into the new epoch; only P5 typed returns and the successor's own classified bootstrap contributions do. If the transition cannot be verified, the epoch is not fresh, or the parent keeps any other channel into the successor, the child inherits in full, and a `BoundedExternal` requirement then denies.
    2. The tainted parent hands its untrusted artifacts only to P5 confined readers.
    3. The readers' typed returns join the successor as `ExternalBounded` (I8).
    4. The successor performs the consequential call under a `BoundedExternal { n }` requirement.

    This follows the Design Patterns paper's dual-LLM and action-selector patterns, enforced by the kernel rather than by framework discipline.

    **Origin ownership (spec 2 section 6.10).** The `QuarantinedContinuation` template runs in the recovery owner, and its successor performs the denied action in a new scope, so it is a linked successor of the denied call's original in exactly spec 2's sense. It uses spec 2's contract and no other: the successor hangs from the original's existing origin claim as one chain link (O2-O5), `origins::verify_linked` revalidates the original's native and process evidence at every recheck point (O6), and capture moves the link to `Captured` (O7), so exactly one continuation of the original can capture. A denial that left no verifiable native original, including a crossing check 4 deny tombstone without retained request material, gets no quarantined continuation until spec 2 O8's retained-denial profile exists. The template is not registered before spec 2 section 6.10 ships.

    **What it does not guarantee.** The successor's call is admitted on a bounded channel that external content influences. The readers saw untrusted artifacts, and their returned values pass to the successor. A one-bit boolean that a framework uses to choose between publishing and deleting is admitted under `BoundedExternal { n: 1 }` with no endorsement. `BoundedExternal` is therefore an explicit policy allowance of up to `n` attacker-influenced bits. It is not a guarantee that external content cannot select the action.

    **I22a. Action-selection contract (optional).** A deployment that needs zero unauthorized action selection sets `action_contract`, typically as `BoundedSelection { max_bits, contract }`. A contract may accompany any level, and attenuation preserves it by digest (I3). The contract is operator-signed:

    ```rust
    pub struct ActionSelectionContractV1 {
        pub schema: String,                                               // "chio.action-selection-contract.v1"
        pub return_contracts: BoundedList<ReturnContractDigest, 8>,       // ordered input slots: slot i takes one typed return under this digest
        pub selector: SelectorTableV1,                                    // (slot 0 value, .., slot k-1 value) -> action template; optional no_input row
        pub authorized_actions: BoundedSet<ActionTemplateDigest, 64>,     // every action the selector can produce
    }
    ```

    - An action template fixes the tool, the server and every argument, except arguments the selector fills from trusted inputs.
    - **Bound inputs.** The crossing plan carries `selector_inputs: BoundedList<ObservationId, 8>`, one per slot and in slot order. Each is the I4a observation id of a committed `ExternalBounded` confined return. Inside the crossing's writer transaction, crossing check 4 requires all of the following, and otherwise refuses with `InsufficientIntegrity`:
      - **Cardinality.** Exactly one input per slot. A missing or extra input denies.
      - **Membership.** Each input is in the call's key state (I17), is a confined-return observation, and its return contract digest equals its slot's digest. An input from another context's state denies.
      - **Distinct.** No observation fills two slots.
      - **Unambiguous, in a defined order.** For each digest `d`, let `s_d` be the number of slots naming `d`. The key state must hold exactly `s_d` unconsumed returns under `d`, and they fill those slots in `CrossingOrder` (spec 10 X4) of their `ConfinedReturn` crossings: `(store_uuid, commit_sequence, member_ordinal)`, compared within the call's store. More unconsumed returns than slots is ambiguous and denies. A call therefore cannot pick whichever historical value makes its action pass, because at most one binding is admissible for a given state.
      - **Consumed once.** The crossing records each input as consumed by this operation, in the same transaction. A second operation that binds a consumed input denies, and a replay of the same operation returns its bound terminal result.
    - Crossing check 4 computes the expected action from the bound inputs' committed, host-recomputed values, in slot order, through the selector. It uses the host's canonical projections (I23), never model text. The bound ids go to the operator-only audit record (I25a), not to caller-visible receipts.
    - It admits the call only when the call's exact action equals that expected action and is in `authorized_actions`. Otherwise it refuses with `InsufficientIntegrity`. This condition applies on both I15a branches. An endorsement satisfies only the level condition, never this one.
    - A value outside the selector's domain is already refused at projection (I23).
    - **No typed return.** The selector's `no_input` row gives the expected action only when the call binds no inputs and the key state holds no unconsumed return under any slot's digest. This is the normal case for a `Trusted` level. If the contract defines no such row, the call is refused. A call that binds no inputs while such a return exists is refused, so influence cannot bypass the selector by being left unbound.
    - **The property.** External content can choose only among `authorized_actions`; it can never reach an unauthorized action. Which authorized action it chooses remains influenced, and the operator accepts that when signing the set.

## 10. Typed return contracts (generalizing P5)

`ReturnContractV1` admits only an 8-byte boolean today (W: `confinement.rs:67-79`). This design adds a closed return-type library, recomputed by the host exactly as the boolean projection is (W: `chio-core-types/src/recovery/confinement.rs:58-73`):

```rust
pub enum ConfinedReturnTypeV1 {
    Boolean,                                                   // 1 bit
    Enum { variants: BoundedList<ProtectedText<64>, 256> },    // ceil(log2(n)) bits; 1 <= n, variants pairwise distinct
    Integer { min: i64, max: i64 },                            // ceil(log2(max - min + 1)) bits; min <= max
    Identifier { min_len: u8, max_len: u8, charset: IdentifierCharsetV1 }, // bit_length(sum over i in min_len..=max_len of |charset|^i - 1) bits; 1 <= min_len <= max_len <= 64
}
```

23. **I23. Capacity.** Each type has a fixed capacity in bits, which becomes `ExternalBounded { max_bits }`.
    - **Exact cardinality.** Capacity is `ceil(log2(N))`, where `N` counts every value the host projection accepts. It is computed with exact integer arithmetic as `bit_length(N - 1)`, never in floating point.
      - `Boolean`: `N = 2`.
      - `Enum`: `N = n` variants.
      - `Integer`: `N = max - min + 1`.
      - `Identifier`: `N = sum over i from min_len to max_len of |charset|^i`, so every permitted length is counted, not only the longest strings. With the 65-character charset below, lengths 1 to 44 give `N = (65^45 - 65) / 64` and 266 bits, while `44 * log2(65)` rounds to 265 and undercounts by one bit. A fixed-length identifier (`min_len = max_len = 44`) gives 265. Lengths 1 to 64 give 386.
    - `Identifier` is the only variable-length type. Any future variable-length type must count every accepted length in the same way.
    - **Validated at load.** Every return type is validated when the policy or contract that names it is loaded, before any projection or capacity calculation. That covers each `ReturnContractV1` and each input slot of an `ActionSelectionContractV1`:
      - `Enum`: at least one variant, and variants pairwise distinct after `ProtectedText` canonicalization;
      - `Integer`: `min <= max`. `N = max - min + 1` is computed in 128-bit or big-integer arithmetic, so the full `i64` range gives `N = 2^64` and 64 bits without overflow;
      - `Identifier`: `1 <= min_len <= max_len <= 64`, and a charset that is non-empty, has no duplicate characters and lies inside the restricted set below.

      So `N >= 1` always holds and `bit_length(N - 1)` is always defined. A type that violates an invariant is rejected at policy load, fail closed: the contract, and every grant or deployment binding that references it, does not load. Capacity is never computed for an unvalidated type.
    - `Identifier` uses a restricted charset (ASCII letters, digits, `.`, `_`, `-`), with no spaces and no punctuation that can form instructions. Free text is not a return type.
    - The host projection rejects any value outside the type. There is no fallback.
24. **I24. Return discipline unchanged.** One value, on the `Value` channel only, with every other channel withheld. `max_bytes` is derived from the type, up to 64.

## 11. Granularity and utility

- **The enforceable property.** It holds at context granularity, over Chio-mediated channels. For a gated call that crossing check 4 admits:
  - **By context, under `Trusted`.** No external or unknown influence reached the context.
  - **By context, under `ProviderOnly`.** Only the listed providers did.
  - **By context, under `BoundedExternal { n }`.** At most `n` bits of external influence reached the context, each through a typed confined return. Those bits may select the action: this is a policy allowance, not a no-steering guarantee.
  - **By context, with an action contract (any level).** The level's property holds, and the action is the contract's selected action and one of its authorized actions (I22a). Attenuation cannot drop or change the contract (I3).
  - **Bootstrap included.** Each property counts bootstrap contributions (I7a). Pinned bootstrap material is `External` unless an operator-signed assertion makes it trusted, so a pinned external document in a fresh runtime's task input cannot start the context at trusted.
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
  - Integrity-gated grants deny there, with `InsufficientIntegrity`. The `integrity_fault` block carries only I19's declared wire classes, chosen from the grant's own requirement: `[IntegrityEndorsement]` for `Trusted` or `ProviderOnly`, and `[IntegrityEndorsement, QuarantinedContinuation]` for `BoundedExternal`. `IntegrityRemedyClass` stays closed.
  - "Run the agent as a mediated process" is operator and integrator guidance in documentation, not a remedy class. It is never encoded in the fault block, so the block stays configuration-blind (I19, spec 2 A5).
  - Grants without the constraint behave as today.
  - A deployment cannot declare an MCP client "trusted", because the kernel cannot verify complete mediation (open decision 3).
- **Hosted sessions** follow the kernel-session rule.

## 13. Receipts and evidence

25. **I25. Receipt metadata.** Every receipt for a grant with a requirement or floor carries `chio_runtime.integrity`. Allow and deny receipts disclose different fields, because with session-wide keys (I17) the commitment changes when another context in the same runtime receives a delivery.
    - **Allow receipts** carry:
      - `required`;
      - `satisfied_by`: `context`, `bounded` or `endorsement`;
      - the action contract digest, when `action_contract` is set;
      - `commitment_ref = HMAC(audit_key, "chio.integrity-commitment-ref.v1\0" || request_namespace_digest || request_id || receipt_nonce || commitment)`. `receipt_nonce` is a 128-bit CSPRNG value carried in the receipt metadata and drawn before the receipt id is computed. The receipt id is a hash over the canonical body including this metadata (`chio-core-types/src/receipt/body.rs:180-243`), so binding the id itself would be a fixed point. It binds the full replay identity and the receipt id, so it is blinded per receipt: two receipts, including two that reuse one request id in different authenticated namespaces, cannot be compared for equality without the audit key;
      - the floor source, when a floor applied.
    - **Caller-visible deny receipts** carry only `required`, `outcome: denied` and the floor source, plus the `integrity_fault` block (I19). They carry no `commitment`, `commitment_ref`, `context_generation` or `satisfied_by`.

    **I25a. Audit basis.** The raw `commitment`, the `context_generation` and the head digests used by crossing check 4 are written to `integrity_admission_audit(request_namespace_digest, request_id, receipt_nonce, receipt_id, decision, commitment, context_generation, heads_digest)`, keyed by `(request_namespace_digest, request_id, receipt_nonce)`, with `receipt_id` recorded once the receipt is signed, in the admission writer, in the decision's transaction (for a guard-only deny, in the deny receipt's transaction). The table is operator audience: it is exported only through operator-authenticated audit and SIEM paths, never to the caller. An auditor joins any consequential effect to the commitment that admitted it by recomputing `commitment_ref` with the audit key.

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
  - With an action contract, such as `BoundedSelection`, zero admitted calls outside the contract's authorized actions, including calls from delegated grants (I3).
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
| Worker-profile attribution or available-record mismatch, or mandatory-claim rejection | Context creation refused, including for ordinary calls; no `Unverified` fallback (I7, spec 7 rule 6.3.5) |
| Worker-profile fact unverified with no mismatch or mandatory-claim rejection | Context starts at `unknown`; gated calls deny (I7) |
| Unbound route output | Joins `External` (I5) |
| Manifest digest changed under an operator binding | The binding is void; output joins `External` |
| Join commits before the intent commit, and no valid current endorsement applies | Intent commit fails `InsufficientIntegrity` (I15) |
| Join commits, then a fresh endorsement over the post-join commitment, then the intent | Admitted once by endorsement (I15a) |
| Delegation raises the level but drops or changes the parent's action contract | Delegation refused: not an attenuation (I3, I9) |
| Endorsed action outside the grant's action contract | Deny (I15a) |
| Endorsed action inside `authorized_actions` but different from the selector's output for the bound inputs | Deny (I15a, I22a) |
| Bootstrap contribution pinned but not covered by a trust assertion | Joins `External`; a `Trusted` requirement denies (I7a) |
| Bootstrap contribution that cannot be classified | Joins `unknown`; every requirement denies (I7a) |
| Bootstrap trust assertion expired, for another run plan or deployment, or a digest mismatch | Assertion ignored; the contribution is `External` (I7a) |
| Bootstrap trust assertion unsigned, malformed (an unknown field or `BootstrapKind`), with a bad signature, or signed by a key the integrity roster does not bind to its signer at the current generation | Rejected and recorded; it confers nothing, and each named contribution is classified as if no assertion existed (`External` when pinned, otherwise `unknown`) (I7a) |
| Endorsement `influence_basis` stale (context gained influence since) | The endorsement does not apply; deny (I15a) |
| Endorsement's continuation already consumed (reuse) | Deny; the first admission's consumption stands (I15a) |
| Endorsement for a different action, request or namespace | Deny (I15a) |
| Endorsement after a deployment, policy or contract change | Deny (I15a) |
| Call with an action contract whose action is not the selector's output, or not authorized | Deny (I22a) |
| Action contract with no committed typed return and no `no_input` row | Deny (I22a) |
| Selector input missing, extra, duplicated, from another context, under the wrong contract digest, or already consumed | Deny (I22a) |
| More unconsumed returns under a slot's digest than the contract has slots for it (ambiguous) | Deny (I22a) |
| Call binds no inputs while an unconsumed return under a slot's digest exists | Deny (I22a) |
| Parent state not in this writer, above the 4,096-row history bound, or unreadable at child creation | Child scope creation refused; never summarized (I7a) |
| Quarantined successor with an unverified remedy record, a reused isolation epoch, or a parent channel into the successor (capability, delegation, mailbox, shared key, parent-authored task) | The exception does not apply; the child inherits the parent's full state, and a `BoundedExternal` requirement denies (I7a, I22) |
| Return type with an empty or invalid value domain (empty or duplicate `Enum` variants, `Integer` with `min > max`, invalid `Identifier` bounds or charset) | Rejected at policy load; the contract and every grant referencing it do not load (I23) |
| P3 endorsement valid under P3 but its key is not on the integrity roster, its semantic influence no longer matches the current state, or its native binding differs | The P3 adapter builds no fact, and crossing check 4 refuses (I15b) |
| Recovery approval whose `influence_basis` is in another digest domain | No fact; refused with `domain_mismatch` (I15b) |
| Knowledge migration partial, commitment or projection version unsupported, or a legacy record unreadable | Not ready; `integrity-gating` cannot be enabled (section 4.1) |
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
  - `chio.bootstrap-trust-assertion.v1`, the body and its signed envelope with the closed `BootstrapKind` vocabulary (I7a);
  - `chio.confined-return-type.v1`;
  - `chio.action-selection-contract.v1`.
- Changes to W: closed enums: `ExplanationFactKind::Integrity`, the `QuarantinedContinuation` template, `InfluenceOriginV1` and `EndorsementSourceV1`. The enum changes are additive.
- The influence representation itself is not just additive. It adds a versioned projection, the frozen `chio.influence-commitment.v1` algorithm with conformance vectors, legacy seed observations and a schema-version bump (section 4.1). Existing signed artifacts, checkpoints, releases and digest domains are unchanged.
- Process ABI: no new op. Influence travels in existing invoke and receive outcomes.

## 17. Rollout

0. **Migration (section 4.1)**: legacy seed observations, head build, `knowledge_projection_version`, and conformance vectors. Tracking and gating stay off until it completes.
1. **Output joins (I4-I8)** behind `integrity-tracking`, recording influence without gating. This also replaces the unconditional external marking.
2. **The constraint, the guard, and crossing check 4 (I9-I17)** behind `integrity-gating`. Grants opt in.
3. **The fault, the recovery-approval endorsement adapter and the quarantined continuation (I18-I22)**, with typed returns (I23-I24). The P3 endorsement adapter (I15b) follows separately. Until it ships, gated P3 calls need a recovery integrity approval. The quarantined continuation is also gated on spec 2 section 6.10's linked-successor origin contract (I22). Both recovery-backed remedies are qualified only for origin-eligible denials until spec 2 O8 ships (I20a).
4. **Evaluation publication**, then optional deployment floors (I12).

GT1 applies: no guarantee is claimed until the conformance scenarios run in hosted CI.

## 18. Tests and conformance evidence

- **Proptest.**
  - Lattice laws over generated observation sets that include duplicates and replays: join is commutative, associative and idempotent, and monotone (I2). The bit total and commitment of `join(s, s)` equal those of `s`.
  - Fan-out identity: generated deliveries of one artifact version to several destinations give one observation per destination. Each destination's state includes that observation, and replaying any one delivery changes no state (I4a).
  - Head maintenance: incremental heads equal heads rebuilt from rows. Inclusion-exclusion over the seven heads equals a direct scan of `P union L union S`.
  - `satisfies` is antitone in state.
  - Attenuation never weakens a requirement (I9), and never drops or changes an action contract, under the product order (I3).
- **Loom.** A join racing an intent commit on the same context gives exactly one order.
  - A post-join intent with no endorsement fails (I15).
  - **Approval, then new join, then intent:** the endorsement is stale and the intent fails (I15a).
  - **Join, then fresh approval over the post-join commitment, then intent:** admitted once (I15a).
- **Endorsement adapter acceptance (I15b).** These use an actual P3 exact-action endorsement:
  - with the correct route key but a key that is not on the integrity roster: refused (`not_integrity_authority`);
  - with the context commitment changed by a join after endorsement: refused (`stale`);
  - with a different native request, or an already-consumed semantic operation: refused (`wrong_action`, `consumed`);
  - with a recovery approval whose `influence_basis` is in another digest domain: refused (`domain_mismatch`);
  - correctly adapted: it allows exactly its bound action once and leaves the influence history unchanged;
  - before the P3 adapter ships, a gated P3 call with only a valid P3 endorsement is refused, and one with a recovery integrity approval is admitted.
- **Migration acceptance (section 4.1).**
  - Upgrade a database containing an external artifact read and a checkpoint, then restart, restore the checkpoint and import an old archive.
  - Evaluate a P3 and a generic gated action. History and old artifact references remain valid, and every live projection keeps the external and unknown restrictions.
  - A rebuild gives the identical new commitment, and the conformance vectors pass.
  - A partial migration, an unsupported commitment version or an unreadable legacy record refuses readiness, and an older binary refuses to open the migrated store.
- **Kani.** `satisfies` is total, and `unknown` always fails.
- **Unit.**
  - Unbound routes join `External`.
  - The operator binding is voided by a manifest change.
  - Attested mailbox inheritance.
  - Initial influence per verified worker profile. Each permitted unverified fallback starts at `unknown`. A worker attribution or available-record mismatch refuses context creation without inserting an initial observation, even when the first action has no integrity requirement (spec 7 rule 6.3.5).
  - Bootstrap classification (I7a): inherited, asserted, pinned without assertion (`External`), and unclassified (`unknown`). Assertions that are expired, for another run plan or deployment, or carry a mismatched digest are ignored. An unsigned body, an assertion with an unknown field or `BootstrapKind`, a bad signature, a signer off the integrity roster, or a `signer_key` the roster does not bind to the named signer is rejected, and the covered contribution stays `External` (pinned) or `unknown`. A fabricated assertion that names a roster principal but is signed by another key never yields `Trusted`.
  - **Lossless inheritance (I7a).** A parent holds `External`, `ModelProvider { p1 }`, `ModelProvider { p2 }`, and two distinct `ExternalBounded` observations of 3 and 5 bits. A child with disjoint keys and no other bootstrap contributions inherits re-keyed observations, and its `origins`, `bounded_bits_total = 8` and `unknown` equal the parent's. Each requirement the parent fails, the child fails too: `Trusted`, `ProviderOnly({p1})` and `BoundedExternal { 7 }`. A child sharing the parent's lineage does not re-key reachable rows, and its bit total stays 8. Re-running creation changes nothing. A parent above 4,096 rows refuses child creation.
  - Typed return capacity and projection rejection. Capacity unit tests (I23): `Boolean` gives 1; `Enum` with 3 variants gives 2; `Integer { 0, 255 }` gives 8; a single-value type gives 0; `Identifier { 1, 44, 65 chars }` gives 266, and `Identifier { 44, 44, 65 chars }` gives 265. Each is computed by `bit_length(N - 1)` and compared with a big-integer reference. `Integer { i64::MIN, i64::MAX }` gives 64 without overflow.
  - Load-time validation (I23). Each of these is rejected at policy load, and no capacity is computed for it:
    - an empty `Enum`;
    - duplicate `Enum` variants;
    - `Integer { min: 5, max: 4 }`;
    - `Identifier` with `min_len = 0`, with `min_len > max_len`, with `max_len > 64`, with an empty charset, with a duplicate character, or with a character outside the restricted set.

    A grant that references a rejected contract does not load.
  - `InsufficientIntegrity` yields the `integrity_fault` block, never an `authority_fault` block. Its field set equals I19's, and `remedy_classes` depends only on the caller's requirement (I18, I19).
- **Conformance.**
  - An injected tool output followed by a consequential call is denied.
  - The quarantined continuation succeeds under `BoundedExternal`. The parent holds `External` and `unknown` observations; the successor, created by a verified remedy record in a fresh epoch with a template task under an assertion, starts trusted, receives two typed returns, and its call under `BoundedExternal { n }` is admitted (I7a exception, I22).
  - Quarantined origin ownership (I22, spec 2 section 6.10): the successor's workflow is a chain link on the denied call's original claim. A second quarantined successor, or the original's own continuation, cannot capture after it, and a denial with no verifiable native original gets no quarantined continuation. Spec 2's origin-ownership cases run with this template.
  - **Origin eligibility (I20a, R-11-09):** a fused integrity refusal from `Unbegun` with a minimal X15 tombstone, and the same refusal with retained request material; a `Prepared` or slow-path refusal with a valid origin; a stale or mismatched native or process origin; and a gated P3 call before its adapter ships. Only a genuinely eligible origin yields a workflow, one exact approval and one approved native capture. Each ineligible case reports `origin_unavailable` to the resolver before any approval is solicited, and the deny block's `remedy_classes` is identical across all cases.
  - A non-remedy child of that same tainted parent still inherits its full state, and its `BoundedExternal` call is denied (I7a).
  - Unverified transitions fall back to inheritance, and each successor's `BoundedExternal` call is denied. The cases are:
    - a missing or unverifiable remedy record;
    - a reused isolation epoch id;
    - a capability or mailbox route from the parent into the successor;
    - a shared session or lineage;
    - a parent-authored task.
  - A same-principal endorsement replayed after new influence is refused.
  - Endorsement cases (I15a):
    - **fresh:** an exact endorsement over the current commitment admits the call once, with `satisfied_by = endorsement`;
    - **stale:** a join committed after approval makes the same endorsement fail;
    - **reused:** a second call naming the consumed continuation is refused;
    - **wrong action:** an endorsement for a different request, namespace or semantic digest is refused;
    - **endorsed but off-selector:** under an action contract whose bound input selects publish, an otherwise valid endorsement for delete (also in `authorized_actions`) is refused. The same endorsement for publish is admitted once.

    The early guard defers each case to the crossing and never admits on the reference alone.
  - **Adversarial one-bit action selector.** An attacker-controlled document flips a boolean return that the framework uses to choose publish or delete.
    - Under `BoundedExternal { n: 1 }`, the delete is admitted with `satisfied_by = bounded`, and the evaluation counts it as an attack success through the allowance.
    - Under `BoundedSelection` with only publish authorized, the delete is refused (I22a).
  - **Attenuation with action contracts (I3, I9).**
    - **Excluded action.** The parent grant's scope permits publish and delete, but its contract authorizes only publish. A delegate that raises the level to `Trusted` and drops the contract is refused at delegation. A delegate holding `{ Trusted, Some(c) }` calls delete from a trusted context and is refused (I22a).
    - **Changed selector mapping.** Contract `d` has the same authorized action set as the parent's contract `c`, but maps a return value to the other action. A delegate that substitutes `d` is refused at delegation (digest mismatch).
  - **Selector input binding (I22a).** A context holds two committed returns under one contract digest, with values `true` and `false`, and the contract has one slot for that digest.
    - A call binding either return is refused as ambiguous, and so is a call binding none.
    - After an earlier operation consumes the older return, the remaining return is the only admissible input. The expected action is computed from its value alone.
    - Binding the consumed return is refused, and so is binding a return from another context. A replay of the admitting operation returns its bound terminal result.
    - Missing and extra inputs are refused.
  - **Pinned external task in a fresh runtime (I7a).** A qualified `container` controller launches with a pinned external document embedded in its task input and no trust assertion. Its context starts with that contribution as `External`, and a consequential call requiring `Trusted` is denied. The same launch with a valid assertion covering that digest starts trusted.
  - **Whole-response anti-oracle differential.** Two runs differ only in which other context in the runtime received a tainting delivery, and when. Their caller-visible deny responses are byte-identical, including the body, `_meta` and all receipt metadata, except request id, timestamps and signatures (I19, I25).
  - MCP-edge gated grants deny.
  - A cross-process taint in one runtime denies, with no cause disclosed.
  - Two contexts in one tenant and isolation epoch read the same artifact version. The second context's gated call is denied (I4a).
  - A gated read-only call in a tracked context takes the durable path, and its output join commits before delivery (I4b).
- **Adversarial suite.** Adaptive injection cases from section 14 are added to `chio-adversarial-suite`.

## 19. Residual risks and open decisions

Residual risks:
- Channels outside mediation (a `direct` worker reading the network) are the reason such contexts start at `unknown`. A misdeclared worker profile would break the premise, so I7 applies spec 7 rule 6.3.5: mismatches deny, and only its allowed unverified fallback starts at `unknown`.
- Operator-bound `Trusted` routes are a trust decision. A wrong binding admits injection through that route.
- Bootstrap trust assertions are a trust decision of the same kind. A wrong assertion admits injection through the asserted contribution (I7a).
- Bounded returns still carry information, up to `max_bits`, and that information can select the action (section 11). `Identifier` returns of 64 characters can encode short strings, so grants choose `n`. Only an action contract limits which actions can be selected (I22a), and attenuation preserves it (I3).
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

### Codex review (PR #1174, round 7)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4185260800 | Define a lossless parent-state inheritance encoding | Fixed now. Every parent observation not already reachable through the child's keys is re-keyed for the child (`source_kind = inherited`, id over the parent observation id and the child destination). Its origin class, provider, bit bound and `unknown` are copied exactly, so the child's derived state equals the parent's and no bits are double counted. Creation is idempotent. A parent set that is outside this writer, above the 4,096-row bound or unreadable refuses child creation; it is never summarized | I4a; I7a; section 8 predicates; section 15; section 18 |
| 4185260813 | Bind selector inputs to specific return records | Fixed now. Contracts declare ordered input slots. The call binds exact confined-return observation ids, one per slot. Crossing check 4 requires slot-matching membership in the key state, distinct inputs, exactly `s_d` unconsumed returns per digest filled in commit order, and single-use consumption. Missing, extra, duplicate, consumed or ambiguous inputs deny, and the expected action comes only from the bound values | I22a; section 8 predicates; section 15; section 18 |

### Independent review pass 2 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-11-04 | Raising integrity to Trusted can remove a parent's action-selection constraint | Fixed. The requirement is now a pair, a level plus an optional action contract, ordered as a product. Attenuation may raise the level but must keep the parent's contract by digest, because equal action sets can still differ in selector mapping. `Trusted` alone is not stronger than `BoundedSelection`. The action condition applies at any level, a `no_input` selector row covers trusted contexts, and an endorsement never authorizes an action outside the contract. New attenuation tests cover an excluded action and a changed selector mapping | section 4 (requirement, I1, I3); I9; I15a; section 8 predicates; I19; I22a; section 11; I25; section 15; section 18 |
| R-11-05 | Pinning bootstrap bytes is treated as proof that those bytes have no external influence | Fixed. Launch qualification and input influence are separate facts. New I7a joins every bootstrap contribution (inherited parent state, task and spawn input, seeds, checkpoint, control and selection metadata) before readiness, following P5. Unclassified contributions start `unknown`, and pinned but unasserted ones start `External`. Trust requires an operator-signed, scoped `BootstrapTrustAssertionV1`. The owner's open question 1 is answered in I7a, and a test covers a pinned external task in a fresh runtime. Spec 7's qualification text says the same | I4; I4a; I7; I7a; section 11; section 15; section 18; section 19; spec 7 rule 6.3.5 |
| R-11-06 | The endorsement fix leaves an unconditional denial invariant and failure-table row | Fixed. The denial implication carries `not endorsed(op, intent_commit(op))`. The failure table separates the endorsed and unendorsed join-first cases. Loom tests both orders: approval, then join, then intent fails; join, then fresh approval, then intent succeeds | section 8 predicates; section 15; section 18 |

### Codex review (PR #1174, round 8)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4185510046 | Apply the selector check to endorsed calls | Fixed now. The endorsement branch of crossing check 4 requires I22a's full `action_ok` (bound inputs, selector output equal to the call's action, membership in `authorized_actions`), exactly as the context branch does. An endorsement bypasses only `satisfies(state, requirement)`. The predicate is restated as `action_ok and (satisfies or endorsed)`, with a new failure row and an off-selector endorsement test | I15a; I22a; section 8 predicates; section 15 failure table; section 18 tests |
| 4185510106 | Include identifier length in the capacity bound | Fixed now. Capacity is `bit_length(N - 1)` over the exact count of accepted values. For `Identifier`, `N` sums `|charset|^i` over every permitted length, with a new explicit `min_len`. The 65-character, length 1-44 case gives 266 bits, not 265. The other types are fixed-cardinality and already exact. Unit tests are added | section 10 type table; I23; section 18 |

### Codex review (PR #1174, round 10)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4185993940 | Exempt quarantined successors from parent-state inheritance | Fixed now. I7a gains one fail-closed exception for a child created by I22's verified isolation-epoch transition. It needs a verified `QuarantinedContinuation` remedy record naming the parent and the new epoch, a fresh epoch id, and no parent channel into the successor other than P5 returns. When it applies, the parent's observation set does not cross. Only P5 typed returns (`ExternalBounded`) and the successor's own classified bootstrap contributions do, and a parent-authored task joins as parent influence. Any failed condition falls back to full inheritance, and every other child keeps the never-less-tainted guarantee | I7a; I22 step 1; section 8 predicates; section 15; section 18 |
| 4185993976 | Reject return types with an empty value domain | Fixed now. Every return type is validated at policy load, before any projection or capacity calculation. An `Enum` has at least one distinct variant. An `Integer` has `min <= max`, computed in 128-bit arithmetic. An `Identifier` has `1 <= min_len <= max_len <= 64` and a non-empty charset with no duplicates inside the restricted set. `N >= 1` always holds, and a malformed contract and every grant referencing it fail to load | I23; type comments; section 15; section 18 |

### Codex review (PR #1174, round 12)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186364901 | Add the no-input case to action_ok | Fixed now. `action_ok` gains an explicit no-input branch: the contract defines a `no_input` row, the call binds zero inputs, no unconsumed return exists under any slot digest, and the action equals that row and is authorized. The normal trusted-context path therefore satisfies the admission invariant | section 8 predicates |

### Independent review pass 3 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-10-03 (consumer side) | The crossing index lacks the ordering contract required by its consumers | Fixed. I22a fills selector slots in spec 10 X4's `CrossingOrder` of the `ConfinedReturn` crossings, `(store_uuid, commit_sequence, member_ordinal)`, which is a total order within the store. Two returns in one batch, or in consecutive batches, therefore have one defined slot order | I22a; section 8 predicates |

### Codex review (PR #1174, round 17)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187142804 | Bind integrity audit references to the replay namespace | Fixed now. `commitment_ref` is an HMAC over a fixed domain, `request_namespace_digest`, `request_id`, `receipt_id` and the commitment. `integrity_admission_audit` is keyed by `(request_namespace_digest, request_id, receipt_id)`. Receipts that reuse a request id across namespaces are therefore unlinkable, and their audit rows stay distinct | I25; I25a |

### Independent review pass 4 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-11-07 | A valid P3 endorsement does not establish the new integrity-approval predicate | Fixed. Crossing check 4's endorsement branch reads one `VerifiedEndorsementFactV1`, built in the writer by one of two adapters. The recovery-approval adapter reuses the existing approval and custody owner. The P3 adapter runs P3's existing verification, then checks integrity-roster authority at the current generation, the native binding, a same-writer recomputation of the semantic influence, and single-use `SemanticCapture`. Digest domains stay distinct. I21's automatic P3 claim is withdrawn: until the P3 adapter ships, gated P3 calls need a recovery integrity approval. Acceptance tests added; open question 1 answered | I13; I15a; I15b; I21; section 8 predicates; section 15; section 18 |
| R-11-08 | The influence refinement lacks a versioned migration contract for existing P3/P4/P5 state | Fixed. New section 4.1: the frozen LtHash16 commitment (SHA-256 element map, final digest domain, conformance vectors); the P4 journal as the one canonical owner with versioned projections and derived heads; immutable historical domains; conservative legacy seed observations; consistent projections for every consumer; readiness gating; downgrade refusal. Rollout gains a migration step 0. Acceptance tests added; open question 2 answered | section 4.1; section 16; section 17; section 18 |

### Codex review (PR #1174, round 18)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187315397 | Seed legacy contexts as unknown before enabling gating | Fixed now. Every context live at migration receives an `unknown` seed observation, whatever its legacy rows say, because tool output was not journaled before tracking. A both-false legacy record no longer counts as trust. Only contexts with provably complete mediated history (created after tracking, or in a fresh post-migration epoch) start without it | section 4.1 legacy seeds |
| 4187315408 | Remove the receipt ID from its own metadata commitment | Fixed now. `commitment_ref` binds a 128-bit `receipt_nonce`, drawn before the id is computed, instead of the receipt id. The audit row is keyed by `(namespace, request_id, receipt_nonce)` and records the receipt id after signing. No fixed point remains | I25; I25a |

### Codex review (PR #1174, round 19)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187433097 | Treat untracked legacy artifacts as unknown | Fixed now. A legacy record with both flags false now projects `unknown = true` unless its producing context's complete mediated history is independently proven. A post-migration context that reads a pre-migration artifact is therefore tainted as unknown and cannot satisfy `Trusted` through it | section 4.1 legacy seeds |

### Independent review pass 5 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-2-02 (cross-reference) | Linked authority successors do not compose with W's new exclusive origin ownership | Applied here. The `QuarantinedContinuation` successor is a linked successor of the denied call's original. It uses spec 2 section 6.10's contract: one chain link on the original's existing origin claim, `verify_linked` revalidation of the original's native and process evidence, and capture as the link transfer. A denial with no verifiable native original gets no quarantined continuation until spec 2 O8's profile exists, and the template is not registered before section 6.10 ships | I22; section 17 phase 3; section 18 |

### Independent review pass 6 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-11-09 | Exact integrity approval still lacks the retained-origin prerequisite applied to quarantine | Fixed. New I20a applies native-origin eligibility to both recovery-backed integrity remedies. The `Integrity` fact carries spec 2's `origin_retained` input, derived from native flow state. Ineligible denials (for example a fused refusal whose X15 tombstone retains no request material, or a stale origin) get `NoRegisteredRemedy`, and the resolver learns `origin_unavailable` before any approval is solicited. The recovery adapter and the P3 fallback are qualified only for origin-eligible denials until spec 2 O8 ships. `remedy_classes` stays configuration-blind. No second approval path or weaker origin check is added | I15b; I20a; I21; section 17 phase 3; section 18; spec 2 section 5 |

### PR #1174 review round 29

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4190699733 (spec 11 side) | Keep initial influence consistent with worker mismatch denial | Applied here. Spec 7 mismatch and mandatory-claim rejection refuse context creation; only its permitted Unverified fallback commits an unknown initial observation. The knowledge owner consumes the existing verifier result | I4a, I7; failure table; unit cases; residual risks |

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

### PR #1174 review round 35 (cross-vendor review and review bots)

| Review | Issue | Disposition | Contract |
|---|---|---|---|
| CV-6 | MCP-session guidance named an undeclared remedy class | Fixed. Kernel-session denials carry only I19's declared classes, chosen from the requirement. "Run the agent as a mediated process" stays as documentation guidance, never encoded in the block | Section 12 |
| 4226832972 | Bootstrap trust assertions were not authenticated | Fixed. `BootstrapKind` is a closed vocabulary; `SignedBootstrapTrustAssertionV1` carries the signer key and a domain-separated signature; verification checks the integrity roster at the current generation, the bound key, the signature, scope and expiry. Unsigned, malformed or off-roster assertions are rejected and confer nothing. The schema is listed | I7a; sections 15, 16 and 18 |
