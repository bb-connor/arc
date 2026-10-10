# Semantic connector packages, influence and transformations

## Package and deployment separation

A semantic package describes what tools read, what their effects change, where outputs go and which evidence establishes those facts. A deployment binds that package to actual operator trust, identities, credentials, provider instances and confinement. Package signatures authenticate the publisher and bytes; they do not confer tenant authority.

Proposed `SemanticPackageV1` contains publisher/package/version, content digest, minimum protocol versions, canonical tool/schema digests, input/output contracts, effect classes, recipient/resource selectors, source-origin rules, ACL evidence requirements, permitted remedy templates, transformation descriptors, required enforcement profile, bounded conformance fixtures and dependency digests. Dependencies are acyclic, digest-pinned and locally resolved before activation. Installation scripts do not execute as part of verification.

`SemanticDeploymentBindingV1` supplies tenant/domain, provider instance and account identity, principal/group mapping, trusted authority scopes, ACL resolver identity, connector build/image digest, approved transform implementation digests, host/proxy topology and effective root policy. Secret references are broker handles. Package code cannot select arbitrary credentials or egress destinations.

The combined resolved contract is compiled once into an immutable registry generation. Activation validates every covered tool and atomically selects a complete snapshot. A malformed reload leaves the last valid snapshot serving with its explicit version, unless an independent emergency revocation disables it. Old offers become stale according to the recovery basis contract. Reconciliation of already captured work continues using retained historical bindings.

## Coverage and policy composition

Key coverage by authenticated server/provider instance, canonical tool identity, input/output schema digest, adapter/implementation digest and protocol version. Every exposed operation is explicitly classified as covered, operator-authorized dynamic resolution, or refused. Discovery descriptions and familiar tool names cannot fill gaps. Nested tools, batches, pagination, redirects, streaming, error results, shell/native filesystem paths and model-provider requests appear in the coverage inventory.

Composition uses an explicit lowering contract over existing policy/manifests. Tenant/operator authority sets ceilings. Package rules may narrow those ceilings and add required evidence. Any operator override that relaxes a package restriction is a separately identified, reviewed policy rule with a reason, scope and tests; it cannot relax kernel capability or deployment ceilings. Report the matched rules and effective constraints. Do not inherit silent first-match precedence from include order.

Compile selectors into a bounded typed AST: validated field paths, literal/enum matches, resource identity derivation, source/sink lookup references and finite combinations. Use existing policy syntax where it can lower faithfully. No arbitrary JavaScript, shell or recursive expression evaluator belongs in the policy core. Reject unsupported semantics instead of approximating them permissively.

## Source, recipient and effect semantics

An input contract identifies confidentiality/influence origins, required evidence and input exposure. An output contract covers successful values, failures, streams, files and no-value completion. An effect contract identifies authoritative resources, mutation class, provider operation identity, idempotency scope, outcome lookup behavior and whether definitive non-acceptance is observable.

Destination is the actual account/resource/audience selected by the transport, not just a URL or agent-provided name. Bind canonical provider IDs, tenant/account and recipient/ACL facts into the action. Verify recipient resolution again at the last locally controlled dispatch boundary and constrain redirects, DNS targets, credentials and proxy routes using existing egress machinery. If the provider offers a version precondition, carry it. If it cannot enforce ACL/version atomically with acceptance, the profile must state that gap and refuse workflows requiring the stronger guarantee.

An external system's permissions can change after a completed disclosure. The contract does not promise to retract delivered bytes when membership changes. It defines which facts and enforcement held at release and what ongoing access checks govern Chio-retained artifacts.

### Submission and provider idempotency

Native capture alone does not prevent duplicate effects if an HTTP client, SDK, proxy or connector retries underneath it. `EffectContractV1` specifies submission cardinality, each effectful endpoint, stable provider operation/idempotency key, key scope and retention horizon, request-equivalence rules, authoritative outcome lookup and terminal non-acceptance evidence. Disable automatic effectful retries, redirects that replay bodies, authentication retries and proxy replay by default. Any transport retry policy is explicit, bounded and part of the qualified adapter/profile digest.

P1 allows one outbound effectful submission under the captured operation. Reconciliation performs authorized observation only. Later provider-deduplicated resubmission requires a separately qualified native recovery transition under the original operation/key/body and retained authority. It cannot be enabled by a generic retry middleware, renewed grant or new continuation. Expired/unknown provider deduplication retention, ambiguous account scope or mismatched body leaves the effect unresolved; it cannot be treated as a fresh opportunity.

An operation that can change several resources declares complete participant/effect cardinality. The initial profile supports a single bounded effect or provider-atomic transaction with a verifiable contract. Non-atomic batches become explicit plan steps, or require a separately qualified composite contract with item-level settlement. An HTTP failure after the first item succeeds is neither total failure nor no effect. Budget and resource disposition follow actual native/provider evidence.

## ACL observations

`AudienceObservationV1` binds source resolver/version, provider account/resource, tenant, subject/group mapping, audience expression, evidence digest, observed version/time, validity deadline and failure behavior. Prefer provider-native IDs over display names. Scope cache keys to the complete provider/account/tenant/query basis. Positive and negative evidence cannot be substituted across accounts or resources.

No-answer, partial pagination, rate limiting, ambiguous identity, stale evidence or resolver error becomes an empty/public audience. Resolver requests are themselves authorized, bounded operations; they do not inherit unlimited network rights because they run before the target tool. Recursion into contract resolution is bounded and cycle-detected. Emergency revocation takes precedence over cached positive evidence.

## Integrity and dynamic annotation

An authenticated transport does not endorse its content. A support ticket submitted by an external customer remains an external influence even when retrieved with a trusted support API credential. Model-produced instructions inherit the influences of the visible context. Contracts can require specific independently verified evidence before privileged actions.

Dynamic annotators declare finite powers. `RestrictOnly` may add confidentiality/influence restrictions or require evidence. `AttestFacts` may assert named fact types only under operator-selected verifier identity and domain. Declassification and integrity endorsement require separate explicit authority; an annotator's confidence field never supplies it. Results bind request/content/schema digests, code/model configuration version, tenant, observation time and expiry. Non-deterministic annotator output is retained exactly for replay.

Use a closed `ScopedEndorsementV1` target: either one exact action under its native operation, or one exact artifact version under an explicit reusable-projection policy. Bind original influence, precisely endorsed assertions/powers, supporting evidence and the authorized verifier scope. An action endorsement enters its native one-shot participant; an artifact endorsement is a retained scoped certificate checked on each use. Neither changes confidentiality labels, clears global influence or derives authority from a disclosure grant. An integrity-only remedy must work without inventing a confidentiality downgrade. P1 profiles that do not implement this participant refuse actions requiring it.

Trusted model-based classification is an explicit dependency with documented failure behavior and evaluation. Common structured contracts should use deterministic provider/schema facts. Classification cannot prove opaque shell code's filesystem/network behavior; broker/confinement coverage remains necessary.

## Transformations and narrowing

A transform descriptor specifies input/output schemas, canonical recipe/version and executable digest, determinism class, confinement profile, resource bounds, authorized confidentiality/integrity powers, applicable purpose/destinations and evidence requirements. The transform executes as a separately checked operation under attenuated capability. Pure field projection is preferable where it meets the task, but a syntactic projection alone is not disclosure authority.

Its `TransformationAttestationV1` binds every input artifact/version and source-label/influence join, exact implementation/configuration, producing operation, output digest/schema, target restrictions, authority policy and failure disposition. Errors and partial outputs inherit source restrictions and remain withheld unless separately authorized.

Three cases are distinct:

- A restrictive rewrite that preserves all labels needs ordinary execution authority and revalidation of its new bytes.
- A scoped declassification/endorsement creates one authorized crossing for the exact derived bytes; it does not sanitize the parent's history.
- An authority-approved persistent derived artifact receives a retained target-label certificate under an explicit reusable-projection policy. Future reads still require capability and audience checks. A one-shot send grant cannot mint such a reusable artifact certificate.

Changing bytes yields a new action intent. It never edits the frozen original call. Preserve the provenance edge and reevaluate destination, source joins and authority. For output transformations, the disposition is selected and bound before dispatch; raw results stay in a sealed staging channel until the chosen projection succeeds. A failed projection cannot fall back to the original result.

`Withhold` releases no tool data on either success or failure. It may release only an explicitly classified status projection. Even success/failure or timing can convey information; contracts must authorize the intended status channel. Withholding does not undo side effects or resolve an uncertain operation. Accepting narrower behavior is a recorded selection of this exact disposition.

## Prerequisites

A prerequisite is a new checked operation in the selected bounded DAG. Edges reference signed, verified facts/effects with exact resource, tenant, purpose, producing operation and validity. Text such as “review complete,” event timestamps or a receipt for another resource cannot satisfy the edge. Cycles, cross-tenant references and ambiguous evidence refuse. The parent cannot synthesize a prerequisite by rewriting its own history.

Edges distinguish `HistoricalFact`, `CurrentPredicate` and `HeldReservation`. A historical review applies to the reviewed version, not the current bytes at the same path. A current predicate requires fresh authoritative evaluation or a provider-enforced version precondition. A held lock/capacity/reservation requires its live lease, ownership, expiry and consuming participant at the dependent operation's commit. A signed receipt that a lock was once acquired cannot prove it is still held. The materializer and native participant both enforce the edge's declared semantics; no edge silently changes category.

## Obligations

| ID | Normative obligation | Proposed acceptance test | Phase |
|---|---|---|---|
| CON-01 | Package publisher identity MUST remain distinct from tenant deployment authority. | `contracts::package_cannot_bind_operator_authority` | P3 |
| CON-02 | Every exposed tool/channel MUST have complete authenticated coverage or refuse. | `contracts::uncovered_nested_stream_and_error_paths` | P3 |
| CON-03 | Policy composition MUST expose resolved precedence and preserve kernel/operator ceilings. | `contracts::override_and_ceiling_matrix` | P3 |
| CON-04 | Recipient resolution MUST bind the actual provider/account/resource and enforced transport. | `contracts::recipient_redirect_and_account_substitution` | P3 |
| CON-05 | ACL observations MUST be scoped, fresh, complete and fail closed on uncertainty. | `contracts::acl_cache_outage_and_pagination` | P3 |
| CON-06 | Dynamic annotators MUST have explicit bounded powers; confidence MUST NOT grant authority. | `contracts::annotator_power_escalation` | P3 |
| CON-07 | Influence/endorsement MUST be independent of confidentiality and transport authentication. | `integrity::trusted_transport_untrusted_ticket` | P3 |
| CON-08 | Transformation release MUST bind exact inputs, code, output, authority and purpose. | `transforms::input_output_code_and_scope_substitution` | P3 |
| CON-09 | A one-shot crossing MUST NOT create reusable public artifact authority. | `transforms::one_shot_cannot_mint_projection_certificate` | P4 |
| CON-10 | Bound output disposition MUST cover success, failure, stream and alternate channels without raw fallback. | `transforms::failure_and_withhold_channels` | P3 |
| CON-11 | Reload MUST activate a complete verified generation while preserving captured historical operations. | `contracts::reload_during_offer_and_unknown_effect` | P3 |
| CON-12 | Provider submission and any retry MUST obey the qualified native effect contract, including deduplication scope, lifetime and complete effect cardinality. | `contracts::hidden_transport_retry_and_partial_batch` | P1 |
| CON-13 | Prerequisites MUST distinguish historical facts, current predicates and held reservations at the dependent effect boundary. | `recovery::expired_lock_and_changed_reviewed_version` | P3 |
