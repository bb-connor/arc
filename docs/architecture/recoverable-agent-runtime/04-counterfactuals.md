# Bounded counterfactual explanations

## Contract

A recovery explanation answers: what restriction applies, which registered alternatives are available, which authority or evidence each alternative requires, and what remains unknown. It is an advisory computation over an explicit observed basis. It does not grant, reserve, consume, dispatch or promise a future outcome.

Reuse the current active-response simulation's architectural separation between `DryRun` and `Live`, expected signer/deployment verification, immutable observation snapshots and reproducible model results. Do not route recovery advice through an active-defense response plan or imply its six modeled effects already cover disclosure, transformations or child-return semantics. Recovery receives its own closed report schema and pure evaluator.

## Inputs and result types

`RecoverySnapshotV1` contains authority domain and tenant, selected policy/contract/registry versions, observation time and validity interval, exact intent digest, relevant flow/influence state, capability scope/expiry facts, authority-scope evidence, destination/ACL observations, known workflow/native-operation status and classified evidence references.

Each observation specifies source, object ID, version or freshness deadline, integrity class and audience label. A SQL transaction can give one store a consistent read point. Facts from other stores/providers form a version vector with explicit gaps; the report must not call that an atomic global snapshot. Mutable provider ACLs require an identified freshness policy and later live enforcement.

The evaluator accepts only already resolved bounded facts. Network consults are separate authenticated operations with their own information-flow and resource limits. If the requester would learn protected data through a consult or its result, the host must mediate that observation before returning advice. “Read only” does not mean public or free of influence.

Proposed results are `FeasibleUnderSnapshot`, `RequiresExactApproval`, `RequiresTransformation`, `RequiresPrerequisite`, `NeedsFreshEvidence`, `BlockedByCapability`, `UnknownOutcome`, `NoRegisteredRemedy` and `SearchBoundReached`. They are distinct from a native admission verdict. Do not encode advice as `{ allowed: true }`.

## Finite search and ordering

The registry supplies concrete remedy templates. The planner enumerates at most the configured offer/step/node limits, using deterministic order and a pinned planner semantics version. No arbitrary program synthesis, recursive tool search or model-generated authority appears in the trusted planner.

First order candidates by policy-permitted effect and disclosure scope. Prefer an existing permitted destination to requesting a wider exception when both satisfy the declared task constraint. Then compare required approvals, irreversible effects, budget estimates and declared latency class. Use a partial order: non-comparable audience/authority changes remain alternatives; a scalar score must not pretend one is universally safer. User/task constraints can rule out a candidate but cannot expand policy.

Costs and latency are estimates with provenance, never authorization or guaranteed future values. If no registered candidate exists, say exactly that. The result does not prove no possible program could accomplish the task.

## Safe explanation projection

The internal explanation graph may contain secret source identities, group membership, policy names or the existence of hidden resources. Its output receives a joined label/influence context and passes a dedicated projection for the recipient's authorized audience. Use opaque correlation references and stable generic reason codes when details cannot be disclosed.

An agent can see “approval required for this destination” without receiving a list of confidential group members. An authorized owner can inspect exact content through an artifact-bound preview. An operator can inspect the protected full graph through a separate capability. Logs, analytics, error messages, missing-vs-present responses and notification routing obey the same audience boundary.

Do not authorize repeated membership probes just because each returns a boolean. Rate and budget limit the explanation endpoint; avoid exposing hidden candidate counts or ranking changes. Where progress/timing reveals a permitted coarse status, document that channel in the deployment profile. This design does not assert constant-time noninterference across arbitrary providers.

## Signed reports

`RecoveryExplanationReportV1` binds its domain/schema, planner version, deployment/policy/contract digests, snapshot digest, exact intent digest, public-safe result digest, protected graph reference, validity deadline and signer identity. Verification checks an expected signer/trust domain, exact deployment selection, canonical bytes and recomputed pure results from authorized evidence.

Report signatures establish provenance. Every live selection reloads the retained offer and resolves current authority. No execution API accepts an explanation report in place of a v2 grant or native capture. Dry-run hosts do not install effect ports; report construction must be possible in a process with no live dispatch handle, issuer key or budget mutator.

The full report and its transitive commitments remain classified. A digest of a secret with a small search space can reveal that secret by offline enumeration; signatures and opaque-looking hashes do not redact it. Recipients without authority to inspect the full basis receive a separately projected `RecoveryExplanationViewV1`, with audience-bound opaque report references and only authorized facts. It may attest the projection under the expected issuer, but cannot claim independent recomputation without the required inputs. Never include protected snapshot/action/graph digests, candidate counts or full signed offers merely to make that view look verifiable.

The same rule applies to approval and grant transport. A worker may receive an opaque authorization reference while the trusted host resolves and attaches the classified signed grant during finalization. Knowing how to use a grant does not automatically authorize viewing every owner, resource and source commitment in it.

## Obligations

| ID | Normative obligation | Proposed acceptance test | Phase |
|---|---|---|---|
| SIM-01 | Counterfactual evaluation MUST operate only on explicit bounded facts and have no effect ports. | `simulation::no_effect_dependencies_or_writes` | P2 |
| SIM-02 | Cross-store observations MUST retain versions and uncertainty without claiming global atomicity. | `simulation::mixed_snapshot_versions` | P2 |
| SIM-03 | Advice/report objects MUST be rejected by every live authority/capture API. | `simulation::report_cannot_authorize` | P2 |
| SIM-04 | Explanations and candidate existence MUST be projected to the authorized audience. | `simulation::hidden_membership_and_resource_probes` | P2 |
| SIM-05 | Search MUST be deterministic, bounded and explicit about incompleteness. | `planner::permutation_bounds_and_partial_order` | P2 |
| SIM-06 | Signed reports MUST bind expected signer, deployment, snapshot, intent and recomputed result. | `simulation::resigned_semantic_tampering` | P2 |
| SIM-07 | Live use MUST freshly validate relevant observations rather than trust a prior feasible result. | `simulation::policy_acl_change_after_report` | P2 |
| SIM-08 | Projected reports and authorization references MUST NOT expose unauthorized transitive commitments or low-entropy secret digests. | `simulation::commitment_dictionary_and_cross_audience_probe` | P2 |
