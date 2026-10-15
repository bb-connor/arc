# CT-WORK v1 sketch for WORK-W1.1a

Review draft for the `chio.work.v1` freeze. It sketches the wire types, the recovery (REC-0a) and substrate types each one embeds, the bounds, the rejection codes and the vector list. The normative contract is the [work runtime specification](2026-10-03-work-runtime-design.md); where this sketch and the specification disagree, the open questions below name the difference. REC-0a references are to `feat/recovery-contracts-v1` at `1c81adac3d`.

## Encoding

- Every type is a closed v1 shape: `deny_unknown_fields`, snake_case field names, and `#[serde(tag = "kind", rename_all = "snake_case")]` for every closed enum. This matches REC-0a.
- Top-level and stored records carry `schema` (a single-variant enum such as `chio.work.request.v1`) and `version: VersionV1`.
- Original bytes are decoded through `UntrustedJsonText` before typed conversion. Embedded REC-0a contracts are decoded with `decode_contract` and keep their own stricter limits.
- Integers are `SafeInteger` (at most 2^53 - 1). Timestamps are owner-clock Unix milliseconds.
- Work identifiers are their own newtypes, with the REC-0a identifier grammar: 1 to 128 bytes, a leading ASCII alphanumeric, then `[A-Za-z0-9._:-]`. Work never reuses a recovery identifier type for a different meaning.
- Schemas go in `spec/schemas/chio-work/v1/`. Generated SDK types come from the REC-0b codegen once it reads that directory.

## Work identifiers and references

| Type | Contents |
| --- | --- |
| `WorkProgramId`, `WorkCommandId`, `WorkPreparationId`, `WorkSlotId`, `WorkTaskId`, `WorkJoinId` | Identifier newtypes |
| `WorkAllocationDigest`, `WorkGraphDigest`, `WorkInvocationDigest`, `WorkCommandDigest` | Lowercase hex SHA-256 newtypes with distinct meanings |
| `WorkHandleV1` | `program_id`, `slot_id`, `allocation_hash`, `receiver_kernel_id`, `request_id: RequestId` (REC-0a) |
| `WorkPreparationRefV1` | `program_id`, `preparation_id`, `command_digest` |
| `WorkCommandRefV1` | `program_id`, `command_id`, `command_digest` |
| `WorkGraphDraftRefV1` / `WorkJoinDraftRefV1` | Owner-retained unsigned draft identity, with `graph_sha256` as the expected base |
| `WorkOwnerOperationRefV1` | `operation: OperationRef` (REC-0a: operation id, native admission digest, operation version) plus `scope: RecoveryScopeV1` (REC-0a) |

## Envelopes

`WorkRequestV1` (`chio.work.request.v1`) has the closed variants `Prepare(WorkPreparationV1)`, `Submit(WorkCommandV1)` and `Query(WorkQueryV1)`. `WorkResponseV1` (`chio.work.response.v1`) has the matching variants `Prepared(WorkPreparedV1)`, `Command(WorkCommandResultV1)` and `Query(WorkQueryResultV1)`. A response whose variant does not match the request is refused by the client.

### Preparation

`WorkPreparationV1` (`chio.work.preparation.v1`) carries `program_id`, `command_id` and `proposal: WorkProposalV1`.

| `WorkProposalV1` | Fields | Embeds |
| --- | --- | --- |
| `delegate` | `parent_id`, `parent_allocation_hash`, `child` | D1 `WorkSlot` |
| `offer` | `slot_id`, `allocation_hash`, `profile_ref: WorkProfileRefV1`, `receiver_kernel_id`, `server_id`, `tool_name`, `arguments`, `request_id` | REC-0a `RequestId` |
| `select` | `offer`, `request_id`, `capability_hash`, `expected_revision` | D1 `Signed<WorkOffer>` |
| `extend` | `expected_bundle_sha256`, `new_work` (at most 16), `dependencies` (at most 64), `join_draft_refs` (at most 16) | S1 `SwarmGraphEdge` |
| `join` | `expected_bundle_sha256`, `join`, `parents` (at most 16 `WorkHandleV1`) | S1 `SwarmGraphJoin` |
| `agreement` | `commitment: WorkCommitmentV1`, `terms: WorkAgreementTermsV1` | none |

`WorkAgreementTermsV1` is `Unpaid { terms_reference }` (decision D5) or `Funded { funding_profile_id, terms_reference }`. `Funded` is refused with `work.unsupported_profile` until WORK-W2.3.

`WorkPreparedV1` has three variants:
- `Prepared { preparation_ref, artifact: WorkPreparedArtifactV1 }`
- `Pending { preparation_ref, owner_operation_ref }`
- `Refused { preparation_ref, rejection: WorkRejectionV1 }`

`WorkPreparedArtifactV1` has one variant per proposal kind:
- `subdivision`: D1 `Signed<Subdivision>`
- `offer`: D1 `Signed<WorkOffer>`, plus the invocation custody reference
- `selection`: D1 `Signed<Selection>`
- `graph_draft`: `WorkGraphDraftRefV1`
- `join_draft`: `WorkJoinDraftRefV1`
- `agreement`: the agreement digest

No variant carries a signing handle, capability bytes or a raw `ToolCallRequest`.

### Commands

`WorkCommandV1` (`chio.work.command.v1`) carries `program_id`, `command_id` and `action: WorkActionV1`.

| `WorkActionV1` | Fields | Embeds |
| --- | --- | --- |
| `delegate` | `subdivision` | D1 `Signed<Subdivision>` |
| `select` | `selection` | D1 `Signed<Selection>` |
| `seal` | `binding` | D1 `DispatchBinding` |
| `extend` | `expected_bundle_sha256`, `draft_ref: WorkGraphDraftRefV1` | none |
| `submit` | `commitment: WorkCommitmentV1` | none |
| `reconcile` | `handle` | none |
| `cancel` | `handle` | none |

`WorkCommandResultV1` carries the original `command_ref` and one outcome:
- `Applied { revision, result: WorkAppliedV1 }`
- `Pending { owner_operation_ref }`
- `Refused { rejection }`

`WorkAppliedV1` has one variant per action:
- `delegated { slot }`
- `selected { revision }`
- `sealed { permit: Signed<DispatchPermit> }`
- `extended { bundle_sha256 }`
- `submitted { owner_operation_ref }`
- `reconciled { view }`
- `cancel_observed { control: WorkflowControlV1 }` (REC-0a)

`WorkCommitmentV1` binds the following. It defines no new signing domain.
- `handle`
- `permit: Signed<DispatchPermit>`
- `profile_ref`
- `invocation_ref: WorkInvocationDigest`, the protected exact-envelope custody reference
- `graph_ref: WorkGraphDigest`
- `funding: Option<WorkFundingRefV1>` (`rail`, `agreement_digest`, `reserve_ref`)

### Queries and views

`WorkQueryV1` has the variants:
- `work { handle }`
- `command { command_ref }`
- `preparation { preparation_ref }`
- `catalog { catalog_ref, cursor }`
- `profile { profile_ref }`

`WorkQueryResultV1` mirrors those variants and adds `unavailable { code }`. Missing is never a proof of native absence.

`WorkViewV1` holds six independent observations, each a `WorkObservationV1<T>`.

`WorkObservationV1<T>` is one of:
- `not_applicable`
- `pending { owner_ref: WorkOwnerOperationRefV1 }`
- `available { source, revision, observed_at, value: T }`
- `unavailable { code }`

| Observation | `T` | REC-0a type |
| --- | --- | --- |
| `execution` | `EffectObservationV1` | Reused unchanged |
| `acceptance` | `WorkAcceptanceV1` | Its producer reference is `OperationRef`; its artifact reference is `ArtifactVersionRefV1` (knowledge) |
| `result_reference` | `ArtifactVersionRefV1` plus `ReleaseDispositionV1` | Both reused |
| `recovery` | `WorkRecoveryLinkV1` | See below |
| `settlement` | `WorkSettlementRefV1` (rail and agreement digest only) | none |
| `bilateral_delivery` | `WorkDeliveryRefV1` (DSSE envelope digest and state) | none |

`WorkRecoveryLinkV1` contains:
- `schema: RecoveryObservationSchema`
- `version: VersionV1`
- `scope: RecoveryScopeV1`
- `workflow_id: WorkflowId`
- `step_id: StepId`
- `continuation_id: ContinuationId`
- `control: WorkflowControlV1`
- `available`, at most 8 values of `WorkRecoveryOperationV1`

`WorkRecoveryOperationV1` names a REC-0a `RecoveryCommandBodyV1` kind: `inspect_workflow`, `select_offer`, `submit_approval`, `resume_workflow` or `cancel_workflow`. It carries no command body. The client issues the recovery command itself, under recovery's own authorization and revision checks. The link allocates no second workflow identity.

`WorkAcceptanceV1` contains:
- `handle`
- `producer: OperationRef`
- `artifact: ArtifactVersionRefV1`
- `artifact_digest`
- `contract_digest: ContractDigest`
- `procedure_digest`
- `evaluator: IssuerId`
- `decision`, either `accepted` or `rejected`
- `evidence`, at most 16 `EvidenceRef`

### Profiles, catalogs and joins

These types are carried by the closed enums above, so they are frozen in W1.1a with them.

- **`WorkProfileRefV1`:** `owner`, `catalog_entry`, `deployment_digest: DeploymentDigest`, `policy_generation: PolicyGeneration`, `profile_digest: ProfileDigest`.
- **`WorkProfileV1`:**
  - The audience-scoped resolved view: tool and schema identity, input and recipient requirements, effects and ceilings, the acceptance procedure, supported recovery operations, validity, and optional funding terms.
  - Each condition records its evidence source and its enforcement assumption.
- **`WorkCatalogPageV1`:** at most 64 `WorkProfileRefV1`, plus an optional cursor bound to the caller scope and catalog generation.
- **`WorkJoinInputsV1`** (`chio.work.join-inputs.v1`):
  - Fields: `graph_sha256`, `join_id`, `next_task_id`, and `parents`, sorted by `task_id`, unique, and at most 16.
  - Each parent binds `task_id`, `receipt_id`, `artifact_ref: ArtifactVersionRefV1`, `artifact_digest` and `acceptance_evidence_digest`.
  - Its RFC 8785 digest is the S1 `result_digest`.

## Bounds

Every bound is enforced during decoding and expansion, before any allocation. A stricter native, D1, S1 or REC-0a limit always wins over a Work limit.

| Boundary | Limit |
| --- | --- |
| Request frame | 2,097,151 bytes plus one newline |
| Response frame | 8,388,608 bytes including framing |
| Nesting depth | 32 for the whole decoded request; 16 inside an embedded REC-0a contract |
| Aggregate nodes and entries | 16,384 JSON nodes and 8,192 collection entries across the request and its expanded embedded artifacts |
| Signature verifications | 8,192 per request; chain depth 32 |
| Command delta | 16 new work items, 64 dependency edges, 16 join drafts and 16 parents per join |
| Catalog page | 64 entries |
| D1 nested envelope | 65,536 bytes |
| Retained invocation | 262,144 bytes |
| Embedded REC-0a contract | `MAX_RECOVERY_WIRE_BYTES` (64 KiB), 4,096 nodes, 256 container entries |
| Identifiers | 128 bytes |

## Rejection codes

`WorkRejectionV1` contains:
- `code: WorkRejectionCodeV1`
- `field: Option<WorkBindingFieldV1>`, which names the binding that failed
- `reference`: the authorized original reference, if any

The stable string form is `work.<code>`. No parser or source text is serialized.

| Code | Meaning |
| --- | --- |
| `work.schema` | Wrong `schema` or `version` |
| `work.malformed` | Shape decode failure, including unknown fields and unknown variants |
| `work.duplicate_key` | Duplicate key anywhere in the original bytes |
| `work.unsafe_integer` | An integer above 2^53 - 1 |
| `work.bounds` | A bound in the table above was exceeded |
| `work.identifier` | An identifier or digest grammar violation |
| `work.binding_mismatch` | A cross-record binding failed; `field` names it |
| `work.conflict` | The same command or preparation ID arrived with a changed body |
| `work.stale_version` | The expected revision or head is not current |
| `work.stale_catalog` | The catalog generation changed under a cursor |
| `work.expired` | The validity interval has passed |
| `work.revoked` | Authority revoked at the final owning check |
| `work.audience` | The caller is not in the record's audience |
| `work.role` | The caller's role cannot prepare or submit this kind |
| `work.cross_tenant` | The reference is outside the caller's tenant or program |
| `work.unsupported_profile` | The profile or variant is not enabled, including `Funded` before WORK-W2.3 |
| `work.busy` | The bounded owner lane is saturated; refused before mutation |

`WorkBindingFieldV1` is one of `program_id`, `command_id`, `slot_id`, `allocation_hash`, `receiver_kernel_id`, `request_id`, `capability_hash`, `profile_ref`, `graph_sha256`, `draft_ref`, `permit` or `invocation_ref`.

Unknown native effect is an `execution` observation, never a rejection.

## Vectors

All vectors go under `spec/schemas/chio-work/v1/vectors/`. Each negative vector names the exact rejection code and field it expects.

1. **Positive round trips:** one per request, response, proposal, prepared, action, applied, query and query-result variant, plus `WorkViewV1` with every observation state.
2. **Closed-outcome negatives:** an unknown `kind`, an unknown field in every record, a wrong `schema`, and a wrong `version`.
3. **Duplicate keys:** at top level, in a nested D1 envelope and in an embedded REC-0a observation.
4. **Exact maximum and one over:**
   - Request frame.
   - Nesting depth.
   - Aggregate nodes and entries.
   - Command delta (16/17 work items, 64/65 edges, 16/17 drafts, 16/17 parents).
   - Catalog (64 accepted, 65 refused).
   - Identifier (128/129 bytes).
   - `SafeInteger` (2^53 - 1 accepted, 2^53 refused).
5. **Bindings:** a mismatch for each `WorkBindingFieldV1` value; a changed body under a reused `command_id`; a reused `preparation_id`; duplicate join parents; unsorted join parents.
6. **Profiles:** a stale catalog cursor; `Funded` agreement terms refused as `work.unsupported_profile`; `Unpaid` accepted.
7. **Embedded REC-0a:** an `EffectObservationV1` `unknown` round trip that stays an observation; a REC-0a contract over its inner limit is refused even inside a Work frame.
8. **Compile-fail cases:** callers cannot construct a verified binding, a `WorkSession` or a native owner type from JSON, and cannot obtain a signing handle from a prepared artifact.

## Open questions for the freeze

1. **Split.** The closed request, response and view enums carry every profile, catalog, acceptance and join type, so W1.1a must freeze all `chio.work.v1` wire types at once. W1.1b then holds `WorkClient<T: WorkTransport>`, the bounded byte wrappers, the `chio-runtime::work` facade, the `work` feature and the public-surface test.
2. **Recovery operation names.** The specification names `ExplainIntent`; REC-0a's command body has `InspectWorkflow`. This sketch follows REC-0a.
3. **Identifier types.** This sketch gives Work identifiers their own newtypes, using REC-0a's grammar, and reuses REC-0a types only where the meaning is the same: `RequestId`, `OperationRef`, `RecoveryScopeV1`, `WorkflowId`, `ArtifactVersionRefV1`, `EvidenceRef`, `ContractDigest`, `DeploymentDigest`, `PolicyGeneration`, `ProfileDigest`, `IssuerId`.
4. **Dependency model.** `HistoricalFact`, `CurrentPredicate` and `HeldReservation` are not in REC-0a; `DependencyGraphV1` lands with REC-3. `WorkJoinInputsV1` does not carry them, and the materializer applies them after REC-3.
5. **Port names.** CT-WORK maps to `RecoveryProcessReservationPort`, `RecoveryProcessOriginPort` and `RecoveryAuthorityPort`. Those are kernel traits that land with REC-1a, not wire types. The wire carries only the REC-0a references listed above, so W1.1a does not wait for REC-1a.
