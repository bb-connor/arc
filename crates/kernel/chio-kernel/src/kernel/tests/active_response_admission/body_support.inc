struct ActiveResponseFixture {
    kernel: ChioKernel,
    operator_issuer: Keypair,
    executor: Keypair,
    submitter: Keypair,
    submission_authority: Keypair,
    request: ActiveResponseAuthorizationRequest,
    capability_hash: String,
    plan_hash: String,
    response_plan: ResponsePlan,
    compact_plan_body: ResponsePlanAuthorizationBody,
    finding_authority: Arc<RecordingFindingAuthority>,
    _runtime: crate::FixedRuntimeScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestActiveResponseExecutionOutcome {
    Success,
    MissingEffectEvidence,
    MutatedResponseBodyHash,
    MutatedResponseTransitionId,
    MutatedEffectResultHash,
    MutatedEffectGeneration,
    MutatedCompletionReceipt,
    MissingEffectRequestedLifecycle,
    ReversedMutationTimestampLifecycle,
    BrokenPriorReceiptLifecycle,
    SpuriousFailureEvidence,
    WrongDispatchProof,
    OutcomeUnknown,
}

struct RecordingActiveResponseExecutor {
    identity: Mutex<ActiveResponseExecutorAuthorityIdentity>,
    signer: Mutex<Keypair>,
    ready: AtomicBool,
    calls: AtomicUsize,
    committed_dispatches: Mutex<BTreeMap<RecordId, ActiveResponseCommittedDispatch>>,
    fenced_dispatches: Mutex<BTreeSet<RecordId>>,
    last_policy_hash: Mutex<Option<Digest32>>,
    last_dispatch_committed_resume: AtomicBool,
    outcome: Mutex<TestActiveResponseExecutionOutcome>,
    execution_barrier: Mutex<Option<Arc<Barrier>>>,
}

struct RecordingFindingAuthority {
    ready: AtomicBool,
    evidence: Mutex<Option<AuthoritativeCorrelatedFindingEvidence>>,
}

impl RecordingFindingAuthority {
    fn new(evidence: AuthoritativeCorrelatedFindingEvidence) -> Self {
        Self {
            ready: AtomicBool::new(true),
            evidence: Mutex::new(Some(evidence)),
        }
    }

    fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::SeqCst);
    }

    fn replace(&self, evidence: AuthoritativeCorrelatedFindingEvidence) {
        *self.evidence.lock().expect("finding evidence lock") = Some(evidence);
    }
}

impl ActiveResponseFindingAuthority for RecordingFindingAuthority {
    fn ensure_ready(&self) -> Result<(), ActiveResponseFindingAuthorityError> {
        if self.ready.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ActiveResponseFindingAuthorityError::Unavailable(
                "test finding index unavailable".to_string(),
            ))
        }
    }

    fn load_correlated_finding(
        &self,
        evidence_id: &OpaqueReceiptRef,
    ) -> Result<Option<AuthoritativeCorrelatedFindingEvidence>, ActiveResponseFindingAuthorityError>
    {
        let evidence = self
            .evidence
            .lock()
            .map_err(|_| {
                ActiveResponseFindingAuthorityError::Unavailable(
                    "test finding evidence lock unavailable".to_string(),
                )
            })?
            .clone();
        Ok(evidence.filter(|evidence| evidence.evidence_id() == evidence_id))
    }
}

impl RecordingActiveResponseExecutor {
    fn new(signer: Keypair, generation: u64) -> Self {
        let subject = signer.public_key();
        Self {
            identity: Mutex::new(
                ActiveResponseExecutorAuthorityIdentity::new(subject, generation)
                    .expect("executor authority identity"),
            ),
            signer: Mutex::new(signer),
            ready: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
            committed_dispatches: Mutex::new(BTreeMap::new()),
            fenced_dispatches: Mutex::new(BTreeSet::new()),
            last_policy_hash: Mutex::new(None),
            last_dispatch_committed_resume: AtomicBool::new(false),
            outcome: Mutex::new(TestActiveResponseExecutionOutcome::Success),
            execution_barrier: Mutex::new(None),
        }
    }

    fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::SeqCst);
    }

    fn set_subject(&self, signer: Keypair) {
        let subject = signer.public_key();
        let generation = self
            .identity
            .lock()
            .expect("executor identity lock")
            .generation();
        *self.identity.lock().expect("executor identity lock") =
            ActiveResponseExecutorAuthorityIdentity::new(subject, generation)
                .expect("changed executor identity");
        *self.signer.lock().expect("executor signer lock") = signer;
    }

    fn set_outcome(&self, outcome: TestActiveResponseExecutionOutcome) {
        *self.outcome.lock().expect("executor outcome lock") = outcome;
    }

    fn set_execution_barrier(&self, barrier: Arc<Barrier>) {
        *self
            .execution_barrier
            .lock()
            .expect("executor barrier lock") = Some(barrier);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn last_policy_hash(&self) -> Option<Digest32> {
        *self
            .last_policy_hash
            .lock()
            .expect("executor policy hash lock")
    }

    fn last_dispatch_committed_resume(&self) -> bool {
        self.last_dispatch_committed_resume.load(Ordering::SeqCst)
    }

    fn corrupt_committed_applying_history(&self, dispatch_id: &RecordId) {
        let mut committed = self
            .committed_dispatches
            .lock()
            .expect("executor committed-dispatch lock");
        let retained = committed
            .get(dispatch_id)
            .cloned()
            .expect("retained committed dispatch");
        let mut snapshot: ResponseSnapshot = serde_json::from_slice(
            retained
                .committed_response_record()
                .canonical_body
                .as_bytes(),
        )
        .expect("committed response snapshot");
        let applying = snapshot
            .mutations
            .as_slice()
            .iter()
            .position(|mutation| {
                matches!(
                    mutation,
                    ResponseMutationRecord::Transition(transition)
                        if transition.to_state == ResponseState::Applying
                )
            })
            .expect("applying transition");
        let mut mutations = snapshot.mutations.clone().into_vec();
        let ResponseMutationRecord::Transition(transition) = &mut mutations[applying] else {
            panic!("applying mutation must be a transition");
        };
        transition.cause = ResponseTransitionCause::ValidationFailed;
        snapshot.mutations = ResponseMutationLog::new(mutations).expect("bounded mutations");
        let canonical = canonical_json_bytes(&snapshot).expect("canonical corrupted snapshot");
        let record = ResponsePlanRecord {
            tenant_id: snapshot.plan.tenant_id.clone(),
            action_id: snapshot.plan.action_id.clone(),
            generation: snapshot.generation,
            state: RecordId::new(snapshot.state.as_str()).expect("response state"),
            body_hash: Digest32::new(*sha256(&canonical).as_bytes()),
            canonical_body: CanonicalBody::new(canonical).expect("corrupted response body"),
            due_at_unix_ms: snapshot.due_at_unix_ms,
        };
        committed.insert(
            dispatch_id.clone(),
            ActiveResponseCommittedDispatch::new(
                retained.response_plan().clone(),
                retained.authorization().clone(),
                record,
            ),
        );
    }
}

impl ActiveResponseExecutorAuthority for RecordingActiveResponseExecutor {
    fn identity(&self) -> ActiveResponseExecutorAuthorityIdentity {
        self.identity
            .lock()
            .expect("executor identity lock")
            .clone()
    }

    fn ensure_ready(&self) -> Result<(), ActiveResponseExecutorError> {
        if self.ready.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ActiveResponseExecutorError::NotReady(
                "test executor unavailable".to_string(),
            ))
        }
    }

    fn execute_active_response(
        &self,
        request: &ActiveResponseExecutionRequest,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        if self
            .fenced_dispatches
            .lock()
            .map_err(|_| {
                ActiveResponseExecutorError::NotReady(
                    "test automatic-dispatch fence index unavailable".to_string(),
                )
            })?
            .contains(request.dispatch_id())
        {
            return Err(ActiveResponseExecutorError::RejectedBeforeCommit(
                "test automatic dispatch is durably fenced".to_string(),
            ));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self
            .last_policy_hash
            .lock()
            .expect("executor policy hash lock") = Some(request.response_plan().policy_hash);
        self.last_dispatch_committed_resume
            .store(request.dispatch_committed_resume(), Ordering::SeqCst);
        if let Some(barrier) = self
            .execution_barrier
            .lock()
            .expect("executor barrier lock")
            .clone()
        {
            barrier.wait();
            barrier.wait();
        }
        let exact_effect_evidence = request
            .response_plan()
            .effects
            .as_slice()
            .iter()
            .enumerate()
            .map(|(index, effect)| {
                ActiveResponseEffectEvidence::new(
                    effect.effect_id.clone(),
                    RecordId::new(format!("effect-transition-{index}"))
                        .expect("effect transition id"),
                    1,
                    Digest32::new([u8::try_from(index).unwrap_or(0).saturating_add(1); 32]),
                )
            })
            .collect::<Vec<_>>();
        let outcome = *self.outcome.lock().expect("executor outcome lock");
        let proof_dispatch_id = (outcome == TestActiveResponseExecutionOutcome::WrongDispatchProof)
            .then(|| {
                RecordId::new(
                    "active_response_dispatch_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
                .expect("wrong proof dispatch id")
            });
        let (
            mut response_record,
            mut completion_receipt,
            mut response_transition_id,
            mut proof_evidence_id,
            mut proof_body_hash,
            dispatch_authorization,
            committed_response_record,
        ) = active_response_execution_proof(
            request,
            &exact_effect_evidence,
            &self.signer.lock().expect("executor signer lock"),
            proof_dispatch_id.as_ref(),
        );
        self.committed_dispatches
            .lock()
            .expect("executor committed-dispatch lock")
            .insert(
                request.dispatch_id().clone(),
                ActiveResponseCommittedDispatch::new(
                    request.response_plan().clone(),
                    dispatch_authorization.clone(),
                    committed_response_record,
                ),
            );
        if outcome == TestActiveResponseExecutionOutcome::OutcomeUnknown {
            return Err(ActiveResponseExecutorError::OutcomeUnknown(
                "test acknowledgement lost".to_string(),
            ));
        }
        let mut effect_evidence =
            if outcome == TestActiveResponseExecutionOutcome::MissingEffectEvidence {
                Vec::new()
            } else {
                exact_effect_evidence
            };
        let mut response_body_hash = response_record.body_hash;
        match outcome {
            TestActiveResponseExecutionOutcome::MutatedResponseBodyHash => {
                response_body_hash = Digest32::new([0x91; 32]);
            }
            TestActiveResponseExecutionOutcome::MutatedResponseTransitionId => {
                response_transition_id = RecordId::new("mutated-response-transition")
                    .expect("mutated response transition id");
            }
            TestActiveResponseExecutionOutcome::MutatedEffectResultHash => {
                if let Some(effect) = effect_evidence.first_mut() {
                    *effect = ActiveResponseEffectEvidence::new(
                        effect.effect_id().clone(),
                        effect.transition_id().clone(),
                        effect.generation(),
                        Digest32::new([0x92; 32]),
                    );
                }
            }
            TestActiveResponseExecutionOutcome::MutatedEffectGeneration => {
                if let Some(effect) = effect_evidence.first_mut() {
                    *effect = ActiveResponseEffectEvidence::new(
                        effect.effect_id().clone(),
                        effect.transition_id().clone(),
                        effect.generation().saturating_add(1),
                        *effect.resulting_version_hash(),
                    );
                }
            }
            TestActiveResponseExecutionOutcome::MutatedCompletionReceipt => {
                completion_receipt.content_hash = "00".repeat(32);
            }
            TestActiveResponseExecutionOutcome::MissingEffectRequestedLifecycle => {
                let proof = rewrite_and_resign_response_lifecycle(
                    &response_record,
                    LifecycleMutation::RemoveEffectRequest,
                    &self.signer.lock().expect("executor signer lock"),
                );
                response_record = proof.response_record;
                completion_receipt = proof.completion_receipt;
                response_transition_id = proof.response_transition_id;
                proof_evidence_id = proof.proof_evidence_id;
                proof_body_hash = proof.proof_body_hash;
                response_body_hash = response_record.body_hash;
            }
            TestActiveResponseExecutionOutcome::ReversedMutationTimestampLifecycle => {
                let proof = rewrite_and_resign_response_lifecycle(
                    &response_record,
                    LifecycleMutation::ReverseEffectRequestTimestamp,
                    &self.signer.lock().expect("executor signer lock"),
                );
                response_record = proof.response_record;
                completion_receipt = proof.completion_receipt;
                response_transition_id = proof.response_transition_id;
                proof_evidence_id = proof.proof_evidence_id;
                proof_body_hash = proof.proof_body_hash;
                response_body_hash = response_record.body_hash;
            }
            TestActiveResponseExecutionOutcome::BrokenPriorReceiptLifecycle => {
                let proof = rewrite_and_resign_response_lifecycle(
                    &response_record,
                    LifecycleMutation::BreakEffectRequestPrior,
                    &self.signer.lock().expect("executor signer lock"),
                );
                response_record = proof.response_record;
                completion_receipt = proof.completion_receipt;
                response_transition_id = proof.response_transition_id;
                proof_evidence_id = proof.proof_evidence_id;
                proof_body_hash = proof.proof_body_hash;
                response_body_hash = response_record.body_hash;
            }
            TestActiveResponseExecutionOutcome::Success
            | TestActiveResponseExecutionOutcome::MissingEffectEvidence
            | TestActiveResponseExecutionOutcome::OutcomeUnknown
            | TestActiveResponseExecutionOutcome::SpuriousFailureEvidence
            | TestActiveResponseExecutionOutcome::WrongDispatchProof => {}
        }
        let failure = (outcome == TestActiveResponseExecutionOutcome::SpuriousFailureEvidence)
            .then(|| {
                ActiveResponseFailureEvidence::new(
                    ErrorCode::new("test.spurious_failure").expect("spurious failure code"),
                    None,
                )
            });
        Ok(ActiveResponseExecutionEvidence::new(
            ActiveResponseExecutionEvidenceParts {
                outcome: ActiveResponseExecutionOutcome::Activated,
                dispatch_id: request.dispatch_id().clone(),
                tenant_id: request.response_plan().tenant_id.clone(),
                action_id: request.response_plan().action_id.clone(),
                plan_hash: request.response_plan().plan_hash,
                executor_authority_generation: request.executor_authority_generation(),
                response_generation: response_record.generation,
                response_transition_id,
                response_body_hash,
                response_record,
                dispatch_authorization,
                proof_evidence_id,
                proof_body_hash,
                completion_receipt,
                effects: effect_evidence,
                failure,
                recovered: false,
            },
        ))
    }

    fn load_committed_active_response_dispatch(
        &self,
        tenant_id: &TenantId,
        dispatch_id: &RecordId,
    ) -> Result<Option<ActiveResponseCommittedDispatch>, ActiveResponseExecutorError> {
        Ok(self
            .committed_dispatches
            .lock()
            .map_err(|_| {
                ActiveResponseExecutorError::NotReady(
                    "test committed-dispatch index unavailable".to_string(),
                )
            })?
            .get(dispatch_id)
            .filter(|committed| &committed.response_plan().tenant_id == tenant_id)
            .cloned())
    }

    fn fence_uncommitted_automatic_dispatch(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> Result<
        crate::kernel::AutomaticActiveResponseDispatchFenceOutcome,
        ActiveResponseExecutorError,
    > {
        if let Some(committed) = self
            .committed_dispatches
            .lock()
            .map_err(|_| {
                ActiveResponseExecutorError::NotReady(
                    "test committed-dispatch index unavailable".to_string(),
                )
            })?
            .get(&binding.dispatch_id)
        {
            if committed.response_plan() != response_plan {
                return Err(ActiveResponseExecutorError::OutcomeUnknown(
                    "test committed dispatch does not match the fence request".to_string(),
                ));
            }
            return Ok(
                crate::kernel::AutomaticActiveResponseDispatchFenceOutcome::DispatchCommitted,
            );
        }
        self.fenced_dispatches
            .lock()
            .map_err(|_| {
                ActiveResponseExecutorError::NotReady(
                    "test automatic-dispatch fence index unavailable".to_string(),
                )
            })?
            .insert(binding.dispatch_id.clone());
        Ok(crate::kernel::AutomaticActiveResponseDispatchFenceOutcome::Fenced)
    }
}

fn append_valid_response_mutation(
    snapshot: &mut ResponseSnapshot,
    mutation: ResponseMutationRecord,
) {
    append_response_mutation_with_prior(snapshot, mutation, None);
}

fn append_response_mutation_with_prior(
    snapshot: &mut ResponseSnapshot,
    mut mutation: ResponseMutationRecord,
    prior_override: Option<OpaqueReceiptRef>,
) {
    let generation = u64::try_from(snapshot.mutations.len()).expect("response mutation count");
    let prior_receipt_id = prior_override.unwrap_or_else(|| {
        if snapshot.mutations.is_empty() {
            snapshot.plan.trigger_finding_receipt_id.clone()
        } else {
            active_defense_response_receipt_for_mutation(
                snapshot,
                snapshot.mutations.len().saturating_sub(1),
            )
            .and_then(|body| body.evidence_id())
            .expect("response receipt lineage head")
        }
    });
    set_response_mutation_chain_fields(&mut mutation, generation, prior_receipt_id);
    let transition_id = expected_response_mutation_transition_id(&snapshot.plan, &mutation)
        .expect("canonical response mutation transition id");
    *response_mutation_transition_id_mut(&mut mutation) = transition_id;
    let mut mutations = snapshot.mutations.clone().into_vec();
    mutations.push(mutation.clone());
    snapshot.mutations = ResponseMutationLog::new(mutations).expect("bounded response mutations");
    snapshot.generation = generation;
    match mutation {
        ResponseMutationRecord::Requested(_) => {
            snapshot.state = ResponseState::Planned;
            snapshot.applying_lease_expires_at_unix_ms = None;
            snapshot.due_at_unix_ms = Some(snapshot.plan.expires_at_unix_ms);
        }
        ResponseMutationRecord::Transition(record) => {
            snapshot.state = record.to_state;
            snapshot.applying_lease_expires_at_unix_ms = record.applying_lease_expires_at_unix_ms;
            snapshot.due_at_unix_ms = response_test_due(
                &snapshot.plan,
                record.to_state,
                record.occurred_at_unix_ms,
                record.applying_lease_expires_at_unix_ms,
            );
        }
        ResponseMutationRecord::Failed(record) => {
            snapshot.state = record.to_state;
            snapshot.applying_lease_expires_at_unix_ms = None;
            snapshot.due_at_unix_ms = response_test_due(
                &snapshot.plan,
                record.to_state,
                record.occurred_at_unix_ms,
                None,
            );
            snapshot.operator_page_required |= record.to_state == ResponseState::RollbackPartial;
        }
        ResponseMutationRecord::Final(record) => {
            snapshot.state = record.final_state;
            snapshot.applying_lease_expires_at_unix_ms = None;
            snapshot.due_at_unix_ms = None;
        }
        ResponseMutationRecord::EffectRequested(_)
        | ResponseMutationRecord::EffectApplied(_)
        | ResponseMutationRecord::EffectFailed(_)
        | ResponseMutationRecord::Rollback(_) => {}
    }
}

fn set_response_mutation_chain_fields(
    mutation: &mut ResponseMutationRecord,
    generation: u64,
    prior_receipt_id: OpaqueReceiptRef,
) {
    match mutation {
        ResponseMutationRecord::Requested(record) => {
            record.generation = generation;
            record.prior_receipt_id = prior_receipt_id;
        }
        ResponseMutationRecord::Transition(record) => {
            record.generation = generation;
            record.prior_receipt_id = prior_receipt_id;
        }
        ResponseMutationRecord::EffectRequested(record) => {
            record.generation = generation;
            record.prior_receipt_id = prior_receipt_id;
        }
        ResponseMutationRecord::EffectApplied(record) => {
            record.generation = generation;
            record.prior_receipt_id = prior_receipt_id;
        }
        ResponseMutationRecord::EffectFailed(record) => {
            record.generation = generation;
            record.prior_receipt_id = prior_receipt_id;
        }
        ResponseMutationRecord::Rollback(record) => {
            record.generation = generation;
            record.prior_receipt_id = prior_receipt_id;
        }
        ResponseMutationRecord::Failed(record) => {
            record.generation = generation;
            record.prior_receipt_id = prior_receipt_id;
        }
        ResponseMutationRecord::Final(record) => {
            record.generation = generation;
            record.prior_receipt_id = prior_receipt_id;
        }
    }
}

fn response_mutation_transition_id_mut(mutation: &mut ResponseMutationRecord) -> &mut RecordId {
    match mutation {
        ResponseMutationRecord::Requested(record) => &mut record.transition_id,
        ResponseMutationRecord::Transition(record) => &mut record.transition_id,
        ResponseMutationRecord::EffectRequested(record) => &mut record.transition_id,
        ResponseMutationRecord::EffectApplied(record) => &mut record.transition_id,
        ResponseMutationRecord::EffectFailed(record) => &mut record.transition_id,
        ResponseMutationRecord::Rollback(record) => &mut record.transition_id,
        ResponseMutationRecord::Failed(record) => &mut record.transition_id,
        ResponseMutationRecord::Final(record) => &mut record.transition_id,
    }
}

fn response_test_due(
    plan: &ResponsePlan,
    state: ResponseState,
    occurred_at_unix_ms: u64,
    applying_lease_expires_at_unix_ms: Option<u64>,
) -> Option<u64> {
    match state {
        ResponseState::Planned | ResponseState::AwaitingApproval | ResponseState::Active => {
            Some(plan.expires_at_unix_ms)
        }
        ResponseState::Applying => applying_lease_expires_at_unix_ms,
        ResponseState::ApplyPartial
        | ResponseState::Expiring
        | ResponseState::RollingBack
        | ResponseState::RollbackPartial => Some(occurred_at_unix_ms),
        ResponseState::Cancelled
        | ResponseState::Expired
        | ResponseState::Failed
        | ResponseState::Lifted => None,
    }
}

fn active_response_execution_proof(
    request: &ActiveResponseExecutionRequest,
    effects: &[ActiveResponseEffectEvidence],
    signer: &Keypair,
    proof_dispatch_id: Option<&RecordId>,
) -> (
    ResponsePlanRecord,
    ChioReceipt,
    RecordId,
    OpaqueReceiptRef,
    Digest32,
    ResponseDispatchAuthorization,
    ResponsePlanRecord,
) {
    let plan = request.response_plan();
    let proof_dispatch_id = proof_dispatch_id.unwrap_or_else(|| request.dispatch_id());
    let (approval, governed) = match request.approval() {
        ActiveResponseExecutionApproval::Automatic => (ResponseDispatchApproval::Automatic, false),
        ActiveResponseExecutionApproval::Governed {
            admission_operation_id,
            admission_operation_version,
            approval_set_hash,
        } => (
            ResponseDispatchApproval::Governed {
                admission_operation_id: RecordId::new(admission_operation_id.clone())
                    .expect("governed admission operation id"),
                admission_operation_version: *admission_operation_version,
                approval_set_hash: active_response_digest_from_hex(approval_set_hash),
            },
            true,
        ),
    };
    let authorized_at_unix_ms = request.authorized_at_unix_ms();
    let execution_dispatch = ResponseExecutionDispatchBinding {
        schema_version: RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
        tenant_id: plan.tenant_id.clone(),
        dispatch_id: proof_dispatch_id.clone(),
        action_id: plan.action_id.clone(),
        plan_hash: plan.plan_hash,
        executor_authority_id: RecordId::new(request.executor_authority_id())
            .expect("executor authority id"),
        executor_authority_generation: request.executor_authority_generation(),
        authorization_capability_hash: active_response_digest_from_hex(
            request.authorization_capability_hash(),
        ),
        governed_intent_hash: active_response_digest_from_hex(request.governed_intent_hash()),
        policy_decision_hash: active_response_digest_from_hex(request.policy_decision_hash()),
        approval: approval.clone(),
        authorized_at_unix_ms,
    };
    let mut applying_snapshot = ResponseSnapshot {
        schema_version: RESPONSE_STATE_SCHEMA_VERSION,
        plan: plan.clone(),
        execution_dispatch: Some(execution_dispatch.clone()),
        dispatch_authorization_hash: None,
        state: ResponseState::Planned,
        generation: 0,
        applying_lease_expires_at_unix_ms: None,
        due_at_unix_ms: Some(plan.expires_at_unix_ms),
        operator_page_required: false,
        mutations: ResponseMutationLog::new(Vec::new()).expect("empty response mutations"),
    };
    append_valid_response_mutation(
        &mut applying_snapshot,
        ResponseMutationRecord::Requested(ResponseRequestedRecord {
            transition_id: RecordId::new("pending-response-request").expect("pending request"),
            generation: 0,
            prior_receipt_id: plan.trigger_finding_receipt_id.clone(),
            occurred_at_unix_ms: plan.created_at_unix_ms,
        }),
    );
    if governed {
        append_valid_response_mutation(
            &mut applying_snapshot,
            ResponseMutationRecord::Transition(ResponseTransitionRecord {
                transition_id: RecordId::new("pending-awaiting-approval")
                    .expect("pending awaiting approval"),
                generation: 1,
                from_state: ResponseState::Planned,
                to_state: ResponseState::AwaitingApproval,
                cause: ResponseTransitionCause::ApprovalRequested,
                applying_lease_expires_at_unix_ms: None,
                scheduler_lease_owner_id: None,
                scheduler_fencing_token: None,
                prior_receipt_id: plan.trigger_finding_receipt_id.clone(),
                occurred_at_unix_ms: plan.created_at_unix_ms,
            }),
        );
    }
    let applying_generation = if governed { 2 } else { 1 };
    append_valid_response_mutation(
        &mut applying_snapshot,
        ResponseMutationRecord::Transition(ResponseTransitionRecord {
            transition_id: RecordId::new("pending-applying").expect("pending applying"),
            generation: applying_generation,
            from_state: if governed {
                ResponseState::AwaitingApproval
            } else {
                ResponseState::Planned
            },
            to_state: ResponseState::Applying,
            cause: if governed {
                ResponseTransitionCause::ApprovalSatisfied
            } else {
                ResponseTransitionCause::ApplyStarted
            },
            applying_lease_expires_at_unix_ms: Some(plan.expires_at_unix_ms),
            scheduler_lease_owner_id: None,
            scheduler_fencing_token: None,
            prior_receipt_id: plan.trigger_finding_receipt_id.clone(),
            occurred_at_unix_ms: authorized_at_unix_ms,
        }),
    );
    let applying_canonical =
        canonical_json_bytes(&applying_snapshot).expect("canonical applying response snapshot");
    let applying_body_hash = Digest32::new(*sha256(&applying_canonical).as_bytes());
    let authorization_body = ResponseDispatchAuthorizationBody {
        schema_version: RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
        key: ResponseDispatchKey {
            tenant_id: plan.tenant_id.clone(),
            dispatch_id: proof_dispatch_id.clone(),
        },
        action_id: plan.action_id.clone(),
        plan_hash: plan.plan_hash,
        response_body_hash: applying_body_hash,
        authorization_capability_hash: execution_dispatch.authorization_capability_hash,
        governed_intent_hash: execution_dispatch.governed_intent_hash,
        policy_decision_hash: execution_dispatch.policy_decision_hash,
        executor_authority_id: execution_dispatch.executor_authority_id.clone(),
        executor_authority_generation: execution_dispatch.executor_authority_generation,
        approval,
        authorized_at_unix_ms,
    };
    let authorization_canonical =
        canonical_json_bytes(&authorization_body).expect("canonical dispatch authorization");
    let authorization_hash = Digest32::new(*sha256(&authorization_canonical).as_bytes());
    let dispatch_authorization = ResponseDispatchAuthorization {
        body: authorization_body,
        canonical_body: CanonicalBody::new(authorization_canonical)
            .expect("canonical dispatch authorization body"),
        body_hash: authorization_hash,
    };
    let mut committed_snapshot = applying_snapshot;
    committed_snapshot.dispatch_authorization_hash = Some(authorization_hash);
    let committed_canonical =
        canonical_json_bytes(&committed_snapshot).expect("canonical committed response snapshot");
    let committed_response_record = ResponsePlanRecord {
        tenant_id: plan.tenant_id.clone(),
        action_id: plan.action_id.clone(),
        generation: committed_snapshot.generation,
        state: RecordId::new(committed_snapshot.state.as_str()).expect("committed response state"),
        canonical_body: CanonicalBody::new(committed_canonical.clone())
            .expect("canonical committed response record"),
        body_hash: Digest32::new(*sha256(&committed_canonical).as_bytes()),
        due_at_unix_ms: committed_snapshot.due_at_unix_ms,
    };
    let mut snapshot = committed_snapshot.clone();
    for (index, effect) in effects.iter().enumerate() {
        let request_generation = snapshot.generation.saturating_add(1);
        append_valid_response_mutation(
            &mut snapshot,
            ResponseMutationRecord::EffectRequested(ResponseEffectRequestedRecord {
                transition_id: RecordId::new(format!("pending-effect-request-{index}"))
                    .expect("pending effect request"),
                generation: request_generation,
                effect_id: effect.effect_id().clone(),
                effect_generation: 1,
                scheduler_lease_owner_id: None,
                scheduler_fencing_token: 1,
                prior_receipt_id: plan.trigger_finding_receipt_id.clone(),
                occurred_at_unix_ms: authorized_at_unix_ms.saturating_add(request_generation),
            }),
        );
        let applied_generation = snapshot.generation.saturating_add(1);
        append_valid_response_mutation(
            &mut snapshot,
            ResponseMutationRecord::EffectApplied(ResponseEffectAppliedRecord {
                transition_id: RecordId::new(format!("pending-effect-applied-{index}"))
                    .expect("pending effect applied"),
                generation: applied_generation,
                effect_id: effect.effect_id().clone(),
                effect_generation: effect
                    .generation()
                    .checked_add(1)
                    .expect("effect generation"),
                resulting_version_hash: *effect.resulting_version_hash(),
                scheduler_lease_owner_id: None,
                scheduler_fencing_token: 1,
                effect_transition_id: Some(effect.transition_id().clone()),
                prior_receipt_id: plan.trigger_finding_receipt_id.clone(),
                occurred_at_unix_ms: authorized_at_unix_ms.saturating_add(applied_generation),
            }),
        );
    }
    let response_generation = snapshot.generation.saturating_add(1);
    let completion_time = authorized_at_unix_ms.saturating_add(response_generation);
    append_valid_response_mutation(
        &mut snapshot,
        ResponseMutationRecord::Transition(ResponseTransitionRecord {
            transition_id: RecordId::new("pending-active").expect("pending active"),
            generation: response_generation,
            from_state: ResponseState::Applying,
            to_state: ResponseState::Active,
            cause: ResponseTransitionCause::ApplyCompleted,
            applying_lease_expires_at_unix_ms: None,
            scheduler_lease_owner_id: None,
            scheduler_fencing_token: None,
            prior_receipt_id: plan.trigger_finding_receipt_id.clone(),
            occurred_at_unix_ms: completion_time,
        }),
    );
    let response_transition_id = snapshot
        .mutations
        .as_slice()
        .last()
        .expect("active response mutation")
        .transition_id()
        .clone();
    let completion_prior = snapshot
        .mutations
        .as_slice()
        .last()
        .expect("active response mutation")
        .prior_receipt_id()
        .clone();
    let canonical = canonical_json_bytes(&snapshot).expect("canonical response snapshot");
    let response_body_hash = Digest32::new(*sha256(&canonical).as_bytes());
    let response_record = ResponsePlanRecord {
        tenant_id: plan.tenant_id.clone(),
        action_id: plan.action_id.clone(),
        generation: response_generation,
        state: RecordId::new(ResponseState::Active.as_str()).expect("active state id"),
        canonical_body: CanonicalBody::new(canonical).expect("canonical response record"),
        body_hash: response_body_hash,
        due_at_unix_ms: Some(plan.expires_at_unix_ms),
    };
    let outcomes = ActiveDefenseEffectOutcomeCommitments::new(
        plan.effects
            .as_slice()
            .iter()
            .zip(effects)
            .map(|(planned, applied)| ActiveDefenseEffectOutcomeCommitment {
                effect: ActiveDefenseEffectCommitment {
                    effect_id: planned.effect_id.clone(),
                    ordinal: planned.ordinal,
                    kind: planned.kind,
                    target: planned.target.clone(),
                    contribution_hash: planned.contribution_hash,
                    observed_base_version_hash: planned.observed_base_version_hash,
                },
                outcome: ActiveDefenseEffectOutcome::Applied {
                    resulting_version_hash: *applied.resulting_version_hash(),
                },
            })
            .collect(),
    )
    .expect("bounded response completion effects");
    let completion = ActiveDefenseReceiptBody::ResponseCompletion(ResponseCompletionReceiptBody {
        header: ActiveDefenseReceiptHeader::new(
            completion_time,
            plan.tenant_id.clone(),
            response_transition_id.clone(),
            vec![completion_prior],
        )
        .expect("response completion header"),
        response: ActiveDefenseResponseBinding {
            policy: ActiveDefensePolicyBinding {
                policy_version: plan.policy_version.clone(),
                policy_hash: plan.policy_hash,
            },
            plan_hash: plan.plan_hash,
            action_id: plan.action_id.clone(),
            trigger_finding_id: plan.trigger_finding_id.clone(),
            trigger_finding_hash: plan.trigger_finding_hash,
            trigger_finding_receipt_id: plan.trigger_finding_receipt_id.clone(),
            affected_set_hash: plan.affected_set_hash,
            plan_expires_at_unix_ms: plan.expires_at_unix_ms,
        },
        execution_dispatch: snapshot.execution_dispatch.clone(),
        dispatch_authorization_hash: Some(authorization_hash),
        response_generation,
        response_body_hash,
        final_state: ResponseState::Active,
        error_code: None,
        effects: outcomes,
    });
    let evidence_id = completion.evidence_id().expect("completion evidence id");
    let body_digest = completion.body_digest().expect("completion body digest");
    let action = ToolCallAction::from_parameters(serde_json::json!({
        "evidence_id": evidence_id.as_str(),
        "kind": completion.kind().as_str(),
        "transition_id": response_transition_id.as_str(),
    }))
    .expect("completion receipt action");
    let metadata = serde_json::json!({
        "active_defense_body": &completion,
        "active_defense_evidence_id": evidence_id.as_str(),
        "occurred_at_unix_ms": completion_time,
    });
    let receipt = ChioReceipt::sign_with_backend(
        ChioReceiptBody {
            id: String::new(),
            timestamp: completion_time / 1_000,
            capability_id: "chio.active-defense.system".to_string(),
            tool_server: "chio.kernel".to_string(),
            tool_name: completion.kind().as_str().to_string(),
            action,
            decision: None,
            receipt_kind: ReceiptKind::TraceObservation,
            boundary_class: BoundaryClass::DetectOnly,
            observation_outcome: Some(ObservationOutcome::Observed),
            tool_origin: ToolOrigin::ChioInternal,
            redaction_mode: RedactionMode::Redacted,
            actor_chain: Vec::new(),
            content_hash: active_response_hex(&body_digest),
            policy_hash: active_response_hex(&plan.policy_hash),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: TrustLevel::Verified,
            tenant_id: Some(plan.tenant_id.as_str().to_string()),
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
        },
        &Ed25519Backend::new(signer.clone()),
    )
    .expect("signed response completion receipt");
    (
        response_record,
        receipt,
        response_transition_id,
        evidence_id,
        body_digest,
        dispatch_authorization,
        committed_response_record,
    )
}

#[derive(Clone, Copy)]
enum LifecycleMutation {
    RemoveEffectRequest,
    ReverseEffectRequestTimestamp,
    BreakEffectRequestPrior,
}

struct RewrittenLifecycleProof {
    response_record: ResponsePlanRecord,
    completion_receipt: ChioReceipt,
    response_transition_id: RecordId,
    proof_evidence_id: OpaqueReceiptRef,
    proof_body_hash: Digest32,
}

fn rewrite_and_resign_response_lifecycle(
    response_record: &ResponsePlanRecord,
    mutation: LifecycleMutation,
    signer: &Keypair,
) -> RewrittenLifecycleProof {
    let original: ResponseSnapshot =
        serde_json::from_slice(response_record.canonical_body.as_bytes())
            .expect("response lifecycle snapshot");
    let mut mutations = original.mutations.clone().into_vec();
    let effect_request_index = mutations
        .iter()
        .position(|record| matches!(record, ResponseMutationRecord::EffectRequested(_)))
        .expect("effect request mutation");
    match mutation {
        LifecycleMutation::RemoveEffectRequest => {
            mutations.remove(effect_request_index);
        }
        LifecycleMutation::ReverseEffectRequestTimestamp => {
            let prior_time = effect_request_index
                .checked_sub(1)
                .and_then(|index| mutations.get(index))
                .map(ResponseMutationRecord::occurred_at_unix_ms)
                .expect("effect request predecessor");
            let ResponseMutationRecord::EffectRequested(request) =
                &mut mutations[effect_request_index]
            else {
                panic!("effect request mutation changed kind");
            };
            request.occurred_at_unix_ms = prior_time.saturating_sub(1);
        }
        LifecycleMutation::BreakEffectRequestPrior => {}
    }
    let mut rebuilt = original.clone();
    rebuilt.state = ResponseState::Planned;
    rebuilt.generation = 0;
    rebuilt.applying_lease_expires_at_unix_ms = None;
    rebuilt.due_at_unix_ms = Some(rebuilt.plan.expires_at_unix_ms);
    rebuilt.operator_page_required = false;
    rebuilt.mutations = ResponseMutationLog::new(Vec::new()).expect("empty rebuilt mutations");
    let mut broke_prior = false;
    for record in mutations {
        let break_this = matches!(mutation, LifecycleMutation::BreakEffectRequestPrior)
            && !broke_prior
            && matches!(record, ResponseMutationRecord::EffectRequested(_));
        if break_this {
            append_response_mutation_with_prior(
                &mut rebuilt,
                record,
                Some(
                    OpaqueReceiptRef::new("forged-response-prior-lineage")
                        .expect("forged prior receipt"),
                ),
            );
            broke_prior = true;
        } else {
            append_valid_response_mutation(&mut rebuilt, record);
        }
    }
    let canonical = canonical_json_bytes(&rebuilt).expect("rewritten response canonical body");
    let body_hash = Digest32::new(*sha256(&canonical).as_bytes());
    let response_record = ResponsePlanRecord {
        tenant_id: rebuilt.plan.tenant_id.clone(),
        action_id: rebuilt.plan.action_id.clone(),
        generation: rebuilt.generation,
        state: RecordId::new(rebuilt.state.as_str()).expect("rewritten response state"),
        canonical_body: CanonicalBody::new(canonical).expect("rewritten response body"),
        body_hash,
        due_at_unix_ms: rebuilt.due_at_unix_ms,
    };
    let completion = active_defense_response_receipt_for_mutation(
        &rebuilt,
        rebuilt.mutations.len().saturating_sub(1),
    )
    .expect("rewritten response completion");
    let proof_evidence_id = completion
        .evidence_id()
        .expect("rewritten completion evidence id");
    let proof_body_hash = completion
        .body_digest()
        .expect("rewritten completion body hash");
    let response_transition_id = rebuilt
        .mutations
        .as_slice()
        .last()
        .expect("rewritten terminal mutation")
        .transition_id()
        .clone();
    let completion_receipt = sign_test_active_defense_completion(&completion, signer);
    RewrittenLifecycleProof {
        response_record,
        completion_receipt,
        response_transition_id,
        proof_evidence_id,
        proof_body_hash,
    }
}

fn sign_test_active_defense_completion(
    completion: &ActiveDefenseReceiptBody,
    signer: &Keypair,
) -> ChioReceipt {
    let ActiveDefenseReceiptBody::ResponseCompletion(body) = completion else {
        panic!("active response proof must be a response completion");
    };
    let evidence_id = completion.evidence_id().expect("completion evidence id");
    let body_digest = completion.body_digest().expect("completion body digest");
    let action = ToolCallAction::from_parameters(serde_json::json!({
        "evidence_id": evidence_id.as_str(),
        "kind": completion.kind().as_str(),
        "transition_id": body.header.transition_id.as_str(),
    }))
    .expect("completion receipt action");
    let metadata = serde_json::json!({
        "active_defense_body": completion,
        "active_defense_evidence_id": evidence_id.as_str(),
        "occurred_at_unix_ms": body.header.occurred_at_unix_ms,
    });
    ChioReceipt::sign_with_backend(
        ChioReceiptBody {
            id: String::new(),
            timestamp: body.header.occurred_at_unix_ms / 1_000,
            capability_id: "chio.active-defense.system".to_string(),
            tool_server: "chio.kernel".to_string(),
            tool_name: completion.kind().as_str().to_string(),
            action,
            decision: None,
            receipt_kind: ReceiptKind::TraceObservation,
            boundary_class: BoundaryClass::DetectOnly,
            observation_outcome: Some(ObservationOutcome::Observed),
            tool_origin: ToolOrigin::ChioInternal,
            redaction_mode: RedactionMode::Redacted,
            actor_chain: Vec::new(),
            content_hash: active_response_hex(&body_digest),
            policy_hash: active_response_hex(&body.response.policy.policy_hash),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: TrustLevel::Verified,
            tenant_id: Some(body.header.tenant_id.as_str().to_string()),
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
        },
        &Ed25519Backend::new(signer.clone()),
    )
    .expect("signed rewritten completion receipt")
}

#[derive(serde::Serialize)]
struct AffectedSetCommitment<'a> {
    tenant_id: &'a str,
    affected_ids: &'a [RecordId],
}

fn signed_submission_proof(
    plan: &ResponsePlanAuthorizationBody,
    governed_intent: &GovernedTransactionIntent,
    submitter: &Keypair,
) -> ActiveResponseSubmissionProof {
    let canonical_plan_body = serde_json::to_value(plan).expect("submission plan value");
    let plan_body_hash =
        GovernedResponsePlanIntentBody::compute_plan_body_hash(&canonical_plan_body)
            .expect("submission plan hash");
    let governed_intent_hash = governed_intent
        .binding_hash()
        .expect("submission governed intent hash");
    let body = ActiveResponseSubmissionProofBody::new(
        plan.action_id.clone(),
        plan.tenant_id.clone(),
        plan_body_hash,
        governed_intent_hash,
        submitter.public_key(),
        plan.created_at_unix_ms,
        plan.expires_at_unix_ms,
    )
    .expect("submission proof body");
    ActiveResponseSubmissionProof::sign_with_backend(body, &Ed25519Backend::new(submitter.clone()))
        .expect("signed submission proof")
}

fn signed_active_response_admission_request(
    fixture: &ActiveResponseFixture,
    response_plan: ResponsePlan,
    authorization: ActiveResponseAuthorizationRequest,
    threshold_proposal: Option<crate::threshold_approval::ThresholdApprovalProposal>,
    approval_tokens: Vec<GovernedApprovalToken>,
) -> ActiveResponseAdmissionRequest {
    let artifact_ref =
        chio_security_types::ports::AdmissionArtifactRef::new("admission-artifact-active-response")
            .expect("admission artifact ref");
    let proof = authorization.submission_proof();
    let payload_digest = crate::kernel::active_response_admission_artifact_payload_digest(
        authorization.plan_body(),
        authorization.operator_capability(),
        authorization.governed_intent(),
        proof,
        &threshold_proposal,
        &approval_tokens,
    )
    .expect("admission artifact payload digest");
    let proof_digest = crate::kernel::active_response_submission_proof_digest(proof)
        .expect("submission proof digest");
    let body = crate::kernel::ActiveResponseArtifactAuthorityAttestationBody::new(
        crate::kernel::ActiveResponseArtifactAuthorityAttestationInput {
            artifact_ref: artifact_ref.clone(),
            action_id: response_plan.action_id.clone(),
            tenant_id: response_plan.tenant_id.clone(),
            artifact_payload_digest: payload_digest,
            submission_proof_digest: proof_digest,
            plan_body_hash: active_response_digest_from_hex(&proof.body.plan_body_hash),
            governed_intent_hash: active_response_digest_from_hex(
                &proof.body.governed_intent_hash,
            ),
            submitter: proof.body.submitter.clone(),
            authority: fixture.submission_authority.public_key(),
            issued_at_unix_ms: proof.body.issued_at_unix_ms,
            expires_at_unix_ms: proof.body.expires_at_unix_ms,
        },
    )
    .expect("artifact authority attestation body");
    let attestation = crate::kernel::ActiveResponseArtifactAuthorityAttestation::sign_with_backend(
        body,
        &Ed25519Backend::new(fixture.submission_authority.clone()),
    )
    .expect("artifact authority attestation");
    ActiveResponseAdmissionRequest::new(
        response_plan,
        authorization,
        artifact_ref,
        attestation,
        threshold_proposal,
        approval_tokens,
    )
    .expect("active-response admission request")
}

#[derive(serde::Serialize)]
struct EffectCommitment<'a> {
    action_id: &'a str,
    ordinal: u16,
    spec: &'a ResponseEffectSpec,
}

fn active_response_domain_digest<T: serde::Serialize>(domain: &[u8], value: &T) -> Digest32 {
    let canonical = canonical_json_bytes(value).expect("canonical test commitment");
    let mut bytes = Vec::with_capacity(domain.len() + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&canonical);
    Digest32::new(*sha256(&bytes).as_bytes())
}

fn active_response_hex(digest: &Digest32) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest.as_bytes() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn active_response_digest_from_hex(value: &str) -> Digest32 {
    fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("test digest is not lowercase hex"),
        }
    }

    let bytes = value.as_bytes();
    assert_eq!(bytes.len(), 64, "test digest must be SHA-256 hex");
    let mut digest = [0_u8; 32];
    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        digest[index] = (nibble(chunk[0]) << 4) | nibble(chunk[1]);
    }
    Digest32::new(digest)
}

fn active_response_target(
    kind: ResponseEffectKind,
    ordinal: u16,
    affected_set_hash: Digest32,
) -> ResponseTarget {
    match kind {
        ResponseEffectKind::EscalateAlert => ResponseTarget::Tenant {
            tenant_id: TenantId::new("tenant-active-response").expect("tenant id"),
        },
        ResponseEffectKind::ThrottleSession
        | ResponseEffectKind::RestrictEgress
        | ResponseEffectKind::SuspendSession => ResponseTarget::Session {
            session_id: ResponseSessionId::new(format!("session-{ordinal}")).expect("session id"),
        },
        ResponseEffectKind::SuspendCapabilitySet => {
            ResponseTarget::CapabilitySet { affected_set_hash }
        }
        ResponseEffectKind::FreezeIssuance => ResponseTarget::Lineage {
            lineage_id: chio_security_types::ports::LineageId::new("lineage-active-response")
                .expect("lineage id"),
        },
    }
}

fn active_response_planned_effect(
    action_id: &ActionId,
    kind: ResponseEffectKind,
    ordinal: u16,
    affected_set_hash: Digest32,
) -> PlannedResponseEffect {
    let contribution_value = serde_json::json!({
        "rawSentinel": format!("must-not-enter-governed-intent-{ordinal}"),
    });
    let contribution_bytes =
        canonical_json_bytes(&contribution_value).expect("canonical contribution");
    let contribution_hash = Digest32::new(*sha256(&contribution_bytes).as_bytes());
    let canonical_contribution =
        CanonicalBody::new(contribution_bytes).expect("bounded canonical contribution");
    let target = active_response_target(kind, ordinal, affected_set_hash);
    let observed_base_version_hash = Digest32::new([ordinal.saturating_add(1) as u8; 32]);
    let spec = ResponseEffectSpec {
        kind,
        target: target.clone(),
        canonical_contribution: canonical_contribution.clone(),
        contribution_hash,
        observed_base_version_hash,
    };
    let commitment = EffectCommitment {
        action_id: action_id.as_str(),
        ordinal,
        spec: &spec,
    };
    let effect_digest = active_response_domain_digest(RESPONSE_EFFECT_ID_DOMAIN, &commitment);
    PlannedResponseEffect {
        effect_id: EffectId::new(format!(
            "response_effect_{}",
            active_response_hex(&effect_digest)
        ))
        .expect("effect id"),
        ordinal,
        kind,
        target,
        canonical_contribution,
        contribution_hash,
        observed_base_version_hash,
    }
}

fn active_response_grant(effect: GovernedResponseEffect) -> ToolGrant {
    make_grant(CHIO_ACTIVE_RESPONSE_SERVER_ID, effect.tool_name())
}

fn correlated_finding_evidence(
    plan_created_at_unix_ms: u64,
    finding_hash: Digest32,
    finding_age_ms: u64,
) -> AuthoritativeCorrelatedFindingEvidence {
    let occurred_at_unix_ms = plan_created_at_unix_ms
        .checked_sub(finding_age_ms)
        .expect("test finding precedes plan");
    let body: CorrelatedFindingReceiptBody = serde_json::from_value(serde_json::json!({
        "header": {
            "schema_version": 1,
            "occurred_at_unix_ms": occurred_at_unix_ms,
            "tenant_id": "tenant-active-response",
            "transition_id": "finding-transition-active-response",
            "prior_receipt_ids": ["event-receipt-active-response"]
        },
        "policy": {
            "policy_version": "policy-version-active-response",
            "policy_hash": vec![0x33_u8; 32]
        },
        "finding_id": "finding-active-response",
        "finding_hash": finding_hash,
        "rule_id": "rule-active-response",
        "rule_version_hash": vec![0x41_u8; 32],
        "group_key_hash": vec![0x42_u8; 32],
        "ordered_event_ids": ["event-active-response"],
        "ordered_evidence_digests": [vec![0x43_u8; 32]],
        "ordered_source_receipt_ids": ["event-receipt-active-response"],
        "first_event_time_unix_ms": occurred_at_unix_ms.saturating_sub(2),
        "last_event_time_unix_ms": occurred_at_unix_ms.saturating_sub(1),
        "lineage_seed": "lineage-active-response"
    }))
    .expect("valid correlated finding receipt body");
    let closed = ActiveDefenseReceiptBody::CorrelatedFinding(body.clone());
    let evidence_id = closed.evidence_id().expect("finding evidence ID");
    AuthoritativeCorrelatedFindingEvidence::from_verified_signed_receipt(evidence_id, body)
        .expect("authoritative correlated finding")
}

fn active_response_fixture(
    concrete_effects: &[ResponseEffectKind],
    declared_effects: Vec<GovernedResponseEffect>,
    granted_effects: &[GovernedResponseEffect],
) -> ActiveResponseFixture {
    active_response_fixture_with_grants_and_approval(
        concrete_effects,
        declared_effects,
        granted_effects
            .iter()
            .copied()
            .map(active_response_grant)
            .collect(),
        ResponseApprovalRequirement::Governed {
            policy_id: RecordId::new("governed-active-response-policy").expect("policy id"),
        },
    )
}

fn active_response_fixture_with_grants_and_approval(
    concrete_effects: &[ResponseEffectKind],
    declared_effects: Vec<GovernedResponseEffect>,
    grants: Vec<ToolGrant>,
    approval_requirement: ResponseApprovalRequirement,
) -> ActiveResponseFixture {
    active_response_fixture_with_grants_approval_and_finding_age(
        concrete_effects,
        declared_effects,
        grants,
        approval_requirement,
        1,
    )
}

fn active_response_fixture_with_grants_approval_and_finding_age(
    concrete_effects: &[ResponseEffectKind],
    declared_effects: Vec<GovernedResponseEffect>,
    grants: Vec<ToolGrant>,
    approval_requirement: ResponseApprovalRequirement,
    finding_age_ms: u64,
) -> ActiveResponseFixture {
    let operator_issuer = make_keypair();
    let mut config = make_config();
    config.keypair = operator_issuer.clone();
    config.policy_hash = "33".repeat(32);
    let mut kernel = make_kernel(config);
    let executor = make_keypair();
    let submitter = make_keypair();
    let submission_authority = make_keypair();
    kernel
        .set_active_response_submission_authority(submission_authority.public_key())
        .expect("active-response submission authority");
    let scope = make_scope(grants);
    let capability = make_capability(&kernel, &executor, scope, 300);
    let runtime = crate::scope_fixed_runtime_for_current_thread(capability.issued_at, Vec::new());
    let capability_hash = crate::threshold_approval::authorization_capability_hash(&capability)
        .expect("capability hash");
    let capability_expires_at_ms = capability
        .expires_at
        .checked_mul(1_000)
        .expect("test capability expiry fits milliseconds");

    let action_id = ActionId::new("action-active-response").expect("action id");
    let tenant_id = TenantId::new("tenant-active-response").expect("tenant id");
    let affected_ids = RecordIdSet::new(vec![
        RecordId::new("affected-a").expect("affected id"),
        RecordId::new("affected-b").expect("affected id"),
    ])
    .expect("sorted affected ids");
    let affected_set_hash = active_response_domain_digest(
        AFFECTED_SET_HASH_DOMAIN,
        &AffectedSetCommitment {
            tenant_id: tenant_id.as_str(),
            affected_ids: affected_ids.as_slice(),
        },
    );
    let effects = PlannedResponseEffects::new(
        concrete_effects
            .iter()
            .copied()
            .enumerate()
            .map(|(ordinal, kind)| {
                active_response_planned_effect(
                    &action_id,
                    kind,
                    u16::try_from(ordinal).expect("effect ordinal"),
                    affected_set_hash,
                )
            })
            .collect(),
    )
    .expect("bounded effects");
    let created_at_unix_ms = capability.issued_at * 1_000;
    let expires_at_unix_ms = (capability.issued_at + 120) * 1_000 + 500;
    let trigger_finding_hash = Digest32::new([0x47; 32]);
    let finding_evidence =
        correlated_finding_evidence(created_at_unix_ms, trigger_finding_hash, finding_age_ms);
    let trigger_finding_receipt_id = finding_evidence.evidence_id().clone();
    let finding_authority = Arc::new(RecordingFindingAuthority::new(finding_evidence));
    kernel
        .set_active_response_finding_authority(finding_authority.clone())
        .expect("active-response finding authority");
    let mut response_plan = ResponsePlan {
        action_id: action_id.clone(),
        trigger_finding_id: RecordId::new("finding-active-response").expect("finding id"),
        trigger_finding_hash,
        trigger_finding_receipt_id,
        tenant_id,
        policy_version: RecordId::new("policy-version-active-response").expect("policy version"),
        policy_hash: Digest32::new([0x33; 32]),
        affected_ids,
        affected_set_hash,
        effects,
        ttl_ms: expires_at_unix_ms - created_at_unix_ms,
        created_at_unix_ms,
        expires_at_unix_ms,
        operator_capability: OperatorCapabilityBinding {
            capability_id: RecordId::new(capability.id.clone()).expect("capability id"),
            capability_digest: active_response_digest_from_hex(&capability_hash),
            expires_at_unix_ms: capability_expires_at_ms,
            executor_subject: RecordId::new(capability.subject.to_hex()).expect("executor subject"),
        },
        approval_requirement,
        submitter: RecordId::new(submitter.public_key().to_hex()).expect("submitter"),
        reason_hash: Digest32::new([0x55; 32]),
        plan_hash: Digest32::new([0; 32]),
    };
    let compact_plan_body = response_plan.authorization_body();
    let canonical_plan_body =
        serde_json::to_value(&compact_plan_body).expect("canonical plan body value");
    let plan_hash = GovernedResponsePlanIntentBody::compute_plan_body_hash(&canonical_plan_body)
        .expect("compact plan hash");
    response_plan.plan_hash = active_response_digest_from_hex(&plan_hash);

    let governed_body = GovernedResponsePlanIntentBody::new(
        CHIO_RESPONSE_PLAN_SCHEMA,
        action_id.as_str(),
        capability.id.clone(),
        capability_hash.clone(),
        capability.expires_at,
        capability.subject.clone(),
        canonical_plan_body,
        plan_hash.clone(),
        serde_json::json!({"affectedSetHash": active_response_hex(&affected_set_hash)}),
        declared_effects,
        response_plan.expires_at_unix_ms / 1_000,
        serde_json::json!({"responsePlanHash": plan_hash.clone()}),
    )
    .expect("governed response plan intent");
    let governed_intent = GovernedTransactionIntent::active_response_plan(governed_body);
    let submission_proof =
        signed_submission_proof(&compact_plan_body, &governed_intent, &submitter);
    let request = ActiveResponseAuthorizationRequest::new(
        capability,
        compact_plan_body.clone(),
        governed_intent,
        submission_proof,
    )
    .expect("active response authorization request");

    ActiveResponseFixture {
        kernel,
        operator_issuer,
        executor,
        submitter,
        submission_authority,
        request,
        capability_hash,
        plan_hash,
        response_plan,
        compact_plan_body,
        finding_authority,
        _runtime: runtime,
    }
}

fn rebuild_request_with_bindings(
    fixture: &ActiveResponseFixture,
    target_binding: serde_json::Value,
    rollback_binding: serde_json::Value,
) -> ActiveResponseAuthorizationRequest {
    let request = &fixture.request;
    let capability = request.operator_capability().clone();
    let plan = request.plan_body().clone();
    let original = request
        .governed_intent()
        .as_active_response_plan()
        .expect("active-response intent");
    let canonical_plan_body = serde_json::to_value(&plan).expect("canonical plan body value");
    let plan_hash = GovernedResponsePlanIntentBody::compute_plan_body_hash(&canonical_plan_body)
        .expect("compact plan hash");
    let governed = GovernedResponsePlanIntentBody::new(
        original.plan_schema(),
        original.plan_id(),
        original.operator_capability_id(),
        original.operator_capability_hash(),
        original.operator_capability_expires_at(),
        original.executor_subject().clone(),
        canonical_plan_body,
        plan_hash,
        target_binding,
        original.ordered_effects().to_vec(),
        original.expires_at(),
        rollback_binding,
    )
    .expect("rebuilt governed response plan");
    let governed_intent = GovernedTransactionIntent::active_response_plan(governed);
    let submission_proof = signed_submission_proof(&plan, &governed_intent, &fixture.submitter);
    ActiveResponseAuthorizationRequest::new(capability, plan, governed_intent, submission_proof)
        .expect("rebuilt active-response request")
}

fn rebuild_request_for_capability(
    fixture: &ActiveResponseFixture,
    capability: CapabilityToken,
) -> ActiveResponseAuthorizationRequest {
    let original = fixture
        .request
        .governed_intent()
        .as_active_response_plan()
        .expect("active-response intent");
    let capability_hash = crate::threshold_approval::authorization_capability_hash(&capability)
        .expect("capability hash");
    let mut plan = fixture.request.plan_body().clone();
    plan.operator_capability = OperatorCapabilityBinding {
        capability_id: RecordId::new(capability.id.clone()).expect("capability id"),
        capability_digest: active_response_digest_from_hex(&capability_hash),
        expires_at_unix_ms: capability
            .expires_at
            .checked_mul(1_000)
            .expect("capability expiry fits milliseconds"),
        executor_subject: RecordId::new(capability.subject.to_hex()).expect("executor subject"),
    };
    let canonical_plan_body = serde_json::to_value(&plan).expect("canonical plan body value");
    let plan_hash = GovernedResponsePlanIntentBody::compute_plan_body_hash(&canonical_plan_body)
        .expect("compact plan hash");
    let governed = GovernedResponsePlanIntentBody::new(
        original.plan_schema(),
        plan.action_id.as_str(),
        capability.id.clone(),
        capability_hash,
        capability.expires_at,
        capability.subject.clone(),
        canonical_plan_body,
        plan_hash.clone(),
        serde_json::json!({
            "affectedSetHash": active_response_hex(&plan.affected_set_hash),
        }),
        original.ordered_effects().to_vec(),
        plan.expires_at_unix_ms / 1_000,
        serde_json::json!({"responsePlanHash": plan_hash}),
    )
    .expect("rebuilt governed response plan");
    let governed_intent = GovernedTransactionIntent::active_response_plan(governed);
    let submission_proof = signed_submission_proof(&plan, &governed_intent, &fixture.submitter);
    ActiveResponseAuthorizationRequest::new(capability, plan, governed_intent, submission_proof)
        .expect("rebuilt active-response request")
}

fn attenuated_operator_capability(
    fixture: &ActiveResponseFixture,
    budget_share_bps: Option<u16>,
    aggregate_invocation_budget: Option<
        chio_core::capability::aggregate_budget::AggregateInvocationBudget,
    >,
) -> CapabilityToken {
    let original = fixture.request.operator_capability();
    let parent_scope_hash = scope_hash(&original.scope).expect("parent scope hash");
    let child_scope_hash = scope_hash(&original.scope).expect("child scope hash");
    let witness =
        compute_attenuation_witness(&original.scope, &original.scope).expect("attenuation witness");
    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: format!(
                    "active-response-attenuated-{}",
                    budget_share_bps.map_or("aggregate".to_string(), |share| share.to_string())
                ),
                issuer: fixture.operator_issuer.public_key(),
                subject: original.subject.clone(),
                scope: original.scope.clone(),
                issued_at: original.issued_at,
                expires_at: original.expires_at,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget,
            },
            caveats: Vec::new(),
            scope_attenuations: Vec::new(),
            attenuation_proof: AttenuationProof {
                parent_scope_hash,
                child_scope_hash,
                normalized_subset_proof: witness,
                aggregate_family_preservation: None,
            },
            budget_share_bps,
        },
        &fixture.operator_issuer,
    )
    .expect("attenuated operator capability")
}
