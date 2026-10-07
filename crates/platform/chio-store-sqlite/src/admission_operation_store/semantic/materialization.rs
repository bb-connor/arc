use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticPrerequisiteRevocationFenceV1 {
    scope: RecoveryScopeV1,
    fact: SemanticFactId,
    resource: ProviderResourceId,
    generation: SafeInteger,
    revoked_at_unix_ms: SafeInteger,
}

fn revocation_fence(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    fact: &SemanticFactId,
    resource: &ProviderResourceId,
) -> Result<Option<SemanticPrerequisiteRevocationFenceV1>, AdmissionOperationStoreError> {
    let key = format!("{}:revocation", fact_identity_key(scope, fact, resource)?);
    let state = load::<SemanticPrerequisiteRevocationFenceV1>(tx, &key)?;
    if state.as_ref().is_some_and(|state| {
        state.scope != *scope
            || state.fact != *fact
            || state.resource != *resource
            || state.generation.get() == 0
            || state.revoked_at_unix_ms.get() == 0
    }) {
        return Err(refused("prerequisite revocation fence changed"));
    }
    Ok(state)
}

fn fact_key(body: &SemanticPrerequisiteV1) -> Result<String, AdmissionOperationStoreError> {
    fact_identity_key(&body.scope, &body.fact, &body.resource)
}
fn fact_identity_key(
    scope: &RecoveryScopeV1,
    fact: &SemanticFactId,
    resource: &ProviderResourceId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "semantic-fact:{}:{}",
        scope_key(scope)?,
        sha256_hex(&protected::encode(&(fact, resource))?)
    ))
}
fn producer_tx(
    tx: &Transaction<'_>,
    producer: &OperationId,
    scope: &RecoveryScopeV1,
) -> Result<NativeSemanticCaptureRecordV1, AdmissionOperationStoreError> {
    let id = AdmissionOperationId::from_persisted(producer.as_str()).map_err(refused)?;
    let operation =
        load_operation_for_participant_tx(tx, &id)?.ok_or_else(|| refused("producer absent"))?;
    if operation.state() != AdmissionOperationState::Completed {
        return Err(refused("producer incomplete"));
    }
    let captured: NativeSemanticCaptureRecordV1 = load(tx, &capture_key(producer.as_str()))?
        .ok_or_else(|| refused("producer not semantic"))?;
    if captured.invocation.action.scope != *scope {
        return Err(refused("producer scope"));
    }
    Ok(captured)
}
fn producer_output(
    tx: &Transaction<'_>,
    producer: &OperationId,
) -> Result<SemanticPayloadV1, AdmissionOperationStoreError> {
    let outcome = crate::tool_outcome_store::load_outcome_connection(tx, producer.as_str())
        .map_err(refused)?
        .ok_or_else(|| refused("producer outcome"))?;
    let blob = crate::tool_outcome_store::load_resolved_blob_connection(tx, &outcome)
        .map_err(refused)?
        .ok_or_else(|| refused("producer bytes"))?;
    chio_core::recovery::decode_contract(blob.bytes()).map_err(refused)
}
pub(super) fn materialized_influence(
    tx: &Transaction<'_>,
    invocation: &SemanticInvocationV1,
    binding: &NativeSecurityAuthorityBindingV1,
    context: &SecurityInvocationContext,
    contract_external: bool,
    model: Option<&chio_core::capability::scope::ModelMetadata>,
    budget: &mut VerificationBudget,
) -> Result<(CanonicalPayloadDigest, bool), AdmissionOperationStoreError> {
    let observed = super::super::security_participant_state::knowledge::observed_influence(
        tx,
        binding.security_authority_id().as_str(),
        &recovery_flow_key(context),
    )?;
    budget
        .charge(
            u32::try_from(super::super::security_participant_state::knowledge::head(
                tx,
                binding.security_authority_id().as_str(),
            )?)
            .map_err(refused)?,
        )
        .map_err(refused)?;
    let action = &invocation.action;
    let plan: SemanticPlanV1 =
        load(tx, &plan_key(&action.scope, &action.plan)?)?.ok_or_else(|| refused("plan absent"))?;
    let step = plan
        .steps
        .as_slice()
        .iter()
        .find(|step| step.step == action.step)
        .ok_or_else(|| refused("step absent"))?;
    budget.charge(32).map_err(refused)?;
    let mut inherited = Vec::new();
    let mut external = false;
    for input in step.inputs.as_slice() {
        budget.charge(32).map_err(refused)?;
        if let SemanticPlanInputV1::FutureOutput { step } = input {
            let parent: NativeSemanticCaptureRecordV1 =
                load(tx, &step_key(&action.scope, &action.plan, step)?)?
                    .ok_or_else(|| refused("parent absent"))?;
            external |= parent.invocation.action.externally_influenced;
            inherited.push(parent.invocation.action.influence);
        }
    }
    if let Some(transformation) = &invocation.transformation {
        let parent = producer_tx(tx, &transformation.body().producer, &action.scope)?;
        let base = parent.invocation.action.influence;
        return Ok((
            knowledge_semantic_influence(
                semantic_observed_influence(
                    base,
                    model
                        .map(semantic_content_digest)
                        .transpose()
                        .map_err(refused)?,
                )
                .map_err(refused)?,
                observed.as_ref(),
            )
            .map_err(refused)?,
            external
                || parent.invocation.action.externally_influenced
                || model.is_some()
                || observed.is_some(),
        ));
    }
    let digest = if inherited.is_empty() {
        semantic_content_digest(&(&action.inputs, contract_external))
    } else {
        semantic_content_digest(&(&action.inputs, contract_external || external, inherited))
    }
    .map_err(refused)?;
    Ok((
        knowledge_semantic_influence(
            semantic_observed_influence(
                digest,
                model
                    .map(semantic_content_digest)
                    .transpose()
                    .map_err(refused)?,
            )
            .map_err(refused)?,
            observed.as_ref(),
        )
        .map_err(refused)?,
        external || model.is_some() || observed.is_some(),
    ))
}
pub(super) fn verify_materialized_plan(
    tx: &Transaction<'_>,
    invocation: &SemanticInvocationV1,
    budget: &mut VerificationBudget,
) -> Result<(), AdmissionOperationStoreError> {
    let action = &invocation.action;
    let plan: SemanticPlanV1 = load(tx, &plan_key(&action.scope, &action.plan)?)?
        .ok_or_else(|| refused("plan not accepted"))?;
    if plan.registry != action.registry
        || semantic_plan_digest(&plan).map_err(refused)? != action.plan
    {
        return Err(refused("plan changed"));
    }
    if plan.steps.as_slice().len() > 8 {
        return Err(refused("fresh semantic capture exceeds the step ceiling"));
    }
    // The initial plan profile serializes unresolved effects. Inspect only
    // its bounded step inventory, under the same transaction as capture.
    for candidate in plan.steps.as_slice() {
        budget.charge(32).map_err(refused)?;
        if candidate.step == action.step {
            continue;
        }
        let Some(prior) = load::<NativeSemanticCaptureRecordV1>(
            tx,
            &step_key(&action.scope, &action.plan, &candidate.step)?,
        )?
        else {
            continue;
        };
        if prior.invocation.action.scope != action.scope
            || prior.invocation.action.step != candidate.step
        {
            return Err(refused("plan participant identity changed"));
        }
        if prior.contract.kind != SemanticOperationKindV1::IssueWrite {
            continue;
        }
        let operation =
            AdmissionOperationId::from_persisted(prior.operation_id.as_str()).map_err(refused)?;
        let operation = load_operation_for_participant_tx(tx, &operation)?
            .ok_or_else(|| refused("plan participant operation absent"))?;
        if !matches!(
            operation.state(),
            AdmissionOperationState::Completed
                | AdmissionOperationState::DeniedAfterDelivery
                | AdmissionOperationState::CompensatedBeforeDispatch
                | AdmissionOperationState::NotAcceptedAfterDispatchCommit
        ) {
            return Err(refused("plan has an unresolved effectful step"));
        }
    }
    let step = plan
        .steps
        .as_slice()
        .iter()
        .find(|step| step.step == action.step)
        .ok_or_else(|| refused("step absent"))?;
    if step.operation != action.operation
        || step.destination != action.destination
        || step.output != action.output
        || step.inputs.as_slice().len() != action.inputs.as_slice().len()
    {
        return Err(refused("unaccepted materialization"));
    }
    let mut producers = Vec::new();
    for dependency in step.dependencies.as_slice() {
        budget.charge(32).map_err(refused)?;
        let prior: NativeSemanticCaptureRecordV1 =
            load(tx, &step_key(&action.scope, &action.plan, dependency)?)?
                .ok_or_else(|| refused("dependency not captured"))?;
        producer_tx(tx, &prior.operation_id, &action.scope)?;
        if prior.invocation.action.plan != action.plan
            || prior.invocation.action.step != *dependency
        {
            return Err(refused("dependency plan changed"));
        }
        producers.push(prior.operation_id);
    }
    for (symbolic, material) in step.inputs.as_slice().iter().zip(action.inputs.as_slice()) {
        budget.charge(32).map_err(refused)?;
        match symbolic {
            SemanticPlanInputV1::Exact {
                resource,
                version,
                material: content,
            } => {
                if resource != &material.resource
                    || version != &material.version
                    || content != &material.content
                {
                    return Err(refused("input version changed"));
                }
            }
            SemanticPlanInputV1::FutureOutput { step } => {
                let prior: NativeSemanticCaptureRecordV1 =
                    load(tx, &step_key(&action.scope, &action.plan, step)?)?
                        .ok_or_else(|| refused("future input not materialized"))?;
                producer_tx(tx, &prior.operation_id, &action.scope)?;
                if prior.invocation.action.output != SemanticOutputDispositionV1::ReturnValue {
                    return Err(refused("withheld producer output"));
                }
                let bytes = producer_output(tx, &prior.operation_id)?;
                let digest = semantic_content_digest(&bytes).map_err(refused)?;
                let destination = prior
                    .route
                    .destinations
                    .as_slice()
                    .iter()
                    .find(|dest| dest.destination == prior.invocation.action.destination)
                    .ok_or_else(|| refused("producer destination"))?;
                if material.content != digest
                    || material.version.as_bytes() != digest.as_bytes()
                    || material.resource != destination.resource
                {
                    return Err(refused("future bytes changed"));
                }
            }
        }
    }
    if let Some(proof) = &invocation.transformation {
        let body = proof.body();
        // The first field-projection profile consumes one exact materialized
        // producer output. Additional or unrelated inputs need a new profile.
        let [SemanticPlanInputV1::FutureOutput {
            step: producer_step,
        }] = step.inputs.as_slice()
        else {
            return Err(refused("unsupported transform input profile"));
        };
        let declared: NativeSemanticCaptureRecordV1 =
            load(tx, &step_key(&action.scope, &action.plan, producer_step)?)?
                .ok_or_else(|| refused("transform input absent"))?;
        if declared.operation_id != body.producer
            || action.inputs.as_slice()[0].content != body.output
        {
            return Err(refused("transform input provenance"));
        }
        if !producers.contains(&body.producer) {
            return Err(refused("transform producer is not a declared prerequisite"));
        }
        let producer = producer_tx(tx, &body.producer, &action.scope)?;
        let producer_action = &producer.invocation.action;
        if producer.contract.kind != SemanticOperationKindV1::FieldProjection
            || producer_action.output != SemanticOutputDispositionV1::ReturnValue
            || semantic_action_digest(producer_action).map_err(refused)? != body.producer_action
            || producer_action.inputs != body.inputs
            || producer.contract.implementation != body.implementation
            || semantic_content_digest(&producer.contract.projection_fields).map_err(refused)?
                != body.configuration
            || producer.contract.output_schema != body.output_schema
            || producer_action.source_label != body.output_label
        {
            return Err(refused("transformation provenance"));
        }
        let output = project_semantic_fields(
            &producer.invocation.payload,
            producer.contract.projection_fields.as_slice(),
            budget,
        )
        .map_err(refused)?;
        if producer_output(tx, &body.producer)? != output
            || invocation.payload != output
            || semantic_content_digest(&output).map_err(refused)? != body.output
        {
            return Err(refused("transformation bytes"));
        }
    } else if !action
        .inputs
        .as_slice()
        .iter()
        .any(|input| input.content == action.payload)
    {
        // Unknown or future bytes cannot be replaced by symbolic identity.
        return Err(refused("unmaterialized input"));
    }
    for prerequisite in invocation.prerequisites.as_slice() {
        budget.charge(32).map_err(refused)?;
        if !producers.contains(&prerequisite.body().producer) {
            return Err(refused("fact producer is not a declared prerequisite"));
        }
    }
    Ok(())
}

pub(super) fn step_key(
    scope: &RecoveryScopeV1,
    _plan: &PlanDigest,
    step: &StepId,
) -> Result<String, AdmissionOperationStoreError> {
    // Stable logical step identity crosses plan revisions. A new plan digest
    // cannot reopen an original captured effect, even through a direct kernel call.
    Ok(format!(
        "semantic-step:{}:{}",
        scope_key(scope)?,
        step.as_str()
    ))
}
pub(super) fn verify_current_prerequisites(
    tx: &Transaction<'_>,
    invocation: &SemanticInvocationV1,
    now: u64,
    budget: &mut VerificationBudget,
) -> Result<(), AdmissionOperationStoreError> {
    for signed in invocation.prerequisites.as_slice() {
        budget.charge(32).map_err(refused)?;
        let body = signed.body();
        let producer = producer_tx(tx, &body.producer, &body.scope)?;
        if !producer
            .invocation
            .action
            .inputs
            .as_slice()
            .iter()
            .any(|input| {
                input.resource == body.resource
                    && input.version == body.version
                    && input.content == body.material
            })
        {
            return Err(refused("prerequisite material"));
        }
        if body.kind == SemanticPrerequisiteKindV1::HistoricalFact {
            continue;
        }
        if load::<bool>(tx, &format!("{}:revoked", fact_key(body)?))?.unwrap_or(false) {
            return Err(refused("prerequisite revoked"));
        }
        let current: SignedSemanticPrerequisiteV1 =
            load(tx, &fact_key(body)?)?.ok_or_else(|| refused("current prerequisite absent"))?;
        if current != *signed || now >= current.body().valid_until_unix_ms.get() {
            return Err(refused("prerequisite no longer current"));
        }
        if body.kind == SemanticPrerequisiteKindV1::HeldReservation {
            let lease = body.lease.as_ref().ok_or_else(|| refused("lease absent"))?;
            if load::<OperationId>(
                tx,
                &format!(
                    "semantic-lease-spent:{}:{}",
                    scope_key(&body.scope)?,
                    lease.as_str()
                ),
            )?
            .is_some()
            {
                return Err(refused("lease spent"));
            }
        }
    }
    Ok(())
}
pub(super) fn verify_dispatch_prerequisites(
    tx: &Transaction<'_>,
    record: &NativeSemanticCaptureRecordV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    for signed in record.invocation.prerequisites.as_slice() {
        let body = signed.body();
        if body.kind == SemanticPrerequisiteKindV1::HistoricalFact {
            continue;
        }
        let current: SignedSemanticPrerequisiteV1 =
            load(tx, &fact_key(body)?)?.ok_or_else(|| refused("current prerequisite absent"))?;
        if current != *signed
            || now >= body.valid_until_unix_ms.get()
            || load::<bool>(tx, &format!("{}:revoked", fact_key(body)?))?.unwrap_or(false)
        {
            return Err(refused("dispatch prerequisite changed"));
        }
        if let Some(lease) = &body.lease {
            let owner: OperationId = load(
                tx,
                &format!(
                    "semantic-lease-spent:{}:{}",
                    scope_key(&body.scope)?,
                    lease.as_str()
                ),
            )?
            .ok_or_else(|| refused("held consumption absent"))?;
            if owner != record.operation_id {
                return Err(refused("held owner changed"));
            }
        }
    }
    Ok(())
}

impl SqliteAdmissionOperationStore {
    /// The configured reservation/predicate authority reports current state.
    /// Historical receipts alone cannot populate a held reservation implicitly.
    pub fn install_semantic_prerequisite(
        &self,
        signed: &SignedSemanticPrerequisiteV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, None)?;
        let body = signed.body();
        let installed = installation(&tx, &body.scope)?;
        let key = semantic_key_digest(signed.authority_key()).map_err(refused)?;
        if !signed.verify_signature().map_err(refused)?
            || !installed
                .deployment
                .body()
                .routes
                .as_slice()
                .iter()
                .any(|route| route.prerequisite_key == key)
        {
            return Err(refused("prerequisite root"));
        }
        producer_tx(&tx, &body.producer, &body.scope)?;
        let now = schema::observe_authority_time(&tx)?;
        if body.issued_at_unix_ms.get() > now || now >= body.valid_until_unix_ms.get() {
            return Err(refused("prerequisite time"));
        }
        let key = fact_key(body)?;
        if let Some(prior) = load::<SignedSemanticPrerequisiteV1>(&tx, &key)? {
            // Reinstalling an old signature cannot clear a revocation or spend.
            if prior == *signed {
                return self.commit_write(tx);
            }
            if prior.body().issued_at_unix_ms >= body.issued_at_unix_ms {
                return Err(refused("predicate regression"));
            }
        }
        if load::<bool>(&tx, &format!("{key}:revoked"))?.unwrap_or(false) {
            return Err(refused("revoked prerequisite needs explicit reinstatement"));
        }
        if revocation_fence(&tx, &body.scope, &body.fact, &body.resource)?
            .is_some_and(|state| body.issued_at_unix_ms <= state.revoked_at_unix_ms)
        {
            return Err(refused("prerequisite predates revocation fence"));
        }
        save(
            &tx,
            &self.serving_owner,
            &body.scope,
            &key,
            "command",
            signed,
        )?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)
    }
    pub fn revoke_semantic_prerequisite(
        &self,
        scope: &RecoveryScopeV1,
        fact: &SemanticFactId,
        resource: &ProviderResourceId,
    ) -> Result<SafeInteger, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, None)?;
        installation(&tx, scope)?;
        let key = fact_identity_key(scope, fact, resource)?;
        let previous = revocation_fence(&tx, scope, fact, resource)?;
        let generation = previous
            .as_ref()
            .map_or(SafeInteger::ZERO, |state| state.generation)
            .checked_add(SafeInteger::new(1).map_err(refused)?)
            .map_err(refused)?;
        let revoked_at_unix_ms =
            SafeInteger::new(schema::observe_authority_time(&tx)?).map_err(refused)?;
        if previous
            .as_ref()
            .is_some_and(|state| state.revoked_at_unix_ms > revoked_at_unix_ms)
        {
            return Err(refused("revocation time regressed"));
        }
        let state = SemanticPrerequisiteRevocationFenceV1 {
            scope: scope.clone(),
            fact: fact.clone(),
            resource: resource.clone(),
            generation,
            revoked_at_unix_ms,
        };
        save(
            &tx,
            &self.serving_owner,
            scope,
            &format!("{key}:revocation"),
            "command",
            &state,
        )?;
        save(
            &tx,
            &self.serving_owner,
            scope,
            &format!("{key}:revoked"),
            "command",
            &true,
        )?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)?;
        Ok(generation)
    }

    /// Explicitly restore one current predicate under a freshly selected
    /// maintenance actor and exact revocation generation.
    pub fn reinstate_semantic_prerequisite(
        &self,
        actor: &AuthenticatedRecoveryActor,
        signed: &SignedSemanticPrerequisiteV1,
        expected_generation: SafeInteger,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let body = signed.body();
        if actor.permission() != RecoveryPermission::Maintain
            || actor.scope() != &body.scope
            || expected_generation.get() == 0
            || body.kind == SemanticPrerequisiteKindV1::HistoricalFact
        {
            return Err(refused("prerequisite reinstatement authority"));
        }
        let mut connection = self.connection()?;
        super::super::recovery::require_intake_headroom(&connection)?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let profile = protected::deployment_tx(&tx, actor.scope())?;
        super::super::recovery::verify_actor(&tx, actor, &profile, now)?;
        let installed = installation(&tx, actor.scope())?;
        let registry = installed.compile()?;
        body.validate().map_err(refused)?;
        let signer = semantic_key_digest(signed.authority_key()).map_err(refused)?;
        if !signed.verify_signature().map_err(refused)? {
            return Err(refused("prerequisite reinstatement signature"));
        }
        let mut budget = VerificationBudget::new(4096).map_err(refused)?;
        let mut selected = false;
        for route in registry.deployment().routes.as_slice() {
            budget.charge(1).map_err(refused)?;
            if route.prerequisite_key != signer {
                continue;
            }
            let (_, contract) = registry
                .resolve(route.server.as_str(), route.tool.as_str())
                .map_err(refused)?;
            for requirement in contract.prerequisites.as_slice() {
                budget.charge(1).map_err(refused)?;
                selected |= requirement.fact == body.fact
                    && requirement.kind == body.kind
                    && requirement.resource == body.resource;
            }
        }
        if !selected {
            return Err(refused("prerequisite reinstatement selected signer"));
        }
        let revoked = revocation_fence(&tx, &body.scope, &body.fact, &body.resource)?
            .ok_or_else(|| refused("prerequisite reinstatement fence absent"))?;
        if revoked.generation != expected_generation
            || body.issued_at_unix_ms <= revoked.revoked_at_unix_ms
            || body.issued_at_unix_ms.get() > now
            || now >= body.valid_until_unix_ms.get()
        {
            return Err(refused("prerequisite reinstatement generation or time"));
        }
        let producer = producer_tx(&tx, &body.producer, &body.scope)?;
        if !producer
            .invocation
            .action
            .inputs
            .as_slice()
            .iter()
            .any(|input| {
                input.resource == body.resource
                    && input.version == body.version
                    && input.content == body.material
            })
        {
            return Err(refused("prerequisite reinstatement material"));
        }
        if let Some(lease) = &body.lease {
            if load::<OperationId>(
                &tx,
                &format!(
                    "semantic-lease-spent:{}:{}",
                    scope_key(&body.scope)?,
                    lease.as_str()
                ),
            )?
            .is_some()
            {
                return Err(refused("prerequisite reinstatement lease spent"));
            }
        }
        let producer_id =
            AdmissionOperationId::from_persisted(body.producer.as_str()).map_err(refused)?;
        let producer_operation = load_operation_for_participant_tx(&tx, &producer_id)?
            .ok_or_else(|| refused("prerequisite reinstatement producer absent"))?;
        let producer_original =
            retained_request::load_retained_request_tx(&tx, &producer_operation)?
                .ok_or_else(|| refused("prerequisite reinstatement original absent"))?;
        let origin = output::authenticated_native_output_influence(
            &tx,
            &producer_operation,
            &producer_original,
            &producer.native_authority,
        )?
        .ok_or_else(|| refused("prerequisite reinstatement origin absent"))?;
        let label = super::super::knowledge::source(
            &tx,
            &profile.native_authority,
            &profile.security_context,
        )?
        .join_restrictions(origin.output_label())
        .map_err(refused)?;
        let assignment = profile
            .actors
            .as_slice()
            .iter()
            .find(|assignment| {
                assignment.subject == actor.capability().subject
                    && assignment.principal == *actor.principal()
                    && assignment
                        .permissions
                        .as_slice()
                        .contains(&RecoveryPermission::Maintain)
            })
            .ok_or_else(|| refused("prerequisite reinstatement audience"))?;
        if matches!(
            assignment.preview_clearance,
            chio_security_types::InformationLabel::Top
        ) || !label.flows_to(&assignment.preview_clearance)
        {
            return Err(refused("prerequisite reinstatement audience"));
        }
        let key = fact_key(body)?;
        let is_revoked = load::<bool>(&tx, &format!("{key}:revoked"))?
            .ok_or_else(|| refused("prerequisite reinstatement disposition absent"))?;
        let current = load::<SignedSemanticPrerequisiteV1>(&tx, &key)?;
        let later = schema::authority_validation_time(&tx, now)?;
        super::super::recovery::verify_actor(&tx, actor, &profile, later)?;
        if later >= body.valid_until_unix_ms.get() {
            return Err(refused("prerequisite reinstatement expired"));
        }
        if !is_revoked {
            if current.as_ref() != Some(signed) {
                return Err(refused("prerequisite reinstatement identity reused"));
            }
            return tx.commit().map_err(sqlite_error);
        }
        if current
            .as_ref()
            .is_some_and(|prior| prior.body().issued_at_unix_ms >= body.issued_at_unix_ms)
        {
            return Err(refused("prerequisite reinstatement regressed"));
        }
        save(
            &tx,
            &self.serving_owner,
            &body.scope,
            &key,
            "command",
            signed,
        )?;
        save(
            &tx,
            &self.serving_owner,
            &body.scope,
            &format!("{key}:revoked"),
            "command",
            &false,
        )?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)
    }
}
