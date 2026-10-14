//! Retained framing sources are readonly evidence of the original Input basis.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FramingSources {
    plan: SourceRecord<SemanticPlanV1>,
    parents: BoundedList<SourceRecord<NativeSemanticCaptureRecordV1>, 16>,
    transformed: Option<SourceRecord<NativeSemanticCaptureRecordV1>>,
}

impl FramingSources {
    pub(super) fn load(
        tx: &Connection,
        invocation: &SemanticInvocationV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let action = &invocation.action;
        let plan: SourceRecord<SemanticPlanV1> = SourceRecord::load(
            tx,
            &plan_key(&action.scope, &action.plan)?,
            &action.scope,
            "command",
        )?;
        let step = plan
            .body
            .steps
            .as_slice()
            .iter()
            .find(|step| step.step == action.step)
            .ok_or_else(|| refused("semantic input retained step absent"))?;
        let mut parents = Vec::new();
        for input in step.inputs.as_slice() {
            if let SemanticPlanInputV1::FutureOutput { step } = input {
                parents.push(SourceRecord::load(
                    tx,
                    &step_key(&action.scope, &action.plan, step)?,
                    &action.scope,
                    "command",
                )?);
            }
        }
        let transformed = invocation
            .transformation
            .as_ref()
            .map(|proof| {
                SourceRecord::load(
                    tx,
                    &capture_key(proof.body().producer.as_str()),
                    &action.scope,
                    "command",
                )
            })
            .transpose()?;
        Ok(Self {
            plan,
            parents: BoundedList::new(parents).map_err(refused)?,
            transformed,
        })
    }

    pub(super) fn validate_at_cut(
        &self,
        tx: &Connection,
        invocation: &SemanticInvocationV1,
        cut: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let action = &invocation.action;
        self.plan.validate_at_cut(
            tx,
            &plan_key(&action.scope, &action.plan)?,
            &action.scope,
            "command",
            cut,
        )?;
        if self.plan.body.registry != action.registry
            || semantic_plan_digest(&self.plan.body).map_err(refused)? != action.plan
        {
            return Err(refused("semantic input retained plan changed"));
        }
        let mut budget = VerificationBudget::new(4096).map_err(refused)?;
        validate_semantic_plan(&self.plan.body, &mut budget).map_err(refused)?;
        let step = self
            .plan
            .body
            .steps
            .as_slice()
            .iter()
            .find(|step| step.step == action.step)
            .ok_or_else(|| refused("semantic input historical step absent"))?;
        let future: Vec<_> = step
            .inputs
            .as_slice()
            .iter()
            .filter_map(|input| match input {
                SemanticPlanInputV1::FutureOutput { step } => Some(step),
                SemanticPlanInputV1::Exact { .. } => None,
            })
            .collect();
        if future.len() != self.parents.as_slice().len() {
            return Err(refused(
                "semantic input historical parent inventory changed",
            ));
        }
        for (step, parent) in future.into_iter().zip(self.parents.as_slice()) {
            parent.validate_at_cut(
                tx,
                &step_key(&action.scope, &action.plan, step)?,
                &action.scope,
                "command",
                cut,
            )?;
            if parent.body.invocation.action.scope != action.scope
                || parent.body.invocation.action.plan != action.plan
                || parent.body.invocation.action.step != *step
            {
                return Err(refused("semantic input historical parent binding changed"));
            }
        }
        match (&invocation.transformation, &self.transformed) {
            (Some(proof), Some(parent)) => {
                parent.validate_at_cut(
                    tx,
                    &capture_key(proof.body().producer.as_str()),
                    &action.scope,
                    "command",
                    cut,
                )?;
                if parent.body.operation_id != proof.body().producer
                    || parent.body.invocation.action.scope != action.scope
                {
                    return Err(refused("semantic input historical transformation changed"));
                }
            }
            (None, None) => {}
            _ => return Err(refused("semantic input historical transformation absent")),
        }
        Ok(())
    }

    pub(super) fn influence_basis(
        &self,
        invocation: &SemanticInvocationV1,
        request: &ToolCallRequest,
        contract_external: bool,
        prior: Option<&ArtifactInfluenceV1>,
    ) -> Result<(CanonicalPayloadDigest, bool, bool), AdmissionOperationStoreError> {
        let inherited: Vec<_> = self
            .parents
            .as_slice()
            .iter()
            .map(|parent| parent.body.invocation.action.influence)
            .collect();
        let parent_external = self.parents.as_slice().iter().any(|parent| {
            parent.body.invocation.action.externally_influenced
                || parent.body.contract.external_influence
        });
        let base = if let Some(parent) = &self.transformed {
            parent.body.invocation.action.influence
        } else if inherited.is_empty() {
            semantic_content_digest(&(&invocation.action.inputs, contract_external))
                .map_err(refused)?
        } else {
            semantic_content_digest(&(
                &invocation.action.inputs,
                contract_external || parent_external,
                inherited,
            ))
            .map_err(refused)?
        };
        let model = request
            .model_metadata
            .as_ref()
            .map(semantic_content_digest)
            .transpose()
            .map_err(refused)?;
        let digest = knowledge_semantic_influence(
            semantic_observed_influence(base, model).map_err(refused)?,
            prior,
        )
        .map_err(refused)?;
        let external = contract_external
            || parent_external
            || self.transformed.as_ref().is_some_and(|parent| {
                parent.body.invocation.action.externally_influenced
                    || parent.body.contract.external_influence
            })
            || request.model_metadata.is_some()
            || prior.is_some_and(|influence| influence.externally_influenced);
        let unknown = prior.is_some_and(|influence| influence.unknown)
            || self
                .parents
                .as_slice()
                .iter()
                .any(|parent| captured_source_incomplete(&parent.body))
            || self
                .transformed
                .as_ref()
                .is_some_and(|parent| captured_source_incomplete(&parent.body));
        Ok((digest, external, unknown))
    }
}

fn captured_source_incomplete(record: &NativeSemanticCaptureRecordV1) -> bool {
    (record.invocation.action.output == SemanticOutputDispositionV1::Withhold
        && record.contract.withheld_status.is_none())
        || record.route.annotators.as_slice().iter().any(|authority| {
            record
                .invocation
                .action
                .inputs
                .as_slice()
                .iter()
                .any(|input| {
                    !record
                        .invocation
                        .annotations
                        .as_slice()
                        .iter()
                        .any(|answer| {
                            semantic_key_digest(answer.authority_key())
                                .is_ok_and(|key| key == authority.key)
                                && answer.body().input == *input
                        })
                })
        })
}
