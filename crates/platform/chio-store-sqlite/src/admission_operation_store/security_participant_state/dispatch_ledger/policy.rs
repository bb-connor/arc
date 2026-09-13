//! Bind retained policy material to the physical operation and observed state.
//! This validates storage provenance, not classifier or manifest trust roots.
use super::*;
use chio_security_types::ports::{Digest32, FlowJoinRequest, FlowStateSnapshot};

const POLICY_SCHEMA: &str = "chio.native-flow-dispatch-policy.v1";
const DECLASSIFIED_POLICY_SCHEMA: &str = "chio.native-flow-dispatch-policy.v2";
const MAX_POLICY_BYTES: usize = 256 * 1024;

#[derive(Deserialize)]
pub(super) struct Policy {
    schema: String,
    pub inputs: Inputs,
    pub decision: Decision,
}

#[derive(Deserialize)]
pub(super) struct Inputs {
    operation_id: AdmissionOperationId,
    operation_version: u64,
    retained_request_digest: AdmissionDigest,
    live_request_digest: Digest32,
    pub native_authority: NativeSecurityAuthorityBindingV1,
    pub observation: FlowStateSnapshot,
    pub observed_at_unix_ms: u64,
    #[serde(deserialize_with = "required_option")]
    stored_context_generation: Option<u64>,
    prepared_at_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub declassification:
        Option<chio_kernel::admission_operation::NativeSecurityDeclassificationGrantV1>,
}

#[derive(Deserialize)]
pub(super) struct Decision {
    request_hash: Digest32,
    pub effective_egress: bool,
    taint_transition: FlowJoinRequest,
    #[serde(deserialize_with = "required_option")]
    pub egress_expires_at_unix_ms: Option<u64>,
    declassification: bool,
}

fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

pub(super) fn decode(
    bytes: &[u8],
) -> Result<(serde_json::Value, Policy), AdmissionOperationStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
        return Err(invalid("native dispatch policy exceeds its byte bound"));
    }
    // Retain every policy field, including those owned by the policy evaluator.
    // The typed view below validates only the storage-boundary contract.
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(invalid)?;
    if canonical_json_bytes(&value).map_err(invalid)? != bytes {
        return Err(invalid("native dispatch policy is not canonical JSON"));
    }
    let policy: Policy = serde_json::from_slice(bytes).map_err(invalid)?;
    let declassified = policy.inputs.declassification.is_some();
    if policy.schema
        != if declassified {
            DECLASSIFIED_POLICY_SCHEMA
        } else {
            POLICY_SCHEMA
        }
        || policy.decision.declassification != declassified
        || (declassified && !policy.decision.effective_egress)
    {
        return Err(invalid(
            "native dispatch policy schema or declassification is unsupported",
        ));
    }
    Ok((value, policy))
}

impl Policy {
    pub(super) fn validate_binding(
        &self,
        operation: &AdmissionOperationV1,
        original: &chio_kernel::admission_operation::RetainedToolAdmissionRequestV1,
        context: &chio_kernel::SecurityInvocationContext,
        live_digest: &AdmissionDigest,
    ) -> Result<(), AdmissionOperationStoreError> {
        let input = &self.inputs;
        let state = &input.observation;
        original.validate_native_security_authority(&input.native_authority)?;
        original.validate_native_security_context(context)?;
        if input.operation_id != *operation.binding().operation_id()
            || input.operation_version != operation.version()
            || input.retained_request_digest.as_str() != sha256_hex(original.canonical_bytes())
            || hex::encode(input.live_request_digest.as_bytes()) != live_digest.as_str()
            || hex::encode(self.decision.request_hash.as_bytes())
                != operation.binding().action_parameter_hash().as_str()
            || input.stored_context_generation != Some(state.context_generation)
            || context.as_v1().flow_state_generation() != Some(state.context_generation)
            || &state.key.tenant_id != context.as_v1().tenant_id()
            || &state.key.principal_id != context.as_v1().principal_id()
            || &state.key.lineage_id != context.as_v1().lineage_root_id()
            || &state.key.session_id != context.as_v1().session_id()
            || &state.key.isolation_epoch_id != context.as_v1().isolation_epoch_id()
            || self.decision.effective_egress != self.decision.egress_expires_at_unix_ms.is_some()
        {
            return Err(invalid(
                "native dispatch policy differs from original custody",
            ));
        }
        let taint = &self.decision.taint_transition;
        if taint.key != state.key
            || !taint.principal_join.flows_to(&state.principal_label)
            || !taint.lineage_join.flows_to(&state.lineage_label)
            || !taint.session_join.flows_to(&state.session_label)
        {
            return Err(invalid(
                "native dispatch policy exceeds recorded input taint",
            ));
        }
        if let Some(grant) = &input.declassification {
            let request = original.request_for_revalidation();
            let body = &grant.body;
            let source = state
                .principal_label
                .join_restrictions(&state.lineage_label)
                .and_then(|label| label.join_restrictions(&state.session_label))
                .map_err(invalid)?;
            if body.capability_id().as_str() != request.capability.id
                || body.agent_id().as_str() != request.agent_id
                || body.destination_id().as_str() != request.server_id
                || body.tool_name().as_str() != request.tool_name
                || body.tenant_id() != &state.key.tenant_id
                || body.subject_id() != &state.key.principal_id
                || body.session_id() != &state.key.session_id
                || body.request_hash() != self.decision.request_hash
                || body.source_label_hash().as_bytes()
                    != chio_core::hashing::sha256(&canonical_json_bytes(&source).map_err(invalid)?)
                        .as_bytes()
            {
                return Err(invalid(
                    "native declassification policy differs from original source and request",
                ));
            }
        }
        for time in [
            input.observed_at_unix_ms,
            input.prepared_at_unix_ms,
            input.valid_until_unix_ms,
        ] {
            super::super::super::schema::validate_trusted_time(
                time,
                "native dispatch policy time",
            )?;
        }
        if input.prepared_at_unix_ms < input.observed_at_unix_ms
            || input.valid_until_unix_ms <= input.prepared_at_unix_ms
            || self
                .decision
                .egress_expires_at_unix_ms
                .is_some_and(|expiry| expiry != input.valid_until_unix_ms)
        {
            return Err(invalid("native dispatch policy has inconsistent deadlines"));
        }
        Ok(())
    }

    pub(super) fn validate_current(
        &self,
        connection: &Transaction<'_>,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.validate_at(now)?;
        let (snapshot, generation) = crate::security_state::observe_native_flow_state(
            connection,
            self.inputs
                .native_authority
                .security_authority_id()
                .as_str(),
            &self.inputs.observation.key,
        )
        .map_err(invalid)?;
        if snapshot.as_ref() != Some(&self.inputs.observation)
            || generation != self.inputs.stored_context_generation
        {
            return Err(invalid(
                "native dispatch observation changed before retention",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_at(&self, now: u64) -> Result<(), AdmissionOperationStoreError> {
        if now < self.inputs.prepared_at_unix_ms || now >= self.inputs.valid_until_unix_ms {
            return Err(invalid("native dispatch policy is stale or expired"));
        }
        if let Some(grant) = &self.inputs.declassification {
            if now / 1000 < grant.body.issued_at_unix_seconds()
                || now / 1000 >= grant.body.expires_at_unix_seconds()
            {
                return Err(invalid(
                    "native declassification grant is not currently valid",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn validate_live_declassification(
        &self,
        request: &chio_kernel::ToolCallRequest,
    ) -> Result<(), AdmissionOperationStoreError> {
        match (
            &self.inputs.declassification,
            &request.declassification_grant,
        ) {
            (None, None) => Ok(()),
            (Some(expected), Some(signed))
                if &expected.body == signed.body()
                    && &expected.authority_key == signed.authority_key()
                    && expected.artifact_hash.as_bytes()
                        == chio_core::hashing::sha256(
                            &canonical_json_bytes(signed).map_err(invalid)?,
                        )
                        .as_bytes()
                    && signed.verify_signature().map_err(invalid)? =>
            {
                Ok(())
            }
            _ => Err(invalid(
                "native declassification differs from the live signed grant",
            )),
        }
    }

    pub(super) fn validate_owned_declassification(
        &self,
        connection: &Connection,
        operation: &AdmissionOperationV1,
        value: &serde_json::Value,
    ) -> Result<(), AdmissionOperationStoreError> {
        let committed = super::super::egress::load_operation(
            connection,
            operation.binding().operation_id(),
            "committed",
        )?;
        let owned = committed.as_ref().and_then(|record| match &record.command {
            crate::security_state::NativeEgressCommand::CommitDeclassified {
                grant,
                consumption,
                ..
            } => Some((grant.as_ref(), consumption.as_ref())),
            _ => None,
        });
        match (&self.inputs.declassification, owned) {
            (None, None) => Ok(()),
            (Some(expected), Some((actual, consumption))) if expected == actual => {
                let receipt: chio_core::receipt::security::ActiveDefenseReceiptBody =
                    serde_json::from_slice(consumption.receipt.canonical_body.as_bytes())
                        .map_err(invalid)?;
                let chio_core::receipt::security::ActiveDefenseReceiptBody::DeclassificationConsumption(body) = receipt else {
                    return Err(invalid("native use is not consumption evidence"));
                };
                if body.policy.policy_version.as_str() != "native-flow-dispatch-policy-v2"
                    || body.policy.policy_hash.as_bytes()
                        != chio_core::hashing::sha256(
                            &canonical_json_bytes(value).map_err(invalid)?,
                        )
                        .as_bytes()
                {
                    return Err(invalid(
                        "native consumption does not bind this exact dispatch policy",
                    ));
                }
                Ok(())
            }
            _ => Err(invalid(
                "native dispatch lacks its original declassification consumption",
            )),
        }
    }
}
