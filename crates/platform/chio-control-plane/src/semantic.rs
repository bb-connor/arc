//! Native semantic remedies use the process runtime and its original admission.
use chio_core_types::recovery::*;
use chio_kernel::recovery::RecoveryPermission;
use chio_kernel::{ChioKernel, KernelError, ToolCallRequest, ToolCallResponse};
use chio_process::ProcessRuntime;
use chio_security_types::{recovery::*, semantic::*};
use chio_store_sqlite::SqliteAdmissionOperationStore;
use std::sync::Arc;

mod connector;
mod http;
mod transport;
#[cfg(test)]
pub(crate) use connector::{hold_submission_capacity_for_test, submission_for_transport_test};
pub use connector::{CapturedSemanticSubmissionV1, PinnedSemanticConnector};
pub use http::HttpSemanticTransport;
pub use transport::{
    ProviderPreconditionGuaranteeV1, SemanticTransport, SemanticTransportRequestV1,
    SemanticTransportRouter,
};

pub struct NativeSemanticRuntime {
    kernel: Arc<ChioKernel>,
    store: Arc<SqliteAdmissionOperationStore>,
    scope: RecoveryScopeV1,
    fence: chio_core_types::StoreMutationFence,
}
fn refused() -> KernelError {
    KernelError::DurableAdmission("native semantic remedy refused".into())
}
impl NativeSemanticRuntime {
    pub fn new(
        kernel: Arc<ChioKernel>,
        store: Arc<SqliteAdmissionOperationStore>,
        scope: RecoveryScopeV1,
        fence: chio_core_types::StoreMutationFence,
    ) -> Self {
        Self {
            kernel,
            store,
            scope,
            fence,
        }
    }
    pub fn accept_plan(
        &self,
        control: &chio_core_types::capability::token::CapabilityToken,
        plan: &SemanticPlanV1,
    ) -> Result<PlanDigest, KernelError> {
        if plan.scope != self.scope {
            return Err(refused());
        }
        let actor = self.kernel.authenticate_recovery_actor(
            &self.scope,
            control,
            RecoveryPermission::Select,
        )?;
        self.store
            .accept_semantic_plan(&actor, plan, &self.fence, now()?)
            .map_err(|_| refused())
    }
    /// Historical matched rules are advisory data. Their use still requires
    /// independently fresh native admission at every effect boundary.
    pub fn read_constraints(
        &self,
        control: &chio_core_types::capability::token::CapabilityToken,
        operation: &OperationId,
    ) -> Result<chio_semantic_contracts::ResolvedSemanticConstraintsV1, KernelError> {
        let actor = self.kernel.authenticate_recovery_actor(
            &self.scope,
            control,
            RecoveryPermission::Maintain,
        )?;
        self.store
            .read_semantic_constraints(&actor, operation, &self.fence, now()?)
            .map_err(|_| refused())
    }
    /// Build only the unsigned exact action. Endorsements and prerequisite
    /// signatures subsequently bind its digest; capture checks the full request.
    pub fn frame_action(
        &self,
        request: &ToolCallRequest,
        mut action: SemanticActionV1,
        payload: &SemanticPayloadV1,
    ) -> Result<SemanticActionV1, KernelError> {
        if action.scope != self.scope {
            return Err(refused());
        }
        action.request_id = RequestId::new(&request.request_id).map_err(|_| refused())?;
        action.request_namespace = self
            .kernel
            .semantic_request_namespace(&request.request_id)?;
        action.capability = CapabilityBodyDigest::from_bytes(
            *semantic_content_digest(&request.capability.signing_body())
                .map_err(|_| refused())?
                .as_bytes(),
        );
        let observation = self.kernel.observe_recovery_source(&self.scope)?;
        let source = observation.snapshot().ok_or_else(refused)?;
        action.native_source = SemanticNativeSourceBasisV1 {
            key: semantic_content_digest(&source.key).map_err(|_| refused())?,
            generation: SafeInteger::new(source.context_generation).map_err(|_| refused())?,
            principal_label: source.principal_label.clone(),
            lineage_label: source.lineage_label.clone(),
            session_label: source.session_label.clone(),
        };
        let framed_source = self.frame_source(request, &action)?;
        action.source_label = source
            .principal_label
            .join_restrictions(&source.lineage_label)
            .and_then(|label| label.join_restrictions(&source.session_label))
            .and_then(|label| label.join_restrictions(&framed_source))
            .map_err(|_| refused())?;
        action.request_semantics = chio_kernel::recovery::semantic_request_semantics(request)?;
        action.payload = semantic_content_digest(payload).map_err(|_| refused())?;
        let observed = self
            .store
            .observe_knowledge_influence(&self.scope, &self.fence, now()?)
            .map_err(|_| refused())?;
        let influence = chio_semantic_contracts::semantic_observed_influence(
            action.influence,
            request
                .model_metadata
                .as_ref()
                .map(semantic_content_digest)
                .transpose()
                .map_err(|_| refused())?,
        )
        .map_err(|_| refused())?;
        action.influence =
            knowledge_semantic_influence(influence, observed.as_ref()).map_err(|_| refused())?;
        action.externally_influenced |= request.model_metadata.is_some() || observed.is_some();
        action.validate().map_err(|_| refused())?;
        Ok(action)
    }

    fn frame_source(
        &self,
        request: &ToolCallRequest,
        action: &SemanticActionV1,
    ) -> Result<chio_security_types::InformationLabel, KernelError> {
        let installed = self
            .store
            .read_semantic_installation(&self.scope, &self.fence, now()?)
            .map_err(|_| refused())?;
        let registry = chio_semantic_contracts::compile_semantic_registry(
            &installed.deployment,
            installed.packages.as_slice(),
            &installed.operator_root,
            installed.publisher_roots.as_slice(),
            installed.exposed.as_slice(),
            &mut chio_semantic_contracts::VerificationBudget::new(4096).map_err(|_| refused())?,
        )
        .map_err(|_| refused())?;
        let (route, contract) = registry
            .resolve(&request.server_id, &request.tool_name)
            .map_err(|_| refused())?;
        if action.registry != registry.digest()
            || action.generation != registry.deployment().generation
            || action.operation != contract.operation
        {
            return Err(refused());
        }
        let destination = route
            .destinations
            .as_slice()
            .iter()
            .find(|destination| destination.destination == action.destination)
            .ok_or_else(refused)?;
        let mut label = action
            .source_label
            .join_restrictions(&contract.source_label)
            .map_err(|_| refused())?;
        if contract.kind == SemanticOperationKindV1::SupportRead {
            label = label
                .join_restrictions(&destination.audience)
                .map_err(|_| refused())?;
        }
        if action.output == SemanticOutputDispositionV1::Withhold {
            let status = contract.withheld_status.as_ref().ok_or_else(refused)?;
            label = label
                .join_restrictions(&status.audience)
                .map_err(|_| refused())?;
        }
        // This is unsigned framing data. Owning admission independently checks
        // the current native source, signed ACL, annotations and every authority.
        Ok(label)
    }

    pub async fn execute_step(
        &self,
        process: &ProcessRuntime,
        process_id: &str,
        operation_key: &str,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        let invocation: SemanticInvocationV1 = decode_contract(
            &chio_core_types::canonical_json_bytes(&request.arguments).map_err(|_| refused())?,
        )
        .map_err(|_| refused())?;
        if invocation.action.scope != self.scope
            || process_id != self.scope.process_id.as_str()
            || operation_key != invocation.action.step.as_str()
            || request.request_id != invocation.action.request_id.as_str()
        {
            return Err(refused());
        }
        // Unknown reads retain their original identity too. No implicit new
        // process attempt can recreate a spent semantic step or endorsement.
        process
            .invoke_known_only(process_id, operation_key, request)
            .await
            .map_err(|_| refused())
    }
}
fn now() -> Result<u64, KernelError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| refused())?
        .as_millis()
        .try_into()
        .map_err(|_| refused())
}
