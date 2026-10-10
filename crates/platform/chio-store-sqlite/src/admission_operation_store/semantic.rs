//! Semantic data participates in the existing fenced native authority store.
use super::recovery::storage as protected;
use super::*;
use chio_core::recovery::*;
use chio_core::PublicKey;
use chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1;
use chio_kernel::recovery::{recovery_flow_key, AuthenticatedRecoveryActor, RecoveryPermission};
use chio_kernel::{SecurityInvocationContext, ToolCallRequest};
use chio_security_types::{recovery::*, semantic::*};
use chio_semantic_contracts::*;

mod annotations;
mod capture;
mod constraints;
mod delivery;
#[cfg(feature = "admission-test-support")]
mod legacy_annotation_capture;
#[cfg(feature = "admission-test-support")]
mod legacy_input_floor;
#[cfg(feature = "admission-test-support")]
mod legacy_status_capture;
mod materialization;
#[cfg(feature = "admission-test-support")]
pub use legacy_annotation_capture::ModeledLegacyIncompleteAnnotationCaptureGuard;
#[cfg(feature = "admission-test-support")]
pub(in crate::admission_operation_store) use legacy_input_floor::modeled_legacy_input_floor_selected;
#[cfg(feature = "admission-test-support")]
pub use legacy_input_floor::ModeledLegacySemanticInputFloorGuard;
#[cfg(feature = "admission-test-support")]
pub use legacy_status_capture::ModeledLegacyMissingStatusCaptureGuard;
pub(in crate::admission_operation_store) mod output;
mod policy;
pub(in crate::admission_operation_store) mod status;
pub(super) use capture::{capture_tx, verify_capture_tx, SemanticCaptureWitness};
pub(in crate::admission_operation_store) use capture::{
    validate_historical_semantic_refused_input_origin, verify_input_tx,
    HistoricalSemanticRefusedInputObservation, SemanticHistoricalInputOriginData,
    SemanticInputAssessment, SemanticInputObservation, SemanticRefusedInputOriginData,
};
pub(in crate::admission_operation_store) use policy::policy_application_receipt;
pub use policy::{
    NativePolicyChangeReceiptV1, NativeSemanticPolicyBasisV1, SemanticPolicyIdentityV1,
};
pub use status::SemanticStatusOriginData;

/// Only trusted host setup supplies roots, native mapping and actual exposure.
/// Publisher signatures cannot select any of these deployment authorities.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSemanticInstallationV1 {
    pub deployment: SignedSemanticDeploymentV1,
    pub packages: NonEmptyBoundedList<SignedSemanticPackageV1, 16>,
    pub operator_root: PublicKey,
    pub publisher_roots: NonEmptyBoundedList<PublicKey, 16>,
    pub exposed: NonEmptyBoundedList<ExposedSemanticToolV1, 16>,
    pub native_authority: NativeSecurityAuthorityBindingV1,
    pub security_context: SecurityInvocationContext,
}
impl std::fmt::Debug for NativeSemanticInstallationV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeSemanticInstallationV1([redacted])")
    }
}
impl NativeSemanticInstallationV1 {
    fn compile(&self) -> Result<CompiledSemanticRegistryV1, AdmissionOperationStoreError> {
        self.compile_with_budget(&mut VerificationBudget::new(4096).map_err(refused)?)
    }
    fn compile_with_budget(
        &self,
        budget: &mut VerificationBudget,
    ) -> Result<CompiledSemanticRegistryV1, AdmissionOperationStoreError> {
        let body = self.deployment.body();
        if body.native_binding
            != semantic_content_digest(&self.native_authority).map_err(refused)?
            || body.context_binding
                != semantic_content_digest(&(
                    recovery_flow_key(&self.security_context),
                    self.security_context.as_v1().context_generation(),
                ))
                .map_err(refused)?
        {
            return Err(refused("signed native mapping"));
        }
        compile_semantic_registry(
            &self.deployment,
            self.packages.as_slice(),
            &self.operator_root,
            self.publisher_roots.as_slice(),
            self.exposed.as_slice(),
            budget,
        )
        .map_err(refused)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSemanticCaptureRecordV1 {
    pub operation_id: OperationId,
    pub invocation: SemanticInvocationV1,
    pub contract: SemanticOperationContractV1,
    pub route: SemanticRouteV1,
    pub native_authority: NativeSecurityAuthorityBindingV1,
    pub security_context: SecurityInvocationContext,
    pub captured_at_unix_ms: SafeInteger,
    pub valid_until_unix_ms: SafeInteger,
}
impl std::fmt::Debug for NativeSemanticCaptureRecordV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeSemanticCaptureRecordV1([redacted])")
    }
}

#[cfg_attr(feature = "admission-test-support", track_caller)]
fn refused(_error: impl std::fmt::Display) -> AdmissionOperationStoreError {
    #[cfg(feature = "admission-test-support")]
    eprintln!("semantic refusal site: {}", std::panic::Location::caller());
    invariant("native semantic remedy refused")
}
fn scope_key(scope: &RecoveryScopeV1) -> Result<String, AdmissionOperationStoreError> {
    protected::scope_key(scope)
}
fn route_key(
    binding: &NativeSecurityAuthorityBindingV1,
    context: &SecurityInvocationContext,
    server: &str,
    tool: &str,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "semantic-route:{}",
        sha256_hex(&protected::encode(&(
            binding.security_authority_id(),
            recovery_flow_key(context),
            context.as_v1().context_generation(),
            server,
            tool
        ))?)
    ))
}
pub(super) fn installation(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<NativeSemanticInstallationV1, AdmissionOperationStoreError> {
    load(tx, &format!("semantic-deployment:{}", scope_key(scope)?))?
        .ok_or_else(|| refused("missing deployment"))
}
fn load<T: serde::de::DeserializeOwned + Serialize>(
    tx: &Connection,
    key: &str,
) -> Result<Option<T>, AdmissionOperationStoreError> {
    protected::raw(tx, key)?
        .map(|row| protected::decode(&row.payload))
        .transpose()
}
fn save<T: Serialize>(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
    key: &str,
    kind: &str,
    value: &T,
) -> Result<(), AdmissionOperationStoreError> {
    protected::save(
        tx,
        owner,
        key,
        &scope_key(scope)?,
        kind,
        &protected::encode(value)?,
        None,
    )
}
fn stopped(tx: &Connection, scope: &RecoveryScopeV1) -> Result<bool, AdmissionOperationStoreError> {
    Ok(load::<bool>(tx, &format!("semantic-stop:{}", scope_key(scope)?))?.unwrap_or(false))
}
fn audience_key(
    scope: &RecoveryScopeV1,
    provider: &ProviderId,
    account: &ProviderAccountId,
    resource: &ProviderResourceId,
    subject_mapping: &CanonicalPayloadDigest,
    query: &CanonicalPayloadDigest,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "semantic-acl:{}:{}",
        scope_key(scope)?,
        sha256_hex(&protected::encode(&(
            provider,
            account,
            resource,
            subject_mapping,
            query,
        ))?)
    ))
}

/// Read an old shared slot only when its complete authenticated identity agrees.
/// A mismatched new slot is an integrity failure, not a reason to fall back.
fn current_audience(
    tx: &Connection,
    expected: &SemanticAudienceObservationV1,
) -> Result<Option<SignedSemanticAudienceV1>, AdmissionOperationStoreError> {
    let exact = |actual: &SemanticAudienceObservationV1| {
        actual.scope == expected.scope
            && actual.provider == expected.provider
            && actual.account == expected.account
            && actual.resource == expected.resource
            && actual.subject_mapping == expected.subject_mapping
            && actual.query == expected.query
    };
    let key = audience_key(
        &expected.scope,
        &expected.provider,
        &expected.account,
        &expected.resource,
        &expected.subject_mapping,
        &expected.query,
    )?;
    if let Some(current) = load::<SignedSemanticAudienceV1>(tx, &key)? {
        if !exact(current.body()) {
            return Err(refused("ACL cache identity changed"));
        }
        return Ok(Some(current));
    }
    let legacy_key = format!(
        "semantic-acl:{}:{}",
        scope_key(&expected.scope)?,
        sha256_hex(&protected::encode(&(
            &expected.provider,
            &expected.account,
            &expected.resource,
        ))?)
    );
    Ok(load::<SignedSemanticAudienceV1>(tx, &legacy_key)?.filter(|current| exact(current.body())))
}
fn capture_key(operation: &str) -> String {
    format!("semantic-capture:{operation}")
}
fn plan_key(
    scope: &RecoveryScopeV1,
    digest: &PlanDigest,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "semantic-plan:{}:{}",
        scope_key(scope)?,
        hex::encode(digest.as_bytes())
    ))
}

impl SqliteAdmissionOperationStore {
    /// Complete atomic reload. Failed validation preserves the prior generation.
    pub fn configure_semantic_deployment(
        &self,
        value: &NativeSemanticInstallationV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        value.compile()?;
        if value.deployment.body().scope.authority_domain.as_str()
            != self.serving_owner.fence.store_uuid
            || value.deployment.body().scope.tenant_id.as_str()
                != value.security_context.as_v1().tenant_id().as_str()
            || value.native_authority.store_uuid().as_str() != self.serving_owner.fence.store_uuid
        {
            return Err(refused("scope"));
        }
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, None)?;
        self.install_semantic_tx(&tx, value)?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)
    }

    /// Reused by the separately authorized product route in its owning transaction.
    pub(super) fn install_semantic_tx(
        &self,
        tx: &Transaction<'_>,
        value: &NativeSemanticInstallationV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        security_participant_state::verify_recovery_initialization(tx, &value.native_authority)?;
        let scope = &value.deployment.body().scope;
        if let Some(old) = load::<NativeSemanticInstallationV1>(
            tx,
            &format!("semantic-deployment:{}", scope_key(scope)?),
        )? {
            if protected::encode(&old)? == protected::encode(value)? {
                return Ok(());
            }
            if value.deployment.body().generation <= old.deployment.body().generation
                || old.operator_root != value.operator_root
                || old.native_authority != value.native_authority
                || recovery_flow_key(&old.security_context)
                    != recovery_flow_key(&value.security_context)
            {
                return Err(refused("generation"));
            }
            // Removing a formerly selected route must leave a refusal tombstone.
            for route in old.deployment.body().routes.as_slice() {
                save(
                    tx,
                    &self.serving_owner,
                    scope,
                    &route_key(
                        &old.native_authority,
                        &old.security_context,
                        route.server.as_str(),
                        route.tool.as_str(),
                    )?,
                    "deployment",
                    scope,
                )?;
            }
        }
        for route in value.deployment.body().routes.as_slice() {
            let key = route_key(
                &value.native_authority,
                &value.security_context,
                route.server.as_str(),
                route.tool.as_str(),
            )?;
            if load::<RecoveryScopeV1>(tx, &key)?.is_some_and(|prior| prior != *scope) {
                return Err(refused("route conflict"));
            }
            save(tx, &self.serving_owner, scope, &key, "deployment", scope)?;
        }
        save(
            tx,
            &self.serving_owner,
            scope,
            &format!("semantic-deployment:{}", scope_key(scope)?),
            "deployment",
            value,
        )?;
        Ok(())
    }

    /// Authenticated native control authority accepts a bounded symbolic plan.
    /// Capture separately checks every step's materialized bytes and capability.
    pub fn accept_semantic_plan(
        &self,
        actor: &AuthenticatedRecoveryActor,
        plan: &SemanticPlanV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<PlanDigest, AdmissionOperationStoreError> {
        self.recovery_mutation(actor, fence, now, |tx, _profile, _now| {
            if actor.permission() != RecoveryPermission::Select
                || plan.scope != *actor.scope()
                || stopped(tx, &plan.scope)?
            {
                return Err(refused("plan authority"));
            }
            super::setup::require_ready(tx, &plan.scope, fence)?;
            let installed = installation(tx, &plan.scope)?;
            let registry = installed.compile()?;
            let mut budget = VerificationBudget::new(4096).map_err(refused)?;
            if plan.registry != registry.digest() {
                return Err(refused("stale plan"));
            }
            validate_semantic_plan(plan, &mut budget).map_err(refused)?;
            for step in plan.steps.as_slice() {
                let route = registry
                    .deployment()
                    .routes
                    .as_slice()
                    .iter()
                    .find(|route| {
                        route.operation == step.operation
                            && route
                                .destinations
                                .as_slice()
                                .iter()
                                .any(|dest| dest.destination == step.destination)
                    })
                    .ok_or_else(|| refused("step"))?;
                registry
                    .resolve(route.server.as_str(), route.tool.as_str())
                    .map_err(refused)?;
            }
            let digest = semantic_plan_digest(plan).map_err(refused)?;
            save(
                tx,
                &self.serving_owner,
                &plan.scope,
                &plan_key(&plan.scope, &digest)?,
                "command",
                plan,
            )?;
            Ok(digest)
        })
    }

    /// A selected resolver publishes complete fresh observations into the same
    /// protected inventory. Uncertain observations invalidate older positives.
    pub fn install_semantic_audience(
        &self,
        value: &SignedSemanticAudienceV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, None)?;
        let body = value.body();
        let installed = installation(&tx, &body.scope)?;
        let key = semantic_key_digest(value.authority_key()).map_err(refused)?;
        if !value.verify_signature().map_err(refused)?
            || !installed
                .deployment
                .body()
                .routes
                .as_slice()
                .iter()
                .any(|route| {
                    route.resolver_key == key
                        && route.destinations.as_slice().iter().any(|dest| {
                            dest.provider == body.provider
                                && dest.account == body.account
                                && dest.resource == body.resource
                                && dest.subject_mapping == body.subject_mapping
                                && dest.acl_query == body.query
                        })
                })
        {
            return Err(refused("resolver"));
        }
        let now = schema::observe_authority_time(&tx)?;
        if body.observed_at_unix_ms.get() > now || body.valid_until_unix_ms.get() <= now {
            return Err(refused("time"));
        }
        let record_key = audience_key(
            &body.scope,
            &body.provider,
            &body.account,
            &body.resource,
            &body.subject_mapping,
            &body.query,
        )?;
        if let Some(prior) = current_audience(&tx, body)? {
            if prior == *value {
                return self.commit_write(tx);
            }
            if prior.body().observed_at_unix_ms >= body.observed_at_unix_ms {
                return Err(refused("resolver regression"));
            }
        }
        save(
            &tx,
            &self.serving_owner,
            &body.scope,
            &record_key,
            "command",
            value,
        )?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)
    }

    pub fn set_semantic_emergency_stop(
        &self,
        scope: &RecoveryScopeV1,
        stop: bool,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, None)?;
        installation(&tx, scope)?;
        save(
            &tx,
            &self.serving_owner,
            scope,
            &format!("semantic-stop:{}", scope_key(scope)?),
            "command",
            &stop,
        )?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)
    }
}
