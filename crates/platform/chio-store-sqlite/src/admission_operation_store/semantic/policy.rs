//! Independent operator signatures apply exact semantic changes atomically.
use super::*;
use chio_core::recovery::SignedPolicyDeploymentChangeV1;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticPolicyIdentityV1 {
    pub deployment: DeploymentDigest,
    pub policy: PolicyDigest,
    pub generation: SafeInteger,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSemanticPolicyBasisV1 {
    pub deployment: DeploymentDigest,
    pub policy: PolicyDigest,
    pub generation: SafeInteger,
    pub writer_fence: SourceDigest,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePolicyChangeReceiptV1 {
    pub proposal_id: ReviewId,
    pub target_deployment: DeploymentDigest,
    pub target_policy: PolicyDigest,
    pub generation: SafeInteger,
    pub applied_at_unix_ms: SafeInteger,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Application {
    change: CanonicalPayloadDigest,
    installation: CanonicalPayloadDigest,
    receipt: NativePolicyChangeReceiptV1,
}
/// Retained native application facts only. The owning product transaction
/// derives its report dependency independently and verifies target identities.
pub(in crate::admission_operation_store) fn policy_application_receipt(
    tx: &Transaction<'_>,
    scope: &RecoveryScopeV1,
    proposal: &ReviewId,
) -> Result<Option<NativePolicyChangeReceiptV1>, AdmissionOperationStoreError> {
    let scoped_key = scope_key(scope)?;
    let key = format!("product-policy-change:{scoped_key}:{}", proposal.as_str());
    let Some(row) = protected::raw(tx, &key)? else {
        return Ok(None);
    };
    if row.scope != scoped_key || row.kind != "command" || row.version == 0 {
        return Err(refused("policy application custody"));
    }
    let application: Application = protected::decode(&row.payload)?;
    if application.receipt.proposal_id != *proposal
        || application.receipt.generation.get() == 0
        || application.receipt.applied_at_unix_ms.get() == 0
    {
        return Err(refused("policy application identity"));
    }
    Ok(Some(application.receipt))
}
fn digest<T: Serialize>(
    domain: RecoveryDigestDomain,
    value: &T,
) -> Result<[u8; 32], AdmissionOperationStoreError> {
    chio_kernel::recovery::recovery_digest(domain, value).map_err(refused)
}
fn fence_digest(fence: &StoreMutationFence) -> Result<SourceDigest, AdmissionOperationStoreError> {
    digest(RecoveryDigestDomain::ServingFence, fence).map(SourceDigest::from_bytes)
}
impl NativeSemanticInstallationV1 {
    /// Content identity only. Full compilation is required by the owning apply.
    /// Generation and native context change the deployment identity separately.
    pub fn policy_basis(&self) -> Result<SemanticPolicyIdentityV1, AdmissionOperationStoreError> {
        let body = self.deployment.body();
        Ok(SemanticPolicyIdentityV1 {
            deployment: DeploymentDigest::from_bytes(digest(
                RecoveryDigestDomain::SemanticDeployment,
                body,
            )?),
            policy: PolicyDigest::from_bytes(digest(
                RecoveryDigestDomain::SemanticPolicy,
                &(
                    &self.operator_root,
                    &self.publisher_roots,
                    &body.packages,
                    &body.routes,
                    &self.exposed,
                ),
            )?),
            generation: body.generation,
        })
    }
}
impl SqliteAdmissionOperationStore {
    /// Trusted local operator snapshot. Incoming maintenance routes expose only
    /// the basis and use independent capability authentication before reading it.
    pub fn read_semantic_installation(
        &self,
        scope: &RecoveryScopeV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeSemanticInstallationV1, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        let result = installation(&tx, scope)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(result)
    }
    pub fn read_semantic_policy_basis(
        &self,
        actor: &AuthenticatedRecoveryActor,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeSemanticPolicyBasisV1, AdmissionOperationStoreError> {
        self.recovery_mutation(actor, fence, now, |tx, _profile, _now| {
            if actor.permission() != RecoveryPermission::Maintain {
                return Err(refused("policy read authority"));
            }
            let identity = installation(tx, actor.scope())?.policy_basis()?;
            Ok(NativeSemanticPolicyBasisV1 {
                deployment: identity.deployment,
                policy: identity.policy,
                generation: identity.generation,
                writer_fence: fence_digest(&self.serving_owner.fence)?,
            })
        })
    }
    pub fn apply_reviewed_semantic_deployment(
        &self,
        change: &SignedPolicyDeploymentChangeV1,
        target: &NativeSemanticInstallationV1,
    ) -> Result<NativePolicyChangeReceiptV1, AdmissionOperationStoreError> {
        if !change.verify_signature().map_err(refused)? {
            return Err(refused("operator signature"));
        }
        // No untrusted compilation or external signing backend runs in a native transaction.
        target.compile()?;
        let body = change.body();
        let target_identity = target.policy_basis()?;
        if target.deployment.body().scope != body.scope
            || body.scope.authority_domain.as_str() != self.serving_owner.fence.store_uuid
            || target.native_authority.store_uuid().as_str() != self.serving_owner.fence.store_uuid
            || body.scope.tenant_id.as_str() != target.security_context.as_v1().tenant_id().as_str()
            || target_identity.deployment != body.target_deployment
            || target_identity.policy != body.target_policy
            || target_identity.generation.get() != body.target_generation.get()
        {
            return Err(refused("target identity"));
        }
        let signed_digest = semantic_content_digest(change).map_err(refused)?;
        let installation_digest = semantic_content_digest(target).map_err(refused)?;
        let key = format!(
            "product-policy-change:{}:{}",
            scope_key(&body.scope)?,
            body.proposal_id.as_str()
        );
        let mut connection = self.connection()?;
        super::super::recovery::require_intake_headroom(&connection)?;
        let tx = self.begin_write(&mut connection, None)?;
        let current = installation(&tx, &body.scope)?;
        if change.authority_key() != &current.operator_root
            || target.operator_root != current.operator_root
        {
            return Err(refused("selected operator root"));
        }
        // Lost-ack replay precedes stale-base checks and never installs again.
        if let Some(old) = load::<Application>(&tx, &key)? {
            if old.change != signed_digest || old.installation != installation_digest {
                return Err(refused("policy application identity reused"));
            }
            self.commit_write(tx)?;
            return Ok(old.receipt);
        }
        let proposal = super::super::product::stored_proposal(&tx, &body.scope, &body.proposal_id)?;
        let report =
            super::super::product::stored_report(&tx, &body.scope, &proposal.proposal.report_id)?;
        let base = current.policy_basis()?;
        if change.authority_key() == &proposal.maintainer_subject
            || change.authority_key() == &report.reporter_subject
            || proposal.digest != body.proposal_digest
            || proposal.proposal.base_deployment != body.base_deployment
            || proposal.proposal.base_policy != body.base_policy
            || proposal.proposal.target_policy != body.target_policy
            || base.deployment != body.base_deployment
            || base.policy != body.base_policy
            || base.generation.get() != body.base_generation.get()
            || body.writer_fence != fence_digest(&self.serving_owner.fence)?
        {
            return Err(refused("reviewed policy base"));
        }
        require_affected_contracts(&proposal.proposal, &current, target)?;
        self.install_semantic_tx(&tx, target)?;
        let now = schema::observe_authority_time(&tx)?;
        let receipt = NativePolicyChangeReceiptV1 {
            proposal_id: body.proposal_id.clone(),
            target_deployment: target_identity.deployment,
            target_policy: target_identity.policy,
            generation: target_identity.generation,
            applied_at_unix_ms: SafeInteger::new(now).map_err(refused)?,
        };
        save(
            &tx,
            &self.serving_owner,
            &body.scope,
            &key,
            "command",
            &Application {
                change: signed_digest,
                installation: installation_digest,
                receipt: receipt.clone(),
            },
        )?;
        super::super::product::complete_policy_review(
            &tx,
            &self.serving_owner,
            &body.scope,
            &body.proposal_id,
            &proposal.proposal.report_id,
        )?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)?;
        Ok(receipt)
    }
}
fn require_affected_contracts(
    proposal: &PolicyMaintenanceProposalV1,
    base: &NativeSemanticInstallationV1,
    target: &NativeSemanticInstallationV1,
) -> Result<(), AdmissionOperationStoreError> {
    let affected = proposal.affected_contracts.as_slice();
    let old = base.deployment.body();
    let new = target.deployment.body();
    for package in affected {
        if !old.packages.as_slice().contains(package) && !new.packages.as_slice().contains(package)
        {
            return Err(refused("unknown affected contract"));
        }
    }
    for route in new.routes.as_slice() {
        let prior = old
            .routes
            .as_slice()
            .iter()
            .find(|p| p.server == route.server && p.tool == route.tool);
        if prior != Some(route)
            && !affected.contains(&route.package)
            && !prior.is_some_and(|p| affected.contains(&p.package))
        {
            return Err(refused("unreported affected route"));
        }
    }
    for route in old.routes.as_slice() {
        if !new
            .routes
            .as_slice()
            .iter()
            .any(|r| r.server == route.server && r.tool == route.tool)
            && !affected.contains(&route.package)
        {
            return Err(refused("unreported removed route"));
        }
    }
    if (base.publisher_roots != target.publisher_roots || base.exposed != target.exposed)
        && old
            .packages
            .as_slice()
            .iter()
            .any(|p| !affected.contains(p))
    {
        return Err(refused("unreported trust or exposure change"));
    }
    Ok(())
}
impl core::fmt::Debug for SemanticPolicyIdentityV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SemanticPolicyIdentityV1([redacted])")
    }
}
impl core::fmt::Debug for NativeSemanticPolicyBasisV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NativeSemanticPolicyBasisV1([redacted])")
    }
}
