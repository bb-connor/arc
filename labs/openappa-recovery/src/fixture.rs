//! Synthetic operator material for this lab only. Never install this key in a runtime.
use crate::{
    resolved_request, DisclosureIntent, DisclosureOffer, HostSnapshot, OperationState,
    PlanningDecision,
};
use chio_core_types::{canonical_json_bytes, Keypair, SignedDeclassificationGrant};
use chio_flow::{canonical_request_hash, information_label_hash};
use chio_security_types::flow::{DeclassificationPurpose, ToolFlowDeclaration};
use chio_security_types::ports::{
    CanonicalBody, DestinationId, Digest32, FlowStateKey, FlowStateSnapshot, GrantId,
    IsolationEpochId, LineageId, RecordId, SessionId, TenantId,
};
use chio_security_types::{
    Compartment, DeclassificationGrantBody, DeclassificationGrantClaims, InformationLabel,
    PrincipalId,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
};

pub type LabResult<T> = Result<T, Box<dyn Error>>;

pub struct Case {
    pub intent: DisclosureIntent,
    pub host: HostSnapshot,
    pub authority: Keypair,
}

impl Case {
    pub fn new() -> LabResult<Self> {
        let owner = PrincipalId::new("support-owner")?;
        let restricted = InformationLabel::try_known(
            BTreeMap::from([(owner.clone(), BTreeSet::from([owner.clone()]))]),
            BTreeSet::from([Compartment::new("customer-support")?]),
        )?;
        let authority = Keypair::from_seed(&[61; 32]);
        let purpose = DeclassificationPurpose::new("publish_support_issue")?;
        let canonical_request = canonical_json_bytes(&serde_json::json!({
            "body": "Synthetic customer ticket: reproduce the indexing failure.",
            "repository": "public-demo", "title": "Indexing failure"
        }))?;
        let intent = DisclosureIntent {
            operation_id: RecordId::new("support-issue-1")?,
            capability_id: RecordId::new("issue-write-capability")?,
            agent_id: RecordId::new("support-agent")?,
            tool_name: RecordId::new("create_issue")?,
            destination: DestinationId::new("public-issue-sink")?,
            purpose: purpose.clone(),
            canonical_request: CanonicalBody::new(canonical_request)?,
            payload_label: restricted.clone(),
        };
        let host = HostSnapshot {
            operation_id: intent.operation_id.clone(),
            flow: FlowStateSnapshot {
                key: FlowStateKey {
                    tenant_id: TenantId::new("lab-tenant")?,
                    principal_id: owner,
                    lineage_id: LineageId::new("support-lineage")?,
                    session_id: SessionId::new("support-session")?,
                    isolation_epoch_id: IsolationEpochId::new("support-epoch")?,
                },
                principal_label: restricted.clone(),
                lineage_label: restricted.clone(),
                session_label: restricted,
                context_generation: 7,
            },
            input_floor: InformationLabel::bottom(),
            policy_clearances: vec![InformationLabel::bottom()],
            manifest: ToolFlowDeclaration::new(
                None,
                Some(InformationLabel::bottom()),
                true,
                BTreeSet::from([purpose.clone()]),
            )?,
            policy_digest: Digest32::new([1; 32]),
            contract_digest: Digest32::new([2; 32]),
            revocation_generation: 3,
            budget_generation: 4,
            capability_revoked: false,
            budget_remaining: 1,
            operation_state: OperationState::BeforeAdmission,
            policy_purposes: BTreeSet::from([purpose]),
            trusted_authorities: BTreeMap::from([(
                RecordId::new("support-owner-key")?,
                authority.public_key(),
            )]),
            now_unix_ms: 150_000,
        };
        Ok(Self {
            intent,
            host,
            authority,
        })
    }

    pub fn offer(&self) -> LabResult<DisclosureOffer> {
        let decision = crate::plan(&self.intent, &self.host)?;
        match decision {
            PlanningDecision::Denied { mut offers, .. } if offers.len() == 1 => {
                Ok(offers.remove(0))
            }
            other => Err(format!("expected one disclosure offer, got {other:?}").into()),
        }
    }

    pub fn grant(&self, expires_at_unix_seconds: u64) -> LabResult<SignedDeclassificationGrant> {
        let request = resolved_request(&self.intent, &self.host, self.host.now_unix_ms)?;
        let body = DeclassificationGrantBody::new(DeclassificationGrantClaims {
            grant_id: GrantId::new("support-grant-1")?,
            capability_id: self.intent.capability_id.clone(),
            tenant_id: self.host.flow.key.tenant_id.clone(),
            subject_id: self.host.flow.key.principal_id.clone(),
            agent_id: self.intent.agent_id.clone(),
            session_id: self.host.flow.key.session_id.clone(),
            source_label_hash: information_label_hash(
                &request.observed_input_taint().principal_join,
            )?,
            target_label: InformationLabel::bottom(),
            destination_id: self.intent.destination.clone(),
            tool_name: self.intent.tool_name.clone(),
            purpose: self.intent.purpose.clone(),
            request_hash: canonical_request_hash(&self.intent.canonical_request)?,
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds,
            authority_key_id: RecordId::new("support-owner-key")?,
        })?;
        Ok(SignedDeclassificationGrant::sign(body, &self.authority)?)
    }
}
