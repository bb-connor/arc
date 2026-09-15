use super::{
    agreement::{Policy, SignedAgreement},
    journal::Journal,
    observer::{self, Domain, FundingSource},
    rail::FundingRail,
    tool::W0Tool,
};
use crate::common::{self, digest, Result};
use chio_core_types::{
    capability::scope::{ChioScope, MonetaryAmount, Operation, ToolGrant},
    PublicKey,
};
use chio_kernel::{
    admission_operation::{
        AdmissionIdentifier, AdmissionOperationStore, AdmissionOperationV1, DurableAdmissionMode,
    },
    ChioKernel, ToolCallRequest,
};
use chio_store_sqlite::{SqliteAuthorityStore, SqliteReceiptStore};
use std::{fs, path::Path, sync::Arc};

pub(super) const SERVER: &str = "experimental-funded-w0";
// Native receipts require a three-letter denomination. The pinned local
// profile maps XTS one-to-one to the mock token's integer base units.
pub(super) const CURRENCY: &str = "XTS";

pub struct Native {
    pub(super) kernel: ChioKernel,
    pub(super) authority: SqliteAuthorityStore,
    pub(super) policy: Policy,
    pub(super) source: Arc<dyn FundingSource>,
    pub(super) journal: Arc<Journal>,
    checkpoint: super::Checkpoint,
    recovery_error: Option<String>,
}

pub fn implementation_digest() -> String {
    chio_core_types::sha256_hex(
        &[
            include_bytes!("allocation.rs").as_slice(),
            include_bytes!("observer.rs").as_slice(),
            include_bytes!("agreement.rs").as_slice(),
            include_bytes!("native.rs").as_slice(),
            include_bytes!("journal.rs").as_slice(),
            include_bytes!("rail.rs").as_slice(),
            include_bytes!("tool.rs").as_slice(),
            include_bytes!("evidence.rs").as_slice(),
            include_bytes!("verification.rs").as_slice(),
            include_bytes!("finding_acceptance.rs").as_slice(),
            include_bytes!("wire.rs").as_slice(),
            include_bytes!("settlement.rs").as_slice(),
            include_bytes!("settlement_observer.rs").as_slice(),
            include_bytes!("lifecycle.rs").as_slice(),
            include_bytes!("local_chain.rs").as_slice(),
            include_bytes!("waiver_terms.rs").as_slice(),
            include_bytes!("capture_resolution.rs").as_slice(),
            include_bytes!("child.rs").as_slice(),
            include_bytes!("child_process.rs").as_slice(),
            include_bytes!("process.rs").as_slice(),
            include_bytes!("lifecycle_process.rs").as_slice(),
            include_bytes!("resolution_process.rs").as_slice(),
            super::local_chain::implementation_digest().as_bytes(),
            super::verification::checker_digest().as_bytes(),
            include_bytes!("../review.rs").as_slice(),
        ]
        .concat(),
    )
}

impl Native {
    #[cfg(test)]
    pub fn provision(state: &Path, buyer: PublicKey, domain: Domain) -> Result<()> {
        Self::provision_with_requirements(
            state,
            buyer,
            domain,
            vec![
                chio_finding::FindingFacetKind::ArtifactIntegrity,
                chio_finding::FindingFacetKind::GuaranteeConsistency,
            ],
        )
    }

    pub(super) fn provision_with_requirements(
        state: &Path,
        buyer: PublicKey,
        domain: Domain,
        required_finding_facets: Vec<chio_finding::FindingFacetKind>,
    ) -> Result<()> {
        super::wire::requirements(&required_finding_facets)?;
        domain.validate()?;
        match fs::symlink_metadata(state) {
            Ok(metadata)
                if metadata.file_type().is_dir() && fs::read_dir(state)?.next().is_none() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err("native funding requires an empty disposable state directory".into())
            }
            Err(error) => return Err(error.into()),
        }
        let provider = common::init(state)?;
        let verifier = common::init(&state.join("verifier"))?;
        let locks = state.join("locks");
        fs::create_dir(&locks)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&locks, fs::Permissions::from_mode(0o700))?;
        }
        let database = state.join("authority.sqlite");
        SqliteAuthorityStore::provision(&database, &locks)?;
        let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
        let now = common::now()?;
        let finding_context = super::finding_acceptance::fixture_context(
            &verifier,
            &provider,
            now,
            now.checked_add(86400)
                .ok_or("Finding context expiry overflow")?,
        )?;
        let policy = Policy {
            authority_uuid: authority.mutation_fence().store_uuid,
            implementation_sha256: implementation_digest(),
            buyer_key: buyer,
            provider_key: provider,
            verifier_key: verifier,
            finding_context,
            required_finding_facets,
            domain,
        };
        fs::write(
            state.join("funding-policy.json"),
            chio_core_types::canonical_json_bytes(&policy)?,
        )?;
        Journal::provision(&state.join("funding.sqlite"), &policy)?;
        Ok(())
    }

    pub fn open(state: &Path, source: Arc<dyn FundingSource>) -> Result<Self> {
        Self::open_with_checkpoint(state, source, Arc::new(|_| Ok(())))
    }

    pub fn open_with_checkpoint(
        state: &Path,
        source: Arc<dyn FundingSource>,
        checkpoint: super::Checkpoint,
    ) -> Result<Self> {
        Self::open_configured(state, source, checkpoint, None)
    }

    pub(super) fn open_configured(
        state: &Path,
        source: Arc<dyn FundingSource>,
        checkpoint: super::Checkpoint,
        subcontract: Option<super::tool::Subcontract>,
    ) -> Result<Self> {
        Self::open_mode(state, source, checkpoint, subcontract, true)
    }

    /// Take a new exclusive owner without starting another capture attempt.
    /// This handle is for the qualified financial successor; it denies new work.
    pub(super) fn open_for_resolution(
        state: &Path,
        source: Arc<dyn FundingSource>,
    ) -> Result<Self> {
        Self::open_mode(state, source, Arc::new(|_| Ok(())), None, false)
    }

    fn open_mode(
        state: &Path,
        source: Arc<dyn FundingSource>,
        checkpoint: super::Checkpoint,
        subcontract: Option<super::tool::Subcontract>,
        recover: bool,
    ) -> Result<Self> {
        let policy: Policy = super::evidence::read(state.join("funding-policy.json"))?;
        let key = common::key(state)?;
        let authority = SqliteAuthorityStore::open_serving(
            state.join("authority.sqlite"),
            state.join("locks"),
        )?;
        if policy.authority_uuid != authority.mutation_fence().store_uuid
            || policy.provider_key != key.public_key()
            || policy.implementation_sha256 != implementation_digest()
            || policy.verifier_key == policy.provider_key
            || policy.verifier_key == policy.buyer_key
        {
            return Err("funding policy does not bind this authority and implementation".into());
        }
        policy.domain.validate()?;
        let journal = Arc::new(Journal::open(&state.join("funding.sqlite"), &policy)?);
        let mut config = common::kernel_config(key);
        config.policy_hash = digest(&policy)?;
        let mut kernel = ChioKernel::new(config);
        kernel.set_receipt_store_handle(Arc::new(SqliteReceiptStore::open(
            state.join("receipts.sqlite"),
        )?))?;
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.set_revocation_store_handle(Arc::new(authority.revocation_store()));
        kernel.require_durable_request_retention();
        kernel.set_payment_adapter(Box::new(FundingRail {
            journal: journal.clone(),
            operations: authority.admission_operation_store(),
            fence: authority.mutation_fence(),
            policy: policy.clone(),
            source: source.clone(),
            checkpoint: checkpoint.clone(),
        }));
        kernel.register_tool_server(Box::new(W0Tool(
            journal.clone(),
            checkpoint.clone(),
            subcontract,
        )));
        kernel.set_durable_admission_store(
            Arc::new(authority.admission_operation_store()),
            Arc::new(authority.tool_outcome_store()),
            authority.mutation_fence(),
        )?;
        kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
        let recovery_error = if recover {
            kernel
                .reconcile_durable_admission_startup()
                .err()
                .map(|error| error.to_string())
        } else {
            Some("exclusive financial resolution handle cannot admit new work".into())
        };
        Ok(Self {
            kernel,
            authority,
            policy,
            source,
            journal,
            checkpoint,
            recovery_error,
        })
    }

    fn scope() -> ChioScope {
        let amount = MonetaryAmount {
            units: 100,
            currency: CURRENCY.into(),
        };
        ChioScope {
            grants: vec![ToolGrant {
                server_id: SERVER.into(),
                tool_name: "review".into(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: Some(1),
                max_cost_per_invocation: Some(amount.clone()),
                max_total_cost: Some(amount),
                dpop_required: None,
            }],
            ..ChioScope::default()
        }
    }

    pub fn request(&self, id: &str, input: &str, submit_by: u64) -> Result<ToolCallRequest> {
        let duration = submit_by
            .checked_sub(common::now()?)
            .and_then(|remaining| remaining.checked_sub(1))
            .filter(|duration| *duration > 0 && *duration <= 600)
            .ok_or("unsupported original capability lifetime")?;
        let capability =
            self.kernel
                .issue_capability(&self.policy.buyer_key, Self::scope(), duration)?;
        if capability.expires_at > submit_by {
            return Err("capability issuance crossed funding deadline".into());
        }
        Ok(ToolCallRequest {
            request_id: id.into(),
            capability,
            server_id: SERVER.into(),
            tool_name: "review".into(),
            agent_id: self.policy.buyer_key.to_hex(),
            arguments: serde_json::json!({"input": input}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        })
    }

    pub(super) fn operation(
        &self,
        request: &ToolCallRequest,
    ) -> Result<Option<AdmissionOperationV1>> {
        let retained = self
            .authority
            .admission_operation_store()
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
                &self.authority.mutation_fence(),
                super::now_ms()?,
            )?;
        retained
            .map(|(operation, original)| {
                if digest(original.request_for_revalidation())? != digest(request)? {
                    return Err("native original request differs from funded request".into());
                }
                Ok(operation)
            })
            .transpose()
    }

    pub fn execute(
        &self,
        agreement: &SignedAgreement,
        request: &ToolCallRequest,
    ) -> Result<serde_json::Value> {
        let terms = agreement.validate(&self.policy, request)?;
        let allocation = super::allocation::allocation_id(
            &self.policy.domain.chain_id,
            &self.policy.domain.escrow,
            &terms,
        )?;
        if let Some(entry) = self.journal.by_request(&request.request_id)? {
            if entry.allocation != allocation
                || digest(&entry.agreement)? != digest(agreement)?
                || digest(&entry.request)? != digest(request)?
            {
                return Err("funding retry changes original request".into());
            }
            if self.operation(request)?.is_some() {
                let recovery = self.kernel.reconcile_recoverable_admissions();
                let mut report = self.report(request)?;
                if let Err(error) = recovery {
                    report["nativeReconciliationError"] =
                        serde_json::Value::String(error.to_string());
                }
                return Ok(report);
            }
            if entry.operation.is_some() || entry.hold.is_some() {
                return Err("funding binding lost its native authority record".into());
            }
        } else if self.operation(request)?.is_some() {
            return Err("native request exists without its funding journal".into());
        }
        if self.recovery_error.is_some() {
            return Err("native startup reconciliation must close before new funded work".into());
        }
        let time = common::now()?;
        super::finding_acceptance::validate_context(
            &self.policy.finding_context,
            &self.policy.verifier_key,
            &self.policy.provider_key,
            time,
        )?;
        if time >= request.capability.expires_at
            || request.capability.issued_at > time
            || request.capability.issuer != self.policy.provider_key
            || !request.capability.verify_signature_at(time)?
            || request.capability.expires_at > terms.submit_by
        {
            return Err("original funding capability is expired or invalid".into());
        }
        if request.server_id != SERVER
            || request.tool_name != "review"
            || digest(&request.capability.scope)? != digest(&Self::scope())?
            || !request.capability.delegation_chain.is_empty()
            || !request.capability.caveats.is_empty()
            || request.capability.aggregate_invocation_budget.is_some()
            || request.capability.budget_share_bps.is_some()
            || request.dpop_proof.is_some()
            || request.execution_nonce.is_some()
            || request.governed_intent.is_some()
            || request.approval_token.is_some()
            || !request.approval_tokens.is_empty()
            || request.threshold_approval_proposal.is_some()
            || request.supplemental_authorization.is_some()
            || request.model_metadata.is_some()
            || request.federated_origin_kernel_id.is_some()
            || request.declassification_grant.is_some()
            || !super::waiver_terms::supported_arguments(&request.arguments)
            || request.arguments["input"]
                .as_str()
                .is_none_or(|input| input.len() > 64 * 1024)
        {
            return Err("unsupported native funding request profile".into());
        }
        let observed = self.source.observe(&allocation)?;
        let verified =
            observer::verify(&self.policy.domain, &terms, &observed, time, common::now()?)?;
        self.journal.stage(&verified, agreement, request)?;
        (self.checkpoint)("after-stage")?;
        let evaluation = self.kernel.evaluate_tool_call_blocking(request);
        // The rail deliberately cannot settle without an observed contract
        // successor. A retained operation and hold remain inspectable on error.
        match self.report(request) {
            Ok(mut report) => {
                if let Err(error) = evaluation {
                    report["nativeEvaluationError"] = serde_json::Value::String(error.to_string());
                }
                Ok(report)
            }
            Err(error) => match evaluation {
                Err(native) => Err(native.into()),
                Ok(_) => Err(error),
            },
        }
    }

    pub fn evidence(&self, request: &ToolCallRequest) -> Result<super::evidence::Evidence> {
        use chio_kernel::tool_outcome::{InvocationOutputV1, ToolOutcomeStore};
        let report = self.report(request)?;
        let field = |name: &str| -> Result<String> {
            Ok(report[name]
                .as_str()
                .ok_or("native evidence lacks original identity")?
                .to_owned())
        };
        let operation = self
            .operation(request)?
            .ok_or("original operation missing")?;
        let store = self.authority.tool_outcome_store();
        let id = operation.binding().operation_id();
        let outcome = store
            .lookup_by_operation(id)?
            .ok_or("native outcome unavailable")?;
        let raw = store
            .load_raw_invocation_by_operation(id)?
            .ok_or("native return bytes unavailable")?;
        let raw = raw.to_persisted();
        let raw_digest = digest(&raw)?;
        if outcome.operation_id() != id
            || operation.tool_outcome_id() != Some(outcome.outcome_id())
            || outcome.raw_output_digest().as_str() != raw_digest
            || raw.operation_id != *id
            || raw.request_id.as_str() != request.request_id
            || raw.tool_server.as_str() != SERVER
            || raw.tool_name.as_str() != "review"
        {
            return Err("retained native outcome binding mismatch".into());
        }
        let InvocationOutputV1::Value { value: output } = raw.output else {
            return Err("native output is not a completed W0 value".into());
        };
        let entry = self
            .journal
            .by_request(&request.request_id)?
            .ok_or("original funding entry missing")?;
        Ok(super::evidence::Evidence {
            binding: super::evidence::Binding {
                allocation_id: field("allocationId")?,
                agreement_sha256: digest(&entry.agreement.body)?,
                authority_uuid: self.policy.authority_uuid.clone(),
                operation_id: field("operationId")?,
                hold_id: field("holdId")?,
                authorization_id: field("authorizationId")?,
                request_sha256: digest(request)?,
                outcome_id: outcome.outcome_id().as_str().to_owned(),
                raw_outcome_sha256: raw_digest,
                expires_at: entry.agreement.body.work.refund_after,
            },
            input: request.arguments["input"]
                .as_str()
                .ok_or("original W0 input missing")?
                .to_owned(),
            output,
        })
    }

    pub fn report(&self, request: &ToolCallRequest) -> Result<serde_json::Value> {
        let entry = self
            .journal
            .by_request(&request.request_id)?
            .ok_or("funding journal missing")?;
        let terms = entry.agreement.validate(&self.policy, request)?;
        if entry.allocation
            != super::allocation::allocation_id(
                &self.policy.domain.chain_id,
                &self.policy.domain.escrow,
                &terms,
            )?
        {
            return Err("funding journal allocation identity changed".into());
        }
        let operation = self
            .operation(request)?
            .ok_or("native funding operation missing")?;
        let id = operation.binding().operation_id().as_str();
        let payment = self
            .authority
            .admission_operation_store()
            .load_payment_journal(id, &self.authority.mutation_fence())?;
        if operation.payment_participant_id().is_some() != payment.is_some() {
            return Err("native payment participant and journal disagree".into());
        }
        // Prepared admission can stop before any payment participant exists.
        // Preserve its identity without inventing a hold or authorization.
        let native_authorization = payment.as_ref().and_then(|p| p.authorization_id.as_deref());
        let hold = payment
            .as_ref()
            .and_then(|p| p.hold_id.as_deref())
            .or_else(|| operation.budget_hold_id().map(|id| id.as_str()));
        let authorization = match (entry.operation.as_deref(), entry.hold.as_deref()) {
            (Some(bound), Some(bound_hold))
                if payment.is_some() && bound == id && Some(bound_hold) == hold =>
            {
                Some(super::rail::authorization_id(&entry.allocation)?)
            }
            (None, None) if native_authorization.is_none() => None,
            _ => return Err("funding correlation conflicts with native identity".into()),
        };
        if native_authorization.is_some_and(|id| Some(id) != authorization.as_deref()) {
            return Err("native payment authorization conflicts with funding journal".into());
        }
        let correlated = authorization.is_some();
        let (terminal, observation_error) = match super::rail::observed_terminal(
            &entry,
            &self.policy,
            &self.journal,
            self.source.as_ref(),
        ) {
            Ok(result) => (result, None),
            Err(error) => (None, Some(error.to_string())),
        };
        let payment_state = match terminal.as_ref().map(|r| r.settlement_status) {
            Some(chio_kernel::payment::RailSettlementStatus::Settled) => "paid",
            Some(chio_kernel::payment::RailSettlementStatus::Released) => "refunded",
            _ if correlated => "pending",
            _ => "not_authorized",
        };
        Ok(
            serde_json::json!({"allocationId": entry.allocation, "operationId": id,
            "holdId": hold, "authorizationId": authorization,
            "nativeAuthorizationId": native_authorization, "startupReconciliationError": self.recovery_error,
            "requestId": request.request_id, "authorityUuid": self.policy.authority_uuid,
            "nativeState": format!("{:?}", operation.state()), "nativePaymentState": payment.as_ref().map(|p| format!("{:?}", p.state)),
            "nativePaymentAction": payment.as_ref().and_then(|p| p.settle_action),
            "fundingCorrelation": if correlated { "bound" } else { "not_authorized" },
            "paymentState": payment_state, "settlementObservationError": observation_error,
            "externalFundsTransferred": terminal.is_some(), "settlementTransaction":terminal.as_ref().map(|r| &r.transaction_id),
            "executions": self.journal.execution_count()?, "profile": observer::PROFILE}),
        )
    }
}
