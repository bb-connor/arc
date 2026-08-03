impl BrokerExecutionBudget for AuthoritativeBrokerExecutionAdapter {
    fn capabilities(&self) -> ExecutionAuthorityCapabilities {
        ExecutionAuthorityCapabilities {
            profile: ExecutionAuthorityProfile::AuthoritativeHoldEvent,
            atomic_multi_key_holds: true,
            combined_capture_and_revocation: true,
            query_by_id: true,
            shared_revocation_write_domain: true,
        }
    }

    fn query_execution_hold(
        &self,
        request: &QueryExecutionHoldRequest,
    ) -> BrokerResult<ExecutionHoldState> {
        let Some(prepared) = self.prepared_for_query(request)? else {
            return Ok(ExecutionHoldState::Unknown);
        };
        self.validate_operation_binding(&prepared, false)
            .map_err(integration_as_broker)?;
        let capture_request = Self::capture_request(&prepared)?;
        if let Some(decision) = self
            .capture
            .query_admission_capture(&capture_request)
            .map_err(capture_as_broker)?
        {
            return self.map_capture(&prepared, decision);
        }
        if let Some(reverse) = self
            .budget
            .query_composite_hold_mutation(&prepared.reverse_event_id)
            .map_err(budget_as_broker)?
        {
            if reverse.hold_id.as_deref() != Some(prepared.authorization.hold_id.as_str())
                || reverse.invocation_state != BudgetInvocationReservationState::Reversed
                || reverse.metadata.event_id.as_deref() != Some(prepared.reverse_event_id.as_str())
            {
                return Err(BrokerError::Invariant(
                    "persisted reverse event diverges from the prepared admission".to_string(),
                ));
            }
            return Ok(ExecutionHoldState::Reversed);
        }
        if let Some(decision) = self
            .budget
            .query_composite_authorization(&prepared.authorization.event_id)
            .map_err(budget_as_broker)?
        {
            return self.map_authorization(&prepared, decision);
        }
        Ok(ExecutionHoldState::Unknown)
    }

    fn authorize_execution_hold(
        &self,
        request: &AuthorizeExecutionHoldRequest,
    ) -> BrokerResult<ExecutionHoldState> {
        let Some(prepared) = self.prepared_for_authorize(request)? else {
            return Ok(ExecutionHoldState::Unknown);
        };
        self.validate_operation_binding(&prepared, false)
            .map_err(integration_as_broker)?;
        let Some(decision) = self
            .budget
            .query_composite_authorization(&prepared.authorization.event_id)
            .map_err(budget_as_broker)?
        else {
            return Ok(ExecutionHoldState::Unknown);
        };
        self.map_authorization(&prepared, decision)
    }

    fn reverse_execution_hold(
        &self,
        request: &ReverseExecutionHoldRequest,
    ) -> BrokerResult<ExecutionHoldState> {
        request.validate()?;
        let admission = self
            .registry
            .load_by_operation(&request.operation_id)
            .map_err(integration_as_broker)?
            .ok_or_else(|| {
                BrokerError::AuthorityUnavailable(
                    "broker reverse has no trusted prepared admission".to_string(),
                )
            })?;
        let prepared = self
            .rehydrate_prepared(admission)
            .map_err(integration_as_broker)?
            .ok_or_else(|| {
                BrokerError::AuthorityUnavailable(
                    "broker reverse has no durable kernel authorization".to_string(),
                )
            })?;
        self.validate_operation_binding(&prepared, false)
            .map_err(integration_as_broker)?;
        if request.invocation_id != prepared.invocation_id
            || request.parent_capability_id != prepared.authorization.capability_id
            || request.broker_capability_id != prepared.broker_capability_id
            || request.hold_id != prepared.authorization.hold_id
            || request.reverse_event_id != prepared.reverse_event_id
        {
            return Err(BrokerError::AuthorizationDenied(
                "broker reverse does not match the trusted prepared admission".to_string(),
            ));
        }
        self.query_execution_hold(&QueryExecutionHoldRequest {
            operation_id: request.operation_id.clone(),
            invocation_id: request.invocation_id.clone(),
            parent_capability_id: request.parent_capability_id.clone(),
            broker_capability_id: request.broker_capability_id.clone(),
            hold_id: request.hold_id.clone(),
            authorize_event_id: prepared.authorization.event_id.clone(),
            reverse_event_id: request.reverse_event_id.clone(),
            capture_event_id: prepared.capture_event_id,
        })
    }

    fn capture_execution_hold(
        &self,
        request: &CaptureExecutionHoldRequest,
    ) -> BrokerResult<ExecutionHoldState> {
        request.validate()?;
        let admission = self
            .registry
            .load_by_operation(&request.operation_id)
            .map_err(integration_as_broker)?
            .ok_or_else(|| {
                BrokerError::AuthorityUnavailable(
                    "broker capture has no trusted prepared admission".to_string(),
                )
            })?;
        let prepared = self
            .rehydrate_prepared(admission)
            .map_err(integration_as_broker)?
            .ok_or_else(|| {
                BrokerError::AuthorityUnavailable(
                    "broker capture has no durable kernel authorization".to_string(),
                )
            })?;
        if request.invocation_id != prepared.invocation_id
            || request.parent_capability_id != prepared.authorization.capability_id
            || request.broker_capability_id != prepared.broker_capability_id
            || request.hold_id != prepared.authorization.hold_id
            || request.capture_event_id != prepared.capture_event_id
            || request.revocation_ids != prepared.authorization.revocation_set.ids()
            || request.revocation_set_digest != prepared.authorization.revocation_set.digest()
            || prepared.authorization.authorization_artifact_digests
                != [request.authorization_artifact_digest.clone()]
            || request.authority_metadata_digest
                != prepared.trusted_context.authority_metadata_digest
        {
            return Err(BrokerError::AuthorizationDenied(
                "broker capture does not match the trusted prepared admission".to_string(),
            ));
        }
        self.validate_operation_binding(&prepared, true)
            .map_err(integration_as_broker)?;
        let capture_request = Self::capture_request(&prepared)?;
        let Some(decision) = self
            .capture
            .query_admission_capture(&capture_request)
            .map_err(capture_as_broker)?
        else {
            return Ok(ExecutionHoldState::Unknown);
        };
        self.map_capture(&prepared, decision)
    }
}

fn validate_internal_quotas(
    quotas: &[BudgetInvocationQuota],
) -> Result<(), BrokerIntegrationError> {
    if quotas.len() < 2 || quotas.len() > 8 {
        return Err(BrokerIntegrationError::InvalidConfiguration(
            "broker admission requires parent and supplemental invocation quotas".to_string(),
        ));
    }
    for quota in quotas {
        quota.validate()?;
    }
    if quotas.windows(2).any(|pair| pair[0].key() >= pair[1].key()) {
        return Err(BrokerIntegrationError::InvalidConfiguration(
            "internal invocation quotas are not strictly sorted".to_string(),
        ));
    }
    if quotas
        .iter()
        .filter(|quota| quota.key().profile() == BudgetQuotaProfile::SupplementalBrokerExecution)
        .count()
        != 1
    {
        return Err(BrokerIntegrationError::InvalidConfiguration(
            "broker admission requires exactly one supplemental execution quota".to_string(),
        ));
    }
    Ok(())
}

fn validate_aggregate_family_evidence(
    quotas: &[BudgetInvocationQuota],
    revocation_set: &CanonicalRevocationSet,
    evidence: Option<&SqliteAggregateFamilyEvidence>,
) -> Result<(), BrokerIntegrationError> {
    let family_quota_count = quotas
        .iter()
        .filter(|quota| quota.key().profile() == BudgetQuotaProfile::AggregateFamilyInvocation)
        .count();
    match (family_quota_count, evidence) {
        (0, None) => Ok(()),
        (1, Some(evidence)) => {
            validate_identifier(
                &evidence.root_capability_id,
                "aggregate family root capability id",
            )?;
            if evidence.root_binding_digest.len() != 64
                || !evidence
                    .root_binding_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(BrokerIntegrationError::InvalidConfiguration(
                    "aggregate family root binding digest must be lowercase SHA-256 hex"
                        .to_string(),
                ));
            }
            if revocation_set
                .ids()
                .binary_search(&evidence.root_capability_id)
                .is_err()
            {
                return Err(BrokerIntegrationError::InvalidConfiguration(
                    "broker revocation set omits the aggregate family root".to_string(),
                ));
            }
            Ok(())
        }
        (0, Some(_)) => Err(BrokerIntegrationError::InvalidConfiguration(
            "aggregate family evidence requires an aggregate family quota".to_string(),
        )),
        (1, None) => Err(BrokerIntegrationError::InvalidConfiguration(
            "aggregate family quota requires authenticated root evidence".to_string(),
        )),
        (_, _) => Err(BrokerIntegrationError::InvalidConfiguration(
            "broker admission contains multiple aggregate family quotas".to_string(),
        )),
    }
}

fn broker_quota_projection(
    quotas: &[BudgetInvocationQuota],
    signed_broker_key_id: &str,
    signed_broker_maximum: u32,
) -> Result<Vec<ExecutionQuota>, BrokerIntegrationError> {
    let mut projected = Vec::with_capacity(quotas.len());
    for quota in quotas {
        let key_id = if quota.key().profile() == BudgetQuotaProfile::SupplementalBrokerExecution {
            if quota.max_invocations() != signed_broker_maximum {
                return Err(BrokerIntegrationError::InvalidConfiguration(
                    "supplemental quota maximum differs from the signed broker capability"
                        .to_string(),
                ));
            }
            signed_broker_key_id.to_string()
        } else {
            kernel_quota_id(quota)?
        };
        projected.push(ExecutionQuota {
            key_id,
            maximum_executions: quota.max_invocations(),
        });
    }
    canonicalize_quotas(projected).map_err(BrokerIntegrationError::from)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KernelQuotaIdentity<'a> {
    profile: &'a str,
    owner_id: &'a str,
    grant_index: Option<u32>,
}

fn kernel_quota_id(quota: &BudgetInvocationQuota) -> Result<String, BrokerIntegrationError> {
    let canonical = canonical_json_bytes(&KernelQuotaIdentity {
        profile: quota.key().profile().as_str(),
        owner_id: quota.key().owner_id(),
        grant_index: quota.key().grant_index(),
    })
    .map_err(|error| {
        BrokerIntegrationError::InvalidConfiguration(format!(
            "kernel quota identity encoding failed: {error}"
        ))
    })?;
    let mut input = Vec::with_capacity(KERNEL_QUOTA_ID_DOMAIN.len() + canonical.len());
    input.extend_from_slice(KERNEL_QUOTA_ID_DOMAIN);
    input.extend_from_slice(&canonical);
    Ok(format!("kernel-quota-{}", sha256_hex(&input)))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrokerAuthorityMetadata<'a> {
    schema: &'static str,
    authority_id: &'a str,
    lease_id: &'a str,
    lease_epoch: u64,
    guarantee_level: &'a str,
    budget_profile: &'a str,
    metering_profile: &'a str,
    revocation_authority_domain: &'a str,
    supplemental_verifier_id: &'a str,
}

fn authority_metadata_digest(
    authority: &BudgetEventAuthority,
    config: &AuthoritativeBrokerExecutionConfig,
    budget: &SqliteBudgetStore,
) -> Result<String, BrokerIntegrationError> {
    let canonical = canonical_json_bytes(&BrokerAuthorityMetadata {
        schema: "chio.broker-authority-metadata.v1",
        authority_id: &authority.authority_id,
        lease_id: &authority.lease_id,
        lease_epoch: authority.lease_epoch,
        guarantee_level: budget.budget_guarantee_level().as_str(),
        budget_profile: budget.budget_authority_profile().as_str(),
        metering_profile: budget.budget_metering_profile().as_str(),
        revocation_authority_domain: &config.revocation_authority_domain,
        supplemental_verifier_id: &config.supplemental_verifier_id,
    })
    .map_err(|error| {
        BrokerIntegrationError::InvalidConfiguration(format!(
            "broker authority metadata encoding failed: {error}"
        ))
    })?;
    let mut input = Vec::with_capacity(BROKER_AUTHORITY_METADATA_DOMAIN.len() + canonical.len());
    input.extend_from_slice(BROKER_AUTHORITY_METADATA_DOMAIN);
    input.extend_from_slice(&canonical);
    Ok(sha256_hex(&input))
}

fn validate_identifier(value: &str, label: &str) -> Result<(), BrokerIntegrationError> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} is empty, oversized, padded, or contains a control byte"
        )));
    }
    Ok(())
}

fn integration_as_broker(error: BrokerIntegrationError) -> BrokerError {
    BrokerError::AuthorityUnavailable(error.to_string())
}

fn budget_as_broker(error: BudgetStoreError) -> BrokerError {
    BrokerError::AuthorityUnavailable(format!("authoritative budget store failed: {error}"))
}

fn capture_as_broker(error: AdmissionCaptureError) -> BrokerError {
    BrokerError::AuthorityUnavailable(format!("combined admission capture failed: {error}"))
}

#[derive(Default)]
pub struct BrokerIntegrationRuntimeParts {
    supplemental_verifier: Option<Arc<BrokerSupplementalQuotaVerifier>>,
    execution_authority: Option<Arc<AuthoritativeBrokerExecutionAdapter>>,
    admin_authorizer: Option<Arc<GovernedAdminAuthorizer>>,
    receipt_sink: Option<Arc<SqliteBrokerReceiptSink>>,
}

impl BrokerIntegrationRuntimeParts {
    pub fn with_supplemental_verifier(
        mut self,
        verifier: Arc<BrokerSupplementalQuotaVerifier>,
    ) -> Self {
        self.supplemental_verifier = Some(verifier);
        self
    }

    pub fn with_execution_authority(
        mut self,
        authority: Arc<AuthoritativeBrokerExecutionAdapter>,
    ) -> Self {
        self.execution_authority = Some(authority);
        self
    }

    pub fn with_admin_authorizer(mut self, authorizer: Arc<GovernedAdminAuthorizer>) -> Self {
        self.admin_authorizer = Some(authorizer);
        self
    }

    pub fn with_receipt_sink(mut self, sink: Arc<SqliteBrokerReceiptSink>) -> Self {
        self.receipt_sink = Some(sink);
        self
    }

    pub fn build(self) -> Result<BrokerIntegrationRuntime, BrokerIntegrationError> {
        let supplemental_verifier =
            self.supplemental_verifier
                .ok_or(BrokerIntegrationError::MissingComponent(
                    "supplemental quota verifier",
                ))?;
        let execution_authority =
            self.execution_authority
                .ok_or(BrokerIntegrationError::MissingComponent(
                    "authoritative budget and capture adapter",
                ))?;
        let admin_authorizer =
            self.admin_authorizer
                .ok_or(BrokerIntegrationError::MissingComponent(
                    "governed admin authorizer",
                ))?;
        let receipt_sink = self
            .receipt_sink
            .ok_or(BrokerIntegrationError::MissingComponent(
                "durable broker receipt sink",
            ))?;
        if supplemental_verifier.verifier_id() != execution_authority.supplemental_verifier_id() {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "supplemental verifier and execution authority IDs differ".to_string(),
            ));
        }
        execution_authority.capabilities().require_production()?;
        Ok(BrokerIntegrationRuntime {
            supplemental_verifier,
            execution_authority,
            admin_authorizer,
            receipt_sink,
        })
    }
}

pub struct BrokerIntegrationRuntime {
    supplemental_verifier: Arc<BrokerSupplementalQuotaVerifier>,
    execution_authority: Arc<AuthoritativeBrokerExecutionAdapter>,
    admin_authorizer: Arc<GovernedAdminAuthorizer>,
    receipt_sink: Arc<SqliteBrokerReceiptSink>,
}

pub trait BrokerControlAuthority: Send + Sync {
    fn control(&self, request: &AuthorityControlRequest) -> BrokerResult<Vec<u8>>;
}

pub struct BrokerAuthorityRpcHandler {
    runtime: Arc<BrokerIntegrationRuntime>,
    liveness: Arc<dyn CapabilityLiveness>,
    revocations: Arc<dyn BrokerRevocations>,
    control: Arc<dyn BrokerControlAuthority>,
}

impl BrokerAuthorityRpcHandler {
    pub fn new(
        runtime: Arc<BrokerIntegrationRuntime>,
        liveness: Arc<dyn CapabilityLiveness>,
        revocations: Arc<dyn BrokerRevocations>,
        control: Arc<dyn BrokerControlAuthority>,
    ) -> Result<Self, BrokerIntegrationError> {
        runtime
            .concrete_execution_authority()
            .capabilities()
            .require_production()?;
        Ok(Self {
            runtime,
            liveness,
            revocations,
            control,
        })
    }
}

impl BrokerAuthorityHandler for BrokerAuthorityRpcHandler {
    fn handle(&self, operation: &AuthorityOperation) -> BrokerResult<AuthorityResult> {
        let execution = self.runtime.concrete_execution_authority();
        match operation {
            AuthorityOperation::Capabilities => {
                Ok(AuthorityResult::Capabilities(execution.capabilities()))
            }
            AuthorityOperation::PrepareExecution(request) => execution
                .trusted_context_for(request.as_ref())
                .map(AuthorityResult::Prepared)
                .map_err(integration_as_broker),
            AuthorityOperation::VerifyLiveParent(request) => self
                .liveness
                .verify_live_parent(request)
                .map(AuthorityResult::LiveParent),
            AuthorityOperation::CheckBrokerRevocation(request) => self
                .revocations
                .check_broker_revocation(request)
                .map(AuthorityResult::Revocation),
            AuthorityOperation::QueryExecutionHold(request) => execution
                .query_execution_hold(request)
                .map(AuthorityResult::Hold),
            AuthorityOperation::AuthorizeExecutionHold(request) => execution
                .authorize_execution_hold(request)
                .map(AuthorityResult::Hold),
            AuthorityOperation::ReverseExecutionHold(request) => execution
                .reverse_execution_hold(request)
                .map(AuthorityResult::Hold),
            AuthorityOperation::CaptureExecutionHold(request) => execution
                .capture_execution_hold(request)
                .map(AuthorityResult::Hold),
            AuthorityOperation::Control(request) => {
                self.control.control(request).map(AuthorityResult::Control)
            }
        }
    }
}

impl BrokerIntegrationRuntime {
    pub fn supplemental_verifier(&self) -> Arc<dyn SupplementalQuotaVerifier> {
        Arc::clone(&self.supplemental_verifier) as Arc<dyn SupplementalQuotaVerifier>
    }

    pub fn broker_destination(&self) -> &SupplementalQuotaDestination {
        self.supplemental_verifier.broker_destination()
    }

    pub fn execution_authority(&self) -> Arc<dyn BrokerExecutionBudget> {
        Arc::clone(&self.execution_authority) as Arc<dyn BrokerExecutionBudget>
    }

    pub fn concrete_execution_authority(&self) -> Arc<AuthoritativeBrokerExecutionAdapter> {
        Arc::clone(&self.execution_authority)
    }

    pub fn admin_authorizer(&self) -> Arc<GovernedAdminAuthorizer> {
        Arc::clone(&self.admin_authorizer)
    }

    pub fn receipt_sink(&self) -> Arc<SqliteBrokerReceiptSink> {
        Arc::clone(&self.receipt_sink)
    }

    /// Install the complete broker quota authority set into an already
    /// durable kernel composition. The admission-operation store must be
    /// installed first so activation cannot advertise a partial runtime.
    pub fn install_kernel_admission(
        &self,
        kernel: &mut chio_kernel::ChioKernel,
    ) -> Result<(), BrokerIntegrationError> {
        let authority = self.concrete_execution_authority();
        kernel.set_budget_store_handle(authority.budget_store())?;
        // General kernel configuration may have installed the managed SQLite
        // revocation reader. Replace it with the combined writer so kernel
        // revocations share the capture authority's linear commit stream.
        kernel.set_revocation_store_handle(authority.revocation_store());
        kernel.set_supplemental_quota_verifier(self.supplemental_verifier())?;
        kernel.set_supplemental_admission_registrar(
            Arc::clone(&authority) as Arc<dyn SupplementalAdmissionRegistrar>
        )?;
        kernel.set_admission_capture_authority(authority.admission_capture_authority())?;
        kernel.enable_aggregate_invocation_admission()?;
        kernel.enable_supplemental_broker_admission()?;
        Ok(())
    }
}
