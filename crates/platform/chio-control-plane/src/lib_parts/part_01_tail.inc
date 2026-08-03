struct KeyringAuthorityArtifactTrustResolver {
    store: Arc<chio_keyring::SqliteKeyLogStore>,
    migration_binding: security::EnterpriseMigrationRuntimeBinding,
}

fn key_enterprise_receipt_to_chio_receipt(
    enterprise_receipt: &chio_keyring::SignedKeyEnterpriseReceipt,
    operator_backend: &dyn SigningBackend,
    configuration_binding: chio_core::Hash,
) -> Result<chio_core::receipt::body::ChioReceipt, CliError> {
    use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
    use chio_core::receipt::decision::ToolCallAction;
    use chio_core::receipt::kinds::{
        BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    };
    use chio_core::receipt::metadata::ActorRef;

    enterprise_receipt
        .verify_operator(&operator_backend.public_key())
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let canonical = enterprise_receipt
        .canonical_bytes()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let action = ToolCallAction::from_parameters(serde_json::json!({
        "eventId": enterprise_receipt.body.event_id.as_str(),
        "eventSequence": enterprise_receipt.body.event_sequence,
        "receiptId": &enterprise_receipt.body.receipt_id,
        "stage": enterprise_receipt.body.stage,
    }))?;
    let body = ChioReceiptBody {
        id: enterprise_receipt.body.receipt_id.clone(),
        timestamp: enterprise_receipt.body.issued_at.div_ceil(1_000),
        capability_id: enterprise_receipt.body.transaction_id.clone(),
        tool_server: "chio.keyring".to_string(),
        tool_name: "authority_key_transition".to_string(),
        action,
        decision: None,
        receipt_kind: ReceiptKind::TraceObservation,
        boundary_class: BoundaryClass::DetectOnly,
        observation_outcome: Some(ObservationOutcome::Observed),
        tool_origin: ToolOrigin::ChioInternal,
        redaction_mode: RedactionMode::Redacted,
        actor_chain: vec![ActorRef {
            actor_id: enterprise_receipt.body.operator_key_id.to_string(),
            actor_kind: Some("key_log_operator".to_string()),
        }],
        content_hash: chio_core::crypto::sha256_hex(&canonical),
        policy_hash: configuration_binding.to_string(),
        evidence: Vec::new(),
        metadata: Some(serde_json::json!({
            "keyEnterpriseReceipt": enterprise_receipt,
        })),
        trust_level: TrustLevel::Verified,
        tenant_id: None,
        kernel_key: operator_backend.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign_with_backend(body, operator_backend)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

fn persist_key_enterprise_receipt(
    enterprise_receipt: &chio_keyring::SignedKeyEnterpriseReceipt,
    operator_backend: &dyn SigningBackend,
    configuration_binding: chio_core::Hash,
    receipt_store: &dyn chio_kernel::ReceiptStore,
    migration_binding: &security::EnterpriseMigrationRuntimeBinding,
) -> Result<bool, CliError> {
    migration_binding.require_enforced().map_err(|error| {
        CliError::cli_other_error(format!(
            "key-log verification migration denied enterprise receipt verification: {error}"
        ))
    })?;
    let receipt = key_enterprise_receipt_to_chio_receipt(
        enterprise_receipt,
        operator_backend,
        configuration_binding,
    )?;
    match receipt_store.load_chio_receipt(&receipt.id)? {
        Some(existing)
            if chio_core::canonical::canonical_json_bytes(&existing)?
                == chio_core::canonical::canonical_json_bytes(&receipt)? =>
        {
            Ok(false)
        }
        Some(_) => Err(CliError::cli_other_error(
            "normal receipt store contains conflicting key-enterprise evidence".to_string(),
        )),
        None => {
            migration_binding.require_enforced().map_err(|error| {
                CliError::cli_other_error(format!(
                    "key-log verification migration denied enterprise receipt persistence: {error}"
                ))
            })?;
            receipt_store.append_chio_receipt(&receipt)?;
            Ok(true)
        }
    }
}

impl chio_kernel::AuthorityArtifactTrustResolver for KeyringAuthorityArtifactTrustResolver {
    fn trusted_issuer_for_artifact(
        &self,
        artifact: &[u8],
        claimed_issuer: &chio_core::PublicKey,
        signature: &chio_core::Signature,
    ) -> Result<Option<chio_core::PublicKey>, String> {
        self.migration_binding.require_enforced().map_err(|error| {
            format!("key-log verification migration denied artifact verification: {error}")
        })?;
        let trusted = self
            .store
            .verify_artifact_with_trusted_time(artifact, claimed_issuer, signature)
            .map_err(|error| error.to_string())?;
        self.migration_binding.require_enforced().map_err(|error| {
            format!("key-log verification migration changed during artifact verification: {error}")
        })?;
        Ok(Some(trusted))
    }
}

pub fn configure_receipt_store(
    kernel: &mut ChioKernel,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    control_authority_public_key: Option<&chio_core::PublicKey>,
    control_authority_trusted_public_keys: &[chio_core::PublicKey],
) -> Result<Option<Arc<dyn chio_kernel::ReceiptStore>>, CliError> {
    configure_receipt_store_inner(
        kernel,
        receipt_db_path,
        control_url,
        control_token,
        control_authority_public_key,
        control_authority_trusted_public_keys,
        None,
    )
}

pub fn configure_receipt_store_with_remote_authority_trust(
    kernel: &mut ChioKernel,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    control_authority_public_key: Option<&chio_core::PublicKey>,
    control_authority_trusted_public_keys: &[chio_core::PublicKey],
    remote_authority_trust: Arc<
        trust_control::service_runtime::remote_authority::RemoteControlAuthorityTrust,
    >,
) -> Result<Option<Arc<dyn chio_kernel::ReceiptStore>>, CliError> {
    configure_receipt_store_inner(
        kernel,
        receipt_db_path,
        control_url,
        control_token,
        control_authority_public_key,
        control_authority_trusted_public_keys,
        Some(remote_authority_trust),
    )
}

fn configure_receipt_store_inner(
    kernel: &mut ChioKernel,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    control_authority_public_key: Option<&chio_core::PublicKey>,
    control_authority_trusted_public_keys: &[chio_core::PublicKey],
    remote_authority_trust: Option<Arc<
        trust_control::service_runtime::remote_authority::RemoteControlAuthorityTrust,
    >>,
) -> Result<Option<Arc<dyn chio_kernel::ReceiptStore>>, CliError> {
    if control_url.is_some() && kernel.requires_web3_evidence() {
        return Err(chio_kernel::KernelError::Web3EvidenceUnavailable(
            "web3-enabled deployments require local receipt persistence with kernel-signed checkpoint support; append-only remote receipt mirrors are unsupported".to_string(),
        )
        .into());
    }
    let configured = match (receipt_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::cli_other_error(
                "use either --receipt-db or --control-url for receipt persistence, not both"
                    .to_string(),
            ));
        }
        (Some(path), None) => {
            if path
                .to_str()
                .is_some_and(chio_store_sqlite::is_in_memory_sqlite_path)
            {
                return Err(CliError::cli_other_error(
                    "refusing to attach an in-memory receipt database as a durable store: an \
                     in-memory SQLite path loses every receipt on restart. Point --receipt-db at \
                     a filesystem path for durable receipts, or omit it and set \
                     allow_ephemeral_receipt_log in policy to run with an in-memory receipt log."
                        .to_string(),
                ));
            }
            kernel.validate_web3_evidence_receipt_store(true)?;
            let store = Arc::new(chio_store_sqlite::SqliteReceiptStore::open(path)?);
            let receipt_store: Arc<dyn chio_kernel::ReceiptStore> = store.clone();
            let root_resolver: Arc<
                dyn chio_core::capability::aggregate_budget::AggregateFamilyRootResolver
                    + Send
                    + Sync,
            > = store;
            kernel.set_receipt_store_handle(Arc::clone(&receipt_store))?;
            kernel.set_aggregate_family_root_resolver(root_resolver);
            Some(receipt_store)
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            control_authority_public_key.ok_or_else(|| {
                CliError::cli_other_error(
                    "remote aggregate family-root resolution requires an independently pinned control-authority public key"
                        .to_string(),
                )
            })?;
            let receipt_store: Arc<dyn chio_kernel::ReceiptStore> = Arc::from(
                trust_control::service_runtime::remote_stores::build_remote_receipt_store(
                    url, token,
                )?,
            );
            let root_resolver = match remote_authority_trust {
                Some(remote_authority_trust) => trust_control::service_runtime::remote_root_resolver::build_remote_aggregate_family_root_resolver(
                    url, token, remote_authority_trust,
                )?,
                None => {
                    let pinned = trust_control::service_runtime::PinnedControlAuthority::new(
                        control_authority_public_key
                            .cloned()
                            .ok_or_else(|| {
                                CliError::cli_other_error(
                                    "remote aggregate family-root resolution requires an independently pinned control-authority public key"
                                        .to_string(),
                                )
                            })?,
                        control_authority_trusted_public_keys.to_vec(),
                    )?;
                    trust_control::service_runtime::remote_root_resolver::build_remote_aggregate_family_root_resolver_with_pinned_authority(
                        url, token, pinned,
                    )?
                }
            };
            kernel.set_receipt_store_handle(Arc::clone(&receipt_store))?;
            kernel.set_aggregate_family_root_resolver(root_resolver);
            Some(receipt_store)
        }
        (None, None) => None,
    };
    kernel.validate_web3_evidence_prerequisites()?;
    Ok(configured)
}

pub fn configure_revocation_store(
    kernel: &mut ChioKernel,
    revocation_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (revocation_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::cli_other_error(
                "use either --revocation-db or --control-url for revocation state, not both"
                    .to_string(),
            ));
        }
        (Some(path), None) => {
            kernel.set_revocation_store(Box::new(chio_store_sqlite::SqliteRevocationStore::open(
                path,
            )?));
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_revocation_store(
                trust_control::service_runtime::remote_stores::build_remote_revocation_store(
                    url, token,
                )?,
            );
        }
        (None, None) => {}
    }
    Ok(())
}

#[derive(Clone)]
pub struct RemoteCapabilityAuthorityWorkloadConfig {
    pub tenant_id: String,
    pub workload_id: String,
    pub server_id: String,
    pub workload_signer: Keypair,
    pub session_admission_signer: Keypair,
    pub authority_successors:
        Vec<trust_control::service_runtime::PinnedAuthoritySuccessor>,
    pub authority_trust:
        Arc<trust_control::service_runtime::remote_authority::RemoteControlAuthorityTrust>,
}

pub fn configure_capability_authority(
    kernel: &mut ChioKernel,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    control_authority_public_key: Option<&chio_core::PublicKey>,
    control_authority_trusted_public_keys: &[chio_core::PublicKey],
    remote_workload: Option<RemoteCapabilityAuthorityWorkloadConfig>,
    issuance_policy: Option<policy::ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<policy::RuntimeAssuranceIssuancePolicy>,
) -> Result<(), CliError> {
    if control_url.is_some() && (authority_seed_path.is_some() || authority_db_path.is_some()) {
        return Err(CliError::cli_other_error(
            "remote control authority cannot be combined with local authority custody"
                .to_string(),
        ));
    }
    if control_url.is_none() && remote_workload.is_some() {
        return Err(CliError::cli_other_error(
            "remote authority workload custody requires --control-url".to_string(),
        ));
    }
    if authority_seed_path.is_some() && authority_db_path.is_some() {
        return Err(CliError::cli_other_error(
            "use either --authority-seed-file or --authority-db, not both".to_string(),
        ));
    }
    if authority_seed_path.is_none() && authority_db_path.is_none() {
        if let Some(url) = control_url {
            if issuance_policy.is_some() || runtime_assurance_policy.is_some() {
                return Err(CliError::cli_other_error(
                    "remote capability issuance policy must be configured on the trust service"
                        .to_string(),
                ));
            }
            let token = require_control_token(control_token)?;
            let current = control_authority_public_key.ok_or_else(|| {
                CliError::cli_other_error(
                    "remote capability issuance requires an independently pinned control-authority public key"
                        .to_string(),
                )
            })?;
            let remote_workload = remote_workload.ok_or_else(|| {
                CliError::cli_other_error(
                    "remote capability issuance requires fixed workload and session-admission signer custody"
                        .to_string(),
                )
            })?;
            let pinned = trust_control::service_runtime::PinnedControlAuthority::with_successors(
                current.clone(),
                control_authority_trusted_public_keys.to_vec(),
                remote_workload.authority_successors.clone(),
            )?;
            let authority =
                trust_control::service_runtime::remote_authority::build_remote_capability_authority(
                    url,
                    token,
                    pinned,
                    remote_workload.authority_trust,
                    &remote_workload.tenant_id,
                    &remote_workload.workload_id,
                    &remote_workload.server_id,
                    remote_workload.workload_signer,
                    remote_workload.session_admission_signer,
                )?;
            kernel.set_external_capability_authority(authority)?;
            kernel.seal_authority_composition();
            return Ok(());
        }
    }

    match (authority_seed_path, authority_db_path) {
        (Some(_), Some(_)) => {
            return Err(CliError::cli_other_error(
                "use either --authority-seed-file or --authority-db, not both".to_string(),
            ));
        }
        (Some(path), None) => {
            let keypair = load_or_create_authority_keypair(path)?;
            if keypair.public_key() != kernel.public_key() {
                return Err(CliError::cli_other_error(
                    "authority seed must be selected as the kernel signer before runtime construction"
                        .to_string(),
                ));
            }
            kernel.set_capability_authority(issuance::wrap_capability_authority(
                kernel.governed_capability_authority(),
                issuance_policy,
                runtime_assurance_policy,
                receipt_db_path,
                budget_db_path,
            )?)?;
        }
        (None, Some(path)) => {
            let keypair = chio_store_sqlite::SqliteCapabilityAuthority::open_existing(path)?
                .local_keypair()?;
            if keypair.public_key() != kernel.public_key() {
                return Err(CliError::cli_other_error(
                    "SQLite authority must be selected as the kernel signer before runtime construction"
                        .to_string(),
                ));
            }
            kernel.set_capability_authority(issuance::wrap_capability_authority(
                kernel.governed_capability_authority(),
                issuance_policy,
                runtime_assurance_policy,
                receipt_db_path,
                budget_db_path,
            )?)?;
        }
        (None, None) => {
            if issuance_policy.is_some()
                || runtime_assurance_policy.is_some()
                || receipt_db_path.is_some()
            {
                kernel.set_capability_authority(issuance::wrap_capability_authority(
                    kernel.governed_capability_authority(),
                    issuance_policy,
                    runtime_assurance_policy,
                    receipt_db_path,
                    budget_db_path,
                )?)?;
            }
        }
    }
    kernel.seal_authority_composition();
    Ok(())
}

pub fn configure_budget_store(
    kernel: &mut ChioKernel,
    budget_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (budget_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::cli_other_error(
                "use either --budget-db or --control-url for budget state, not both".to_string(),
            ));
        }
        (Some(path), None) => {
            kernel.set_budget_store(Box::new(chio_store_sqlite::SqliteBudgetStore::open(path)?))?;
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_budget_store(
                trust_control::service_runtime::budget::build_remote_budget_store(url, token)?,
            )?;
        }
        (None, None) => {}
    }
    Ok(())
}

/// Closed product composition for ordinary aggregate and threshold admission.
///
/// This function consumes the kernel so a failed store installation or feature
/// activation cannot leak a partially configured runtime to the caller.
pub struct OrdinaryAdmissionRuntimeConfig<'a> {
    pub enable_aggregate_invocation_admission: bool,
    pub admission_operation_db_path: Option<&'a Path>,
    pub approval_db_path: Option<&'a Path>,
    pub budget_db_path: Option<&'a Path>,
    pub control_url: Option<&'a str>,
    pub control_token: Option<&'a str>,
}

/// Closed product composition for an externally signed partition-escrow
/// authority. Construction consumes the kernel so a partially installed
/// authority topology cannot escape on failure.
pub struct PartitionEscrowRemoteAdmissionRuntimeConfig<'a> {
    pub control_url: &'a str,
    pub control_token: &'a str,
    pub admission_operation_db_path: &'a Path,
    pub authority: Arc<
        trust_control::service_runtime::budget::SealedPartitionEscrowRemoteAuthority,
    >,
}
