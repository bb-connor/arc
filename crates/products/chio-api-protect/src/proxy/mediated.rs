use super::*;

use chio_core_types::capability::governance::GovernedTransactionIntent;
use chio_core_types::capability::threshold_approval::ThresholdApprovalProposal;
use chio_core_types::declassification::SignedDeclassificationGrant;
use chio_core_types::message::OpaqueSupplementalAuthorization;
use chio_kernel::budget_store::BudgetStore;
use chio_kernel::dpop::{DpopConfig, DpopNonceStore, DpopProof};
use chio_kernel::execution_nonce::{
    ExecutionNonceConfig, ExecutionNonceStore, InMemoryExecutionNonceStore, SignedExecutionNonce,
};
use chio_kernel::{
    AdmissionOperationStore, ApprovalStore, ChioKernel, KernelConfig, KernelError, ToolCallRequest,
    ToolInvocationCost, ToolServerConnection, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};

/// A configured budget store together with whether it supports the pre-execution
/// hold APIs the mediated reservation path depends on.
///
/// The local SQLite store implements `get_budget_hold`, `mark_hold_reserved`, and
/// `reap_expired_reserved_holds`, so a reserved hold can be resolved by nonce on
/// `/v1/reconcile` and reclaimed by the TTL reaper. The remote control-plane
/// store forwards only charge/reverse/reconcile and falls back to the no-op trait
/// defaults for those hold APIs, so a reservation minted against it could never
/// be reconciled by nonce or reaped. Tracking hold-capability at the point of
/// construction lets the mediated routes fail closed rather than mint an
/// unreconcilable reserved nonce.
pub(crate) struct ConfiguredBudgetStore {
    pub(crate) store: Arc<dyn BudgetStore>,
    pub(crate) hold_capable: bool,
    /// The one resolved local filesystem path used to open `store`.
    ///
    /// Remote stores have no local path. Local admission-operation and
    /// execution-nonce authorities must derive their sibling paths from this
    /// retained value instead of resolving the operator input a second time.
    pub(crate) resolved_path: Option<String>,
    /// The retained parent descriptor shared by the local budget, admission,
    /// and nonce authorities.
    pub(crate) authority_directory:
        Option<Arc<chio_store_sqlite::durable_sqlite::TrustedSqliteDirectory>>,
    pub(crate) admission_operation_path: Option<String>,
    pub(crate) execution_nonce_path: Option<String>,
}

/// Side-effect-free budget topology prepared before any durable database is
/// created. Local mediation retains the one resolved path and trusted parent
/// descriptor that every authority will use. Remote topology is constructed
/// here because client construction validates the control URL without making a
/// network request or mutating durable state.
pub(crate) enum PreparedBudgetStore {
    Local {
        resolved_path: String,
        authority_directory: Arc<chio_store_sqlite::durable_sqlite::TrustedSqliteDirectory>,
        admission_operation_path: String,
        execution_nonce_path: String,
    },
    Remote {
        store: Arc<dyn BudgetStore>,
    },
}

impl PreparedBudgetStore {
    pub(crate) fn local_authority_paths(&self) -> Option<(&str, &str, &str)> {
        match self {
            Self::Local {
                resolved_path,
                admission_operation_path,
                execution_nonce_path,
                ..
            } => Some((
                resolved_path,
                admission_operation_path,
                execution_nonce_path,
            )),
            Self::Remote { .. } => None,
        }
    }
}

/// Durable authorities required by the governed admission coordinator.
///
/// Legacy one-of-one approvals and threshold approval sets use the same atomic
/// admission operation. Threshold mode additionally installs the authenticated
/// policy resolver and trust roots before it is activated.
pub(crate) struct MediationAdmissionAuthorities {
    operation_store: Arc<dyn AdmissionOperationStore>,
    approval_store: Arc<dyn ApprovalStore>,
    execution_nonce_store: Arc<dyn ExecutionNonceStore>,
    threshold_policy: Option<MediationThresholdPolicy>,
}

struct MediationThresholdPolicy {
    policy_hash: String,
    trusted_policy_authorities: Vec<PublicKey>,
    requirement_resolver:
        Arc<dyn chio_kernel::threshold_approval::ThresholdApprovalRequirementResolver>,
}

/// Build the governed-admission authorities beside a local budget database.
/// Separate SQLite files preserve each store's schema provenance while keeping
/// their lifecycle tied to the operator-configured budget path.
#[cfg(test)]
pub(crate) fn build_mediation_admission_authorities(
    budget_path: &str,
    approval_store: Arc<dyn ApprovalStore>,
    threshold_config: Option<&ThresholdApprovalCollectorConfig>,
) -> Result<MediationAdmissionAuthorities, ProtectError> {
    let authority_directory = Arc::new(
        chio_store_sqlite::durable_sqlite::TrustedSqliteDirectory::open_for_database(budget_path)
            .map_err(|error| ProtectError::Config(error.to_string()))?,
    );
    build_mediation_admission_authorities_in_directory(
        budget_path,
        authority_directory,
        approval_store,
        threshold_config,
    )
}

/// Build governed-admission siblings through the exact parent descriptor that
/// opened the budget authority.
#[cfg(test)]
pub(crate) fn build_mediation_admission_authorities_in_directory(
    budget_path: &str,
    authority_directory: Arc<chio_store_sqlite::durable_sqlite::TrustedSqliteDirectory>,
    approval_store: Arc<dyn ApprovalStore>,
    threshold_config: Option<&ThresholdApprovalCollectorConfig>,
) -> Result<MediationAdmissionAuthorities, ProtectError> {
    if budget_path.to_ascii_lowercase().starts_with("file:") {
        return Err(ProtectError::Config(
            "budget_db must be a plain filesystem path, not a SQLite file URI".to_string(),
        ));
    }
    if !std::path::Path::new(budget_path).is_absolute() {
        return Err(ProtectError::Config(
            "mediation authorities require the resolved absolute budget_db path".to_string(),
        ));
    }
    let operation_path = resolved_plain_database_path(
        &format!("{budget_path}.admission-operations"),
        "admission operation store",
    )?;
    let nonce_path = resolved_plain_database_path(
        &format!("{budget_path}.execution-nonces"),
        "execution nonce store",
    )?;
    build_mediation_admission_authorities_with_paths(
        budget_path,
        &operation_path,
        &nonce_path,
        authority_directory,
        approval_store,
        threshold_config,
    )
}

/// Open the exact admission and nonce paths retained during side-effect-free
/// topology preparation. Production uses this entry point so no operator or
/// derived path is resolved after another durable store has been created.
pub(crate) fn build_mediation_admission_authorities_with_paths(
    budget_path: &str,
    operation_path: &str,
    nonce_path: &str,
    authority_directory: Arc<chio_store_sqlite::durable_sqlite::TrustedSqliteDirectory>,
    approval_store: Arc<dyn ApprovalStore>,
    threshold_config: Option<&ThresholdApprovalCollectorConfig>,
) -> Result<MediationAdmissionAuthorities, ProtectError> {
    if !std::path::Path::new(budget_path).is_absolute()
        || !std::path::Path::new(operation_path).is_absolute()
        || !std::path::Path::new(nonce_path).is_absolute()
    {
        return Err(ProtectError::Config(
            "mediation authorities require resolved absolute database paths".to_string(),
        ));
    }
    let operation_store: Arc<dyn AdmissionOperationStore> = Arc::new(
        chio_store_sqlite::SqliteAdmissionOperationStore::open_hardened(
            operation_path,
            Arc::clone(&authority_directory),
        )
        .map_err(|error| {
            ProtectError::Config(format!(
                "cannot open mediation admission-operation store `{operation_path}`: {error}"
            ))
        })?,
    );
    let execution_nonce_store: Arc<dyn ExecutionNonceStore> = Arc::new(
        chio_store_sqlite::SqliteExecutionNonceStore::open_hardened(
            nonce_path,
            authority_directory,
        )
        .map_err(|error| {
            ProtectError::Config(format!(
                "cannot open mediation execution-nonce store `{nonce_path}`: {error}"
            ))
        })?,
    );

    let threshold_policy = threshold_config.map(|config| {
        let expected_policy_hash = config.current_policy_hash.clone();
        let request_context_resolver = Arc::clone(&config.request_context_resolver);
        let requirement_resolver: Arc<
            dyn chio_kernel::threshold_approval::ThresholdApprovalRequirementResolver,
        > = Arc::new(
            move |matched_request: &chio_kernel::threshold_approval::ThresholdApprovalRequest,
                  policy_hash: &str|
                  -> Result<
                chio_kernel::threshold_approval::ThresholdApprovalRequirement,
                chio_kernel::threshold_approval::ThresholdApprovalResolutionError,
            > {
                if policy_hash != expected_policy_hash {
                    return Err(
                        chio_kernel::threshold_approval::ThresholdApprovalResolutionError::StalePolicy {
                            expected: expected_policy_hash.clone(),
                            received: policy_hash.to_string(),
                        },
                    );
                }
                let context = request_context_resolver
                    .resolve_threshold_approval_request_context(
                        matched_request.request_id(),
                        policy_hash,
                    )?;
                if context.matched_request() != matched_request
                    || context.proposal_context().matched_request() != matched_request
                {
                    return Err(
                        chio_kernel::threshold_approval::ThresholdApprovalResolutionError::Corrupt(
                            "authenticated threshold context does not match the admitted request"
                                .to_string(),
                        ),
                    );
                }
                let requirement = context.proposal_context().requirement();
                if requirement.policy_hash() != policy_hash {
                    return Err(
                        chio_kernel::threshold_approval::ThresholdApprovalResolutionError::StalePolicy {
                            expected: policy_hash.to_string(),
                            received: requirement.policy_hash().to_string(),
                        },
                    );
                }
                Ok(requirement.clone())
            },
        );
        MediationThresholdPolicy {
            policy_hash: config.current_policy_hash.clone(),
            trusted_policy_authorities: config.trusted_policy_authorities.clone(),
            requirement_resolver,
        }
    });

    Ok(MediationAdmissionAuthorities {
        operation_store,
        approval_store,
        execution_nonce_store,
        threshold_policy,
    })
}

/// Resolve a durable budget database to the one absolute plain filesystem path
/// used by every local mediation authority.
///
/// Existing path components are canonicalized before the budget store opens so
/// an existing symlink is reduced to its target once. Missing trailing
/// components are appended to the nearest existing canonical ancestor. The
/// resulting path is retained and is never resolved again when sibling stores
/// are opened.
fn resolved_budget_database_path(path: &str) -> Result<String, ProtectError> {
    resolved_plain_database_path(path, "budget_db")
}

/// Build the sidecar's budget store, preferring the hold-capable local SQLite
/// store (`--budget-db`) over the remote control-plane store (`--control-url`)
/// when both are configured; falling back to the remote store; else `None` (the
/// mediated route then denies fail-closed).
///
/// Only the local SQLite store is hold-capable. The mediated authorization and
/// reconcile routes need a hold-capable store to persist and resolve a durable
/// reserved hold, so when both are configured the local store is chosen and
/// mediation keeps working; a remote-only deployment stays not hold-capable and
/// those routes reject fail-closed rather than mint an unreconcilable reserved
/// nonce.
pub(crate) fn prepare_budget_store(
    config: &ProtectConfig,
) -> Result<Option<PreparedBudgetStore>, ProtectError> {
    if let Some(path) = config.budget_db.as_deref() {
        let resolved_path = resolved_budget_database_path(path)?;
        let admission_operation_path = resolved_plain_database_path(
            &format!("{resolved_path}.admission-operations"),
            "admission operation store",
        )?;
        let execution_nonce_path = resolved_plain_database_path(
            &format!("{resolved_path}.execution-nonces"),
            "execution nonce store",
        )?;
        let authority_directory = Arc::new(
            chio_store_sqlite::durable_sqlite::TrustedSqliteDirectory::open_for_database(
                &resolved_path,
            )
            .map_err(|error| ProtectError::Config(error.to_string()))?,
        );
        return Ok(Some(PreparedBudgetStore::Local {
            resolved_path,
            authority_directory,
            admission_operation_path,
            execution_nonce_path,
        }));
    }
    if let Some(control_url) = config.control_url.as_deref() {
        let token = config.control_token.as_deref().unwrap_or("");
        let store =
            chio_control_plane::trust_control::service_runtime::budget::build_remote_budget_store(
                control_url,
                token,
            )
            .map_err(|error| ProtectError::Config(error.to_string()))?;
        return Ok(Some(PreparedBudgetStore::Remote {
            store: Arc::from(store),
        }));
    }
    Ok(None)
}

/// Open the already-resolved budget authority. This function never consults
/// operator input or resolves a path a second time.
pub(crate) fn open_prepared_budget_store(
    prepared: Option<PreparedBudgetStore>,
) -> Result<Option<ConfiguredBudgetStore>, ProtectError> {
    match prepared {
        Some(PreparedBudgetStore::Local {
            resolved_path,
            authority_directory,
            admission_operation_path,
            execution_nonce_path,
        }) => {
            let store = chio_store_sqlite::budget_store::SqliteBudgetStore::open_hardened(
                &resolved_path,
                Arc::clone(&authority_directory),
            )
            .map_err(|error| ProtectError::Config(error.to_string()))?;
            Ok(Some(ConfiguredBudgetStore {
                store: Arc::new(store),
                hold_capable: true,
                resolved_path: Some(resolved_path),
                authority_directory: Some(authority_directory),
                admission_operation_path: Some(admission_operation_path),
                execution_nonce_path: Some(execution_nonce_path),
            }))
        }
        Some(PreparedBudgetStore::Remote { store }) => Ok(Some(ConfiguredBudgetStore {
            store,
            hold_capable: false,
            resolved_path: None,
            authority_directory: None,
            admission_operation_path: None,
            execution_nonce_path: None,
        })),
        None => Ok(None),
    }
}

/// Maximum number of known-positive revocations retained in the optional
/// in-process acceleration cache. Correctness always comes from the live shared
/// authority; this bound prevents historical revocation volume from becoming
/// unbounded startup memory.
pub(crate) const REVOCATION_ACCELERATION_CACHE_MAX_IDS: usize = 256;

/// Read only the newest bounded slice of one already-open SQLite authority into
/// the in-process acceleration cache. Production calls this before erasing the
/// concrete type behind the exact `Arc<dyn RevocationStore>` shared by the
/// evaluator, kernel, release route, and proxy state. Older positives remain
/// authoritative and are discovered on cache miss through that live handle.
pub(crate) fn load_revocation_store_ids(
    store: &chio_store_sqlite::SqliteRevocationStore,
    path: &str,
) -> Result<std::collections::HashSet<String>, ProtectError> {
    store
        .list_revocations(REVOCATION_ACCELERATION_CACHE_MAX_IDS, None)
        .map(|records| {
            records
                .into_iter()
                .map(|record| record.capability_id)
                .collect()
        })
        .map_err(|error| {
            ProtectError::Config(format!("cannot read revocation-db `{path}`: {error}"))
        })
}

/// Build a `ChioKernel` for tool-call mediation with the budget store, a strict
/// execution-nonce config, and DPoP verification state installed.
///
/// The mediated `/v1/evaluate` route is a PURE pre-execution authorization gate.
/// Strict execution-nonce mode is always on, so every request reaches the
/// authorization preflight: the kernel verifies the capability (plus any DPoP
/// proof, governed intent, and approval token), reserves the pre-execution
/// budget hold and KEEPS IT OPEN, and mints a fresh execution nonce. It never
/// dispatches a tool server, never consumes a presented nonce, and never signs
/// a completed or settled spend. The caller presents the minted nonce to the
/// real tool server, which verifies and consumes it and reconciles the reserved
/// hold at the execution site.
///
/// A SINGLE kernel is built once at sidecar startup and reused for the service
/// lifetime (held behind a `Mutex` in `ProxyState`). Reuse remains load-bearing
/// for ephemeral approval-token and DPoP replay state. When durable admission
/// authorities are configured, both execution nonces and DPoP replay digests
/// share the SQLite execution-nonce authority and survive service restart. It
/// is also the same execution-nonce store that mints on `/v1/evaluate` and
/// verifies and consumes on `/v1/reconcile`, so a reconciled nonce cannot be
/// replayed. The route never
/// registers the caller-named `server_id`: the reserve-for-caller authorization
/// path never dispatches a tool on this kernel and so no longer requires the
/// target to be registered, which keeps the kernel's tool-server map from
/// growing on every caller-arbitrary request.
///
/// `trusted_capability_issuers` are trusted as capability authorities in
/// addition to the sidecar signer, so an externally minted capability that the
/// sidecar's other endpoints accept is not rejected here as untrusted.
///
/// `receipt_store` is the sidecar's shared durable receipt authority. Direct
/// mediation requires authoritative point lookup from this exact store for
/// restart-safe publication and exact replay. It must be installed before
/// admission recovery runs.
///
/// `payment_adapter` is the operator-configured payment rail. When present it is
/// installed on the kernel so a governed `MustPrepay` (x402/ACP) quote is
/// authorized and captured before the reserve-for-caller path mints a nonce.
/// When `None` the kernel carries no adapter, so the governed prepayment gate
/// denies `MustPrepay` fail-closed: only a configured adapter enables it.
pub(crate) fn build_mediation_kernel(
    signer: &Keypair,
    budget_store: Arc<dyn BudgetStore>,
    receipt_store: Option<Arc<dyn chio_kernel::ReceiptStore>>,
    revocation_store: Option<Arc<dyn chio_kernel::RevocationStore>>,
    trusted_capability_issuers: &[PublicKey],
    tool_servers: Vec<Box<dyn ToolServerConnection>>,
    payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
    admission_authorities: Option<MediationAdmissionAuthorities>,
) -> Result<ChioKernel, ProtectError> {
    let mut ca_public_keys = vec![signer.public_key()];
    for issuer in trusted_capability_issuers {
        if !ca_public_keys.contains(issuer) {
            ca_public_keys.push(issuer.clone());
        }
    }
    let policy_hash = admission_authorities
        .as_ref()
        .and_then(|authorities| authorities.threshold_policy.as_ref())
        .map(|policy| policy.policy_hash.clone())
        .unwrap_or_else(|| chio_core_types::sha256_hex(b"chio_api_protect_mediation_v1"));
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: signer.clone(),
        ca_public_keys,
        max_delegation_depth: 5,
        policy_hash,
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        // Ephemeral construction remains available for isolated embeddings.
        // Production construction replaces the default with the sidecar's
        // shared revocation authority below.
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        // The dispatch-intent payment journal is off on this reserve-only kernel.
        // Its money-path durability is the reserved-hold TTL reaper plus settle
        // by reconcile-by-nonce, not a general dispatch-intent journal: this
        // kernel reserves a hold and mints a nonce but never dispatches a tool.
        // An operation-owned MustPrepay reservation still writes its HoldPlaced
        // payment row atomically with budget authorization, because its rail
        // capture and any pre-dispatch compensation must survive restart.
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    });
    kernel
        .set_budget_store_handle(budget_store)
        .map_err(|error| {
            ProtectError::Config(format!(
                "failed to install budget authority on the mediation kernel: {error}"
            ))
        })?;
    if let Some(receipt_store) = receipt_store {
        kernel
            .set_receipt_store_handle(receipt_store)
            .map_err(|error| {
                ProtectError::Config(format!(
                    "failed to install receipt authority on the mediation kernel: {error}"
                ))
            })?;
    }
    if let Some(revocation_store) = revocation_store {
        kernel.set_revocation_store_handle(revocation_store);
    }
    let mut threshold_policy = None;
    let mut admission_recovery_required = false;
    let dpop_config = DpopConfig::default();
    let dpop_ttl = std::time::Duration::from_secs(dpop_config.proof_ttl_secs);
    let (execution_nonce_store, dpop_nonce_store): (Box<dyn ExecutionNonceStore>, DpopNonceStore) =
        if let Some(authorities) = admission_authorities {
            let MediationAdmissionAuthorities {
                operation_store,
                approval_store,
                execution_nonce_store,
                threshold_policy: configured_threshold_policy,
            } = authorities;
            admission_recovery_required = true;
            kernel
                .set_admission_operation_store_handle(operation_store)
                .map_err(|error| {
                    ProtectError::Config(format!(
                        "failed to install admission-operation authority on the mediation kernel: {error}"
                    ))
                })?;
            kernel
                .set_approval_store_handle(approval_store)
                .map_err(|error| {
                    ProtectError::Config(format!(
                        "failed to install approval authority on the mediation kernel: {error}"
                    ))
                })?;
            threshold_policy = configured_threshold_policy;
            (
                Box::new(Arc::clone(&execution_nonce_store)),
                DpopNonceStore::with_authoritative_store(
                    dpop_config.nonce_store_capacity,
                    dpop_ttl,
                    execution_nonce_store,
                ),
            )
        } else {
            (
                Box::new(InMemoryExecutionNonceStore::from_config(
                    &ExecutionNonceConfig::default(),
                )),
                DpopNonceStore::new(dpop_config.nonce_store_capacity, dpop_ttl),
            )
        };
    let nonce_cfg = ExecutionNonceConfig {
        require_nonce: true,
        ..ExecutionNonceConfig::default()
    };
    kernel
        .set_execution_nonce_store(nonce_cfg, execution_nonce_store)
        .map_err(|error| {
            ProtectError::Config(format!(
                "failed to install execution nonce authority on the mediation kernel: {error}"
            ))
        })?;
    // Install DPoP verification state so a grant with `dpop_required` can verify
    // a presented proof. Without it every dpop_required capability denies
    // fail-closed with no way to present a proof.
    kernel.set_dpop_store(dpop_nonce_store, dpop_config);
    // Install the operator's payment rail so the governed prepayment gate can
    // authorize and capture a MustPrepay (x402/ACP) quote before the
    // reserve-for-caller path mints a nonce. Absent an adapter the gate denies
    // MustPrepay fail-closed, so only a configured adapter enables prepayment.
    if let Some(payment_adapter) = payment_adapter {
        kernel
            .set_payment_adapter(payment_adapter)
            .map_err(|error| {
                ProtectError::Config(format!(
                    "failed to install payment adapter on the mediation kernel: {error}"
                ))
            })?;
    }
    if admission_recovery_required {
        kernel
            .recover_tool_dispatch_admission_operations()
            .map_err(|error| {
                ProtectError::Config(format!(
                    "failed to recover governed mediation admissions: {error}"
                ))
            })?;
        let payment_recovery = kernel.reconcile_payment_journal(0).map_err(|error| {
            ProtectError::Config(format!(
                "failed to reconcile governed mediation payments: {error}"
            ))
        })?;
        if payment_recovery.resolved > 0
            || payment_recovery.reconcile_failed > 0
            || payment_recovery.deferred_to_admission_operation > 0
        {
            warn!(
                resolved = payment_recovery.resolved,
                reconcile_failed = payment_recovery.reconcile_failed,
                deferred_to_admission_operation = payment_recovery.deferred_to_admission_operation,
                "governed mediation payment journal recovered before serving"
            );
        }
    }
    for server in tool_servers {
        kernel.register_tool_server(server);
    }
    if let Some(threshold_policy) = threshold_policy {
        kernel
            .set_threshold_approval_requirement_resolver(
                threshold_policy.requirement_resolver,
            )
            .map_err(|error| {
                ProtectError::Config(format!(
                    "failed to install threshold requirement authority on the mediation kernel: {error}"
                ))
            })?;
        kernel
            .set_threshold_approval_policy_authorities(
                threshold_policy.trusted_policy_authorities,
            )
            .map_err(|error| {
                ProtectError::Config(format!(
                    "failed to install threshold policy authorities on the mediation kernel: {error}"
                ))
            })?;
        kernel
            .enable_threshold_governed_approvals()
            .map_err(|error| {
                ProtectError::Config(format!(
                    "failed to activate threshold governed admission on the mediation kernel: {error}"
                ))
            })?;
    }
    // Rebuild the delegated reserve-for-caller accounting from the durable budget
    // store. A delegated reservation keeps its child's sibling-sum share admitted
    // against the parent while its hold stays open, but that admission is
    // in-memory only, so a kernel built fresh over a populated store (a restart)
    // would otherwise admit a sibling against the parent as if the still-open
    // reservation consumed nothing. Since the durable hold record does not carry
    // the parent capability id or the shares needed to rebuild the reservation,
    // this arms a fail-closed gate that denies delegated admission while any such
    // hold from a prior service instance remains open. Fail-closed: a store read error here
    // aborts startup so the sidecar refuses to mediate over a store it could not
    // inspect.
    kernel
        .arm_restart_reserved_hold_gate()
        .map_err(|error| ProtectError::Config(error.to_string()))?;
    Ok(kernel)
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SidecarEvaluateToolCallMediatedRequest {
    capability: chio_core_types::capability::token::CapabilityToken,
    tool_server: String,
    tool_name: String,
    #[serde(default)]
    parameters: serde_json::Value,
    #[serde(default)]
    agent_id: Option<String>,
    /// Optional caller-chosen request identifier. When present it is forwarded
    /// verbatim so the caller can bind a governed approval token to this exact
    /// request (the kernel requires `approval_token.request_id == request_id`).
    /// When absent the sidecar mints one; that is fine for capabilities that do
    /// not carry an approval-gated governed intent.
    #[serde(default)]
    request_id: Option<String>,
    /// Optional governed transaction intent bound to this invocation. Forwarded
    /// so a grant carrying `GovernedIntentRequired` (or an approval threshold)
    /// can be authorized instead of denied.
    #[serde(default)]
    governed_intent: Option<GovernedTransactionIntent>,
    /// Optional approval token authorizing this governed invocation, forwarded
    /// alongside `governed_intent` so an approval-gated grant can be authorized.
    #[serde(default)]
    approval_token: Option<GovernedApprovalToken>,
    /// Canonical threshold approval token set. Supplying this together with the
    /// singular compatibility field is rejected by the kernel as ambiguous.
    #[serde(default)]
    approval_tokens: Vec<GovernedApprovalToken>,
    /// Policy-authority-signed proposal binding a threshold approval set.
    #[serde(default)]
    threshold_approval_proposal: Option<ThresholdApprovalProposal>,
    /// Opaque broker authorization verified by the installed supplemental
    /// authorization authority before admission.
    #[serde(default)]
    supplemental_authorization: Option<OpaqueSupplementalAuthorization>,
    /// One-shot signed declassification authority for this exact invocation.
    #[serde(default)]
    declassification_grant: Option<SignedDeclassificationGrant>,
    /// Optional DPoP proof-of-possession. Forwarded so a grant carrying
    /// `dpop_required` can verify the proof instead of denying fail-closed.
    #[serde(default)]
    dpop_proof: Option<DpopProof>,
    /// A signed execution nonce. This endpoint MINTS nonces; it does not settle
    /// presented ones. The field is parsed only so a caller that mistakenly
    /// presents a nonce here is rejected explicitly (fail-closed) rather than
    /// having the nonce silently ignored.
    #[serde(default)]
    execution_nonce: Option<SignedExecutionNonce>,
}

fn mediated_request_id_conflict_response() -> Response {
    (
        StatusCode::CONFLICT,
        axum::Json(serde_json::json!({
            "error": "chio_request_id_reused",
            "message": "request_id is unavailable; choose a fresh request_id",
        })),
    )
        .into_response()
}

fn mediated_unavailable_response() -> Response {
    internal_json_error_response(
        "chio_mediation_unavailable",
        "mediated authorization is unavailable",
    )
}

fn mediated_authorization_response(response: chio_kernel::ToolCallResponse) -> Response {
    let status = match &response.verdict {
        chio_kernel::Verdict::Allow => "authorized",
        chio_kernel::Verdict::Deny => "deny",
        chio_kernel::Verdict::PendingApproval => "pending_approval",
    };
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "status": status,
            "receipt": response.receipt,
            "execution_nonce": response.execution_nonce,
        })),
    )
        .into_response()
}

pub(crate) async fn sidecar_evaluate_tool_call_mediated_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read mediated evaluate body: {error}");
            return sidecar_bad_request("failed to read evaluate body").into_response();
        }
    };
    let parsed: SidecarEvaluateToolCallMediatedRequest = match serde_json::from_slice(&body_bytes) {
        Ok(parsed) => parsed,
        Err(error) => {
            warn!("failed to decode mediated evaluate payload: {error}");
            return sidecar_bad_request("invalid mediated payload").into_response();
        }
    };
    // This endpoint is a pre-execution authorization gate: it mints an execution
    // nonce for the caller to present downstream. It does not consume or settle a
    // presented nonce. Reject one fail-closed so a caller cannot mistake this for
    // a completion endpoint (and so the sidecar never consumes the downstream
    // nonce, which would make the real tool server reject the caller as a
    // replay).
    if parsed.execution_nonce.is_some() {
        return sidecar_bad_request(
            "/v1/evaluate issues execution nonces; it does not accept a presented nonce. \
             Present the minted nonce to the tool server, not to this endpoint",
        )
        .into_response();
    }
    // Declassification is consumed at the dispatching security-kernel boundary,
    // where the exact invocation and information-flow transition are known. This
    // route only reserves authority for a later caller dispatch, so accepting a
    // grant here would leave it outside both dispatch verification and nonce
    // binding. Reject it explicitly instead of forwarding a security artifact
    // that this boundary cannot consume.
    if parsed.declassification_grant.is_some() {
        return sidecar_bad_request(
            "declassification_grant must be presented to the dispatching security kernel, not to the reserve-only /v1/evaluate route",
        )
        .into_response();
    }
    // Bound caller-controlled collections before authentication. The production
    // verifier applies the stricter delegation-depth limit after signature and
    // lineage validation.
    const MAX_MEDIATED_DELEGATION_CHAIN: usize = 32;
    if parsed.capability.delegation_chain.len() > MAX_MEDIATED_DELEGATION_CHAIN {
        return sidecar_bad_request("capability delegation chain is too long").into_response();
    }
    const MAX_MEDIATED_SCOPE_GRANTS: usize = 64;
    if parsed.capability.scope.grants.len() > MAX_MEDIATED_SCOPE_GRANTS {
        return sidecar_bad_request("capability scope carries too many grants").into_response();
    }

    let Some(mediation_kernel) = state.mediation_kernel.as_ref() else {
        warn!("mediated authorization unavailable: no mediation kernel is configured");
        return mediated_unavailable_response();
    };
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(error) => {
            warn!("mediated capability authentication clock failed: {error}");
            return mediated_unavailable_response();
        }
    };
    let authenticated = {
        let kernel = mediation_kernel.lock().await;
        kernel.verify_stored_capability_for_reuse(&parsed.capability, now)
    };
    if let Err(error) = authenticated {
        warn!("mediated capability authentication failed: {error}");
        return mediated_unavailable_response();
    }

    // A mediated reservation requires a hold-capable budget store. Log the
    // operator-facing cause while keeping every client topology response equal.
    if !state.mediation_hold_capable {
        warn!("mediated authorization unavailable: budget authority cannot persist holds");
        return mediated_unavailable_response();
    }
    if state
        .sidecar_control_token
        .as_deref()
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        warn!("mediated authorization unavailable: reconcile control token is not configured");
        return mediated_unavailable_response();
    }
    if state.budget_store.is_none() {
        warn!("mediated authorization unavailable: budget authority is not configured");
        return mediated_unavailable_response();
    }

    // Reject the authenticated capability when its own id OR any ancestor
    // in its delegation chain is revoked, so a delegated child of a revoked root
    // cannot keep earning mediated reservations until expiry. `capability_is_revoked`
    // consults the in-memory release set first (no I/O for a known-revoked id) and
    // then the durable revocation store, failing closed if that store cannot be
    // read, so a revocation a sibling replica or `chio trust revoke --revocation-db`
    // recorded after this service instance started is honored here exactly as on
    // the proxy and validate paths. The mediation kernel shares the same store
    // and checks it again during admission, closing a revoke-between-checks race.
    let mut revoked = state.capability_is_revoked(&parsed.capability.id).await;
    if !revoked {
        for ancestor in &parsed.capability.delegation_chain {
            if state.capability_is_revoked(&ancestor.capability_id).await {
                revoked = true;
                break;
            }
        }
    }
    if revoked {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": "chio_capability_revoked",
                "message": "capability has been revoked",
            })),
        )
            .into_response();
    }
    let agent_id = parsed
        .agent_id
        .unwrap_or_else(|| parsed.capability.subject.to_hex());
    let request_id = parsed
        .request_id
        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
    let kernel_request = ToolCallRequest {
        request_id,
        capability: parsed.capability,
        tool_name: parsed.tool_name,
        server_id: parsed.tool_server,
        agent_id,
        arguments: parsed.parameters,
        supplemental_authorization: parsed.supplemental_authorization,
        dpop_proof: parsed.dpop_proof,
        // The route mints the nonce; it never forwards a presented one (rejected
        // above), so the kernel always takes the authorization-reserve path.
        execution_nonce: None,
        governed_intent: parsed.governed_intent,
        approval_token: parsed.approval_token,
        approval_tokens: parsed.approval_tokens,
        threshold_approval_proposal: parsed.threshold_approval_proposal,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    if let Err(error) = kernel_request.validate() {
        warn!("mediated authorization request validation failed: {error}");
        return sidecar_bad_request("invalid mediated authorization").into_response();
    }
    // Single-phase authorization on the shared, service-lifetime kernel: verify +
    // reserve the budget hold (kept open) + mint a fresh execution nonce. The
    // reserve-for-caller path never dispatches, so it does not require the
    // caller-named server to be registered; the route therefore never registers
    // it and holds the kernel behind a shared (non-mut) lock. No dispatch, no
    // reconcile, no settlement. The lock is released at the end of the block,
    // before any await, so authorizations serialize without holding the kernel
    // across receipt-persistence I/O.
    let outcome = {
        let kernel = mediation_kernel.lock().await;
        kernel.authorize_tool_call_reserving_blocking_with_metadata_outcome(&kernel_request, None)
    };
    let response = match outcome {
        Ok(chio_kernel::CallerReservationAuthorizationOutcome::Authorized(response)) => response,
        Ok(chio_kernel::CallerReservationAuthorizationOutcome::Replayed(response)) => {
            return mediated_authorization_response(response)
        }
        Err(KernelError::CallerReservationConflict(_)) => {
            return mediated_request_id_conflict_response()
        }
        Err(error) => {
            warn!("mediated authorization error: {error}");
            return internal_json_error_response(
                "chio_mediation_failed",
                "mediated authorization failed",
            );
        }
    };
    if let Err(error) = record_tool_receipt(&state, &response.receipt).await {
        // The reserve receipt persisted here is a local audit entry, not the
        // authoritative record. When the reserve SUCCEEDED (Verdict::Allow with a
        // minted nonce) the reservation is durable in the budget store and the
        // caller holds the signed nonce, which reconciles at /v1/reconcile (that
        // route persists its own authoritative receipt). Any governed MustPrepay
        // prepayment was already captured to back this exact reservation. Tearing
        // the reservation down here would refund nothing on the prepaid path (direct
        // financial loss) and strand the caller without the nonce it paid for, so
        // return the nonce and log the persistence failure, mirroring the accepted
        // /v1/reconcile behavior. A denied or pending verdict placed no hold and
        // minted no nonce, so its unpersisted receipt still fails closed.
        if !matches!(
            (&response.verdict, response.execution_nonce.as_deref()),
            (chio_kernel::Verdict::Allow, Some(_))
        ) {
            warn!("failed to persist mediated receipt: {error}");
            return internal_json_error_response(
                "chio_receipt_persistence_failed",
                "mediated receipt persistence failed",
            );
        }
        warn!(
            "mediated reserve receipt persistence failed; returning minted nonce to caller: {error}"
        );
    }
    mediated_authorization_response(response)
}

/// `POST /v1/reconcile` request shape. The caller presents the execution nonce
/// minted by `/v1/evaluate`, the exact `arguments` that nonce authorized, and
/// the measured `realized_cost`. The kernel settles the reserved hold the nonce
/// names at `min(realized, reserved)` and returns an authoritative
/// mediated-spend receipt.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SidecarReconcileRequest {
    execution_nonce: SignedExecutionNonce,
    #[serde(default)]
    arguments: serde_json::Value,
    realized_cost: ToolInvocationCost,
}

/// Settle a reserved authorization by the execution nonce that names its hold.
///
/// This route is gated by the reconcile control middleware: only the trusted
/// tool server, presenting the sidecar-control token, reconciles. The controlled
/// agent that called `/v1/evaluate` must not reach this endpoint, or it could
/// settle its own reservation at cost zero and defeat the cumulative spend cap.
///
/// The presented nonce is the credential: the shared kernel that minted it
/// verifies it (signature under the sidecar key, expiry, single-use replay),
/// settles the exact reserved hold at `min(realized, reserved)`, releases the
/// difference back to the grant, and signs a completed authoritative receipt.
/// The `realized_cost` is the tool server's own report and is not bound to an
/// attested oracle cost at this boundary. Fail-closed: a
/// forged, tampered, replayed, or argument-mismatched nonce, or a hold that is
/// already closed, is rejected with a 4xx and never settles.
pub(crate) async fn sidecar_reconcile_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read reconcile body: {error}");
            return sidecar_bad_request("failed to read reconcile body").into_response();
        }
    };
    let parsed: SidecarReconcileRequest = match serde_json::from_slice(&body_bytes) {
        Ok(parsed) => parsed,
        Err(error) => {
            warn!("failed to decode reconcile payload: {error}");
            return sidecar_bad_request("invalid reconcile payload").into_response();
        }
    };
    let Some(mediation_kernel) = state.mediation_kernel.as_ref() else {
        return internal_json_error_response(
            "chio_mediation_unavailable",
            "reconcile route requires a configured budget store (--control-url or --budget-db)",
        );
    };
    // A reserved hold can only be resolved by nonce when the budget store
    // implements the hold APIs. The remote control-plane store cannot, so a
    // reconcile against it could never settle the reserved hold the nonce names.
    // Reject fail-closed rather than attempt a settle that cannot succeed.
    if !state.mediation_hold_capable {
        return internal_json_error_response(
            "chio_mediation_requires_local_budget_store",
            "mediated reconcile requires a hold-capable local budget store (--budget-db); \
             a remote control-plane budget store (--control-url) cannot resolve a reserved hold",
        );
    }
    // Settle on the shared kernel. The same instance minted the nonce, so its
    // execution-nonce store is the single-use authority here: a forged, tampered,
    // or already-reconciled nonce is rejected. The lock releases at the end of
    // the block, before receipt-persistence I/O.
    let reconciled = {
        let kernel = mediation_kernel.lock().await;
        kernel.reconcile_reserved_authorization_by_nonce(
            &parsed.execution_nonce,
            &parsed.arguments,
            &parsed.realized_cost,
        )
    };
    let reconciled = match reconciled {
        Ok(response) => response,
        Err(error) => {
            warn!("reconcile rejected: {error}");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "chio_reconcile_rejected",
                    "message": "reconcile request was rejected",
                })),
            )
                .into_response();
        }
    };
    // The settle already consumed the nonce and closed the reserved hold, and that
    // is irreversible: a retry cannot recreate this authoritative receipt. If
    // durable persistence then fails, returning 500 would discard the only proof
    // of a settled spend, leaving the tool server and operator audit with nothing
    // to reconcile against. Log the failure and return the signed receipt so the
    // caller can persist or retry it. This is the opposite of /v1/evaluate, whose
    // reservation is still open and reversible when persistence fails; here the
    // spend is done, so the receipt must reach the caller.
    if let Err(error) = record_tool_receipt(&state, &reconciled.receipt).await {
        warn!("reconcile settled but receipt persistence failed; returning authoritative receipt to caller: {error}");
    }
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "status": "reconciled",
            "receipt": reconciled.receipt,
        })),
    )
        .into_response()
}

/// Release expired, unreconciled reserved budget holds on the shared kernel so a
/// caller that authorizes but never reconciles cannot permanently burn budget.
/// Returns the number of holds released; a sidecar without a configured budget
/// store (no mediation kernel) releases nothing. Factored out of the startup
/// interval worker so it is directly unit-testable with a controlled clock.
pub(crate) async fn reap_expired_reserved_holds_once(
    state: &Arc<ProxyState>,
    now_unix_secs: i64,
) -> Result<usize, KernelError> {
    let Some(mediation_kernel) = state.mediation_kernel.as_ref() else {
        return Ok(0);
    };
    let kernel = mediation_kernel.lock().await;
    kernel.reap_expired_reserved_budget_holds(now_unix_secs)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore};
    use chio_security_types::flow::{DeclassificationPurpose, InformationLabel, PrincipalId};
    use chio_security_types::ports::{
        DestinationId, Digest32, GrantId, RecordId, SessionId, TenantId,
    };
    use chio_security_types::{DeclassificationGrantBody, DeclassificationGrantClaims};
    use chio_test_support::prelude::*;
    use tower::ServiceExt;

    struct TestMediationAdmissionConfig {
        budget_path: String,
        approval_path: String,
        threshold_config: Option<ThresholdApprovalCollectorConfig>,
    }

    fn durable_mediation_budget_and_admission(
        directory: &std::path::Path,
        threshold_config: Option<ThresholdApprovalCollectorConfig>,
    ) -> (Arc<dyn BudgetStore>, TestMediationAdmissionConfig) {
        let budget_path = directory.join("budget.db");
        let approval_path = directory.join("approvals.db");
        let budget: Arc<dyn BudgetStore> = Arc::new(
            chio_store_sqlite::budget_store::SqliteBudgetStore::open(&budget_path).test_unwrap(),
        );
        (
            budget,
            TestMediationAdmissionConfig {
                budget_path: budget_path.to_string_lossy().into_owned(),
                approval_path: approval_path.to_string_lossy().into_owned(),
                threshold_config,
            },
        )
    }

    fn signed_declassification_grant() -> SignedDeclassificationGrant {
        let id = |value: &str| RecordId::new(value).test_unwrap();
        let body = DeclassificationGrantBody::new(DeclassificationGrantClaims {
            grant_id: GrantId::new("grant-api-protect").test_unwrap(),
            capability_id: id("capability-api-protect"),
            tenant_id: TenantId::new("tenant-api-protect").test_unwrap(),
            subject_id: PrincipalId::new("subject-api-protect").test_unwrap(),
            agent_id: id("agent-api-protect"),
            session_id: SessionId::new("session-api-protect").test_unwrap(),
            source_label_hash: Digest32::new([1; 32]),
            target_label: InformationLabel::bottom(),
            destination_id: DestinationId::new("server-api-protect").test_unwrap(),
            tool_name: id("tool-api-protect"),
            purpose: DeclassificationPurpose::new("support").test_unwrap(),
            request_hash: Digest32::new([2; 32]),
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            authority_key_id: id("authority-api-protect"),
        })
        .test_unwrap();
        SignedDeclassificationGrant::sign(body, &Keypair::from_seed(&[7; 32])).test_unwrap()
    }

    /// Build an ephemeral kernel used only to mint capabilities in tests. It
    /// shares the budget store with the state's mediation kernel; cost is never
    /// resolved through an injected tool server, so capabilities carry their own
    /// monetary constraints.
    fn issuing_kernel(
        signer: &Keypair,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: &[PublicKey],
    ) -> Arc<ChioKernel> {
        Arc::new(
            build_mediation_kernel(
                signer,
                budget,
                None,
                None,
                trusted_capability_issuers,
                Vec::new(),
                None,
                None,
            )
            .test_unwrap(),
        )
    }

    fn issue_cost_bearing_capability(
        kernel: &Arc<ChioKernel>,
        agent: &Keypair,
        server: &str,
        tool: &str,
        max_per: u64,
        max_total: u64,
        currency: &str,
    ) -> CapabilityToken {
        use chio_core_types::capability::scope::MonetaryAmount;
        let grant = ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: Some(MonetaryAmount {
                units: max_per,
                currency: currency.to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: max_total,
                currency: currency.to_string(),
            }),
            dpop_required: None,
        };
        let scope = ChioScope {
            grants: vec![grant],
            ..ChioScope::default()
        };
        kernel
            .issue_capability(&agent.public_key(), scope, 3600)
            .test_unwrap()
    }

    /// Issue a capability whose single grant caps invocations only, with no
    /// monetary ceiling. The mediated reserve path debits an invocation but
    /// authorizes no monetary hold, so its reversal on tear-down and TTL reap is
    /// exercised separately from the monetary reserve.
    fn issue_invocation_capability(
        kernel: &Arc<ChioKernel>,
        agent: &Keypair,
        server: &str,
        tool: &str,
        max_invocations: u32,
    ) -> CapabilityToken {
        let grant = ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(max_invocations),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let scope = ChioScope {
            grants: vec![grant],
            ..ChioScope::default()
        };
        kernel
            .issue_capability(&agent.public_key(), scope, 3600)
            .test_unwrap()
    }

    /// Control token the mediated test state configures so `/v1/reconcile`, now
    /// behind the reconcile control gate, admits the trusted tool server that
    /// presents it. `/v1/evaluate` is not gated, so evaluate tests are unaffected.
    const MEDIATED_CONTROL_TOKEN: &str = "tool-server-control-token";

    /// Build proxy state for the mediated route with the standard reconcile
    /// control token configured.
    fn mediated_test_state(
        signer: Keypair,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: Vec<PublicKey>,
    ) -> Arc<ProxyState> {
        mediated_test_state_with_control_token(
            signer,
            budget,
            trusted_capability_issuers,
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
        )
    }

    /// Build proxy state for the mediated route. `signer` is the sidecar signer
    /// the shared mediation kernel is built from (so capabilities minted by it
    /// are trusted), and `trusted_capability_issuers` are additional external
    /// issuers to trust. `sidecar_control_token` gates `/v1/reconcile`; `None`
    /// leaves the sidecar with no configured token, so reconcile fails closed.
    fn mediated_test_state_with_control_token(
        signer: Keypair,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: Vec<PublicKey>,
        sidecar_control_token: Option<String>,
    ) -> Arc<ProxyState> {
        // The default in-memory budget store implements the hold APIs, so it is
        // treated as hold-capable (matching a local `--budget-db` deployment).
        mediated_test_state_inner(
            signer,
            budget,
            trusted_capability_issuers,
            sidecar_control_token,
            None,
            true,
        )
    }

    /// Build proxy state for the mediated route with an explicit hold-capability
    /// flag. `hold_capable == false` models a remote `--control-url` budget store
    /// whose hold APIs fall back to the no-op trait defaults, so the mediated
    /// routes must fail closed rather than mint an unreconcilable reserved nonce.
    fn mediated_test_state_inner(
        signer: Keypair,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: Vec<PublicKey>,
        sidecar_control_token: Option<String>,
        receipt_store: Option<SqliteReceiptStore>,
        hold_capable: bool,
    ) -> Arc<ProxyState> {
        // No payment adapter by default, so governed MustPrepay stays denied
        // fail-closed; the prepayment tests build the mediation kernel with one.
        mediated_test_state_core(
            signer,
            budget,
            trusted_capability_issuers,
            sidecar_control_token,
            receipt_store,
            hold_capable,
            None,
            None,
            None,
        )
    }

    /// Build proxy state for the mediated route with an explicit payment adapter
    /// for the shared mediation kernel. A configured adapter lets an approved
    /// governed `MustPrepay` request authorize (the quote is prepaid before a
    /// reserved nonce is minted); `None` keeps it denied fail-closed.
    #[allow(clippy::too_many_arguments)]
    fn mediated_test_state_core(
        signer: Keypair,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: Vec<PublicKey>,
        sidecar_control_token: Option<String>,
        receipt_store: Option<SqliteReceiptStore>,
        hold_capable: bool,
        payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
        revocation_store: Option<Arc<dyn chio_kernel::RevocationStore>>,
        admission_config: Option<TestMediationAdmissionConfig>,
    ) -> Arc<ProxyState> {
        let (approval_store, admission_authorities, threshold_config, kernel_receipt_store): (
            Arc<dyn ApprovalStore>,
            Option<MediationAdmissionAuthorities>,
            Option<ThresholdApprovalCollectorConfig>,
            Arc<dyn chio_kernel::ReceiptStore>,
        ) = if let Some(config) = admission_config {
            let kernel_receipt_store: Arc<dyn chio_kernel::ReceiptStore> = Arc::new(
                chio_store_sqlite::SqliteReceiptStore::open(&config.approval_path).test_unwrap(),
            );
            let approval_store: Arc<dyn ApprovalStore> = Arc::new(
                SqliteApprovalStore::open_colocated_with_receipt_store(&config.approval_path)
                    .test_unwrap(),
            );
            let authorities = build_mediation_admission_authorities(
                &config.budget_path,
                Arc::clone(&approval_store),
                config.threshold_config.as_ref(),
            )
            .test_unwrap();
            (
                approval_store,
                Some(authorities),
                config.threshold_config,
                kernel_receipt_store,
            )
        } else {
            let authority_directory = chio_test_support::private_fs::private_tempdir(
                "chio-api-protect-mediation-authorities-",
            )
            .test_unwrap()
            .keep();
            let receipt_path = authority_directory.join("receipts.db");
            let budget_path = authority_directory
                .join("budget.db")
                .to_string_lossy()
                .into_owned();
            let kernel_receipt_store: Arc<dyn chio_kernel::ReceiptStore> =
                Arc::new(chio_store_sqlite::SqliteReceiptStore::open(&receipt_path).test_unwrap());
            let approval_store: Arc<dyn ApprovalStore> = Arc::new(
                SqliteApprovalStore::open_colocated_with_receipt_store(&receipt_path).test_unwrap(),
            );
            let authorities = build_mediation_admission_authorities(
                &budget_path,
                Arc::clone(&approval_store),
                None,
            )
            .test_unwrap();
            (
                approval_store,
                Some(authorities),
                None,
                kernel_receipt_store,
            )
        };
        let signer_public_key = signer.public_key();
        let mut trusted_capability_issuers = trusted_capability_issuers;
        if !trusted_capability_issuers.contains(&signer_public_key) {
            trusted_capability_issuers.push(signer_public_key.clone());
        }
        let trusted_receipt_signers = vec![signer_public_key];
        let evaluator = RequestEvaluator::new_ephemeral_with_approval_store(
            Vec::new(),
            signer.clone(),
            "test-policy".to_string(),
            Arc::clone(&approval_store),
        );
        let egress_contract = default_upstream_egress_contract("http://127.0.0.1:1").test_unwrap();
        let http_client = client_builder_with_contract(&egress_contract)
            .build()
            .test_unwrap();
        // One shared mediation kernel for the service lifetime:
        // reuse keeps the approval-token and DPoP replay stores authoritative and
        // makes the nonce minted on `/v1/evaluate` the one settled on
        // `/v1/reconcile`.
        let mediation_kernel = Mutex::new(
            build_mediation_kernel(
                &signer,
                Arc::clone(&budget),
                Some(kernel_receipt_store),
                revocation_store.clone(),
                &trusted_capability_issuers,
                Vec::new(),
                payment_adapter,
                admission_authorities,
            )
            .test_unwrap(),
        );
        let approval_admin = match threshold_config {
            Some(config) => ApprovalAdmin::new_with_threshold_policy(
                Arc::clone(&approval_store),
                config.current_policy_hash,
                config.trusted_policy_authorities,
                config.request_context_resolver,
            )
            .test_unwrap(),
            None => ApprovalAdmin::new(Arc::clone(&approval_store)),
        };
        let persisted_tool_receipts = receipt_store
            .as_ref()
            .map(|store| store.load_tool_receipts(&trusted_receipt_signers))
            .transpose()
            .test_unwrap()
            .unwrap_or_default();
        Arc::new(ProxyState {
            evaluator,
            signer_keypair: signer,
            upstream: "http://127.0.0.1:1".to_string(),
            http_client,
            egress_contract,
            approval_admin,
            receipt_log: Mutex::new(ReceiptLog {
                receipts: Vec::new(),
            }),
            tool_receipt_log: Mutex::new(ToolReceiptLog {
                receipts: persisted_tool_receipts,
            }),
            receipt_store: receipt_store.map(Mutex::new),
            revocation_store,
            revoked_capability_ids: Mutex::new(std::collections::HashSet::new()),
            trusted_capability_issuers,
            trusted_receipt_signers,
            sidecar_control_token,
            budget_store: Some(budget),
            mediation_hold_capable: hold_capable,
            mediation_kernel: Some(mediation_kernel),
            reaper_handle: Mutex::new(None),
            allow_advisory: false,
            receipt_backend: "ephemeral",
            revocation_backend: "ephemeral",
        })
    }

    fn with_loopback_peer(request: axum::http::Request<Body>) -> axum::http::Request<Body> {
        use axum::extract::ConnectInfo;
        let mut request = request;
        request
            .extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                4100,
            ))));
        request
    }

    // --- Scaffolding for governed and DPoP authorization tests ---

    use chio_core_types::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        GovernedToolInvocationIntentBody, GovernedTransactionIntent, MeteredBillingContext,
        MeteredBillingQuote, MeteredSettlementMode,
    };
    use chio_core_types::capability::scope::{Constraint, MonetaryAmount};
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;
    use chio_kernel::dpop::{DpopProof, DpopProofBody, DPOP_SCHEMA};

    fn issue_governed_capability(
        kernel: &Arc<ChioKernel>,
        agent: &Keypair,
        server: &str,
        tool: &str,
        max_per: u64,
        currency: &str,
        approval_threshold_units: u64,
    ) -> CapabilityToken {
        let grant = ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![
                Constraint::GovernedIntentRequired,
                Constraint::RequireApprovalAbove {
                    threshold_units: approval_threshold_units,
                },
            ],
            max_invocations: None,
            max_cost_per_invocation: Some(MonetaryAmount {
                units: max_per,
                currency: currency.to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: max_per,
                currency: currency.to_string(),
            }),
            dpop_required: None,
        };
        let scope = ChioScope {
            grants: vec![grant],
            ..ChioScope::default()
        };
        kernel
            .issue_capability(&agent.public_key(), scope, 3600)
            .test_unwrap()
    }

    fn issue_governed_dpop_capability(
        kernel: &Arc<ChioKernel>,
        agent: &Keypair,
        destinations: &[(&str, &str)],
        max_per: u64,
        max_total: u64,
        currency: &str,
        approval_threshold_units: u64,
    ) -> CapabilityToken {
        let grants = destinations
            .iter()
            .map(|(server, tool)| ToolGrant {
                server_id: (*server).to_string(),
                tool_name: (*tool).to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![
                    Constraint::GovernedIntentRequired,
                    Constraint::RequireApprovalAbove {
                        threshold_units: approval_threshold_units,
                    },
                ],
                max_invocations: None,
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: max_per,
                    currency: currency.to_string(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: max_total,
                    currency: currency.to_string(),
                }),
                dpop_required: Some(true),
            })
            .collect();
        kernel
            .issue_capability(
                &agent.public_key(),
                ChioScope {
                    grants,
                    ..ChioScope::default()
                },
                3600,
            )
            .test_unwrap()
    }

    fn issue_dpop_capability(
        kernel: &Arc<ChioKernel>,
        agent: &Keypair,
        server: &str,
        tool: &str,
        max_per: u64,
        currency: &str,
    ) -> CapabilityToken {
        issue_dpop_capability_with_total(kernel, agent, server, tool, max_per, max_per, currency)
    }

    fn issue_dpop_capability_with_total(
        kernel: &Arc<ChioKernel>,
        agent: &Keypair,
        server: &str,
        tool: &str,
        max_per: u64,
        max_total: u64,
        currency: &str,
    ) -> CapabilityToken {
        let grant = ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: Some(MonetaryAmount {
                units: max_per,
                currency: currency.to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: max_total,
                currency: currency.to_string(),
            }),
            dpop_required: Some(true),
        };
        let scope = ChioScope {
            grants: vec![grant],
            ..ChioScope::default()
        };
        kernel
            .issue_capability(&agent.public_key(), scope, 3600)
            .test_unwrap()
    }

    fn governed_intent(
        id: &str,
        server: &str,
        tool: &str,
        units: u64,
        currency: &str,
    ) -> GovernedTransactionIntent {
        GovernedTransactionIntent::tool_invocation(GovernedToolInvocationIntentBody {
            id: id.to_string(),
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            purpose: "invoice-settlement".to_string(),
            max_amount: Some(MonetaryAmount {
                units,
                currency: currency.to_string(),
            }),
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
        })
    }

    /// A governed intent that mandates prepayment: it carries a metered-billing
    /// context in `MustPrepay` settlement mode with a quote for `units`. The
    /// kernel denies it unless a payment adapter is configured to prepay the
    /// quote before the reserve-for-caller path mints a nonce.
    fn governed_mustprepay_intent(
        id: &str,
        server: &str,
        tool: &str,
        units: u64,
        currency: &str,
    ) -> GovernedTransactionIntent {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_unwrap()
            .as_secs();
        let mut intent = governed_intent(id, server, tool, units, currency);
        intent
            .as_tool_invocation_mut()
            .test_expect("governed test intent is a tool invocation")
            .metered_billing = Some(MeteredBillingContext {
            settlement_mode: MeteredSettlementMode::MustPrepay,
            quote: MeteredBillingQuote {
                quote_id: format!("quote-{id}"),
                provider: "billing.chio".to_string(),
                billing_unit: "call".to_string(),
                quoted_units: 1,
                quoted_cost: MonetaryAmount {
                    units,
                    currency: currency.to_string(),
                },
                issued_at: now.saturating_sub(5),
                expires_at: Some(now + 300),
            },
            max_billed_units: Some(2),
        });
        intent
    }

    fn governed_approval_token(
        approver: &Keypair,
        subject: &PublicKey,
        intent: &GovernedTransactionIntent,
        request_id: &str,
    ) -> GovernedApprovalToken {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_unwrap()
            .as_secs();
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: format!("approval-{request_id}"),
                approver: approver.public_key(),
                subject: subject.clone(),
                governed_intent_hash: intent.binding_hash().test_unwrap(),
                threshold_proposal_hash: None,
                request_id: request_id.to_string(),
                issued_at: now.saturating_sub(1),
                expires_at: now + 300,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .test_unwrap()
    }

    fn dpop_proof_for(
        agent: &Keypair,
        cap: &CapabilityToken,
        server: &str,
        tool: &str,
        parameters: &serde_json::Value,
    ) -> DpopProof {
        // Match the kernel's action-hash computation exactly: SHA-256 hex over
        // the canonical JSON of the tool arguments.
        let args_bytes = chio_core_types::canonical::canonical_json_bytes(parameters).test_unwrap();
        let action_hash = chio_core_types::crypto::sha256_hex(&args_bytes);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_unwrap()
            .as_secs();
        DpopProof::sign(
            DpopProofBody {
                schema: DPOP_SCHEMA.to_string(),
                capability_id: cap.id.clone(),
                tool_server: server.to_string(),
                tool_name: tool.to_string(),
                action_hash,
                nonce: uuid::Uuid::now_v7().to_string(),
                issued_at: now,
                agent_key: agent.public_key(),
            },
            agent,
        )
        .test_unwrap()
    }

    /// POST a body to `/v1/evaluate` and return the status and parsed JSON.
    async fn post_evaluate(
        state: Arc<ProxyState>,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        post_json(state, "/v1/evaluate", body).await
    }

    async fn post_evaluate_raw(
        state: Arc<ProxyState>,
        body: &serde_json::Value,
    ) -> (StatusCode, Vec<u8>) {
        post_json_bytes_with_bearer(state, "/v1/evaluate", body, None).await
    }

    /// POST a body to `/v1/reconcile` presenting the standard control token, so
    /// the reconcile control gate admits it, and return the status and JSON.
    async fn post_reconcile(
        state: Arc<ProxyState>,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        post_json_with_bearer(state, "/v1/reconcile", body, Some(MEDIATED_CONTROL_TOKEN)).await
    }

    async fn post_json(
        state: Arc<ProxyState>,
        uri: &str,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        post_json_with_bearer(state, uri, body, None).await
    }

    async fn post_json_with_bearer(
        state: Arc<ProxyState>,
        uri: &str,
        body: &serde_json::Value,
        bearer: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let (status, bytes) = post_json_bytes_with_bearer(state, uri, body, bearer).await;
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    }

    async fn post_json_bytes_with_bearer(
        state: Arc<ProxyState>,
        uri: &str,
        body: &serde_json::Value,
        bearer: Option<&str>,
    ) -> (StatusCode, Vec<u8>) {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(bearer) = bearer {
            builder = builder.header("authorization", format!("Bearer {bearer}"));
        }
        let request = with_loopback_peer(
            builder
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        );
        let response = build_app(state).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, bytes.to_vec())
    }

    include!("mediated_authorization_tests.rs");
    include!("mediated_persistence_tests.rs");
}
