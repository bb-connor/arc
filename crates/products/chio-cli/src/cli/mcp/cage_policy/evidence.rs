//! Export and verify existing cage receipts without launching another tool.

use super::*;
use chio_cage::{
    verify_signed_cage_receipt_with_trusted_key, CageEnforcementState, CageReceiptBody,
};
use chio_core::receipt::body::ChioReceipt;

#[path = "evidence_start.rs"]
mod start;
pub(crate) use start::verify_native_start_file;

#[cfg(test)]
#[path = "evidence_tests.rs"]
mod tests;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeLaunchEvidence {
    /// Preserve the canonical policy bytes used by the launch contract.
    pub signed_policy: String,
    pub enforcement: ChioReceipt,
    pub terminal: ChioReceipt,
}

/// An original launch with its exit receipt only when one was retained.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeLaunchObservation {
    pub signed_policy: String,
    pub enforcement: ChioReceipt,
    pub terminal: Option<ChioReceipt>,
}

pub(crate) struct NativeObservedWindow {
    pub started_at_unix_ms: u64,
    pub exited_at_unix_ms: Option<u64>,
    pub tools: BTreeSet<String>,
    pub manifest: chio_manifest::ToolManifest,
    pub target_argv: Vec<String>,
}

pub(crate) fn verify_native_launch_observation(
    evidence: &NativeLaunchObservation,
    server_id: &str,
    trusted_policy_signer: &chio_core::PublicKey,
) -> Result<NativeObservedWindow, CliError> {
    if let Some(terminal) = &evidence.terminal {
        let window = verify_native_launch_evidence(
            &NativeLaunchEvidence {
                signed_policy: evidence.signed_policy.clone(),
                enforcement: evidence.enforcement.clone(),
                terminal: terminal.clone(),
            },
            server_id,
            trusted_policy_signer,
        )?;
        return Ok(NativeObservedWindow {
            started_at_unix_ms: window.started_at_unix_ms,
            exited_at_unix_ms: Some(window.exited_at_unix_ms),
            tools: window.tools,
            manifest: window.manifest,
            target_argv: window.target_argv,
        });
    }
    let (policy, enforcement) = verify_policy_bound_enforcement(
        &evidence.signed_policy,
        &evidence.enforcement,
        server_id,
        trusted_policy_signer,
    )?;
    Ok(NativeObservedWindow {
        started_at_unix_ms: enforcement.recorded_at_unix_ms,
        exited_at_unix_ms: None,
        tools: policy
            .signed_manifest
            .manifest
            .tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect(),
        manifest: policy.signed_manifest.manifest,
        target_argv: policy.runtime.target_argv,
    })
}

pub(crate) struct NativeLaunchWindow {
    pub started_at_unix_ms: u64,
    pub exited_at_unix_ms: u64,
    pub tools: BTreeSet<String>,
    pub manifest: chio_manifest::ToolManifest,
    pub target_argv: Vec<String>,
}

fn require(condition: bool, message: &str) -> Result<(), CliError> {
    if condition {
        Ok(())
    } else {
        Err(CliError::cli_other_error(format!(
            "native launch evidence: {message}"
        )))
    }
}

fn verify_policy_bound_enforcement(
    signed_policy: &str,
    receipt: &ChioReceipt,
    server_id: &str,
    trusted_policy_signer: &chio_core::PublicKey,
) -> Result<(McpCageLaunchPolicy, CageReceiptBody), CliError> {
    require(
        signed_policy.len() <= MAX_CAGE_POLICY_BYTES,
        "policy is too large",
    )?;
    let policy = decode_cage_policy(
        Path::new("exported-launch-policy"),
        signed_policy.as_bytes(),
        trusted_policy_signer,
    )?;
    require(
        policy.schema == MCP_CAGE_LAUNCH_POLICY_SCHEMA
            && policy.enterprise_migration.stage
                == chio_security_types::EnterpriseMigrationStage::Enforced
            && policy.signed_manifest.manifest.server_id == server_id
            && policy.broker.is_none(),
        "expected the pinned server's Enforced local policy",
    )?;
    let registry = resolve_launch_manifest_registry(
        &policy,
        chio_manifest::RuntimeToolTopology::local(),
        None,
        "run evidence",
    )?;
    let manifest = registry
        .authorize_cage_manifest(server_id)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let key = chio_core::PublicKey::from_hex(&policy.receipt.trusted_signer_public_key)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let enforcement = verify_signed_cage_receipt_with_trusted_key(receipt, &key)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    require(
        receipt.tool_server == server_id
            && receipt.tool_name == "cage-launch"
            && receipt.capability_id == policy.receipt.capability_id
            && receipt.tenant_id == policy.receipt.tenant_id,
        "receipt context differs from signed policy",
    )?;
    require(
        enforcement.enforcement_record.state == CageEnforcementState::FullyEnforced,
        "receipt is not a released Enforced launch",
    )?;
    let actual = enforcement
        .enforcement_record
        .fully_enforced
        .as_ref()
        .ok_or_else(|| CliError::cli_other_error("missing full enforcement evidence"))?;
    let prepared = &actual.prepared;
    require(
        prepared.manifest_digest == manifest.manifest_digest()
            && prepared.helper_binding_digest == policy.runtime.cage_init_binding_digest
            && prepared.target_binding_digest == policy.runtime.target_binding_digest
            && prepared.applied_execution_identity == policy.runtime.execution_identity,
        "observed launch differs from signed manifest, artifacts or execution identity",
    )?;
    Ok((policy, enforcement))
}

pub(crate) fn verify_native_launch_evidence(
    evidence: &NativeLaunchEvidence,
    server_id: &str,
    trusted_policy_signer: &chio_core::PublicKey,
) -> Result<NativeLaunchWindow, CliError> {
    let (policy, enforcement) = verify_policy_bound_enforcement(
        &evidence.signed_policy,
        &evidence.enforcement,
        server_id,
        trusted_policy_signer,
    )?;
    let key = chio_core::PublicKey::from_hex(&policy.receipt.trusted_signer_public_key)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let terminal = verify_signed_cage_receipt_with_trusted_key(&evidence.terminal, &key)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    require(
        evidence.terminal.tool_server == server_id
            && evidence.terminal.tool_name == "cage-launch"
            && evidence.terminal.capability_id == policy.receipt.capability_id
            && evidence.terminal.tenant_id == policy.receipt.tenant_id,
        "receipt context differs from signed policy",
    )?;
    require(
        terminal.enforcement_record.state == CageEnforcementState::Exited
            && enforcement.attempt_id == terminal.attempt_id
            && enforcement.started_at_unix_ms == terminal.started_at_unix_ms
            && enforcement.bindings == terminal.bindings
            && enforcement.enforcement_record.fully_enforced
                == terminal.enforcement_record.fully_enforced
            && enforcement.recorded_at_unix_ms <= terminal.recorded_at_unix_ms,
        "enforcement and terminal receipts belong to different launches",
    )?;
    let exit = terminal
        .enforcement_record
        .exit
        .as_ref()
        .ok_or_else(|| CliError::cli_other_error("missing terminal exit evidence"))?;
    require(
        enforcement.recorded_at_unix_ms <= exit.exited_at_unix_ms,
        "terminal exit predates released enforcement receipt",
    )?;
    Ok(NativeLaunchWindow {
        started_at_unix_ms: enforcement.recorded_at_unix_ms,
        exited_at_unix_ms: exit.exited_at_unix_ms,
        tools: policy
            .signed_manifest
            .manifest
            .tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect(),
        manifest: policy.signed_manifest.manifest.clone(),
        target_argv: policy.runtime.target_argv.clone(),
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn export_native_launch_evidence(
    policy_path: &Path,
    server_id: &str,
    trusted_policy_signer: &chio_core::PublicKey,
    receipt_ids: &BTreeSet<String>,
) -> Result<BTreeMap<String, NativeLaunchEvidence>, CliError> {
    export_native_launch_observations(policy_path, server_id, trusted_policy_signer, receipt_ids)?
        .into_iter()
        .map(|(id, observed)| {
            let terminal = observed.terminal.ok_or_else(|| {
                CliError::cli_other_error("native launch has no retained terminal receipt")
            })?;
            Ok((
                id,
                NativeLaunchEvidence {
                    signed_policy: observed.signed_policy,
                    enforcement: observed.enforcement,
                    terminal,
                },
            ))
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub(crate) fn export_native_launch_observations(
    policy_path: &Path,
    server_id: &str,
    trusted_policy_signer: &chio_core::PublicKey,
    receipt_ids: &BTreeSet<String>,
) -> Result<BTreeMap<String, NativeLaunchObservation>, CliError> {
    use chio_kernel::receipt_query::ReceiptQuery;
    use chio_kernel::ReceiptStore;

    let bytes = read_cage_policy(policy_path)?;
    let policy = decode_cage_policy(policy_path, &bytes, trusted_policy_signer)?;
    require(
        policy.receipt.database_path.is_file(),
        "receipt store is absent",
    )?;
    let anchor = policy
        .receipt
        .rollback_anchor_root
        .as_ref()
        .ok_or_else(|| CliError::cli_other_error("missing signed receipt rollback anchor"))?;
    let store = chio_store_sqlite::SqliteReceiptStore::open_for_finding_pool(
        &policy.receipt.database_path,
        anchor,
    )
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let key = chio_core::PublicKey::from_hex(&policy.receipt.trusted_signer_public_key)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let mut launches = BTreeMap::new();
    let mut since = u64::MAX;
    for id in receipt_ids {
        let receipt = store
            .load_retained_chio_receipt(id)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
            .ok_or_else(|| CliError::cli_other_error("referenced cage receipt is absent"))?;
        let body = verify_signed_cage_receipt_with_trusted_key(&receipt, &key)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        require(
            body.enforcement_record.state == CageEnforcementState::FullyEnforced,
            "referenced receipt is not full enforcement",
        )?;
        since = since.min(receipt.timestamp);
        require(
            launches
                .insert(body.attempt_id, (id.clone(), receipt))
                .is_none(),
            "duplicate enforcement receipt for one attempt",
        )?;
    }
    require(!launches.is_empty(), "no referenced native launches")?;
    let mut query = ReceiptQuery {
        tool_server: Some(server_id.into()),
        tool_name: Some("cage-launch".into()),
        capability_id: Some(policy.receipt.capability_id.clone()),
        since: Some(since),
        limit: 200,
        ..ReceiptQuery::default()
    }
    .local_operator_admin();
    let mut terminals = BTreeMap::new();
    let mut examined = 0;
    loop {
        let page = store
            .query_receipts(&query)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        examined += page.receipts.len();
        require(
            examined <= 4096,
            "native receipt export exceeds 4096 records",
        )?;
        for stored in page.receipts {
            let body = verify_signed_cage_receipt_with_trusted_key(&stored.receipt, &key)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
            if launches.contains_key(&body.attempt_id)
                && body.enforcement_record.state == CageEnforcementState::Exited
            {
                require(
                    terminals.insert(body.attempt_id, stored.receipt).is_none(),
                    "duplicate terminal receipt for one launch",
                )?;
            }
        }
        match page.next_cursor {
            Some(cursor) => query.cursor = Some(cursor),
            None => break,
        }
    }
    let signed_policy =
        String::from_utf8(bytes).map_err(|error| CliError::cli_other_error(error.to_string()))?;
    launches
        .into_iter()
        .map(|(attempt, (id, enforcement))| {
            let evidence = NativeLaunchObservation {
                signed_policy: signed_policy.clone(),
                enforcement,
                terminal: terminals.remove(&attempt),
            };
            verify_native_launch_observation(&evidence, server_id, trusted_policy_signer)?;
            Ok((id, evidence))
        })
        .collect()
}
