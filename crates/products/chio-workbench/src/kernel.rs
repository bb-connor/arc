use crate::{tools::WorkspaceTools, Error, Result, Role};
use chio_core::{
    capability::{
        attenuation::{compute_attenuation_witness, delegate, scope_hash, AttenuationProof},
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
    },
    crypto::{sha256_hex, Keypair},
};
use chio_core_types::delegation_receipt::ScopeAttenuation;
use chio_kernel::{ChioKernel, HotPathDeadlineConfig, KernelConfig, MemoryBudgetConfig};
use chio_store_sqlite::{receipt_store::SqliteReceiptStore, SqliteAuthorityStore};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::Path,
    sync::Arc,
};

pub(crate) fn signing_key(state: &Path) -> Result<Keypair> {
    use rustix::fs::{openat, Mode, OFlags};
    let directory = File::open(state)?;
    let flags = OFlags::CLOEXEC | OFlags::NOFOLLOW;
    match openat(
        &directory,
        "kernel.seed",
        flags | OFlags::RDONLY,
        Mode::empty(),
    ) {
        Ok(fd) => {
            let mut file = File::from(fd);
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.len() != 32
                || metadata.mode() & 0o077 != 0
            {
                return Err(Error::Invalid(
                    "kernel.seed must be a private 32-byte regular file".into(),
                ));
            }
            let mut bytes = [0; 32];
            file.read_exact(&mut bytes)?;
            Ok(Keypair::from_seed(&bytes))
        }
        Err(rustix::io::Errno::NOENT) => {
            let key = Keypair::generate();
            let mut file = File::from(
                openat(
                    &directory,
                    "kernel.seed",
                    flags | OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
                    Mode::RUSR | Mode::WUSR,
                )
                .map_err(invalid)?,
            );
            file.write_all(&key.seed_bytes())?;
            file.sync_all()?;
            directory.sync_all()?;
            Ok(key)
        }
        Err(error) => Err(invalid(error)),
    }
}

pub(crate) fn build(state: &Path, tools: WorkspaceTools, key: Keypair) -> Result<Arc<ChioKernel>> {
    // Keep admission journals, budgets and revocations under one fenced SQLite
    // authority. Receipt projection remains in the standard receipt store.
    let locks = state.join("locks");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&locks)?;
    let database = state.join("authority.sqlite");
    if !database.exists() {
        SqliteAuthorityStore::provision(&database, &locks).map_err(invalid)?;
    }
    let authority = SqliteAuthorityStore::open_serving(&database, &locks).map_err(invalid)?;
    let mut kernel = ChioKernel::try_new(KernelConfig {
        ca_public_keys: vec![key.public_key()],
        keypair: key,
        max_delegation_depth: 1,
        policy_hash: sha256_hex(b"chio-workbench-local-v1:role-tools:bounded-calls:confined-files"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: 60,
        max_stream_total_bytes: 131072,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: false,
        allow_ephemeral_revocation_store: false,
        checkpoint_batch_size: 100,
        retention_config: None,
        memory_budget: MemoryBudgetConfig::defaults(),
        deadlines: HotPathDeadlineConfig::default(),
    })
    .map_err(|error| Error::Invalid(error.to_string()))?;
    // Reads consume invocation quotas too. The joint authority requires every
    // quota mutation to belong to a durable admission operation.
    kernel
        .configure_durable_admission(
            chio_kernel::admission_operation::DurableAdmissionMode::All,
            false,
        )
        .map_err(invalid)?;
    kernel.set_receipt_store(Box::new(
        SqliteReceiptStore::open(state.join("receipts.sqlite")).map_err(invalid)?,
    ))?;
    kernel.set_revocation_store(Box::new(authority.revocation_store()));
    kernel.set_budget_store(Box::new(authority.budget_store()));
    kernel
        .set_durable_admission_store(
            Arc::new(authority.admission_operation_store()),
            Arc::new(authority.tool_outcome_store()),
            authority.mutation_fence(),
        )
        .map_err(invalid)?;
    kernel.register_tool_server(Box::new(tools));
    Ok(Arc::new(kernel))
}

pub(crate) fn scope(role: Role, calls: u32, delegable: bool) -> ChioScope {
    ChioScope {
        grants: role
            .tools()
            .iter()
            .map(|tool| ToolGrant {
                server_id: "workspace".into(),
                tool_name: (*tool).into(),
                operations: if delegable {
                    vec![Operation::Invoke, Operation::Delegate]
                } else {
                    vec![Operation::Invoke]
                },
                constraints: vec![],
                max_invocations: Some(calls),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            })
            .collect(),
        ..ChioScope::default()
    }
}

pub(crate) fn child(
    parent: &CapabilityToken,
    parent_key: &Keypair,
    authority: &Keypair,
    role: Role,
    calls: u32,
) -> Result<CapabilityToken> {
    let scope = scope(role, calls, false);
    let subject = Keypair::generate().public_key();
    let delegation = delegate(
        parent,
        &scope,
        parent_key,
        &subject,
        ScopeAttenuation {
            budget_share_bps: Some(share(parent, calls)?),
            ..ScopeAttenuation::default()
        },
        crate::now(),
        *uuid::Uuid::new_v4().as_bytes(),
    )
    .map_err(invalid)?;
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: format!("cap-{}", uuid::Uuid::new_v4()),
                issuer: authority.public_key(),
                subject,
                scope: scope.clone(),
                issued_at: crate::now(),
                expires_at: parent.expires_at,
                delegation_chain: vec![delegation.link],
                aggregate_invocation_budget: None,
            },
            caveats: vec![],
            scope_attenuations: vec![],
            budget_share_bps: Some(share(parent, calls)?),
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&parent.scope).map_err(invalid)?,
                child_scope_hash: scope_hash(&scope).map_err(invalid)?,
                normalized_subset_proof: compute_attenuation_witness(&parent.scope, &scope)
                    .map_err(invalid)?,
            },
        },
        authority,
    )
    .map_err(invalid)?;
    Ok(token)
}

fn share(parent: &CapabilityToken, calls: u32) -> Result<u16> {
    let total = parent
        .scope
        .grants
        .first()
        .and_then(|grant| grant.max_invocations)
        .filter(|total| *total > 0)
        .ok_or_else(|| Error::Invalid("parent allowance missing".into()))?;
    u16::try_from(u64::from(calls) * 10_000 / u64::from(total)).map_err(invalid)
}

fn invalid(error: impl std::fmt::Display) -> Error {
    Error::Invalid(error.to_string())
}
