//! Real cage lifecycle around the same native authority and TLS provider case.
use super::*;
use chio_cage::{
    CageEnforcementState, CageReceiptSigningContext, ExecutionIdentity, OperatorCeilings,
    RuntimeResourcePaths,
};
use chio_manifest::{NativeSyscallProfile, VerifiedManifestRegistry};
use chio_mcp_adapter::edge::AdapterError;
use chio_mcp_adapter::transport::{
    CageReceiptPersistence, CageRequiredLaunch, NativeMcpLaunch, NativeMcpLaunchFactory,
};
use chio_security_types::{
    CageLaunchContractDigests, EnterpriseMigrationRuntimeBinding, EnterpriseMigrationStateStore,
};
use chio_store_sqlite::SqliteReceiptStore;
use std::collections::{BTreeMap, BTreeSet};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
#[cfg_attr(
    not(target_arch = "x86_64"),
    ignore = "requires Linux x86_64 cage enforcement"
)]
fn native_kernel_confined_broker_mcp_preserves_capture_and_terminal_receipts() -> TestResult {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    run_native_delivery(DeliveryRoute::ConfinedMcp, None)
}

pub(super) struct ConfinedDelivery {
    pub tool: Arc<crate::native_mcp::NativeBrokerMcpTool>,
    pub registry: Arc<VerifiedManifestRegistry>,
    receipts: PathBuf,
    anchor: tempfile::TempDir,
    signer: PublicKey,
}

impl ConfinedDelivery {
    pub fn new(
        directory: &Path,
        broker: &BrokerDaemonConfig,
        broker_pid: u32,
        signer: &Keypair,
    ) -> TestResult<Self> {
        let target = fs::canonicalize(
            std::env::var_os("CHIO_BROKER_MCP_TOOL")
                .ok_or("CHIO_BROKER_MCP_TOOL must identify the actual static tool")?,
        )?;
        let helper = fs::canonicalize(
            std::env::var_os("CHIO_CAGE_TEST_HELPER")
                .ok_or("CHIO_CAGE_TEST_HELPER must identify the actual static cage-init")?,
        )?;
        let directory = fs::canonicalize(directory)?;
        let anchor = tempfile::Builder::new()
            .prefix("chio-confined-broker-anchor-")
            .tempdir_in("/dev/shm")?;
        fs::set_permissions(anchor.path(), fs::Permissions::from_mode(0o700))?;
        let receipts = directory.join("cage-receipts.sqlite3");
        let registry = host::manifests(signer, true)?;
        let args = vec![
            "--tenant-scope".into(),
            broker.tenant_scope.clone(),
            "--tool-name".into(),
            host::TOOL.into(),
            "--receipt-signer".into(),
            broker.broker_identity.to_hex(),
        ];
        let receipt_store = Arc::new(SqliteReceiptStore::open_for_finding_pool(
            &receipts,
            anchor.path(),
        )?);
        receipt_store.wait_for_writer_ready(Duration::from_secs(30))?;
        let mut factory = ConfinedFactory {
            target: target.clone(),
            helper,
            args: args.clone(),
            directory,
            receipts: receipts.clone(),
            anchor: anchor.path().to_path_buf(),
            signer: signer.clone(),
            receipt_store: std::sync::Mutex::new(receipt_store),
            migration: std::sync::Mutex::new(None),
            contract: String::new(),
            peer: chio_cage::BrokerPeerIdentity {
                pid: broker_pid,
                uid: broker.trusted_service_uid,
                gid: rustix::process::getegid().as_raw(),
            },
        };
        factory.contract = factory.authorization_contract_digest()?;
        let admitted = chio_cage::admit(
            registry.authorize_cage_manifest(host::SERVER)?,
            &factory.ceilings(),
        )?;
        *factory
            .migration
            .lock()
            .map_err(|_| "cage migration lock poisoned")? =
            Some(factory.provision_migration(&admitted, &factory.contract)?);
        let factory = Arc::new(factory);
        let tool = Arc::new(crate::native_mcp::NativeBrokerMcpTool::new(
            target.to_str().ok_or("tool path is not UTF-8")?.into(),
            args,
            host::SERVER,
            registry.clone(),
            factory,
        )?);
        Ok(Self {
            tool,
            registry,
            receipts,
            anchor,
            signer: signer.public_key(),
        })
    }

    pub fn verify_receipts(&self, canary: &[u8]) -> TestResult {
        let store = SqliteReceiptStore::open_for_finding_pool(&self.receipts, self.anchor.path())?;
        let connection = rusqlite::Connection::open(&self.receipts)?;
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM claim_receipt_log_entries",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 2, "one enforcement receipt and one terminal receipt");
        let rows = store.receipts_canonical_bytes_range(1, count.try_into()?)?;
        assert_eq!(
            rows.len(),
            2,
            "one enforcement receipt and one terminal receipt"
        );
        let mut bodies = Vec::new();
        for (_, bytes) in rows {
            assert_raw_absent(canary, &bytes, "persisted cage receipt");
            let receipt = serde_json::from_slice(&bytes)?;
            bodies.push(chio_cage::verify_signed_cage_receipt_with_trusted_key(
                &receipt,
                &self.signer,
            )?);
        }
        assert_eq!(
            bodies[0].enforcement_record.state,
            CageEnforcementState::FullyEnforced
        );
        assert_eq!(
            bodies[1].enforcement_record.state,
            CageEnforcementState::Exited
        );
        assert_eq!(bodies[0].attempt_id, bodies[1].attempt_id);
        assert_eq!(bodies[0].bindings, bodies[1].bindings);
        assert_eq!(
            bodies[0].admitted_policy_digest,
            bodies[1].admitted_policy_digest
        );
        assert!(bodies[0].admitted_policy_digest.is_some());
        Ok(())
    }

    pub fn diagnose_preparation(&self, broker: &BrokerDaemonConfig) {
        let diagnose = || -> TestResult {
            if !self.receipts.exists() {
                eprintln!("confined cage receipt store was not opened");
                return Ok(());
            }
            let connection = rusqlite::Connection::open(&self.receipts)?;
            let mut statement = connection
                .prepare("SELECT raw_json FROM claim_receipt_log_entries ORDER BY entry_seq")?;
            for raw in statement.query_map([], |row| row.get::<_, String>(0))? {
                let receipt = serde_json::from_str(&raw?)?;
                let body =
                    chio_cage::verify_signed_cage_receipt_with_trusted_key(&receipt, &self.signer)?;
                eprintln!(
                    "confined cage preparation record: {:?}",
                    body.enforcement_record
                );
            }
            let connection = rusqlite::Connection::open(&broker.databases.receipt_database_path)?;
            let mut statement =
                connection.prepare("SELECT canonical_receipt FROM broker_failure_receipts")?;
            for raw in statement.query_map([], |row| row.get::<_, Vec<u8>>(0))? {
                let receipt = serde_json::from_slice(&raw?)?;
                crate::receipt::verify_failure_receipt(&receipt, &broker.broker_identity)?;
                eprintln!("confined broker failure: {}", receipt.body.diagnostic_code);
            }
            Ok(())
        };
        if let Err(error) = diagnose() {
            eprintln!("confined cage diagnosis failed: {error}");
        }
    }
}

// This fixture composes the public production cage and adapter APIs. It never
// synthesizes an enforcement record or substitutes a tool for the real binary.
struct ConfinedFactory {
    target: PathBuf,
    helper: PathBuf,
    args: Vec<String>,
    directory: PathBuf,
    receipts: PathBuf,
    anchor: PathBuf,
    signer: Keypair,
    peer: chio_cage::BrokerPeerIdentity,
    receipt_store: std::sync::Mutex<Arc<SqliteReceiptStore>>,
    migration: std::sync::Mutex<Option<EnterpriseMigrationRuntimeBinding>>,
    contract: String,
}

impl ConfinedFactory {
    fn runtime(&self) -> TestResult<chio_cage::RetainedRuntimeResources> {
        let identity = ExecutionIdentity::from_observed_credentials(
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
            rustix::process::getgroups()?
                .into_iter()
                .map(|gid| gid.as_raw())
                .collect(),
        )?;
        let argv = std::iter::once(
            self.target
                .to_str()
                .ok_or("target path is not UTF-8")?
                .into(),
        )
        .chain(self.args.clone())
        .collect();
        Ok(chio_cage::retain_runtime_resources(
            &RuntimeResourcePaths::new(
                self.helper.clone(),
                self.target.clone(),
                self.directory.clone(),
                BTreeSet::new(),
                identity,
            )
            .with_target_argv(argv),
        )?)
    }

    fn build(
        &self,
        command: &str,
        args: &[&str],
        server: &str,
        registry: Arc<VerifiedManifestRegistry>,
        stream: UnixStream,
    ) -> TestResult<CageRequiredLaunch> {
        if Path::new(command) != self.target || args != self.args || server != host::SERVER {
            return Err("confined launch input changed".into());
        }
        let admitted =
            chio_cage::admit(registry.authorize_cage_manifest(server)?, &self.ceilings())?;
        let runtime = self.runtime()?;
        let broker_contract = canonical_json_bytes(&self.peer)?;
        let socket = chio_cage::retain_broker_ipc(
            File::from(OwnedFd::from(stream)),
            hex::encode(Sha256::digest(&broker_contract)),
            self.peer,
        )?;
        let compiled = chio_cage::compile(admitted, runtime, &BTreeMap::new(), Some(socket))?;
        let contract = self.authorization_contract_digest()?;
        if contract != self.contract || compiled.plan().resource_limits != Self::limits() {
            return Err("provisioned cage configuration changed".into());
        }
        let migration = self
            .migration
            .lock()
            .map_err(|_| "cage migration lock poisoned")?
            .clone()
            .ok_or("cage migration was not provisioned")?;
        let context = CageReceiptSigningContext::new(
            "native-parent-process-boundary",
            server,
            "cage-launch",
            compiled.profile_digest(),
            Some(TENANT_SCOPE.into()),
        )?
        .with_admitted_policy_digest(&contract)?;
        let persistence = CageReceiptPersistence::new(
            format!("native-broker-cage-{}", compiled.plan_digest()),
            context,
            Arc::new(Ed25519Backend::new(self.signer.clone())),
            self.signer.public_key(),
            self.receipt_store
                .lock()
                .map_err(|_| "cage receipt store lock poisoned")?
                .clone(),
        )?;
        Ok(CageRequiredLaunch::new(
            registry,
            server,
            compiled,
            persistence,
            migration,
        )?)
    }

    fn limits() -> chio_cage::ResourceLimitPlan {
        chio_cage::ResourceLimitPlan {
            nofile_soft: 192,
            nofile_hard: 192,
        }
    }

    fn ceilings(&self) -> OperatorCeilings {
        OperatorCeilings::new(
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::from([NativeSyscallProfile::BrokeredNativeV1]),
        )
        .with_forbidden_paths(BTreeSet::from([
            self.directory.clone(),
            self.anchor.clone(),
        ]))
    }

    fn provision_migration(
        &self,
        admitted: &chio_cage::AdmittedManifest,
        contract: &str,
    ) -> TestResult<EnterpriseMigrationRuntimeBinding> {
        let digest = |value: &[u8]| Digest32::new(Sha256::digest(value).into());
        let key = EnterpriseMigrationKey {
            deployment_id: RecordId::new(DEPLOYMENT_ID)?,
            scope_kind: EnterpriseMigrationScopeKind::ToolServer,
            scope_id: RecordId::new(host::SERVER)?,
            control: EnterpriseMigrationControl::CageEnforcement,
        };
        let inputs = CageLaunchContractDigests {
            policy_schema_digest: digest(b"chio.native-broker-process-cage.v1"),
            policy_signer_digest: digest(&canonical_json_bytes(&self.signer.public_key())?),
            signed_manifest_digest: digest(admitted.signed_manifest_digest().as_bytes()),
            registered_public_key_digest: digest(&canonical_json_bytes(&self.signer.public_key())?),
            operator_ceilings_digest: digest(admitted.operator_ceiling_digest().as_bytes()),
            runtime_digest: digest(contract.as_bytes()),
            limits_digest: digest(&canonical_json_bytes(&Self::limits())?),
            receipt_digest: digest(&canonical_json_bytes(&(&self.receipts, &self.anchor))?),
            broker_binding_digest: digest(&canonical_json_bytes(&self.peer)?),
            migration_ledger_digest: digest(&canonical_json_bytes(&key)?),
        };
        let posture = |stage| {
            chio_security_types::cage_migration_posture_digest(
                &key.deployment_id,
                &key.scope_id,
                stage,
                &inputs,
            )
        };
        let path = self.directory.join("cage-migration.sqlite3");
        let store = SqliteEnterpriseMigrationStateStore::open(
            &path,
            SqliteEnterpriseMigrationOpenPolicy::new(vec![self.signer.public_key()], Vec::new())?,
        )?;
        let genesis = EnterpriseMigrationTransitionBody::genesis(
            key.clone(),
            posture(EnterpriseMigrationStage::Disabled)?,
            digest(contract.as_bytes()),
            digest(b"boundary cage approval"),
            digest(b"boundary cage evidence"),
            1,
            self.signer.public_key().to_hex(),
        )?;
        store.register(&sign_enterprise_migration_transition(
            genesis,
            &self.signer,
        )?)?;
        let mut state = store.load(&key)?.ok_or("cage genesis absent")?;
        while state.stage != EnterpriseMigrationStage::Enforced {
            let next = state.stage.next().ok_or("cage enforcement stage absent")?;
            let promotion = EnterpriseMigrationTransitionBody::promotion(
                &state,
                posture(next)?,
                digest(contract.as_bytes()),
                digest(&canonical_json_bytes(&next)?),
                digest(contract.as_bytes()),
                next.generation() + 1,
                self.signer.public_key().to_hex(),
            )?;
            store.compare_and_promote(&sign_enterprise_migration_transition(
                promotion,
                &self.signer,
            )?)?;
            state = store.load(&key)?.ok_or("cage promotion absent")?;
        }
        let head = state.minimum_head();
        drop(store);
        let store: Arc<dyn EnterpriseMigrationStateStore> =
            Arc::new(SqliteEnterpriseMigrationStateStore::open(
                &path,
                SqliteEnterpriseMigrationOpenPolicy::new(
                    vec![self.signer.public_key()],
                    vec![head],
                )?,
            )?);
        Ok(EnterpriseMigrationRuntimeBinding::load(
            &store,
            &key,
            EnterpriseMigrationStage::Enforced,
            posture(EnterpriseMigrationStage::Enforced)?,
        )?)
    }
}

impl NativeMcpLaunchFactory for ConfinedFactory {
    fn authorization_contract_digest(&self) -> std::result::Result<String, AdapterError> {
        let contract = || -> TestResult<String> {
            let runtime = self.runtime()?;
            Ok(hex::encode(Sha256::digest(canonical_json_bytes(
                &serde_json::json!({
                    "schema": "chio.native-broker-process-cage.v1",
                    "helper": runtime.helper().binding_digest(),
                    "target": runtime.target().binding_digest(),
                    "argv": self.args, "directory": self.directory, "peer": self.peer,
                    "receipts": self.receipts, "anchor": self.anchor,
                    "signer": self.signer.public_key(),
                }),
            )?)))
        };
        contract().map_err(|error| AdapterError::ConnectionFailed(error.to_string()))
    }

    fn prepare_launch(
        &self,
        _: &str,
        _: &[&str],
        _: &str,
        _: Arc<VerifiedManifestRegistry>,
    ) -> std::result::Result<NativeMcpLaunch, AdapterError> {
        Err(AdapterError::ConnectionFailed(
            "prepared broker stream is required".into(),
        ))
    }

    fn prepare_broker_launch(
        &self,
        command: &str,
        args: &[&str],
        server: &str,
        registry: Arc<VerifiedManifestRegistry>,
        stream: UnixStream,
    ) -> std::result::Result<CageRequiredLaunch, AdapterError> {
        self.build(command, args, server, registry, stream)
            .map_err(|error| {
                eprintln!("confined cage preparation failed: {error}");
                AdapterError::ConnectionFailed(error.to_string())
            })
    }
}
