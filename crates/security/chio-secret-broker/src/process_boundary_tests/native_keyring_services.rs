//! Real witness and auditor executables for the confined broker invocation.
use super::*;
use chio_core_types::SigningBackend;
use chio_keyring::{
    AuditServiceConfig, KeyLogPolicy, KeyLogPolicyDocument, UnixKeyLogWitnessClient, WitnessId,
    WitnessServiceConfig,
};
use std::collections::BTreeMap;

pub(super) struct KeyServices {
    _children: Vec<ManagedChild>,
    pub witnesses: Vec<UnixKeyLogWitnessClient>,
    pub witness_endpoints: BTreeMap<String, PathBuf>,
    pub audit_endpoints: BTreeMap<String, PathBuf>,
}

pub(super) fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

pub(super) fn policy_document() -> KeyLogPolicyDocument {
    KeyLogPolicyDocument {
        schema: chio_keyring::KEY_LOG_POLICY_DOCUMENT_SCHEMA.into(),
        log_id: "log.native.broker".into(),
        authority_id: "authority.native.broker".into(),
        bootstrap_public_key: backend(230).public_key().to_hex(),
        operator_public_key: backend(231).public_key().to_hex(),
        witness_roster_id: "witnesses.native.broker".into(),
        witness_public_keys: (0..3_u8)
            .map(|i| {
                (
                    format!("witness.{i}"),
                    backend(240 + i).public_key().to_hex(),
                )
            })
            .collect(),
        recovery_policy_id: "recovery.native.broker".into(),
        recovery_public_keys: BTreeMap::new(),
        recovery_threshold: 0,
        artifact_time_public_keys: BTreeMap::from([(
            "clock.native.broker".into(),
            backend(233).public_key().to_hex(),
        )]),
        auditor_public_keys: (0..2_u8)
            .map(|i| (format!("audit.{i}"), backend(250 + i).public_key().to_hex()))
            .collect(),
        max_checkpoint_future_skew_millis: 60_000,
    }
}

fn spawn_service(variable: &str, config: &Path) -> TestResult<ManagedChild> {
    let binary = fs::canonicalize(std::env::var_os(variable).ok_or_else(|| {
        format!("{variable} must identify the owning candidate's key-log executable")
    })?)?;
    Ok(ManagedChild::new(
        Command::new(binary)
            .env_clear()
            .arg("--config")
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?,
    ))
}

impl KeyServices {
    pub fn witnesses(directory: &Path, policy: &KeyLogPolicy) -> TestResult<Self> {
        let mut services = Self {
            _children: Vec::new(),
            witnesses: Vec::new(),
            witness_endpoints: BTreeMap::new(),
            audit_endpoints: BTreeMap::new(),
        };
        for index in 0..3_u8 {
            let identifier = format!("witness.{index}");
            let seed = directory.join(format!("witness-{index}.seed"));
            write_private(&seed, &[240 + index; 32]);
            let socket = directory.join(format!("witness-{index}.sock"));
            let config_path = directory.join(format!("witness-{index}.json"));
            let config = WitnessServiceConfig {
                schema: chio_keyring::KEY_LOG_WITNESS_SERVICE_CONFIG_SCHEMA.into(),
                policy_path: directory.join("policy.json"),
                database_path: directory.join(format!("witness-{index}.sqlite3")),
                socket_path: socket.clone(),
                witness_id: identifier.clone(),
                seed_file_path: seed,
                provision: true,
            };
            write_private(&config_path, &canonical_json_bytes(&config)?);
            services
                ._children
                .push(spawn_service("CHIO_KEYLOG_WITNESS", &config_path)?);
            let client = UnixKeyLogWitnessClient::new(
                socket.clone(),
                WitnessId::new(&identifier)?,
                backend(240 + index).public_key(),
                policy.configuration_binding()?,
            )?;
            let started = Instant::now();
            while client.readiness(&format!("native-start-{index}")).is_err() {
                if started.elapsed() >= Duration::from_secs(10) {
                    return Err("native witness did not become ready".into());
                }
                thread::sleep(Duration::from_millis(20));
            }
            services.witness_endpoints.insert(identifier, socket);
            services.witnesses.push(client);
        }
        Ok(services)
    }

    pub fn start_auditors(&mut self, directory: &Path) -> TestResult {
        for index in 0..2_u8 {
            let identifier = format!("audit.{index}");
            let seed = directory.join(format!("audit-{index}.seed"));
            write_private(&seed, &[250 + index; 32]);
            let socket = directory.join(format!("audit-{index}.sock"));
            let config_path = directory.join(format!("audit-{index}.json"));
            let config = AuditServiceConfig {
                schema: chio_keyring::KEY_LOG_AUDIT_SERVICE_CONFIG_SCHEMA.into(),
                policy_path: directory.join("policy.json"),
                database_path: directory.join(format!("audit-{index}.sqlite3")),
                operator_database_path: directory.join("operator.sqlite3"),
                socket_path: socket.clone(),
                monitor_id: identifier.clone(),
                seed_file_path: seed,
                witness_sockets: self.witness_endpoints.clone(),
                poll_interval_millis: 20,
                provision: true,
            };
            write_private(&config_path, &canonical_json_bytes(&config)?);
            self._children
                .push(spawn_service("CHIO_KEYLOG_AUDIT", &config_path)?);
            self.audit_endpoints.insert(identifier, socket);
        }
        Ok(())
    }
}

pub(super) fn migration_config(
    directory: &Path,
    policy: &KeyLogPolicy,
) -> TestResult<serde_json::Value> {
    let signer = Keypair::from_seed(&[234; 32]);
    let key = EnterpriseMigrationKey {
        deployment_id: RecordId::new("deployment.native.keyring")?,
        scope_kind: EnterpriseMigrationScopeKind::Deployment,
        scope_id: RecordId::new("deployment.native.keyring")?,
        control: EnterpriseMigrationControl::KeyLogVerification,
    };
    let binding = policy.configuration_binding()?;
    let posture = |stage| {
        chio_control_plane::key_log_verification_migration_posture_digest(
            &key.deployment_id,
            stage,
            binding,
        )
    };
    let digest = Digest32::new(Sha256::digest(b"native keyring fixture provisioning").into());
    let path = directory.join("migration.sqlite3");
    let store = SqliteEnterpriseMigrationStateStore::open(
        &path,
        SqliteEnterpriseMigrationOpenPolicy::new(vec![signer.public_key()], Vec::new())?,
    )?;
    let genesis = EnterpriseMigrationTransitionBody::genesis(
        key.clone(),
        posture(EnterpriseMigrationStage::Disabled)?,
        digest,
        digest,
        digest,
        1,
        signer.public_key().to_hex(),
    )?;
    store.register(&sign_enterprise_migration_transition(genesis, &signer)?)?;
    let mut state = store
        .load(&key)?
        .ok_or("key-log migration genesis absent")?;
    while state.stage != EnterpriseMigrationStage::Enforced {
        let stage = state.stage.next().ok_or("key-log migration stage absent")?;
        let promotion = EnterpriseMigrationTransitionBody::promotion(
            &state,
            posture(stage)?,
            digest,
            digest,
            digest,
            stage.generation() + 1,
            signer.public_key().to_hex(),
        )?;
        store.compare_and_promote(&sign_enterprise_migration_transition(promotion, &signer)?)?;
        state = store
            .load(&key)?
            .ok_or("key-log migration promotion absent")?;
    }
    Ok(serde_json::json!({
        "state_database_path": path, "deployment_id": key.deployment_id,
        "stage": EnterpriseMigrationStage::Enforced,
        "trusted_transition_signers": [signer.public_key().to_hex()],
        "minimum_heads": [state.minimum_head()],
    }))
}
