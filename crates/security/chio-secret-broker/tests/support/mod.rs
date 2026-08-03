use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use chio_core_types::Keypair;
use chio_secret_broker::daemon_runtime::BrokerDaemonMigrationConfig;
use chio_secret_broker::migration::production_broker_migration_posture_digest;
use chio_security_types::ports::{Digest32, RecordId};
use chio_security_types::{
    EnterpriseMigrationControl, EnterpriseMigrationKey, EnterpriseMigrationScopeKind,
    EnterpriseMigrationStage, EnterpriseMigrationStateStore, EnterpriseMigrationTransitionBody,
};
use chio_store_sqlite::{
    sign_enterprise_migration_transition, SqliteEnterpriseMigrationOpenPolicy,
    SqliteEnterpriseMigrationStateStore,
};
use chio_test_support::prelude::*;

pub fn enforced_broker_migration(
    directory: &Path,
    deployment_id: &str,
    credential_provider: &str,
) -> BrokerDaemonMigrationConfig {
    let directory = fs::canonicalize(directory).test_expect("canonical migration directory");
    let state_database_path = directory.join("enterprise-migration.sqlite3");
    let signer = Keypair::from_seed(&[159; 32]);
    let store = SqliteEnterpriseMigrationStateStore::open(
        &state_database_path,
        SqliteEnterpriseMigrationOpenPolicy::new(vec![signer.public_key()], Vec::new())
            .test_expect("migration open policy"),
    )
    .test_expect("open migration ledger");
    let deployment_id = RecordId::new(deployment_id).test_expect("migration deployment identifier");
    let credential_provider =
        RecordId::new(credential_provider).test_expect("migration provider identifier");
    let mut minimum_heads = Vec::new();
    for (control, seed) in [
        (EnterpriseMigrationControl::BrokerCredentialCustody, 0x41_u8),
        (EnterpriseMigrationControl::BrokerQuotaEnforcement, 0x51_u8),
    ] {
        let key = EnterpriseMigrationKey {
            deployment_id: deployment_id.clone(),
            scope_kind: EnterpriseMigrationScopeKind::Provider,
            scope_id: credential_provider.clone(),
            control,
        };
        let genesis = EnterpriseMigrationTransitionBody::genesis(
            key.clone(),
            production_broker_migration_posture_digest(
                &deployment_id,
                &credential_provider,
                control,
                EnterpriseMigrationStage::Disabled,
            )
            .test_expect("disabled migration posture"),
            Digest32::new([seed; 32]),
            Digest32::new([seed.saturating_add(1); 32]),
            Digest32::new([seed.saturating_add(2); 32]),
            1,
            signer.public_key().to_hex(),
        )
        .test_expect("migration genesis");
        let genesis = sign_enterprise_migration_transition(genesis, &signer)
            .test_expect("sign migration genesis");
        let _ = store
            .register(&genesis)
            .test_expect("register migration genesis");
        let mut state = store
            .load(&key)
            .test_expect("load migration genesis")
            .test_expect("migration genesis exists");
        while state.stage < EnterpriseMigrationStage::Enforced {
            let next_stage = state.stage.next().test_expect("next migration stage");
            let generation = next_stage.generation();
            let promotion = EnterpriseMigrationTransitionBody::promotion(
                &state,
                production_broker_migration_posture_digest(
                    &deployment_id,
                    &credential_provider,
                    control,
                    next_stage,
                )
                .test_expect("promoted migration posture"),
                Digest32::new([seed.saturating_add(generation as u8 * 3); 32]),
                Digest32::new([seed.saturating_add(generation as u8 * 3 + 1); 32]),
                Digest32::new([seed.saturating_add(generation as u8 * 3 + 2); 32]),
                generation + 1,
                signer.public_key().to_hex(),
            )
            .test_expect("migration promotion");
            let promotion = sign_enterprise_migration_transition(promotion, &signer)
                .test_expect("sign migration promotion");
            let _ = store
                .compare_and_promote(&promotion)
                .test_expect("promote migration state");
            state = store
                .load(&key)
                .test_expect("load promoted migration state")
                .test_expect("promoted migration state exists");
        }
        minimum_heads.push(state.minimum_head());
    }
    minimum_heads.sort_unstable();
    drop(store);
    fs::set_permissions(&state_database_path, fs::Permissions::from_mode(0o600))
        .test_expect("harden migration ledger");
    BrokerDaemonMigrationConfig {
        state_database_path,
        deployment_id,
        credential_provider,
        trusted_transition_signers: vec![signer.public_key()],
        minimum_heads,
        credential_custody_stage: EnterpriseMigrationStage::Enforced,
        quota_enforcement_stage: EnterpriseMigrationStage::Enforced,
    }
}
