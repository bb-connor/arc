use std::sync::Arc;

#[cfg(any(test, feature = "conformance"))]
use std::collections::BTreeSet;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

use chio_core_types::{canonical_json_bytes, sha256};
use chio_security_types::ports::{Digest32, RecordId};
use chio_security_types::{
    EnterpriseMigrationControl, EnterpriseMigrationKey, EnterpriseMigrationRuntimeBinding,
    EnterpriseMigrationScopeKind, EnterpriseMigrationStage, EnterpriseMigrationStateStore,
};
use serde::Serialize;

use crate::{validate_identifier, BrokerError, Result};

pub const BROKER_MIGRATION_POSTURE_SCHEMA: &str = "chio.broker-migration-posture.v1";

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionBrokerMigrationPostureDigest<'a> {
    schema: &'static str,
    deployment_id: &'a RecordId,
    credential_provider: &'a RecordId,
    control: EnterpriseMigrationControl,
    stage: EnterpriseMigrationStage,
}

/// Derive the exact externally anchored posture used by production broker
/// credential-custody and quota-enforcement migration records.
pub fn production_broker_migration_posture_digest(
    deployment_id: &RecordId,
    credential_provider: &RecordId,
    control: EnterpriseMigrationControl,
    stage: EnterpriseMigrationStage,
) -> Result<Digest32> {
    if !matches!(
        control,
        EnterpriseMigrationControl::BrokerCredentialCustody
            | EnterpriseMigrationControl::BrokerQuotaEnforcement
    ) {
        return Err(BrokerError::InvalidRequest(
            "broker migration posture uses a non-broker control".to_string(),
        ));
    }
    let canonical = canonical_json_bytes(&ProductionBrokerMigrationPostureDigest {
        schema: BROKER_MIGRATION_POSTURE_SCHEMA,
        deployment_id,
        credential_provider,
        control,
        stage,
    })
    .map_err(|error| {
        BrokerError::InvalidRequest(format!("broker migration posture encoding failed: {error}"))
    })?;
    Ok(Digest32::new(*sha256(&canonical).as_bytes()))
}

pub(crate) trait BrokerMigrationEnforcer: Send + Sync {
    fn ensure_ready(&self) -> Result<()>;

    fn require_credential_custody_enforced(&self, credential_provider: &str) -> Result<()>;

    fn require_quota_enforcement_enforced(&self, credential_provider: &str) -> Result<()>;

    fn require_provider_enforced(&self, credential_provider: &str) -> Result<()> {
        self.require_credential_custody_enforced(credential_provider)?;
        self.require_quota_enforcement_enforced(credential_provider)
    }
}

pub(crate) struct ProductionBrokerMigrationEnforcer {
    credential_provider: RecordId,
    credential_custody: EnterpriseMigrationRuntimeBinding,
    quota_enforcement: EnterpriseMigrationRuntimeBinding,
}

impl ProductionBrokerMigrationEnforcer {
    pub(crate) fn load(
        store: &Arc<dyn EnterpriseMigrationStateStore>,
        deployment_id: &RecordId,
        credential_provider: &RecordId,
        credential_custody_stage: EnterpriseMigrationStage,
        quota_enforcement_stage: EnterpriseMigrationStage,
    ) -> Result<Self> {
        if !credential_custody_stage.operational_failure_must_deny()
            || !quota_enforcement_stage.operational_failure_must_deny()
        {
            return Err(BrokerError::AuthorizationDenied(
                "production broker migration controls must be durably enforced".to_string(),
            ));
        }
        let key = |control| EnterpriseMigrationKey {
            deployment_id: deployment_id.clone(),
            scope_kind: EnterpriseMigrationScopeKind::Provider,
            scope_id: credential_provider.clone(),
            control,
        };
        let credential_key = key(EnterpriseMigrationControl::BrokerCredentialCustody);
        let quota_key = key(EnterpriseMigrationControl::BrokerQuotaEnforcement);
        let credential_posture = production_broker_migration_posture_digest(
            deployment_id,
            credential_provider,
            credential_key.control,
            credential_custody_stage,
        )?;
        let quota_posture = production_broker_migration_posture_digest(
            deployment_id,
            credential_provider,
            quota_key.control,
            quota_enforcement_stage,
        )?;
        let enforcer = Self {
            credential_provider: credential_provider.clone(),
            credential_custody: EnterpriseMigrationRuntimeBinding::load(
                store,
                &credential_key,
                credential_custody_stage,
                credential_posture,
            )
            .map_err(|error| {
                BrokerError::AuthorizationDenied(format!(
                    "broker credential-custody migration binding failed: {error}"
                ))
            })?,
            quota_enforcement: EnterpriseMigrationRuntimeBinding::load(
                store,
                &quota_key,
                quota_enforcement_stage,
                quota_posture,
            )
            .map_err(|error| {
                BrokerError::AuthorizationDenied(format!(
                    "broker quota-enforcement migration binding failed: {error}"
                ))
            })?,
        };
        enforcer.require_provider_enforced(credential_provider.as_str())?;
        Ok(enforcer)
    }

    fn require_exact_provider(&self, credential_provider: &str) -> Result<()> {
        validate_identifier(credential_provider, "broker credential provider", 256)?;
        if credential_provider != self.credential_provider.as_str() {
            return Err(BrokerError::AuthorizationDenied(
                "credential provider has no enforced enterprise migration binding".to_string(),
            ));
        }
        Ok(())
    }
}

impl BrokerMigrationEnforcer for ProductionBrokerMigrationEnforcer {
    fn ensure_ready(&self) -> Result<()> {
        self.require_provider_enforced(self.credential_provider.as_str())
    }

    fn require_credential_custody_enforced(&self, credential_provider: &str) -> Result<()> {
        self.require_exact_provider(credential_provider)?;
        self.credential_custody.require_enforced().map_err(|error| {
            BrokerError::AuthorizationDenied(format!(
                "broker credential custody migration enforcement denied: {error}"
            ))
        })
    }

    fn require_quota_enforcement_enforced(&self, credential_provider: &str) -> Result<()> {
        self.require_exact_provider(credential_provider)?;
        self.quota_enforcement.require_enforced().map_err(|error| {
            BrokerError::AuthorizationDenied(format!(
                "broker quota enforcement migration enforcement denied: {error}"
            ))
        })
    }
}

#[cfg(any(test, feature = "conformance"))]
pub(crate) struct TestBrokerMigrationEnforcer {
    credential_providers: BTreeSet<String>,
    #[cfg(test)]
    credential_custody_enforced: AtomicBool,
    #[cfg(test)]
    quota_enforcement_enforced: AtomicBool,
}

#[cfg(any(test, feature = "conformance"))]
impl TestBrokerMigrationEnforcer {
    pub(crate) fn new(credential_providers: impl IntoIterator<Item = String>) -> Arc<Self> {
        Arc::new(Self {
            credential_providers: credential_providers.into_iter().collect(),
            #[cfg(test)]
            credential_custody_enforced: AtomicBool::new(true),
            #[cfg(test)]
            quota_enforcement_enforced: AtomicBool::new(true),
        })
    }

    #[cfg(test)]
    pub(crate) fn set_credential_custody_enforced(&self, enforced: bool) {
        self.credential_custody_enforced
            .store(enforced, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn set_quota_enforcement_enforced(&self, enforced: bool) {
        self.quota_enforcement_enforced
            .store(enforced, Ordering::SeqCst);
    }

    fn require_exact_provider(&self, credential_provider: &str) -> Result<()> {
        if self.credential_providers.contains(credential_provider) {
            Ok(())
        } else {
            Err(BrokerError::AuthorizationDenied(
                "credential provider has no test enterprise migration binding".to_string(),
            ))
        }
    }
}

#[cfg(any(test, feature = "conformance"))]
impl BrokerMigrationEnforcer for TestBrokerMigrationEnforcer {
    fn ensure_ready(&self) -> Result<()> {
        let provider = self.credential_providers.first().ok_or_else(|| {
            BrokerError::AuthorizationDenied(
                "test enterprise migration binding has no credential provider".to_string(),
            )
        })?;
        self.require_provider_enforced(provider)
    }

    fn require_credential_custody_enforced(&self, credential_provider: &str) -> Result<()> {
        self.require_exact_provider(credential_provider)?;
        #[cfg(test)]
        if !self.credential_custody_enforced.load(Ordering::SeqCst) {
            return Err(BrokerError::AuthorizationDenied(
                "test broker credential custody migration enforcement denied".to_string(),
            ));
        }
        Ok(())
    }

    fn require_quota_enforcement_enforced(&self, credential_provider: &str) -> Result<()> {
        self.require_exact_provider(credential_provider)?;
        #[cfg(test)]
        if !self.quota_enforcement_enforced.load(Ordering::SeqCst) {
            return Err(BrokerError::AuthorizationDenied(
                "test broker quota enforcement migration enforcement denied".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use chio_core_types::Keypair;
    use chio_security_types::{
        EnterpriseMigrationMinimumHead, EnterpriseMigrationState, EnterpriseMigrationTransitionBody,
    };
    use chio_store_sqlite::{
        sign_enterprise_migration_transition, SqliteEnterpriseMigrationOpenPolicy,
        SqliteEnterpriseMigrationStateStore,
    };
    use chio_test_support::prelude::*;

    use super::*;

    struct LedgerFixture {
        _directory: tempfile::TempDir,
        path: PathBuf,
        signer: Keypair,
        deployment_id: RecordId,
        credential_provider: RecordId,
        minimum_heads: Vec<EnterpriseMigrationMinimumHead>,
    }

    fn key(
        deployment_id: &RecordId,
        credential_provider: &RecordId,
        control: EnterpriseMigrationControl,
    ) -> EnterpriseMigrationKey {
        EnterpriseMigrationKey {
            deployment_id: deployment_id.clone(),
            scope_kind: EnterpriseMigrationScopeKind::Provider,
            scope_id: credential_provider.clone(),
            control,
        }
    }

    fn promote(
        store: &SqliteEnterpriseMigrationStateStore,
        signer: &Keypair,
        deployment_id: &RecordId,
        credential_provider: &RecordId,
        state: &EnterpriseMigrationState,
        posture_digest: Digest32,
        seed: u8,
    ) -> EnterpriseMigrationState {
        let generation = state
            .stage
            .next()
            .test_expect("next migration stage")
            .generation();
        let body = EnterpriseMigrationTransitionBody::promotion(
            state,
            posture_digest,
            Digest32::new([seed; 32]),
            Digest32::new([seed.saturating_add(1); 32]),
            Digest32::new([seed.saturating_add(2); 32]),
            generation + 1,
            signer.public_key().to_hex(),
        )
        .test_expect("migration promotion body");
        let transition = sign_enterprise_migration_transition(body, signer)
            .test_expect("signed migration promotion");
        let _ = store
            .compare_and_promote(&transition)
            .test_expect("persist migration promotion");
        store
            .load(&key(deployment_id, credential_provider, state.key.control))
            .test_expect("load promoted migration state")
            .test_expect("promoted migration state exists")
    }

    fn ledger(wrong_enforced_posture: Option<EnterpriseMigrationControl>) -> LedgerFixture {
        let directory = crate::private_tempdir().test_expect("migration ledger directory");
        let path = directory
            .path()
            .canonicalize()
            .test_expect("canonical migration ledger directory")
            .join("migration.sqlite3");
        let signer = Keypair::from_seed(&[177; 32]);
        let store = SqliteEnterpriseMigrationStateStore::open(
            &path,
            SqliteEnterpriseMigrationOpenPolicy::new(vec![signer.public_key()], Vec::new())
                .test_expect("migration ledger open policy"),
        )
        .test_expect("migration ledger");
        let deployment_id = RecordId::new("deployment-production").test_expect("deployment id");
        let credential_provider = RecordId::new("generic-https").test_expect("credential provider");
        let mut minimum_heads = Vec::new();
        for (control, seed) in [
            (EnterpriseMigrationControl::BrokerCredentialCustody, 0x61_u8),
            (EnterpriseMigrationControl::BrokerQuotaEnforcement, 0x71_u8),
        ] {
            let migration_key = key(&deployment_id, &credential_provider, control);
            let body = EnterpriseMigrationTransitionBody::genesis(
                migration_key.clone(),
                production_broker_migration_posture_digest(
                    &deployment_id,
                    &credential_provider,
                    control,
                    EnterpriseMigrationStage::Disabled,
                )
                .test_expect("migration genesis posture"),
                Digest32::new([seed; 32]),
                Digest32::new([seed.saturating_add(1); 32]),
                Digest32::new([seed.saturating_add(2); 32]),
                1,
                signer.public_key().to_hex(),
            )
            .test_expect("migration genesis body");
            let transition = sign_enterprise_migration_transition(body, &signer)
                .test_expect("signed migration genesis");
            let _ = store
                .register(&transition)
                .test_expect("persist migration genesis");
            let mut state = store
                .load(&migration_key)
                .test_expect("load migration genesis")
                .test_expect("migration genesis exists");
            while state.stage < EnterpriseMigrationStage::Enforced {
                let next_stage = state.stage.next().test_expect("next migration stage");
                let posture = if wrong_enforced_posture == Some(control)
                    && next_stage == EnterpriseMigrationStage::Enforced
                {
                    Digest32::new([0xf1; 32])
                } else {
                    production_broker_migration_posture_digest(
                        &deployment_id,
                        &credential_provider,
                        control,
                        next_stage,
                    )
                    .test_expect("migration promotion posture")
                };
                state = promote(
                    &store,
                    &signer,
                    &deployment_id,
                    &credential_provider,
                    &state,
                    posture,
                    seed.saturating_add(next_stage.generation() as u8 * 4),
                );
            }
            minimum_heads.push(state.minimum_head());
        }
        minimum_heads.sort_unstable();
        drop(store);
        LedgerFixture {
            _directory: directory,
            path,
            signer,
            deployment_id,
            credential_provider,
            minimum_heads,
        }
    }

    fn open_runtime_store(
        fixture: &LedgerFixture,
        minimum_heads: Vec<EnterpriseMigrationMinimumHead>,
    ) -> Arc<dyn EnterpriseMigrationStateStore> {
        Arc::new(
            SqliteEnterpriseMigrationStateStore::open(
                &fixture.path,
                SqliteEnterpriseMigrationOpenPolicy::new(
                    vec![fixture.signer.public_key()],
                    minimum_heads,
                )
                .test_expect("runtime migration open policy"),
            )
            .test_expect("runtime migration store"),
        )
    }

    #[test]
    fn production_binding_rejects_missing_provider_digest_and_stage() {
        let missing_directory = crate::private_tempdir().test_expect("missing ledger directory");
        let missing_path = missing_directory
            .path()
            .canonicalize()
            .test_expect("canonical missing ledger directory")
            .join("missing.sqlite3");
        let missing_signer = Keypair::from_seed(&[178; 32]);
        let missing_store: Arc<dyn EnterpriseMigrationStateStore> = Arc::new(
            SqliteEnterpriseMigrationStateStore::open(
                &missing_path,
                SqliteEnterpriseMigrationOpenPolicy::new(
                    vec![missing_signer.public_key()],
                    Vec::new(),
                )
                .test_expect("missing binding policy"),
            )
            .test_expect("missing binding store"),
        );
        let deployment_id =
            RecordId::new("deployment-production").test_expect("missing deployment id");
        let provider = RecordId::new("generic-https").test_expect("missing provider");
        assert!(ProductionBrokerMigrationEnforcer::load(
            &missing_store,
            &deployment_id,
            &provider,
            EnterpriseMigrationStage::Enforced,
            EnterpriseMigrationStage::Enforced,
        )
        .is_err());

        let fixture = ledger(None);
        let store = open_runtime_store(&fixture, fixture.minimum_heads.clone());
        let wrong_provider = RecordId::new("wrong-provider").test_expect("wrong provider");
        assert!(ProductionBrokerMigrationEnforcer::load(
            &store,
            &fixture.deployment_id,
            &wrong_provider,
            EnterpriseMigrationStage::Enforced,
            EnterpriseMigrationStage::Enforced,
        )
        .is_err());
        assert!(ProductionBrokerMigrationEnforcer::load(
            &store,
            &fixture.deployment_id,
            &fixture.credential_provider,
            EnterpriseMigrationStage::Shadow,
            EnterpriseMigrationStage::Enforced,
        )
        .is_err());
        assert!(ProductionBrokerMigrationEnforcer::load(
            &store,
            &fixture.deployment_id,
            &fixture.credential_provider,
            EnterpriseMigrationStage::LegacyRemoved,
            EnterpriseMigrationStage::Enforced,
        )
        .is_err());

        let wrong_digest_fixture =
            ledger(Some(EnterpriseMigrationControl::BrokerCredentialCustody));
        let wrong_digest_store = open_runtime_store(
            &wrong_digest_fixture,
            wrong_digest_fixture.minimum_heads.clone(),
        );
        assert!(ProductionBrokerMigrationEnforcer::load(
            &wrong_digest_store,
            &wrong_digest_fixture.deployment_id,
            &wrong_digest_fixture.credential_provider,
            EnterpriseMigrationStage::Enforced,
            EnterpriseMigrationStage::Enforced,
        )
        .is_err());
    }

    #[test]
    fn externally_anchored_head_mismatch_fails_before_binding() {
        let fixture = ledger(None);
        let mut wrong_heads = fixture.minimum_heads.clone();
        wrong_heads[0].transition_digest = Digest32::new([0xee; 32]);
        let policy = SqliteEnterpriseMigrationOpenPolicy::new(
            vec![fixture.signer.public_key()],
            wrong_heads,
        )
        .test_expect("wrong-head open policy shape");
        assert!(SqliteEnterpriseMigrationStateStore::open(&fixture.path, policy).is_err());
    }

    #[test]
    fn post_start_ledger_replacement_is_an_operational_denial() {
        let fixture = ledger(None);
        let runtime_store = open_runtime_store(&fixture, fixture.minimum_heads.clone());
        let enforcer = ProductionBrokerMigrationEnforcer::load(
            &runtime_store,
            &fixture.deployment_id,
            &fixture.credential_provider,
            EnterpriseMigrationStage::Enforced,
            EnterpriseMigrationStage::Enforced,
        )
        .test_expect("migration binding before ledger replacement");
        let displaced = fixture.path.with_extension("displaced");
        fs::rename(&fixture.path, &displaced).test_expect("displace migration ledger");
        fs::File::create(&fixture.path).test_expect("replace migration ledger path");

        assert!(enforcer.ensure_ready().is_err());
        assert!(enforcer
            .require_provider_enforced(fixture.credential_provider.as_str())
            .is_err());
    }

    #[test]
    fn post_start_promotion_denies_until_runtime_binding_is_rebuilt() {
        let fixture = ledger(None);
        let runtime_store = open_runtime_store(&fixture, fixture.minimum_heads.clone());
        let enforcer = ProductionBrokerMigrationEnforcer::load(
            &runtime_store,
            &fixture.deployment_id,
            &fixture.credential_provider,
            EnterpriseMigrationStage::Enforced,
            EnterpriseMigrationStage::Enforced,
        )
        .test_expect("initial production migration binding");
        enforcer.ensure_ready().test_expect("initial binding ready");

        let writer = SqliteEnterpriseMigrationStateStore::open(
            &fixture.path,
            SqliteEnterpriseMigrationOpenPolicy::new(
                vec![fixture.signer.public_key()],
                fixture.minimum_heads.clone(),
            )
            .test_expect("promotion writer policy"),
        )
        .test_expect("promotion writer");
        let mut promoted_heads = Vec::new();
        for (control, seed) in [
            (EnterpriseMigrationControl::BrokerCredentialCustody, 0x91_u8),
            (EnterpriseMigrationControl::BrokerQuotaEnforcement, 0xa1_u8),
        ] {
            let migration_key = key(
                &fixture.deployment_id,
                &fixture.credential_provider,
                control,
            );
            let state = writer
                .load(&migration_key)
                .test_expect("load state before post-start promotion")
                .test_expect("state exists before post-start promotion");
            let promoted = promote(
                &writer,
                &fixture.signer,
                &fixture.deployment_id,
                &fixture.credential_provider,
                &state,
                production_broker_migration_posture_digest(
                    &fixture.deployment_id,
                    &fixture.credential_provider,
                    control,
                    EnterpriseMigrationStage::LegacyRemoved,
                )
                .test_expect("legacy-removed posture"),
                seed,
            );
            promoted_heads.push(promoted.minimum_head());
        }
        promoted_heads.sort_unstable();
        assert!(enforcer.ensure_ready().is_err());
        assert!(enforcer
            .require_credential_custody_enforced(fixture.credential_provider.as_str())
            .is_err());
        assert!(enforcer
            .require_quota_enforcement_enforced(fixture.credential_provider.as_str())
            .is_err());
        drop(writer);

        let rebuilt_store = open_runtime_store(&fixture, promoted_heads);
        let rebuilt = ProductionBrokerMigrationEnforcer::load(
            &rebuilt_store,
            &fixture.deployment_id,
            &fixture.credential_provider,
            EnterpriseMigrationStage::LegacyRemoved,
            EnterpriseMigrationStage::LegacyRemoved,
        )
        .test_expect("rebuilt production migration binding");
        rebuilt.ensure_ready().test_expect("rebuilt binding ready");
    }
}
