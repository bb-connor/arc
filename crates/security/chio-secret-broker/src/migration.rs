use std::sync::Arc;

#[cfg(test)]
use std::collections::BTreeSet;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::sync::Mutex;

use chio_core_types::{canonical_json_bytes, sha256};
use chio_security_types::ports::{Digest32, RecordId};
use chio_security_types::{
    EnterpriseMigrationControl, EnterpriseMigrationKey, EnterpriseMigrationRuntimeBinding,
    EnterpriseMigrationScopeKind, EnterpriseMigrationStateStore,
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
}

/// Derive the exact externally anchored posture used by production broker
/// credential-custody and quota-enforcement migration records.
pub fn production_broker_migration_posture_digest(
    deployment_id: &RecordId,
    credential_provider: &RecordId,
    control: EnterpriseMigrationControl,
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
    ) -> Result<Self> {
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
        )?;
        let quota_posture = production_broker_migration_posture_digest(
            deployment_id,
            credential_provider,
            quota_key.control,
        )?;
        let enforcer = Self {
            credential_provider: credential_provider.clone(),
            credential_custody: EnterpriseMigrationRuntimeBinding::load(
                store,
                &credential_key,
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
        self.credential_custody.revalidate().map_err(|error| {
            BrokerError::AuthorizationDenied(format!(
                "broker credential custody migration enforcement denied: {error}"
            ))
        })
    }

    fn require_quota_enforcement_enforced(&self, credential_provider: &str) -> Result<()> {
        self.require_exact_provider(credential_provider)?;
        self.quota_enforcement.revalidate().map_err(|error| {
            BrokerError::AuthorizationDenied(format!(
                "broker quota enforcement migration enforcement denied: {error}"
            ))
        })
    }
}

/// Runs on every quota-enforcement check of a test enforcer. An error denies
/// that check.
#[cfg(test)]
pub(crate) type QuotaCheckHook = Box<dyn FnMut() -> Result<()> + Send>;

#[cfg(test)]
pub(crate) struct TestBrokerMigrationEnforcer {
    credential_providers: BTreeSet<String>,
    #[cfg(test)]
    credential_custody_enforced: AtomicBool,
    #[cfg(test)]
    quota_enforcement_enforced: AtomicBool,
    quota_check_hook: Mutex<Option<QuotaCheckHook>>,
}

#[cfg(test)]
impl TestBrokerMigrationEnforcer {
    pub(crate) fn new(credential_providers: impl IntoIterator<Item = String>) -> Arc<Self> {
        Arc::new(Self {
            credential_providers: credential_providers.into_iter().collect(),
            #[cfg(test)]
            credential_custody_enforced: AtomicBool::new(true),
            #[cfg(test)]
            quota_enforcement_enforced: AtomicBool::new(true),
            quota_check_hook: Mutex::new(None),
        })
    }

    pub(crate) fn on_quota_check(&self, hook: QuotaCheckHook) -> Result<()> {
        *self.quota_check_hook.lock().map_err(|_| {
            BrokerError::Invariant("test quota check hook lock is poisoned".to_string())
        })? = Some(hook);
        Ok(())
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

#[cfg(test)]
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
        let mut hook = self.quota_check_hook.lock().map_err(|_| {
            BrokerError::Invariant("test quota check hook lock is poisoned".to_string())
        })?;
        match hook.as_mut() {
            Some(hook) => hook(),
            None => Ok(()),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use chio_core_types::Keypair;
    use chio_security_types::{EnterpriseMigrationHead, EnterpriseMigrationTransitionBody};
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
        heads: Vec<EnterpriseMigrationHead>,
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

    fn ledger(wrong_posture: Option<EnterpriseMigrationControl>) -> LedgerFixture {
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
        let mut heads = Vec::new();
        for (control, seed) in [
            (EnterpriseMigrationControl::BrokerCredentialCustody, 0x61_u8),
            (EnterpriseMigrationControl::BrokerQuotaEnforcement, 0x71_u8),
        ] {
            let migration_key = key(&deployment_id, &credential_provider, control);
            let posture = if wrong_posture == Some(control) {
                Digest32::new([0xf1; 32])
            } else {
                production_broker_migration_posture_digest(
                    &deployment_id,
                    &credential_provider,
                    control,
                )
                .test_expect("migration registration posture")
            };
            let body = EnterpriseMigrationTransitionBody::enforced(
                migration_key.clone(),
                posture,
                Digest32::new([seed; 32]),
                Digest32::new([seed.saturating_add(1); 32]),
                Digest32::new([seed.saturating_add(2); 32]),
                1,
                signer.public_key().to_hex(),
            )
            .test_expect("migration registration body");
            let transition = sign_enterprise_migration_transition(body, &signer)
                .test_expect("signed migration registration");
            let _ = store
                .register(&transition)
                .test_expect("persist migration registration");
            let state = store
                .load(&migration_key)
                .test_expect("load migration registration")
                .test_expect("migration registration exists");
            heads.push(state.head());
        }
        heads.sort_unstable();
        drop(store);
        LedgerFixture {
            _directory: directory,
            path,
            signer,
            deployment_id,
            credential_provider,
            heads,
        }
    }

    fn open_runtime_store(
        fixture: &LedgerFixture,
        heads: Vec<EnterpriseMigrationHead>,
    ) -> Arc<dyn EnterpriseMigrationStateStore> {
        Arc::new(
            SqliteEnterpriseMigrationStateStore::open(
                &fixture.path,
                SqliteEnterpriseMigrationOpenPolicy::new(vec![fixture.signer.public_key()], heads)
                    .test_expect("runtime migration open policy"),
            )
            .test_expect("runtime migration store"),
        )
    }

    fn load_error(
        store: &Arc<dyn EnterpriseMigrationStateStore>,
        deployment_id: &RecordId,
        credential_provider: &RecordId,
    ) -> String {
        ProductionBrokerMigrationEnforcer::load(store, deployment_id, credential_provider)
            .test_expect_err("production migration binding must refuse")
            .to_string()
    }

    #[test]
    fn production_binding_refuses_an_unregistered_ledger() {
        let directory = crate::private_tempdir().test_expect("empty ledger directory");
        let path = directory
            .path()
            .canonicalize()
            .test_expect("canonical empty ledger directory")
            .join("empty.sqlite3");
        let signer = Keypair::from_seed(&[178; 32]);
        let store: Arc<dyn EnterpriseMigrationStateStore> = Arc::new(
            SqliteEnterpriseMigrationStateStore::open(
                &path,
                SqliteEnterpriseMigrationOpenPolicy::new(vec![signer.public_key()], Vec::new())
                    .test_expect("empty ledger policy"),
            )
            .test_expect("empty ledger store"),
        );
        let deployment_id = RecordId::new("deployment-production").test_expect("deployment id");
        let provider = RecordId::new("generic-https").test_expect("credential provider");
        assert_eq!(
            load_error(&store, &deployment_id, &provider),
            "broker authorization denied: broker credential-custody migration binding failed: \
             enterprise migration control is not durably registered"
        );
    }

    #[test]
    fn production_binding_refuses_an_unregistered_provider() {
        let fixture = ledger(None);
        let store = open_runtime_store(&fixture, fixture.heads.clone());
        let wrong_provider = RecordId::new("wrong-provider").test_expect("wrong provider");
        assert_eq!(
            load_error(&store, &fixture.deployment_id, &wrong_provider),
            "broker authorization denied: broker credential-custody migration binding failed: \
             enterprise migration control is not durably registered"
        );
    }

    #[test]
    fn production_binding_refuses_a_registered_posture_mismatch() {
        let credential = ledger(Some(EnterpriseMigrationControl::BrokerCredentialCustody));
        let store = open_runtime_store(&credential, credential.heads.clone());
        assert_eq!(
            load_error(
                &store,
                &credential.deployment_id,
                &credential.credential_provider
            ),
            "broker authorization denied: broker credential-custody migration binding failed: \
             enterprise migration posture differs from the registered posture"
        );

        let quota = ledger(Some(EnterpriseMigrationControl::BrokerQuotaEnforcement));
        let store = open_runtime_store(&quota, quota.heads.clone());
        assert_eq!(
            load_error(&store, &quota.deployment_id, &quota.credential_provider),
            "broker authorization denied: broker quota-enforcement migration binding failed: \
             enterprise migration posture differs from the registered posture"
        );
    }

    #[test]
    fn externally_anchored_head_mismatch_fails_before_binding() {
        let fixture = ledger(None);
        let mut wrong_heads = fixture.heads.clone();
        wrong_heads[0].transition_digest = Digest32::new([0xee; 32]);
        let policy =
            SqliteEnterpriseMigrationOpenPolicy::new(vec![fixture.signer.public_key()], wrong_heads)
                .test_expect("wrong-head open policy shape");
        assert!(SqliteEnterpriseMigrationStateStore::open(&fixture.path, policy).is_err());
    }

    #[test]
    fn post_start_ledger_replacement_is_an_operational_denial() {
        let fixture = ledger(None);
        let runtime_store = open_runtime_store(&fixture, fixture.heads.clone());
        let enforcer = ProductionBrokerMigrationEnforcer::load(
            &runtime_store,
            &fixture.deployment_id,
            &fixture.credential_provider,
        )
        .test_expect("migration binding before ledger replacement");
        enforcer.ensure_ready().test_expect("initial binding ready");
        let displaced = fixture.path.with_extension("displaced");
        fs::rename(&fixture.path, &displaced).test_expect("displace migration ledger");
        fs::File::create(&fixture.path).test_expect("replace migration ledger path");

        assert_eq!(
            enforcer
                .ensure_ready()
                .test_expect_err("replaced ledger must deny")
                .to_string(),
            "broker authorization denied: broker credential custody migration enforcement \
             denied: enterprise migration state store failed: IntegrityFailure: store.integrity_failure"
        );
        assert_eq!(
            enforcer
                .require_quota_enforcement_enforced(fixture.credential_provider.as_str())
                .test_expect_err("replaced ledger must deny quota enforcement")
                .to_string(),
            "broker authorization denied: broker quota enforcement migration enforcement \
             denied: enterprise migration state store failed: IntegrityFailure: store.integrity_failure"
        );
    }
}
