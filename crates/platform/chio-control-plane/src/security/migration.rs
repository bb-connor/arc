use std::sync::Arc;

use chio_security_types::ports::Digest32;
use chio_security_types::{
    EnterpriseMigrationKey, EnterpriseMigrationStage, EnterpriseMigrationState,
    EnterpriseMigrationStateStore,
};
pub use chio_security_types::{
    EnterpriseMigrationRuntimeError, EnterpriseOperationalFailureDisposition,
};

#[derive(Clone)]
pub struct EnterpriseMigrationRuntimeBinding(
    chio_security_types::EnterpriseMigrationRuntimeBinding,
);

impl EnterpriseMigrationRuntimeBinding {
    pub fn load(
        store: &Arc<dyn EnterpriseMigrationStateStore>,
        key: &EnterpriseMigrationKey,
        configured_stage: EnterpriseMigrationStage,
        configured_posture_digest: Digest32,
    ) -> Result<Self, EnterpriseMigrationRuntimeError> {
        chio_security_types::EnterpriseMigrationRuntimeBinding::load(
            store,
            key,
            configured_stage,
            configured_posture_digest,
        )
        .map(Self)
    }

    #[must_use]
    pub const fn state(&self) -> &EnterpriseMigrationState {
        self.0.state()
    }

    pub fn revalidate(&self) -> Result<(), EnterpriseMigrationRuntimeError> {
        self.0.revalidate()
    }

    pub fn require_enforced(&self) -> Result<(), EnterpriseMigrationRuntimeError> {
        self.0.require_enforced()
    }

    pub fn require_legacy_fallback_permitted(&self) -> Result<(), EnterpriseMigrationRuntimeError> {
        self.0.require_legacy_fallback_permitted()
    }

    #[must_use]
    pub fn operational_failure_disposition(&self) -> EnterpriseOperationalFailureDisposition {
        self.0.operational_failure_disposition()
    }

    #[must_use]
    pub fn portable_binding(&self) -> chio_security_types::EnterpriseMigrationRuntimeBinding {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::Keypair;
    use chio_security_types::ports::RecordId;
    use chio_security_types::{
        EnterpriseMigrationCasOutcome, EnterpriseMigrationControl, EnterpriseMigrationScopeKind,
        EnterpriseMigrationTransitionBody, EnterpriseRuntimeBindingError,
    };
    use chio_store_sqlite::{
        sign_enterprise_migration_transition, SqliteEnterpriseMigrationOpenPolicy,
        SqliteEnterpriseMigrationStateStore,
    };

    fn key() -> EnterpriseMigrationKey {
        EnterpriseMigrationKey {
            deployment_id: RecordId::new("production.us-east-1")
                .unwrap_or_else(|error| panic!("deployment id: {error}")),
            scope_kind: EnterpriseMigrationScopeKind::Provider,
            scope_id: RecordId::new("provider.payments")
                .unwrap_or_else(|error| panic!("provider id: {error}")),
            control: EnterpriseMigrationControl::BrokerCredentialCustody,
        }
    }

    const fn digest(byte: u8) -> Digest32 {
        Digest32::new([byte; 32])
    }

    fn signer() -> Keypair {
        Keypair::from_seed(&[0x57; 32])
    }

    fn open_store(
        signer: &Keypair,
    ) -> (tempfile::TempDir, Arc<SqliteEnterpriseMigrationStateStore>) {
        let directory =
            tempfile::tempdir().unwrap_or_else(|error| panic!("migration directory: {error}"));
        let policy =
            SqliteEnterpriseMigrationOpenPolicy::new(vec![signer.public_key()], Vec::new())
                .unwrap_or_else(|error| panic!("migration policy: {error}"));
        let canonical_directory = std::fs::canonicalize(directory.path())
            .unwrap_or_else(|error| panic!("canonical migration directory: {error}"));
        let store = SqliteEnterpriseMigrationStateStore::open(
            canonical_directory.join("migration.sqlite3"),
            policy,
        )
        .unwrap_or_else(|error| panic!("migration store: {error}"));
        (directory, Arc::new(store))
    }

    fn register(
        store: &SqliteEnterpriseMigrationStateStore,
        signer: &Keypair,
    ) -> EnterpriseMigrationState {
        let body = EnterpriseMigrationTransitionBody::genesis(
            key(),
            digest(1),
            digest(2),
            digest(3),
            digest(4),
            100,
            signer.public_key().to_hex(),
        )
        .unwrap_or_else(|error| panic!("migration genesis: {error}"));
        let transition = sign_enterprise_migration_transition(body, signer)
            .unwrap_or_else(|error| panic!("sign migration genesis: {error}"));
        match store
            .register(&transition)
            .unwrap_or_else(|error| panic!("register migration: {error}"))
        {
            chio_security_types::EnterpriseMigrationRegisterOutcome::Registered(state) => state,
            outcome => panic!("unexpected migration registration: {outcome:?}"),
        }
    }

    fn promote(
        store: &SqliteEnterpriseMigrationStateStore,
        signer: &Keypair,
        prior: &EnterpriseMigrationState,
        posture: Digest32,
        seed: u8,
        time: u64,
    ) -> EnterpriseMigrationState {
        let body = EnterpriseMigrationTransitionBody::promotion(
            prior,
            posture,
            digest(seed),
            digest(seed.wrapping_add(1)),
            digest(seed.wrapping_add(2)),
            time,
            signer.public_key().to_hex(),
        )
        .unwrap_or_else(|error| panic!("migration promotion: {error}"));
        let transition = sign_enterprise_migration_transition(body, signer)
            .unwrap_or_else(|error| panic!("sign migration promotion: {error}"));
        match store
            .compare_and_promote(&transition)
            .unwrap_or_else(|error| panic!("promote migration: {error}"))
        {
            EnterpriseMigrationCasOutcome::Promoted(state) => state,
            EnterpriseMigrationCasOutcome::Conflict(state) => {
                panic!("migration promotion conflicted at {state:?}")
            }
        }
    }

    #[test]
    fn enforced_binding_denies_operational_fallback_and_downgrades() {
        let signer = signer();
        let (_directory, concrete) = open_store(&signer);
        let key = key();
        let disabled = register(concrete.as_ref(), &signer);
        let shadow = promote(concrete.as_ref(), &signer, &disabled, digest(3), 10, 200);
        let _enforced = promote(concrete.as_ref(), &signer, &shadow, digest(5), 20, 300);

        let store: Arc<dyn EnterpriseMigrationStateStore> = concrete;
        let binding = EnterpriseMigrationRuntimeBinding::load(
            &store,
            &key,
            EnterpriseMigrationStage::Enforced,
            digest(5),
        )
        .unwrap_or_else(|error| panic!("bind enforced runtime: {error}"));
        binding
            .require_enforced()
            .unwrap_or_else(|error| panic!("revalidate enforced runtime: {error}"));
        assert_eq!(
            binding.operational_failure_disposition(),
            EnterpriseOperationalFailureDisposition::Deny
        );
        assert!(matches!(
            EnterpriseMigrationRuntimeBinding::load(
                &store,
                &key,
                EnterpriseMigrationStage::Shadow,
                digest(3),
            ),
            Err(EnterpriseMigrationRuntimeError::Binding(
                EnterpriseRuntimeBindingError::DowngradeAttempt
            ))
        ));
    }

    #[test]
    fn shadow_binding_stops_fallback_after_durable_state_changes() {
        let signer = signer();
        let (_directory, concrete) = open_store(&signer);
        let key = key();
        let disabled = register(concrete.as_ref(), &signer);
        let shadow = promote(concrete.as_ref(), &signer, &disabled, digest(3), 10, 200);

        let store: Arc<dyn EnterpriseMigrationStateStore> = concrete.clone();
        let binding = EnterpriseMigrationRuntimeBinding::load(
            &store,
            &key,
            EnterpriseMigrationStage::Shadow,
            digest(3),
        )
        .unwrap_or_else(|error| panic!("bind shadow runtime: {error}"));
        assert_eq!(
            binding.operational_failure_disposition(),
            EnterpriseOperationalFailureDisposition::LegacyFallbackAllowed
        );

        let _enforced = promote(concrete.as_ref(), &signer, &shadow, digest(5), 20, 300);
        assert_eq!(
            binding.operational_failure_disposition(),
            EnterpriseOperationalFailureDisposition::Deny
        );
        assert!(matches!(
            binding.revalidate(),
            Err(EnterpriseMigrationRuntimeError::StateChanged)
        ));
    }
}
