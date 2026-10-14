pub use chio_security_types::{EnterpriseMigrationRuntimeBinding, EnterpriseMigrationRuntimeError};

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use chio_core::Keypair;
    use chio_security_types::ports::{Digest32, PortError, PortResult, RecordId};
    use chio_security_types::{
        EnterpriseMigrationControl, EnterpriseMigrationKey, EnterpriseMigrationRegisterOutcome,
        EnterpriseMigrationScopeKind, EnterpriseMigrationState, EnterpriseMigrationStateStore,
        EnterpriseMigrationTransition, EnterpriseMigrationTransitionBody,
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
        let directory = chio_test_support::private_tempdir()
            .unwrap_or_else(|error| panic!("migration directory: {error}"));
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
        posture: Digest32,
    ) -> EnterpriseMigrationState {
        let body = EnterpriseMigrationTransitionBody::enforced(
            key(),
            posture,
            digest(2),
            digest(3),
            digest(4),
            100,
            signer.public_key().to_hex(),
        )
        .unwrap_or_else(|error| panic!("migration registration: {error}"));
        let transition = sign_enterprise_migration_transition(body, signer)
            .unwrap_or_else(|error| panic!("sign migration registration: {error}"));
        match store
            .register(&transition)
            .unwrap_or_else(|error| panic!("register migration: {error}"))
        {
            EnterpriseMigrationRegisterOutcome::Registered(state) => state,
            outcome => panic!("unexpected migration registration: {outcome:?}"),
        }
    }

    /// Serves one durable record that the test replaces in place.
    struct ReplaceableStore(Mutex<Option<EnterpriseMigrationState>>);

    impl ReplaceableStore {
        fn replace(&self, state: Option<EnterpriseMigrationState>) {
            *self
                .0
                .lock()
                .unwrap_or_else(|error| panic!("replaceable store lock: {error}")) = state;
        }
    }

    impl EnterpriseMigrationStateStore for ReplaceableStore {
        fn register(
            &self,
            _: &EnterpriseMigrationTransition,
        ) -> PortResult<EnterpriseMigrationRegisterOutcome> {
            Err(PortError::unavailable())
        }

        fn load(
            &self,
            key: &EnterpriseMigrationKey,
        ) -> PortResult<Option<EnterpriseMigrationState>> {
            let state = self.0.lock().map_err(|_| PortError::unavailable())?;
            Ok(state.as_ref().filter(|state| &state.key == key).cloned())
        }
    }

    #[test]
    fn enforced_binding_revalidates_its_registration() {
        let signer = signer();
        let (_directory, concrete) = open_store(&signer);
        let registered = register(concrete.as_ref(), &signer, digest(1));
        let store: Arc<dyn EnterpriseMigrationStateStore> = concrete;
        let binding = EnterpriseMigrationRuntimeBinding::load(&store, &key(), digest(1))
            .unwrap_or_else(|error| panic!("bind enforced runtime: {error}"));
        assert_eq!(binding.state(), &registered);
        binding
            .revalidate()
            .unwrap_or_else(|error| panic!("revalidate enforced runtime: {error}"));
    }

    #[test]
    fn binding_refuses_a_posture_that_differs_from_the_registration() {
        let signer = signer();
        let (_directory, concrete) = open_store(&signer);
        let _ = register(concrete.as_ref(), &signer, digest(1));
        let store: Arc<dyn EnterpriseMigrationStateStore> = concrete;
        let Err(error) = EnterpriseMigrationRuntimeBinding::load(&store, &key(), digest(9)) else {
            panic!("a mismatched posture must not bind");
        };
        assert_eq!(error, EnterpriseMigrationRuntimeError::PostureMismatch);
        assert_eq!(
            error.to_string(),
            "enterprise migration posture differs from the registered posture"
        );
    }

    #[test]
    fn binding_refuses_an_unregistered_control() {
        let signer = signer();
        let (_directory, concrete) = open_store(&signer);
        let store: Arc<dyn EnterpriseMigrationStateStore> = concrete;
        let Err(error) = EnterpriseMigrationRuntimeBinding::load(&store, &key(), digest(1)) else {
            panic!("an unregistered control must not bind");
        };
        assert_eq!(error, EnterpriseMigrationRuntimeError::Unregistered);
        assert_eq!(
            error.to_string(),
            "enterprise migration control is not durably registered"
        );
    }

    #[test]
    fn changed_registration_invalidates_the_binding() {
        let signer = signer();
        let (_first_directory, first) = open_store(&signer);
        let original = register(first.as_ref(), &signer, digest(1));
        let (_second_directory, second) = open_store(&signer);
        let replacement = register(second.as_ref(), &signer, digest(5));
        assert_ne!(original, replacement);

        let replaceable = Arc::new(ReplaceableStore(Mutex::new(Some(original))));
        let store: Arc<dyn EnterpriseMigrationStateStore> = replaceable.clone();
        let binding = EnterpriseMigrationRuntimeBinding::load(&store, &key(), digest(1))
            .unwrap_or_else(|error| panic!("bind original registration: {error}"));
        binding
            .revalidate()
            .unwrap_or_else(|error| panic!("revalidate original registration: {error}"));

        replaceable.replace(Some(replacement));
        let error = binding
            .revalidate()
            .err()
            .unwrap_or_else(|| panic!("a replaced registration must invalidate the binding"));
        assert_eq!(error, EnterpriseMigrationRuntimeError::StateChanged);
        assert_eq!(
            error.to_string(),
            "enterprise migration state changed after runtime binding"
        );

        replaceable.replace(None);
        assert_eq!(
            binding.revalidate(),
            Err(EnterpriseMigrationRuntimeError::Unregistered)
        );
    }
}
