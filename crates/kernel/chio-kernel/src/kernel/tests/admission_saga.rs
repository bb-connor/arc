fn prepared_admission_operation() -> AdmissionOperation {
    AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::ToolDispatch,
        coordinator_authority_id: "kernel:test".to_string(),
        request_id: "request-admission-store".to_string(),
        capability_id: "capability-admission-store".to_string(),
        authorization_capability_hash: "11".repeat(32),
        request_binding_hash: "22".repeat(32),
        policy_hash: "33".repeat(32),
        broker_attempt_id: None,
        budget_hold_id: Some("hold-admission-store".to_string()),
        approval_set_hash: None,
        execution_nonce_id: None,
        coordinator_lease_epoch: 1,
    })
    .unwrap()
}

struct ProfiledTestStore {
    inner: InMemoryAdmissionOperationStore,
    profile: AdmissionOperationStoreProfile,
}

impl ProfiledTestStore {
    fn new(profile: AdmissionOperationStoreProfile) -> Self {
        Self {
            inner: InMemoryAdmissionOperationStore::new(),
            profile,
        }
    }
}

impl AdmissionOperationStore for ProfiledTestStore {
    fn authority_profile(&self) -> AdmissionOperationStoreProfile {
        self.profile
    }

    fn create_prepared(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationCreateOutcome, AdmissionOperationError> {
        self.inner.create_prepared(operation)
    }

    fn load(
        &self,
        operation_id: &str,
    ) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
        self.inner.load(operation_id)
    }

    fn compare_and_swap(
        &self,
        operation_id: &str,
        expected_version: u64,
        coordinator_lease_epoch: u64,
        next_state: AdmissionOperationState,
        next_dispatch_state: AdmissionDispatchState,
        next_coordinator_lease_epoch: u64,
        last_error: Option<String>,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        self.inner.compare_and_swap(
            operation_id,
            expected_version,
            coordinator_lease_epoch,
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        )
    }
}

#[test]
fn admission_operation_requires_an_installed_store() {
    let kernel = make_kernel(make_config());
    let error = kernel
        .persist_prepared_admission_operation(prepared_admission_operation())
        .unwrap_err();
    assert!(error.to_string().contains("admission operation store"));
}

#[test]
fn single_worker_persists_prepared_operation_idempotently() {
    let mut kernel = make_kernel(make_config());
    let store = std::sync::Arc::new(ProfiledTestStore::new(
        AdmissionOperationStoreProfile::SingleNodeDurable,
    ));
    kernel
        .set_admission_operation_store_handle(store.clone())
        .unwrap();
    let operation = prepared_admission_operation();

    assert_eq!(
        kernel
            .persist_prepared_admission_operation(operation.clone())
            .unwrap(),
        operation
    );
    assert_eq!(
        kernel
            .persist_prepared_admission_operation(operation.clone())
            .unwrap(),
        operation
    );
    assert_eq!(store.load(operation.operation_id()).unwrap(), Some(operation));
}

#[test]
fn kernel_rejects_ephemeral_local_operation_store_as_durable_authority() {
    let mut kernel = make_kernel(make_config());
    let error = kernel
        .set_admission_operation_store_handle(std::sync::Arc::new(
            InMemoryAdmissionOperationStore::new(),
        ))
        .unwrap_err();
    assert!(error.to_string().contains("durable"));
}

#[test]
fn multi_worker_configuration_rejects_single_node_durable_operation_store() {
    let mut kernel = make_kernel(make_config());
    kernel
        .set_admission_operation_store_handle(std::sync::Arc::new(ProfiledTestStore::new(
            AdmissionOperationStoreProfile::SingleNodeDurable,
        )))
        .unwrap();
    let error = kernel.set_dispatch_worker_count(2).unwrap_err();
    assert!(error.to_string().contains("shared linearizable"));
}

#[test]
fn multi_worker_configuration_accepts_shared_linearizable_operation_store() {
    let mut kernel = make_kernel(make_config());
    kernel
        .set_admission_operation_store_handle(std::sync::Arc::new(
            ProfiledTestStore::new(AdmissionOperationStoreProfile::SharedLinearizable),
        ))
        .unwrap();
    kernel.set_dispatch_worker_count(4).unwrap();
    assert_eq!(
        kernel
            .persist_prepared_admission_operation(prepared_admission_operation())
            .unwrap()
            .state(),
        AdmissionOperationState::Prepared
    );
}
