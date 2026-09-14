use super::*;

pub(super) struct Fixture {
    pub(super) kernel: ChioKernel,
    pub(super) request: ToolCallRequest,
    pub(super) nonce: Arc<NonceState>,
    approval: Arc<ApprovalState>,
}

impl Fixture {
    pub(super) fn new() -> TestResult<Self> {
        let (mut kernel, _, _, request, _) =
            request_with_replayed_approval("prepared-credentials")?;
        // Reuse the complete signed fixture, replacing its deliberately spent
        // approval backend and nonce backend with fresh, observable stores.
        let nonce = Arc::new(NonceState {
            store: InMemoryExecutionNonceStore::from_config(
                kernel
                    .execution_nonce_config
                    .as_ref()
                    .ok_or("nonce config")?,
            ),
            mode: AtomicU8::new(1),
            reserves: AtomicU64::new(0),
            rollbacks: AtomicU64::new(0),
        });
        kernel.set_execution_nonce_store(
            kernel
                .execution_nonce_config
                .clone()
                .ok_or("nonce config")?,
            Box::new(NonceProbe(nonce.clone())),
        );
        let approval = Arc::new(ApprovalState {
            store: InMemoryGovernedApprovalReplayStore::default(),
            reserves: AtomicU64::new(0),
            commits: AtomicU64::new(0),
            rollbacks: AtomicU64::new(0),
        });
        kernel.set_governed_approval_replay_store(Box::new(ApprovalProbe(approval.clone())));
        Ok(Self {
            kernel,
            request,
            nonce,
            approval,
        })
    }

    pub(super) fn prepare(&self) -> Result<PreparedDispatchCredentials<'_, '_>, KernelError> {
        self.kernel.prepare_dispatch_credentials(
            &self.request,
            &self.request.capability,
            true,
            current_unix_timestamp(),
            false,
        )
    }

    pub(super) fn writes(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.nonce.reserves.load(Ordering::SeqCst),
            self.nonce.rollbacks.load(Ordering::SeqCst),
            self.approval.reserves.load(Ordering::SeqCst),
            self.approval.commits.load(Ordering::SeqCst),
            self.approval.rollbacks.load(Ordering::SeqCst),
        )
    }

    pub(super) fn dpop_occupancy(&self) -> TestResult<usize> {
        Ok(self
            .kernel
            .dpop_nonce_store
            .as_ref()
            .ok_or("dpop store")?
            .utilization()?
            .0)
    }

    pub(super) fn nonce_consumed(&self) -> TestResult<bool> {
        let Some(nonce) = self.request.execution_nonce.as_ref() else {
            return Ok(false);
        };
        Ok(self.nonce.store.is_consumed(nonce.nonce_id())?)
    }

    pub(super) fn assert_no_writes(&self) -> TestResult {
        assert_eq!(self.writes(), (0, 0, 0, 0, 0));
        assert_eq!(self.dpop_occupancy()?, 0);
        assert!(!self.nonce_consumed()?);
        Ok(())
    }
}

pub(super) struct NonceState {
    store: InMemoryExecutionNonceStore,
    pub(super) mode: AtomicU8,
    reserves: AtomicU64,
    rollbacks: AtomicU64,
}

struct NonceProbe(Arc<NonceState>);

impl ExecutionNonceStore for NonceProbe {
    fn reserve(&self, nonce_id: &str) -> Result<bool, KernelError> {
        self.0.reserves.fetch_add(1, Ordering::SeqCst);
        self.0.store.reserve(nonce_id)
    }

    fn reserve_until(&self, nonce_id: &str, expiry: i64) -> Result<bool, KernelError> {
        self.0.reserves.fetch_add(1, Ordering::SeqCst);
        self.0.store.reserve_until(nonce_id, expiry)
    }

    fn supports_dispatch_reservations(&self) -> bool {
        let mode = self.0.mode.load(Ordering::SeqCst);
        assert_ne!(mode, 2, "injected reservation capability panic");
        mode == 1
    }

    fn reserve_for_dispatch(
        &self,
        nonce: &str,
        expiry: i64,
        owner: &str,
    ) -> Result<bool, KernelError> {
        self.0.reserves.fetch_add(1, Ordering::SeqCst);
        self.0.store.reserve_for_dispatch(nonce, expiry, owner)
    }

    fn rollback_dispatch_reservation(&self, nonce: &str, owner: &str) -> Result<bool, KernelError> {
        self.0.rollbacks.fetch_add(1, Ordering::SeqCst);
        self.0.store.rollback_dispatch_reservation(nonce, owner)
    }
}

struct ApprovalState {
    store: InMemoryGovernedApprovalReplayStore,
    reserves: AtomicU64,
    commits: AtomicU64,
    rollbacks: AtomicU64,
}

struct ApprovalProbe(Arc<ApprovalState>);

impl GovernedApprovalReplayStore for ApprovalProbe {
    fn reserve_for_dispatch(
        &self,
        subject: &str,
        request: &str,
        intent: &str,
        expiry: u64,
        owner: &str,
    ) -> Result<bool, KernelError> {
        self.0.reserves.fetch_add(1, Ordering::SeqCst);
        self.0
            .store
            .reserve_for_dispatch(subject, request, intent, expiry, owner)
    }

    fn commit_dispatch_reservation(
        &self,
        subject: &str,
        request: &str,
        intent: &str,
        owner: &str,
    ) -> Result<bool, KernelError> {
        self.0.commits.fetch_add(1, Ordering::SeqCst);
        self.0
            .store
            .commit_dispatch_reservation(subject, request, intent, owner)
    }

    fn rollback_dispatch_reservation(
        &self,
        subject: &str,
        request: &str,
        intent: &str,
        owner: &str,
    ) -> Result<bool, KernelError> {
        self.0.rollbacks.fetch_add(1, Ordering::SeqCst);
        self.0
            .store
            .rollback_dispatch_reservation(subject, request, intent, owner)
    }
}
