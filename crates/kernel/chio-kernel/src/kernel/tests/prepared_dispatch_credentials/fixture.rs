use super::*;

pub(super) struct Fixture {
    pub(super) kernel: ChioKernel,
    pub(super) request: ToolCallRequest,
    pub(super) nonce: Arc<NonceState>,
    pub(super) clock: Arc<FixtureClock>,
    approval: Arc<ApprovalState>,
    dpop: Option<Arc<TestAdmissionOperationStore>>,
}

impl Fixture {
    pub(super) fn new() -> TestResult<Self> {
        Self::create(false)
    }

    pub(super) fn new_with_dpop() -> TestResult<Self> {
        Self::create(true)
    }

    fn create(dpop_required: bool) -> TestResult<Self> {
        let clock = Arc::new(FixtureClock(AtomicU64::new(current_unix_timestamp())));
        let mut config = make_config();
        config.policy_hash = sha256_hex(b"prepared-credential-test-policy");
        let mut kernel = ChioKernel::new_with_clock(config, clock.clone());
        let dpop = dpop_required.then(|| {
            super::super::durable_admission::dpop_acquisition::install_fixture_authority(
                &mut kernel,
            )
        });
        let agent = make_keypair();
        let mut grant = make_grant("prepared-server", "execute");
        grant.dpop_required = dpop_required.then_some(true);
        let capability = make_capability(&kernel, &agent, make_scope(vec![grant]), 3600);
        let mut request = make_request(
            "prepared-credentials",
            &capability,
            "execute",
            "prepared-server",
        );
        let mut intent = make_governed_intent(
            "prepared-intent",
            "prepared-server",
            "execute",
            "approved operation",
            1,
            "USD",
        );
        bind_test_tool_approval(
            &mut kernel,
            &capability,
            &request.arguments,
            &request.request_id,
            &mut intent,
        );
        request.approval_token = Some(make_governed_approval_token(
            &kernel.config.keypair,
            &capability.subject,
            &intent,
            &request.request_id,
        ));
        request.governed_intent = Some(intent);
        if dpop_required {
            request.dpop_proof = Some(make_dpop_proof(
                &agent,
                &capability,
                &request.server_id,
                &request.tool_name,
                &request.arguments,
                "prepared-proof",
            ));
        }
        let nonce_config = ExecutionNonceConfig {
            nonce_ttl_secs: 300,
            nonce_store_capacity: 1024,
            require_nonce: false,
        };
        request.execution_nonce = Some(mint_execution_nonce(
            kernel.signing_authority.backend.as_ref(),
            binding_for_request(&capability, &request),
            &nonce_config,
            i64::try_from(current_unix_timestamp())?,
        )?);
        kernel.set_execution_nonce_store(
            nonce_config.clone(),
            Box::new(InMemoryExecutionNonceStore::from_config(&nonce_config)),
        );
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
            clock,
            request,
            nonce,
            approval,
            dpop,
        })
    }

    pub(super) fn prepare(&self) -> Result<PreparedDispatchCredentials<'_, '_>, KernelError> {
        self.kernel.prepare_dispatch_credentials(
            &self.request,
            &self.request.capability,
            self.dpop.is_some(),
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
            .dpop
            .as_ref()
            .map_or(0, |store| store.dpop_history().len()))
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
    fn reserve_until(&self, nonce_id: &str, expiry: i64) -> Result<bool, KernelError> {
        self.0.reserves.fetch_add(1, Ordering::SeqCst);
        self.0.store.reserve_until(nonce_id, expiry)
    }

    fn reserve_for_dispatch(
        &self,
        nonce: &str,
        expiry: i64,
        owner: &str,
    ) -> Result<bool, KernelError> {
        self.0.reserves.fetch_add(1, Ordering::SeqCst);
        assert_ne!(
            self.0.mode.load(Ordering::SeqCst),
            2,
            "injected reservation panic"
        );
        self.0.store.reserve_for_dispatch(nonce, expiry, owner)
    }

    fn rollback_dispatch_reservation(&self, nonce: &str, owner: &str) -> Result<bool, KernelError> {
        self.0.rollbacks.fetch_add(1, Ordering::SeqCst);
        self.0.store.rollback_dispatch_reservation(nonce, owner)
    }
    fn is_consumed(&self, id: &str) -> Result<bool, KernelError> {
        self.0.store.is_consumed(id)
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

pub(super) struct FixtureClock(AtomicU64);
impl FixtureClock {
    pub(super) fn set(&self, seconds: u64) {
        self.0.store(seconds, Ordering::SeqCst);
    }
}
impl chio_security_types::clock::Clock for FixtureClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        use chio_security_types::clock::{ClockReading, MonotonicInstant, UnixMillis};
        Ok(ClockReading::new(
            UnixMillis::from_secs(self.0.load(Ordering::SeqCst))?,
            MonotonicInstant::from_nanos(0),
        ))
    }
}
