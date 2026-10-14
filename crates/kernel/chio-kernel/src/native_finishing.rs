//! Original native financing is prepared before nonce issuance or dispatch.
use crate::admission_operation::{
    AdmissionOperationState, AdmissionOperationStoreError, AdmissionOperationV1,
    AdmissionRecoveryLease, NativeSecurityAuthorityBindingV1, RetainedToolAdmissionRequestV1,
};
use crate::{SecurityInvocationContext, ToolCallRequest};

/// A marker identifies the actual configured Process provider. It exposes no
/// source capsule, quantity, constructor or permission. The native Sqlite
/// adapter accepts only the concrete private-frame Process implementation and
/// obtains its borrowed physical source under Native then Process locks.
pub trait NativeProcessFinishingSourceProvider: Send + Sync {
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync);
}

/// The actual Process Runtime/Registry owns the concrete mutation provider.
/// This marker exposes no SQL, quantity, census, or financial authority.
pub trait NativeProcessCurrentWriteProvider: Send + Sync {
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync);
}

/// An owning runtime clone retains the real mutation sequencer without a
/// Kernel Arc cycle. It cannot construct a phase loan or choose a write price.
#[derive(Clone)]
pub struct NativeProcessCurrentWriteEnforcement {
    runtime: crate::kernel::DurableAdmissionRuntime,
}

impl NativeProcessCurrentWriteEnforcement {
    pub(crate) fn from_actual_runtime(runtime: &crate::kernel::DurableAdmissionRuntime) -> Self {
        Self {
            runtime: runtime.clone(),
        }
    }

    pub fn run(
        &self,
        provider: &dyn NativeProcessCurrentWriteProvider,
    ) -> Result<(), crate::KernelError> {
        self.runtime
            .run_original_process_current_write_scope(provider)
    }
}

impl core::fmt::Debug for NativeProcessCurrentWriteEnforcement {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NativeProcessCurrentWriteEnforcement([redacted])")
    }
}

/// Preparation control-flow DATA from the configured physical bank. Every
/// producer still obtains and verifies its separate original phase loan.
/// Existing custody cannot be replaced by a later fresh Source/quote roster.
pub enum OriginalNativeFinishingPreparationData {
    Prepared {
        process_source: Option<crate::process_return_custody::ProcessReturnSourceDataV1>,
    },
    Confirmed {
        original_process_source: Option<crate::process_return_custody::ProcessReturnSourceDataV1>,
        original_process_account_digest: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeInitialFinishingPhase {
    BeforeNonce,
    BeforeInput,
    /// The earlier actual account must already exist. This is never a second
    /// opportunity to create an initial account after original nonce custody.
    ExistingAccountBeforeInput,
}

/// Ephemeral transport created only inside the Kernel original callback.
/// It is not a bank loan: the physical store independently authenticates the
/// operation, retained original, lease, initialization and complete source cut.
/// The live request is borrowed and is never serialized into a bank record.
pub struct NativeInitialFinishingAuthority<'call> {
    operation: &'call AdmissionOperationV1,
    lease: &'call AdmissionRecoveryLease,
    original: &'call RetainedToolAdmissionRequestV1,
    binding: &'call NativeSecurityAuthorityBindingV1,
    context: &'call SecurityInvocationContext,
    request: &'call ToolCallRequest,
    trusted_now_unix_ms: u64,
    phase: NativeInitialFinishingPhase,
    bank_issuer: NativeProcessBankProofIssuer<'call>,
    configured_receipt_registration:
        Option<&'call crate::receipt_store::NativeReceiptStoreRegistration>,
}

impl core::fmt::Debug for NativeInitialFinishingAuthority<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NativeInitialFinishingAuthority([redacted])")
    }
}

/// Borrowed original-call inputs, checked before finishing authority is issued.
pub(crate) struct NativeInitialFinishingContext<'call> {
    pub(crate) operation: &'call AdmissionOperationV1,
    pub(crate) lease: &'call AdmissionRecoveryLease,
    pub(crate) original: &'call RetainedToolAdmissionRequestV1,
    pub(crate) binding: &'call NativeSecurityAuthorityBindingV1,
    pub(crate) context: &'call SecurityInvocationContext,
    pub(crate) request: &'call ToolCallRequest,
    pub(crate) trusted_now_unix_ms: u64,
}

impl<'call> NativeInitialFinishingAuthority<'call> {
    pub(crate) fn from_original_callback(
        inputs: NativeInitialFinishingContext<'call>,
        bank_issuer: NativeProcessBankProofIssuer<'call>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let NativeInitialFinishingContext {
            operation,
            lease,
            original,
            binding,
            context,
            request,
            trusted_now_unix_ms,
        } = inputs;
        operation.validate()?;
        original.validate_binding(operation.binding())?;
        original.validate_request_material(request)?;
        original.validate_original_semantic_request(request)?;
        original.validate_native_security_authority(binding)?;
        original.validate_native_security_context(context)?;
        original.validate_bounded_native_materializer()?;
        if original.original_semantic_request_commitment().is_none()
            || operation.dispatch_commit().is_some()
            || operation.budget_hold_id().is_some()
            || trusted_now_unix_ms >= lease.expires_at_unix_ms()
            || lease.store_fence().store_uuid != binding.store_uuid().as_str()
        {
            return Err(unavailable());
        }
        let nonce = operation
            .binding()
            .participant_requirements()
            .execution_nonce;
        let phase = match operation.state() {
            AdmissionOperationState::Prepared
                if nonce
                    && request.execution_nonce.is_none()
                    && operation.execution_nonce_issuance_digest().is_none()
                    && operation.execution_nonce_preflight_digest().is_none() =>
            {
                NativeInitialFinishingPhase::BeforeNonce
            }
            AdmissionOperationState::BrokerAttemptRegistered if !nonce => {
                NativeInitialFinishingPhase::BeforeInput
            }
            AdmissionOperationState::BrokerAttemptRegistered
                if nonce
                    && request.execution_nonce.is_some()
                    && operation.execution_nonce_issuance_digest().is_some()
                    && operation.execution_nonce_preflight_digest().is_some() =>
            {
                NativeInitialFinishingPhase::ExistingAccountBeforeInput
            }
            _ => return Err(unavailable()),
        };
        Ok(Self {
            operation,
            lease,
            original,
            binding,
            context,
            request,
            trusted_now_unix_ms,
            phase,
            bank_issuer,
            configured_receipt_registration: None,
        })
    }

    /// Only the original Kernel callback can attach its actual configured sink.
    /// This borrow conveys identity, never a Source, account or purpose Loan.
    pub(crate) fn with_configured_receipt_registration(
        mut self,
        registration: &'call crate::receipt_store::NativeReceiptStoreRegistration,
    ) -> Self {
        self.configured_receipt_registration = Some(registration);
        self
    }

    /// Concrete sink identity captured at opt-in owned registration. Ordinary
    /// sink installation leaves this absent and grants no Native receipt owner.
    pub fn configured_receipt_registration(
        &self,
    ) -> Option<&crate::receipt_store::NativeReceiptStoreRegistration> {
        self.configured_receipt_registration
    }

    pub fn process_bank_issuer(&self) -> &NativeProcessBankProofIssuer<'call> {
        &self.bank_issuer
    }
    pub fn operation(&self) -> &AdmissionOperationV1 {
        self.operation
    }
    pub fn lease(&self) -> &AdmissionRecoveryLease {
        self.lease
    }
    pub fn original(&self) -> &RetainedToolAdmissionRequestV1 {
        self.original
    }
    pub fn binding(&self) -> &NativeSecurityAuthorityBindingV1 {
        self.binding
    }
    pub fn context(&self) -> &SecurityInvocationContext {
        self.context
    }
    pub fn request(&self) -> &ToolCallRequest {
        self.request
    }
    pub fn trusted_now_unix_ms(&self) -> u64 {
        self.trusted_now_unix_ms
    }
    pub fn phase(&self) -> NativeInitialFinishingPhase {
        self.phase
    }
}

fn unavailable() -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(
        "original native finishing preparation is unavailable".into(),
    )
}

/// Issued inside the real configured mutation scope, never by a provider
/// marker, decoded inventory, copied funding or caller-selected amount.
/// The borrow keeps the sequencer held through the synchronous owner call.
/// ```compile_fail
/// use chio_kernel::native_finishing::NativeProcessBankProofIssuer;
/// fn duplicate(issuer: &NativeProcessBankProofIssuer<'_>) {
///     let _: NativeProcessBankProofIssuer<'_> = Clone::clone(issuer);
/// }
/// ```
pub struct NativeProcessBankProofIssuer<'scope> {
    store: &'scope dyn crate::admission_operation::QualifiedAdmissionOperationStore,
    fence: &'scope crate::admission_operation::StoreMutationFence,
    now: u64,
    scope_generation: u64,
    _guard: &'scope crate::admission_operation::AdmissionMutationGuard<'scope>,
}
impl<'scope> NativeProcessBankProofIssuer<'scope> {
    pub(crate) fn in_configured_writer(
        store: &'scope dyn crate::admission_operation::QualifiedAdmissionOperationStore,
        fence: &'scope crate::admission_operation::StoreMutationFence,
        now: u64,
        guard: &'scope crate::admission_operation::AdmissionMutationGuard<'scope>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        static NEXT_SCOPE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let scope_generation = NEXT_SCOPE
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |n| n.checked_add(1),
            )
            .map_err(|_| unavailable())?;
        Ok(Self {
            store,
            fence,
            now,
            _guard: guard,
            scope_generation,
        })
    }

    pub fn require_scoped_bank(
        &self,
        bank: &crate::process_return_custody::VerifiedProcessReturnBank,
        actual: &crate::process_return_custody::ProcessReturnInventoryDataV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !bank.issued_in_scope(
            self.scope_generation,
            self.store as *const _ as *const () as usize,
        ) || bank.fence_data() != self.fence
            || bank.observed_at_unix_ms() != self.now
            || bank.inventory_data() != actual
        {
            return Err(unavailable());
        }
        Ok(())
    }
    pub fn require_process_authority(
        &self,
        authority: &str,
    ) -> Result<(), AdmissionOperationStoreError> {
        if authority != self.fence.store_uuid {
            return Err(unavailable());
        }
        Ok(())
    }
    pub fn verify_in_current_writer(
        &self,
        actual_store: &dyn crate::admission_operation::QualifiedAdmissionOperationStore,
        private_owner_port: &dyn crate::process_return_custody::NativeProcessReturnCustodyPort,
        actual_inventory: &crate::process_return_custody::ProcessReturnInventoryDataV1,
    ) -> Result<
        crate::process_return_custody::VerifiedProcessReturnBank,
        AdmissionOperationStoreError,
    > {
        // Compare the configured concrete object, ignoring trait-object vtables.
        if !std::ptr::addr_eq(self.store, actual_store) {
            return Err(unavailable());
        }
        crate::process_return_custody::VerifiedProcessReturnBank::from_scoped_owner(
            private_owner_port,
            actual_inventory,
            self.fence,
            self.now,
            self.scope_generation,
            self.store as *const _ as *const () as usize,
        )
    }
}
impl core::fmt::Debug for NativeProcessBankProofIssuer<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NativeProcessBankProofIssuer([redacted])")
    }
}

impl NativeProcessBankProofIssuer<'_> {
    pub fn require_scoped_owner(
        &self,
        store: &dyn crate::admission_operation::QualifiedAdmissionOperationStore,
        fence: &crate::admission_operation::StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::addr_eq(self.store, store) || self.fence != fence || self.now != now {
            return Err(unavailable());
        }
        Ok(())
    }

    /// Mint from the actual owner's private verified publication port while
    /// the already-held Kernel guard excludes every competing scoped writer.
    pub fn fund_original_enrollment_in_writer(
        &self,
        actual_store: &dyn crate::admission_operation::QualifiedAdmissionOperationStore,
        private_owner_port: &dyn crate::process_return_custody::NativeProcessReturnCustodyPort,
        original_source: &crate::process_return_custody::ProcessReturnSourceDataV1,
    ) -> Result<
        crate::process_return_custody::FundedProcessReturnEnrollment,
        AdmissionOperationStoreError,
    > {
        if !std::ptr::addr_eq(self.store, actual_store) {
            return Err(unavailable());
        }
        crate::process_return_custody::FundedProcessReturnEnrollment::from_original_native_source(
            private_owner_port,
            original_source,
            self.fence,
            self.now,
        )
    }
}
