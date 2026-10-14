//! Process finishing of one original native invocation. Each step is an
//! exact replay once committed; any failure retains the whole account debt.
use super::*;
use crate::native_return_custody::provider::ProcessNativeFinishingSource;

impl ProcessRuntime {
    /// Retain the native-funded original nonce custody of a pending source
    /// after the Process journal retained the issued nonce itself.
    pub(crate) fn retain_original_native_nonce(
        &self,
        source: &ProcessNativeFinishingSource,
    ) -> Result<(), ProcessError> {
        source.with_account(|account| {
            if !account.source().original_nonce_pending {
                return Ok(());
            }
            let nonce = self
                .kernel
                .original_funded_process_nonce_custody(account.source())?;
            self.retain_original_funded_nonce_custody(account, nonce)
        })
    }

    /// The native outcome is uncertain. Retain the prepaid notice; the account
    /// keeps every later output purpose until a genuine fate exists.
    pub(crate) fn retain_original_native_uncertainty(
        &self,
        source: &ProcessNativeFinishingSource,
    ) -> Result<(), ProcessError> {
        source.with_account(|account| {
            self.retain_original_return_unavailable(
                account,
                chio_kernel::process_return_custody::ProcessReturnUnavailableReasonDataV1::NativeResultUncertain,
            )
        })
    }

    /// The original native operation is terminal. Retain its exact Process
    /// fate, reconcile the Process account and let the native owner settle
    /// its account after reading the committed Process reconciliation back.
    pub(crate) fn finish_original_native_return(
        &self,
        source: &ProcessNativeFinishingSource,
    ) -> Result<(), ProcessError> {
        source.with_account(|account| {
            #[cfg(feature = "admission-test-support")]
            eprintln!("native terminal custody: load retained fate");
            let receipt = match self.retained_original_native_return_receipt(account)? {
                Some(receipt) => receipt,
                None => {
                    #[cfg(feature = "admission-test-support")]
                    eprintln!("native terminal custody: mint original fate");
                    let capture = self
                        .kernel
                        .original_funded_process_native_return(account.source())?;
                    #[cfg(feature = "admission-test-support")]
                    eprintln!("native terminal custody: persist original fate");
                    self.retain_original_native_return_custody(account, capture)?
                }
            };
            #[cfg(feature = "admission-test-support")]
            eprintln!("native terminal custody: load reconciliation");
            if self
                .retained_original_native_return_reconciliation(account)?
                .is_none()
            {
                let (receipt_digest, sequence, event) = receipt.final_coordinates()?;
                let reconciliation = self.kernel.original_reconciled_process_native_return(
                    account.source(),
                    &receipt_digest,
                    sequence,
                    &event,
                )?;
                #[cfg(feature = "admission-test-support")]
                eprintln!("native terminal custody: persist reconciliation");
                self.reconcile_original_native_return_custody(account, &receipt, reconciliation)?;
            }
            Ok(())
        })?;
        #[cfg(feature = "admission-test-support")]
        eprintln!("native terminal custody: settle native account");
        self.kernel.settle_original_native_finishing(source)?;
        Ok(())
    }

    /// Startup restoration of settled native owed work: for every retained
    /// original account, mint the actual native capture proof if its fate is
    /// still missing, retain the Process custody, reconcile the account
    /// exactly once, and deliver the genuine settlement callback once the
    /// committed Process reconciliation exists, all without a new authorized
    /// invoke and without consulting present-time process liveness. A proof
    /// the native owner cannot yet mint leaves that account's whole debt
    /// open as a durable per-operation hold instead of wedging startup.
    pub(crate) fn reconcile_retained_native_returns(&self) -> Result<(), ProcessError> {
        let digests = self.with_store(|store| store.native_return_account_digests());
        let digests = match digests {
            Ok(digests) => digests,
            Err(ProcessError::Configuration(
                "Process complete original return bank has not been installed",
            )) => return Ok(()),
            Err(error) => return Err(error),
        };
        for digest in digests {
            let Some(account) = self
                .retained_original_native_return_account(&digest)
                .ok()
                .flatten()
            else {
                continue;
            };
            let _ = (|| -> Result<(), ProcessError> {
                let receipt = match self.retained_original_native_return_receipt(&account)? {
                    Some(receipt) => receipt,
                    None => {
                        let capture = self
                            .kernel
                            .original_funded_process_native_return(account.source())?;
                        self.retain_original_native_return_custody(&account, capture)?
                    }
                };
                if self
                    .retained_original_native_return_reconciliation(&account)?
                    .is_none()
                {
                    let (receipt_digest, sequence, event) = receipt.final_coordinates()?;
                    let reconciliation = self.kernel.original_reconciled_process_native_return(
                        account.source(),
                        &receipt_digest,
                        sequence,
                        &event,
                    )?;
                    self.reconcile_original_native_return_custody(
                        &account,
                        &receipt,
                        reconciliation,
                    )?;
                }
                // The committed Process reconciliation closes the native
                // account through the concrete retained-custody carrier: a
                // crash between reconcile and settle is completed here
                // exactly once.
                let carrier = ProcessNativeFinishingSource::from_retained_custody(self, account)?;
                self.kernel.settle_original_native_finishing(&carrier)?;
                Ok(())
            })();
        }
        Ok(())
    }
}
