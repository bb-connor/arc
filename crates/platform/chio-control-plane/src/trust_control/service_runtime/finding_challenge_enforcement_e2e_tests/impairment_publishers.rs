//! Impairment publishers scripted for finalization against the settlement choke point.

use super::*;

/// A publisher that reports the vault burned this evidence hash without
/// producing the transaction that did it. That is exactly the ambiguity
/// the choke point must refuse to read as a slash.
pub(super) struct AmbiguousPublisher;

impl FindingImpairmentPublisher for AmbiguousPublisher {
    fn publish(
        &self,
        _intent: &chio_settle::FindingImpairmentIntent,
        _call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        Ok(FindingImpairmentAttempt::Rejected {
            rejection: FindingVaultRejection::EvidenceAlreadyUsed,
            stored: None,
        })
    }

    fn observe(
        &self,
        _intent: &chio_settle::FindingImpairmentIntent,
        _call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        Ok(FindingImpairmentAttempt::Rejected {
            rejection: FindingVaultRejection::EvidenceAlreadyUsed,
            stored: None,
        })
    }
}

/// A publisher that broadcasts, stores the raw transaction, and only
/// observes a receipt for it on a later attempt. That is the ordinary
/// shape of a real one: the transaction is not mined when publish
/// returns.
pub(super) struct MiningPublisher {
    tx_hash: String,
    attempts: Mutex<u32>,
}

impl MiningPublisher {
    pub(super) fn new() -> Self {
        Self {
            tx_hash: chain_hash(0x77),
            attempts: Mutex::new(0),
        }
    }

    pub(super) fn attempts(&self) -> u32 {
        self.attempts.lock().map(|guard| *guard).unwrap_or_default()
    }

    fn observation(
        &self,
        intent: &chio_settle::FindingImpairmentIntent,
        call: &PreparedEvmCall,
        mined: bool,
    ) -> FindingImpairmentAttempt {
        FindingImpairmentAttempt::Observed {
            stored: StoredImpairmentTransaction {
                chain_id: intent.chain_id.clone(),
                tx_hash: self.tx_hash.clone(),
                to_address: call.to_address.clone(),
                input_data: Some(call.data.clone()),
                receipt: mined.then(|| EvmTransactionReceipt {
                    tx_hash: self.tx_hash.clone(),
                    block_number: 21_000_100,
                    block_hash: chain_hash(0xbc),
                    status: true,
                    from_address: call.from_address.clone(),
                    to_address: call.to_address.clone(),
                    gas_used: 210_000,
                    observed_at: OBSERVED_AT,
                    logs: Vec::new(),
                }),
                finality: mined.then_some(SettlementFinalityStatus::Finalized),
            },
        }
    }
}

impl FindingImpairmentPublisher for MiningPublisher {
    fn publish(
        &self,
        intent: &chio_settle::FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        let attempt = match self.attempts.lock() {
            Ok(mut guard) => {
                *guard = guard.saturating_add(1);
                *guard
            }
            Err(_) => return Err(FindingImpairmentPublishError::Transient("poisoned".into())),
        };
        let mined = attempt > 1;
        Ok(self.observation(intent, call, mined))
    }

    fn observe(
        &self,
        intent: &chio_settle::FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        Ok(self.observation(intent, call, self.attempts() > 1))
    }
}

/// A publisher that cannot reach the chain and says so. It reports no
/// attempt at all, which is the one shape that leaves the coordinator
/// unable to tell whether anything was broadcast.
pub(super) struct UnreachableChainPublisher;

impl FindingImpairmentPublisher for UnreachableChainPublisher {
    fn publish(
        &self,
        _intent: &chio_settle::FindingImpairmentIntent,
        _call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        Err(FindingImpairmentPublishError::Transient(
            "no route to the chain".to_string(),
        ))
    }

    fn observe(
        &self,
        _intent: &chio_settle::FindingImpairmentIntent,
        _call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        Err(FindingImpairmentPublishError::Transient(
            "no route to the chain".to_string(),
        ))
    }
}

/// A publisher that must never be asked to move anything. A resumed
/// finalization has already impaired the vault, so any dispatch on that
/// path would be a second one.
pub(super) struct UnreachablePublisher;

impl FindingImpairmentPublisher for UnreachablePublisher {
    fn publish(
        &self,
        _intent: &chio_settle::FindingImpairmentIntent,
        _call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        Err(FindingImpairmentPublishError::Permanent(
            "a confirmed impairment must never be dispatched again".to_string(),
        ))
    }

    fn observe(
        &self,
        intent: &chio_settle::FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        let tx_hash = chain_hash(0x77);
        Ok(FindingImpairmentAttempt::Observed {
            stored: StoredImpairmentTransaction {
                chain_id: intent.chain_id.clone(),
                tx_hash: tx_hash.clone(),
                to_address: call.to_address.clone(),
                input_data: Some(call.data.clone()),
                receipt: Some(EvmTransactionReceipt {
                    tx_hash,
                    block_number: 21_000_100,
                    block_hash: chain_hash(0xbc),
                    status: true,
                    from_address: call.from_address.clone(),
                    to_address: call.to_address.clone(),
                    gas_used: 210_000,
                    observed_at: OBSERVED_AT,
                    logs: Vec::new(),
                }),
                finality: Some(SettlementFinalityStatus::Finalized),
            },
        })
    }
}

/// A publisher whose first receipt is finalized but whose immediate
/// re-observation no longer finds that receipt on the canonical chain.
pub(super) struct ReorgedReceiptPublisher;

impl FindingImpairmentPublisher for ReorgedReceiptPublisher {
    fn publish(
        &self,
        intent: &chio_settle::FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        let tx_hash = chain_hash(0x78);
        Ok(FindingImpairmentAttempt::Observed {
            stored: StoredImpairmentTransaction {
                chain_id: intent.chain_id.clone(),
                tx_hash: tx_hash.clone(),
                to_address: call.to_address.clone(),
                input_data: Some(call.data.clone()),
                receipt: Some(EvmTransactionReceipt {
                    tx_hash,
                    block_number: 21_000_101,
                    block_hash: chain_hash(0xbd),
                    status: true,
                    from_address: call.from_address.clone(),
                    to_address: call.to_address.clone(),
                    gas_used: 210_000,
                    observed_at: OBSERVED_AT,
                    logs: Vec::new(),
                }),
                finality: Some(SettlementFinalityStatus::Finalized),
            },
        })
    }

    fn observe(
        &self,
        intent: &chio_settle::FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        Ok(FindingImpairmentAttempt::Observed {
            stored: StoredImpairmentTransaction {
                chain_id: intent.chain_id.clone(),
                tx_hash: chain_hash(0x78),
                to_address: call.to_address.clone(),
                input_data: Some(call.data.clone()),
                receipt: None,
                finality: None,
            },
        })
    }
}
