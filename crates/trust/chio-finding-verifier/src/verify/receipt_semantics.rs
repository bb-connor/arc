//! Explicit execution and financial receipt semantics retain separate authority.
use super::*;
use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;
use chio_core_types::receipt::execution_evidence::verify_pre_settlement_execution_receipt;

pub(super) fn verify_required_receipt_semantics(
    receipt: &ChioReceipt,
    required_semantics: &str,
    admitted_kernel_keys: &[PublicKey],
    nonce_resolver: &dyn FindingNonceResolver,
) -> Result<(), String> {
    if required_semantics == PRE_SETTLEMENT_EXECUTION_PROFILE {
        return verify_pre_settlement_execution_receipt(receipt, admitted_kernel_keys)
            .map(|_| ())
            .map_err(|reason| {
                format!("receipt is not pre-settlement execution evidence: {reason:?}")
            });
    }
    if required_semantics != MEDIATED_SPEND_PROFILE {
        return Err("unsupported receipt semantics profile".to_string());
    }
    let nonce = nonce_resolver
        .nonce_for(receipt)
        .ok_or_else(|| "execution nonce evidence not supplied".to_string())?;
    is_authoritative_spend_receipt(receipt, admitted_kernel_keys, nonce)
        .map_err(|reason| format!("receipt is not authoritative mediated spend: {reason:?}"))?;
    let issued_at = u64::try_from(nonce.nonce.issued_at)
        .map_err(|_| "execution nonce validity interval is invalid".to_string())?;
    let expires_at = u64::try_from(nonce.nonce.expires_at)
        .map_err(|_| "execution nonce validity interval is invalid".to_string())?;
    if issued_at >= expires_at || receipt.timestamp < issued_at || receipt.timestamp >= expires_at {
        return Err("execution nonce was not active at receipt issuance".to_string());
    }
    Ok(())
}
