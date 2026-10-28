use chio_core::web3::settlement::Web3SettlementDispatchArtifact;

use super::{ApprovalBinding, SettlementError};

impl ApprovalBinding {
    pub(crate) fn assert_dispatch(
        &self,
        lane: &str,
        dispatch: &Web3SettlementDispatchArtifact,
    ) -> Result<(), SettlementError> {
        if self.dispatch_id != dispatch.dispatch_id {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} dispatch mismatch"
            )));
        }
        let capability_id = dispatch
            .capital_instruction
            .body
            .query
            .capability_id
            .as_deref()
            .unwrap_or(&dispatch.dispatch_id);
        if self.capability_id != capability_id {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} capability mismatch"
            )));
        }
        let expected_chain = format!("eip155:{}", self.chain_id);
        if dispatch.chain_id != expected_chain {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} chain mismatch: dispatch chain {:?} is not the approval-bound chain {expected_chain:?}",
                dispatch.chain_id
            )));
        }
        if !dispatch
            .beneficiary_address
            .trim()
            .eq_ignore_ascii_case(self.payee_address.trim())
        {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} payee mismatch: dispatch payee {:?} is not the approval-bound payee {:?}",
                dispatch.beneficiary_address, self.payee_address
            )));
        }
        if u128::from(dispatch.settlement_amount.units) != self.amount_minor_units {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} amount mismatch: dispatch amount {} is not the approval-bound amount {}",
                dispatch.settlement_amount.units, self.amount_minor_units
            )));
        }
        if !self
            .settlement_currency
            .eq_ignore_ascii_case(&dispatch.settlement_amount.currency)
        {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} settlement currency mismatch"
            )));
        }
        Ok(())
    }

    pub(crate) fn assert_token_symbol(
        &self,
        lane: &str,
        lane_token_symbol: &str,
    ) -> Result<(), SettlementError> {
        if !lane_token_symbol
            .trim()
            .eq_ignore_ascii_case(self.token_symbol.trim())
        {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} token mismatch: lane token {lane_token_symbol:?} is not the \
                 approval-bound token {:?}",
                self.token_symbol
            )));
        }
        Ok(())
    }

    pub(crate) fn require_symbol_only_lane(&self) -> Result<(), SettlementError> {
        if self.token_contract.is_some() {
            return Err(SettlementError::InvalidBinding(
                "symbol-only settlement cannot enforce a token contract".to_string(),
            ));
        }
        Ok(())
    }
}
