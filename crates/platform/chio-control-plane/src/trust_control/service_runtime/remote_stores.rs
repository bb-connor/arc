use super::client::build_client;
use super::errors::{into_receipt_store_error, into_revocation_store_error};
use super::*;

pub fn build_remote_receipt_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn ReceiptStore>, CliError> {
    Ok(Box::new(RemoteReceiptStore {
        client: build_client(control_url, control_token)?,
    }))
}

pub fn build_remote_revocation_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn RevocationStore>, CliError> {
    Ok(Box::new(RemoteRevocationStore {
        client: build_client(control_url, control_token)?,
    }))
}

impl RevocationStore for RemoteRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        self.client
            .list_revocations(&RevocationQuery {
                capability_id: Some(capability_id.to_string()),
                limit: Some(1),
            })
            .map(|response| response.revoked.unwrap_or(false))
            .map_err(into_revocation_store_error)
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        self.client
            .revoke_capability(capability_id)
            .map(|response| response.newly_revoked)
            .map_err(into_revocation_store_error)
    }
}

impl ReceiptStore for RemoteReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.client
            .append_tool_receipt(receipt)
            .map_err(into_receipt_store_error)
    }

    fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        self.client
            .append_child_receipt(receipt)
            .map_err(into_receipt_store_error)
    }

    /// Point-load a tool receipt by id over the control-plane remote protocol so
    /// a store-authoritative `--control-url` deployment resolves a parent receipt
    /// that the kernel's bounded in-memory mirror has evicted, instead of falling
    /// back to the `Ok(None)` default and falsely denying a governed call-chain
    /// continuation (RFC-0004 F03/F25). The query is bounded to a single row.
    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        let response = self
            .client
            .list_tool_receipts(&ToolReceiptQuery {
                receipt_id: Some(receipt_id.to_string()),
                limit: Some(1),
                ..ToolReceiptQuery::default()
            })
            .map_err(into_receipt_store_error)?;
        match response.receipts.into_iter().next() {
            Some(value) => Ok(Some(serde_json::from_value(value)?)),
            None => Ok(None),
        }
    }

    /// Point-load a child receipt by id over the control-plane remote protocol
    /// (same bounded-mirror-eviction rationale as [`Self::load_chio_receipt`]).
    fn load_child_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChildRequestReceipt>, ReceiptStoreError> {
        let response = self
            .client
            .list_child_receipts(&ChildReceiptQuery {
                receipt_id: Some(receipt_id.to_string()),
                limit: Some(1),
                ..ChildReceiptQuery::default()
            })
            .map_err(into_receipt_store_error)?;
        match response.receipts.into_iter().next() {
            Some(value) => Ok(Some(serde_json::from_value(value)?)),
            None => Ok(None),
        }
    }

    fn record_capability_snapshot(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        self.client
            .record_capability_snapshot(token, parent_capability_id)
            .map_err(into_receipt_store_error)
    }

    fn resolve_credit_bond(
        &self,
        bond_id: &str,
    ) -> Result<Option<chio_kernel::CreditBondRow>, ReceiptStoreError> {
        self.client
            .list_credit_bonds(&CreditBondListQuery {
                bond_id: Some(bond_id.to_string()),
                facility_id: None,
                capability_id: None,
                agent_subject: None,
                tool_server: None,
                tool_name: None,
                disposition: None,
                lifecycle_state: None,
                limit: Some(1),
            })
            .map(|report| report.bonds.into_iter().next())
            .map_err(into_receipt_store_error)
    }
}
