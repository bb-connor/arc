//! The proxy's single durable receipt sink. Legacy receipt rows are never adopted.
use super::*;
use std::time::Duration;

const APPEND_BUDGET: Duration = Duration::from_secs(5);

pub(crate) fn load_signer(config: &ProtectConfig, durable: bool) -> Result<Keypair, ProtectError> {
    if config.signer_seed_file.is_some() && config.signer_seed_hex.is_some() {
        return Err(ProtectError::Config(
            "signing file and inline seed conflict".into(),
        ));
    }
    if let Some(path) = &config.signer_seed_file {
        return chio_control_plane::load_existing_authority_keypair(path)
            .map_err(|error| ProtectError::SigningCustody(Box::new(error)));
    }
    if durable {
        return Err(ProtectError::Config(
            "durable receipts require existing private signing custody (signer_seed_file)".into(),
        ));
    }
    match &config.signer_seed_hex {
        Some(seed) => Keypair::from_seed_hex(seed).map_err(ProtectError::from),
        None => Ok(Keypair::generate()),
    }
}

pub(crate) struct SqliteReceiptStore {
    pub(crate) core: Arc<chio_store_sqlite::SqliteReceiptStore>,
}

impl SqliteReceiptStore {
    #[cfg(test)]
    pub(crate) fn open(path: &str) -> Result<Self, ProtectError> {
        Ok(Self::from_shared(Arc::new(
            chio_store_sqlite::SqliteReceiptStore::open(path)?,
        )))
    }

    pub(crate) fn from_shared(core: Arc<chio_store_sqlite::SqliteReceiptStore>) -> Self {
        Self { core }
    }

    pub(crate) fn is_reachable(&self) -> bool {
        self.core
            .receipt_store_health()
            .is_ok_and(|health| health.healthy)
    }

    pub(crate) fn append(
        &self,
        receipt: &HttpReceipt,
        signer: &Keypair,
    ) -> Result<(), ProtectError> {
        let projection = receipt.to_chio_receipt_with_keypair(signer)?;
        self.append_tool_receipt(&projection)
    }

    pub(crate) fn append_tool_receipt(&self, receipt: &ChioReceipt) -> Result<(), ProtectError> {
        self.core.append_new_chio_receipt(receipt, APPEND_BUDGET)?;
        Ok(())
    }

    /// Preserve revocations written by old proxy versions. New writes use the
    /// existing durable sibling revocation store shared with the kernel.
    pub(crate) fn load_revoked_capability_ids(&self) -> Result<HashSet<String>, ProtectError> {
        Ok(self
            .core
            .legacy_revoked_capability_ids()?
            .into_iter()
            .collect())
    }

    #[cfg(test)]
    pub(crate) fn load_tool_receipts(&self) -> Result<Vec<ChioReceipt>, ProtectError> {
        let page = self.core.query_receipts(&chio_kernel::ReceiptQuery {
            limit: 128,
            ..chio_kernel::ReceiptQuery::default().local_operator_admin()
        })?;
        Ok(page
            .receipts
            .into_iter()
            .map(|row| row.receipt)
            .filter(|receipt| {
                receipt
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("chio_http_receipt_v1"))
                    .is_none()
            })
            .collect())
    }

    #[cfg(test)]
    pub(crate) fn load_receipts(&self) -> Result<Vec<HttpReceipt>, ProtectError> {
        let page = self.core.query_receipts(&chio_kernel::ReceiptQuery {
            limit: 128,
            ..chio_kernel::ReceiptQuery::default().local_operator_admin()
        })?;
        page.receipts
            .iter()
            .filter_map(|row| {
                row.receipt
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("chio_http_receipt_v1"))
            })
            .map(|value| -> Result<_, ProtectError> {
                Ok(input::decode(
                    &chio_core_types::canonical_json_bytes(value)?,
                    input::MAX_RECEIPT_BYTES,
                )?)
            })
            .collect()
    }
}
