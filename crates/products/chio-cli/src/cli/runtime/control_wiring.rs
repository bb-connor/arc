//! The control-plane endpoint a runtime routes its receipt, revocation and
//! budget stores through, with the egress allowances its dials run under.

use std::path::Path;

use chio_egress_contract::EgressAllowanceSet;
use chio_kernel::ChioKernel;

use crate::mcp_cli::payment_config::PaymentAdapterConfig;

use super::{
    configure_budget_store, configure_receipt_store, configure_revocation_store, CliError,
};

#[derive(Clone, Copy)]
pub(super) struct ControlEdge<'a> {
    pub(super) url: Option<&'a str>,
    pub(super) token: Option<&'a str>,
    pub(super) egress: &'a EgressAllowanceSet,
}

impl<'a> ControlEdge<'a> {
    pub(super) fn new(
        url: Option<&'a str>,
        token: Option<&'a str>,
        egress: &'a EgressAllowanceSet,
    ) -> Self {
        Self { url, token, egress }
    }

    pub(super) fn receipts(
        &self,
        kernel: &mut ChioKernel,
        db_path: Option<&Path>,
    ) -> Result<(), CliError> {
        configure_receipt_store(kernel, db_path, self.url, self.token, self.egress)
    }

    pub(super) fn revocations(
        &self,
        kernel: &mut ChioKernel,
        db_path: Option<&Path>,
    ) -> Result<(), CliError> {
        configure_revocation_store(kernel, db_path, self.url, self.token, self.egress)
    }

    pub(super) fn budgets(
        &self,
        kernel: &mut ChioKernel,
        db_path: Option<&Path>,
    ) -> Result<(), CliError> {
        configure_budget_store(kernel, db_path, self.url, self.token, self.egress)
    }
}

pub(crate) fn resolve_sidecar_payment_adapter(
    egress: &EgressAllowanceSet,
) -> Result<Option<Box<dyn chio_kernel::PaymentAdapter>>, CliError> {
    let config = PaymentAdapterConfig::from_env(egress).map_err(|error| {
        CliError::cli_other_error(format!("invalid payment adapter configuration: {error}"))
    })?;
    Ok(config.map(|config| config.build_adapter()))
}
