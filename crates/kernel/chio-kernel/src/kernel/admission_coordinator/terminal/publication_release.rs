//! Current output authority is separate from the committed financial decision.
use super::*;

pub(super) struct TerminalPublicationInput<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) matched_grant_index: usize,
    pub(super) purchase: Option<&'a crate::finding_purchase::VerifiedFindingPurchase>,
    pub(super) recovery: Option<&'a crate::finding_recovery::VerifiedFindingRecovery>,
    pub(super) recovery_status: Option<&'a crate::finding_purchase::VerifiedFindingStatusProof>,
}

impl ChioKernel {
    pub(super) fn revalidate_terminal_publication(
        &self,
        input: TerminalPublicationInput<'_>,
        delivery: &mut delivery_contract::DeliveryEvaluation,
    ) -> Result<Option<FindingDenial>, KernelError> {
        if delivery.denial.is_some() || (input.purchase.is_none() && input.recovery.is_none()) {
            return Ok(None);
        }
        let now = self.read_authority_time()?.get() / 1_000;
        let purchase_status = self.revalidate_completed_purchase_status(input.purchase, now);
        #[cfg(not(feature = "finding-market"))]
        let purchase_status = purchase_status.map_err(FindingDenial::unavailable);
        let denial = purchase_status
            .and_then(|_| {
                self.revalidate_completed_recovery_status(
                    input.matched_grant_index,
                    input.request,
                    input.recovery,
                    input.recovery_status,
                    now,
                )
            })
            .err();
        if denial.is_some() {
            delivery.denial = Some(delivery_contract::finding_status_delivery_denial());
        }
        // The signed receipt, original charge, and resolution remain unchanged.
        // This denial withholds output and cannot create another rail action.
        Ok(denial)
    }
}
