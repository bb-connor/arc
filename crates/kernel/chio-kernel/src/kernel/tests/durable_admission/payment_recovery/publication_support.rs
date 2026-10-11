use super::*;
use crate::finding_denial::FindingDenial;
use crate::finding_purchase::*;

pub(super) struct RevealServer {
    pub(super) output: serde_json::Value,
    pub(super) invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for RevealServer {
    fn server_id(&self) -> &str {
        "durable-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(self.output.clone())
    }
    async fn invoke_with_cost(
        &self,
        tool: &str,
        args: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        Ok((
            self.invoke(tool, args, bridge).await?,
            Some(ToolInvocationCost {
                units: 10,
                currency: "USD".into(),
                breakdown: None,
            }),
        ))
    }
}

pub(super) struct PurchaseVerifier(pub(super) VerifiedFindingStatusProof);
impl FindingPurchaseVerifier for PurchaseVerifier {
    fn verify_purchase(
        &self,
        view: &FindingPurchaseContextView<'_>,
    ) -> Result<VerifiedFindingPurchase, FindingDenial> {
        Ok(VerifiedFindingPurchase {
            finding_id: view.marker.finding_id.clone(),
            listing_id: view.marker.listing_id.clone(),
            payload_sha256: view.expected_output_digest.into(),
            payload_media_type: "application/json".into(),
            expected_status_feed_id: self.0.feed_id.clone(),
            accepted_price: MonetaryAmount {
                units: 10,
                currency: "USD".into(),
            },
            payer_key_hex: view.capability.subject.to_hex(),
            reservation_id: "review-publication-reservation".into(),
            purchase_intent_id: "review-publication-purchase".into(),
            authoritative_payment_operation_id: "review-publication-payment".into(),
            accepted_bid_envelope_sha256: "a".repeat(64),
            venue_admission_envelope_sha256: "b".repeat(64),
            status_proof: Some(self.0.clone()),
        })
    }
    fn verify_purchase_admission(
        &self,
        _: &FindingPurchaseContextView<'_>,
        _: &VerifiedFindingPurchase,
        _: u64,
    ) -> Result<(), FindingDenial> {
        Ok(())
    }
    fn mark_capture_pending(
        &self,
        _: &VerifiedFindingPurchase,
        _: u64,
    ) -> Result<(), FindingDenial> {
        Ok(())
    }
}

pub(super) struct StatusVerifier {
    pub(super) proof: VerifiedFindingStatusProof,
    pub(super) revoked: std::sync::atomic::AtomicBool,
    pub(super) calls: AtomicU64,
}
impl FindingStatusProofVerifier for StatusVerifier {
    fn verify_status_proof(
        &self,
        _: &FindingStatusProofContextView<'_>,
    ) -> Result<VerifiedFindingStatusProof, FindingDenial> {
        Ok(self.proof.clone())
    }
    fn verify_status_admission(
        &self,
        _: &FindingStatusProofContextView<'_>,
        _: &VerifiedFindingStatusProof,
        _: u64,
    ) -> Result<(), FindingDenial> {
        Ok(())
    }
    fn verify_current_status_admission(
        &self,
        _: &FindingCurrentStatusContextView<'_>,
        _: u64,
    ) -> Result<(), FindingDenial> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.revoked.load(Ordering::SeqCst) {
            Err(FindingDenial::status_denied(
                "finding retracted after the resolved commit",
            ))
        } else {
            Ok(())
        }
    }
}
