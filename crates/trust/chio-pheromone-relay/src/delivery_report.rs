//! A recipient verdict can retire an outbox batch only when it binds that batch.
use crate::PheromoneRelayError;
use chio_core_types::{canonical_json_bytes, crypto::sha256_hex};
use chio_federation::pheromone_gossip::PheromoneGossipBatch;
use chio_pheromone_runtime::{
    PheromoneBatchOutcome, PheromoneReceiveReport, PHEROMONE_RECEIVE_REPORT_SCHEMA,
};

/// Parse original report bytes and bind a positive verdict to the complete sent
/// batch. Transport peer authentication is a caller precondition. HTTP also pins
/// the sender kernel; Iroh resolves the sender at the authenticated receive gate.
pub fn decode_delivery_report(
    bytes: &[u8],
    batch: &PheromoneGossipBatch,
    expected_sender: Option<&str>,
) -> Result<PheromoneReceiveReport, PheromoneRelayError> {
    let report: PheromoneReceiveReport = crate::input::decode(bytes)?;
    let batch_bytes = canonical_json_bytes(batch)
        .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?;
    if report.schema != PHEROMONE_RECEIVE_REPORT_SCHEMA
        || report.batch_sha256 != sha256_hex(&batch_bytes)
        || report.recipient_kernel_id != batch.recipient_kernel_id
        || report.authenticated_sender_kernel_id.is_empty()
        || expected_sender.is_some_and(|sender| sender != report.authenticated_sender_kernel_id)
        || report.accepted != (report.batch_outcome == PheromoneBatchOutcome::Accepted)
    {
        return Err(invalid_report());
    }
    if report.accepted
        && (report.accepted_frame_count != batch.frames.len() as u64
            || report.rejected_frame_count != 0
            || report.frames.len() != batch.frames.len()
            || report
                .frames
                .iter()
                .enumerate()
                .any(|(index, frame)| !frame.accepted || frame.frame_index != index))
    {
        return Err(invalid_report());
    }
    Ok(report)
}

fn invalid_report() -> PheromoneRelayError {
    PheromoneRelayError::BodyHashMismatch(
        "delivery report does not bind the complete sent batch".into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_federation::pheromone_gossip::PHEROMONE_GOSSIP_BATCH_SCHEMA;
    use chio_pheromone_runtime::PheromoneFrameReport;

    #[test]
    fn delivery_acknowledgement_binds_identity_and_complete_verdict(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let batch: PheromoneGossipBatch = serde_json::from_str(include_str!(
            "../../../../examples/chio-3vendor/fixtures/pheromone/gossip-batch.json"
        ))?;
        assert_eq!(batch.schema, PHEROMONE_GOSSIP_BATCH_SCHEMA);
        let report = PheromoneReceiveReport {
            schema: PHEROMONE_RECEIVE_REPORT_SCHEMA.into(),
            accepted: true,
            batch_outcome: PheromoneBatchOutcome::Accepted,
            accepted_frame_count: batch.frames.len() as u64,
            rejected_frame_count: 0,
            batch_sha256: sha256_hex(&canonical_json_bytes(&batch)?),
            recipient_kernel_id: batch.recipient_kernel_id.clone(),
            authenticated_sender_kernel_id: "sender".into(),
            received_at_unix_ms: u64::MAX,
            frames: batch
                .frames
                .iter()
                .enumerate()
                .map(|(frame_index, _)| PheromoneFrameReport {
                    frame_index,
                    accepted: true,
                    code: "accepted".into(),
                    detail: "accepted".into(),
                    deposit_nonce: None,
                })
                .collect(),
        };
        let bytes = canonical_json_bytes(&report)?;
        assert_eq!(
            decode_delivery_report(&bytes, &batch, Some("sender"))?,
            report
        );
        for change in 0..7 {
            let mut bad = report.clone();
            match change {
                0 => bad.schema = "unknown".into(),
                1 => bad.batch_sha256 = "0".repeat(64),
                2 => bad.recipient_kernel_id = "other".into(),
                3 => bad.authenticated_sender_kernel_id = "other".into(),
                4 => bad.batch_outcome = PheromoneBatchOutcome::Rejected,
                5 => bad.accepted_frame_count += 1,
                _ => bad.frames.clear(),
            }
            assert!(matches!(
                decode_delivery_report(&canonical_json_bytes(&bad)?, &batch, Some("sender")),
                Err(PheromoneRelayError::BodyHashMismatch(_))
            ));
        }
        let ambiguous = String::from_utf8(bytes)?.replacen(
            "\"accepted\":true",
            "\"accepted\":false,\"accepted\":true",
            1,
        );
        assert!(matches!(
            decode_delivery_report(ambiguous.as_bytes(), &batch, Some("sender")),
            Err(PheromoneRelayError::Input(_))
        ));
        Ok(())
    }
}
