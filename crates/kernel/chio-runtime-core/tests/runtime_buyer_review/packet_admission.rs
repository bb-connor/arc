use super::{buyer_fixture, verify_buyer_attestation_packet};

#[test]
fn buyer_packet_rejects_mismatched_cross_boundary_admission_report_digest(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let baseline =
        verify_buyer_attestation_packet(&packet, &lineage, &continuation, &admission, &bilateral)?;
    assert_eq!(
        baseline.failure_code.as_deref(),
        Some("chio_buyer_packet_dsse_unresolved")
    );
    packet.cross_boundary_admission_report_sha256 = "0".repeat(64);
    let refused =
        verify_buyer_attestation_packet(&packet, &lineage, &continuation, &admission, &bilateral)?;
    assert!(!refused.accepted);
    assert_eq!(
        refused.failure_code.as_deref(),
        Some("chio_buyer_packet_hash_mismatch")
    );
    Ok(())
}
