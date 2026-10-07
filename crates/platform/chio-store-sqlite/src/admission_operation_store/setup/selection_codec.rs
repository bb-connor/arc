//! Canonical legacy setup custody is decoded without relaxing shared storage.
use super::*;

/// The historical canonical representation has no command-bound member.
/// Its exposed Resume identity is retained exactly and treated as already bound.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacySelection {
    probe: RecoverySetupProbeV1,
    creation: CanonicalPayloadDigest,
    command: RecoveryCommandV1,
    operator: PublicKey,
    receipt_key: PublicKey,
    previous_fence: SourceDigest,
    evidence: Option<Evidence>,
    report: Option<SignedRecoverySetupReportV1>,
}

pub(super) fn decode(payload: &[u8]) -> Result<Selection, AdmissionOperationStoreError> {
    if let Ok(current) = protected::decode::<Selection>(payload) {
        return Ok(current);
    }
    // A serde default cannot establish compatibility because the owning
    // decoder compares canonical serialized bytes to the retained preimage.
    // The exact historical representation is checked independently.
    let legacy: LegacySelection = protected::decode(payload)?;
    Ok(Selection {
        probe: legacy.probe,
        creation: legacy.creation,
        command: legacy.command,
        command_bound: true,
        operator: legacy.operator,
        receipt_key: legacy.receipt_key,
        previous_fence: legacy.previous_fence,
        evidence: legacy.evidence,
        report: legacy.report,
    })
}
