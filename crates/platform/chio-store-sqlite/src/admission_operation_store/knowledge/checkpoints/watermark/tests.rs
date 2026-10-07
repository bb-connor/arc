//! The maximal public identity must fit the private head payload ceiling.
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn checkpoint_head_maximal_protocol_identity_fits_its_closed_payload_bound() -> TestResult {
    let maximum = SafeInteger::new((1u64 << 53) - 1)?;
    let head = CheckpointHead {
        domain_version: VersionV1,
        scope: RecoveryScopeV1 {
            authority_domain: AuthorityDomainId::new(&"a".repeat(128))?,
            tenant_id: RecoveryTenantId::new(&"t".repeat(128))?,
            process_id: ProcessId::new(&"p".repeat(128))?,
        },
        checkpoint: CheckpointId::new(&"c".repeat(128))?,
        current_revision: maximum,
        highest_revision: maximum,
        current_envelope: CanonicalPayloadDigest::from_bytes([255; 32]),
    };
    let bytes = protected::encode(&head)?;
    assert!(bytes.len() <= 2048);
    let decoded: CheckpointHead = protected::decode(&bytes)?;
    assert_eq!(protected::encode(&decoded)?, bytes);
    // The fixed scope/digest framing is independent of the identifier suffix.
    let head_key = key(&head.scope, &head.checkpoint)?;
    assert!(head_key.starts_with("knowledge-checkpoint-head:"));
    assert_eq!(head_key.split(':').count(), 3);
    assert_ne!(
        head_key,
        key(
            &head.scope,
            &CheckpointId::new(&format!("{}:1", "c".repeat(126)))?,
        )?
    );
    Ok(())
}
