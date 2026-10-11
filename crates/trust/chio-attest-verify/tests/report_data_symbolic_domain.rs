//! Exhaustive runtime coverage of the existing bounded Kani input domain.
//! This complements the proof; it does not stand in for a Kani verdict.

use chio_attest_verify::{expect_report_data, QuoteVerificationContext};
use chio_core_types::crypto::PublicKey;
use sha2::{Digest, Sha256};

#[test]
fn all_symbolic_seed_and_root_positions_preserve_report_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    for seed in u8::MIN..=u8::MAX {
        let mut bytes = [seed; 65];
        bytes[0] = 4;
        let key = PublicKey::from_p256_sec1(&bytes)?;
        let wire = key.to_hex();
        for index in 0..32 {
            let mut root = [0; 32];
            root[index] = 1;
            let first = expect_report_data(&key, &root);
            let mut transcript = wire.as_bytes().to_vec();
            transcript.extend_from_slice(&root);
            let expected: [u8; 32] = Sha256::digest(&transcript).into();
            assert_eq!(&first[..32], &expected);
            assert_eq!(first, expect_report_data(&key, &root));
            assert_eq!(&first[32..], &[0; 32]);
            assert_eq!(
                first,
                QuoteVerificationContext::new(&key, &root).expected_report_data()
            );
            root[index] ^= 1;
            assert_ne!(first[..32], expect_report_data(&key, &root)[..32]);
        }
    }
    Ok(())
}
