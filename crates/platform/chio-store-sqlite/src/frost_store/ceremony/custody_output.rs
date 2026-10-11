//! Authenticated custody of public outgoing envelopes. No plaintext share DTO.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "output",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum CustodyOutput {
    Round1(Box<FrostRound1Package>),
    Round2(Vec<SealedFrostRound2Package>),
}

pub(super) fn encrypt(
    output: StoredCeremonyOutput,
    custody: &FrostCustodyKey,
    aad: &[u8],
) -> Result<EncryptedBlob, FrostStoreError> {
    let wire = match output {
        StoredCeremonyOutput::Round1(package) => CustodyOutput::Round1(package),
        StoredCeremonyOutput::Round2(packages) => CustodyOutput::Round2(packages),
    };
    let plaintext = Zeroizing::new(
        canonical_json_bytes(&wire)
            .map_err(|_| FrostStoreError::Custody("output encoding failed"))?,
    );
    encrypt_material(&plaintext, custody, aad)
}

pub(super) fn decrypt(
    ciphertext: &EncryptedBlob,
    custody: &FrostCustodyKey,
    aad: &[u8],
    config: &FrostCeremonyConfig,
) -> Result<StoredCeremonyOutput, FrostStoreError> {
    let plaintext = Zeroizing::new(
        decrypt_blob_with_aad(custody.key(), ciphertext, aad)
            .map_err(|_| FrostStoreError::Custody("ceremony output authentication failed"))?,
    );
    let wire: CustodyOutput =
        chio_core::canonical::UntrustedJsonText::from_wire(&plaintext, 32 * 1024 * 1024)
            .and_then(|text| text.decode_canonical())
            .map_err(|_| FrostStoreError::Custody("ceremony output decoding failed"))?;
    match wire {
        CustodyOutput::Round1(package) => Ok(StoredCeremonyOutput::Round1(package)),
        CustodyOutput::Round2(packages) => {
            let expected = config
                .participants
                .len()
                .checked_sub(1)
                .ok_or(FrostStoreError::Custody("empty roster"))?;
            let mut recipients = std::collections::BTreeSet::new();
            for package in &packages {
                package.verify(config)?;
                if package.sender_participant_id() != config.local_participant_id
                    || !recipients.insert(package.recipient_participant_id())
                {
                    return Err(FrostStoreError::Custody(
                        "outbound package sender or recipient mismatch",
                    ));
                }
            }
            if packages.len() != expected {
                return Err(FrostStoreError::Custody(
                    "outbound recipient set incomplete",
                ));
            }
            Ok(StoredCeremonyOutput::Round2(packages))
        }
    }
}
