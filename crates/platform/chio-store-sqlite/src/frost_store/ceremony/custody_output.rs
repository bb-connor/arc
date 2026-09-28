//! The sole plaintext round-two serialization boundary. The DTOs never leave
//! this module, and encoding returns authenticated ciphertext immediately.
use super::*;
use chio_federation_authority::FrostRound2Metadata;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(tag = "state", content = "output", rename_all = "snake_case")]
enum CustodyOutput {
    Round1(Box<FrostRound1Package>),
    Round2(Vec<CustodyRound2>),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CustodyRound2 {
    metadata: FrostRound2Metadata,
    secret_bytes: Zeroizing<Vec<u8>>,
}

pub(super) fn encrypt(
    output: StoredCeremonyOutput,
    custody: &FrostCustodyKey,
    aad: &[u8],
) -> Result<EncryptedBlob, FrostStoreError> {
    let wire = match output {
        StoredCeremonyOutput::Round1(package) => CustodyOutput::Round1(package),
        StoredCeremonyOutput::Round2(packages) => CustodyOutput::Round2(
            packages
                .iter()
                .map(|package| CustodyRound2 {
                    metadata: package.metadata(),
                    secret_bytes: package.secret_bytes(),
                })
                .collect(),
        ),
    };
    // Write directly into zeroizing storage. A serde_json::Value or canonical
    // JSON intermediate would retain additional nonzeroizing secret copies.
    let mut plaintext = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *plaintext, &wire)
        .map_err(|_| FrostStoreError::Custody("ceremony output encoding failed"))?;
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
    // Only authenticated plaintext can reach this private decoder. Each
    // round-two package must also reestablish its signed ceremony binding.
    let wire: CustodyOutput = serde_json::from_slice(&plaintext)
        .map_err(|_| FrostStoreError::Custody("ceremony output decoding failed"))?;
    match wire {
        CustodyOutput::Round1(package) => Ok(StoredCeremonyOutput::Round1(package)),
        CustodyOutput::Round2(packages) => {
            let packages = packages
                .into_iter()
                .map(|package| {
                    FrostRound2Package::from_custody(config, package.metadata, package.secret_bytes)
                        .map_err(FrostStoreError::from)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let expected =
                config
                    .participants
                    .len()
                    .checked_sub(1)
                    .ok_or(FrostStoreError::Custody(
                        "ceremony participant set is empty",
                    ))?;
            let recipients = packages
                .iter()
                .map(FrostRound2Package::recipient_participant_id)
                .collect::<std::collections::BTreeSet<_>>();
            if packages.len() != expected || recipients.len() != expected {
                return Err(FrostStoreError::Custody(
                    "ceremony output recipient set is incomplete or duplicated",
                ));
            }
            Ok(StoredCeremonyOutput::Round2(packages))
        }
    }
}
