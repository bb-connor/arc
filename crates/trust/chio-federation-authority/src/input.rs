//! Bounded public artifact readers and canonical private-key custody.
use super::*;
use zeroize::Zeroizing;

pub fn authority_profile_from_json(
    json: &str,
) -> Result<AuthorityProfileDocument, ChioAuthorityError> {
    let document: AuthorityProfileDocument =
        chio_core_types::canonical::UntrustedJsonText::from_wire(json.as_bytes(), 16 * 1024 * 1024)
            .and_then(|text| text.decode_signed())
            .map_err(ChioAuthorityError::UntrustedInput)?;
    document.validate()?;
    Ok(document)
}

pub fn issuance_request_from_json(json: &str) -> Result<ChioIssuanceRequest, ChioAuthorityError> {
    let document: ChioIssuanceRequest =
        chio_core_types::canonical::UntrustedJsonText::from_wire(json.as_bytes(), 16 * 1024 * 1024)
            .and_then(|text| text.decode_signed())
            .map_err(ChioAuthorityError::UntrustedInput)?;
    document.validate()?;
    Ok(document)
}

/// Decode exact canonical custody JSON directly into zeroizing key fields.
pub fn signing_keys_from_json(
    json: &str,
) -> Result<LocalAuthoritySigningKeysDocument, ChioAuthorityError> {
    let document: LocalAuthoritySigningKeysDocument =
        chio_core_types::canonical::UntrustedJsonText::from_wire(json.as_bytes(), 16 * 1024 * 1024)
            .and_then(|text| text.decode_canonical_with(signing_keys_custody_bytes))
            .map_err(ChioAuthorityError::UntrustedInput)?;
    document.validate()?;
    Ok(document)
}

pub fn revocation_publication_request_from_json(
    json: &str,
) -> Result<RevocationPublicationRequest, ChioAuthorityError> {
    let document: RevocationPublicationRequest =
        chio_core_types::canonical::UntrustedJsonText::from_wire(json.as_bytes(), 16 * 1024 * 1024)
            .and_then(|text| text.decode_signed())
            .map_err(ChioAuthorityError::UntrustedInput)?;
    document.validate()?;
    Ok(document)
}

pub fn peer_pins_from_json(json: &str) -> Result<PeerPinsDocument, ChioAuthorityError> {
    let document: PeerPinsDocument =
        chio_core_types::canonical::UntrustedJsonText::from_wire(json.as_bytes(), 16 * 1024 * 1024)
            .and_then(|text| text.decode_signed())
            .map_err(ChioAuthorityError::UntrustedInput)?;
    document.validate()?;
    Ok(document)
}

pub fn authority_profile_json(
    profile: &AuthorityProfileDocument,
) -> Result<String, ChioAuthorityError> {
    serde_json::to_string_pretty(profile)
        .map_err(|error| ChioAuthorityError::Json(error.to_string()))
}

pub fn issuance_request_json(request: &ChioIssuanceRequest) -> Result<String, ChioAuthorityError> {
    serde_json::to_string_pretty(request)
        .map_err(|error| ChioAuthorityError::Json(error.to_string()))
}

/// Canonical custody output. The serialized private keys are wiped on drop.
pub fn signing_keys_json(
    keys: &LocalAuthoritySigningKeysDocument,
) -> Result<Zeroizing<String>, ChioAuthorityError> {
    let mut bytes = signing_keys_custody_bytes(keys)
        .map_err(|error| ChioAuthorityError::Canonical(error.to_string()))?;
    String::from_utf8(core::mem::take(&mut *bytes))
        .map(Zeroizing::new)
        .map_err(|error| ChioAuthorityError::Json(error.to_string()))
}

pub fn issuance_bundle_json(bundle: &ChioIssuanceBundle) -> Result<String, ChioAuthorityError> {
    serde_json::to_string_pretty(bundle)
        .map_err(|error| ChioAuthorityError::Json(error.to_string()))
}

pub fn revocation_publication_request_json(
    request: &RevocationPublicationRequest,
) -> Result<String, ChioAuthorityError> {
    serde_json::to_string_pretty(request)
        .map_err(|error| ChioAuthorityError::Json(error.to_string()))
}

pub fn peer_pins_json(document: &PeerPinsDocument) -> Result<String, ChioAuthorityError> {
    serde_json::to_string_pretty(document)
        .map_err(|error| ChioAuthorityError::Json(error.to_string()))
}

pub fn signed_revocation_checkpoint_json(
    checkpoint: &SignedChioRevocationCheckpoint,
) -> Result<String, ChioAuthorityError> {
    serde_json::to_string_pretty(checkpoint)
        .map_err(|error| ChioAuthorityError::Json(error.to_string()))
}

/// Borrow plaintext only for the explicit private-key custody export. These
/// projections never escape this function or give the owning key types serde.
fn signing_keys_custody_bytes(
    keys: &LocalAuthoritySigningKeysDocument,
) -> chio_core_types::Result<Zeroizing<Vec<u8>>> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Seed<'a> {
        id: &'a str,
        seed_hex: &'a str,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Custody<'a> {
        schema: &'a str,
        lease_authority_seeds: Vec<Seed<'a>>,
        governance_authority_seeds: Vec<Seed<'a>>,
        revocation_authority_seed_hex: &'a str,
    }
    fn project(entries: &[NamedSeedHex]) -> Vec<Seed<'_>> {
        entries
            .iter()
            .map(|entry| Seed {
                id: entry.id.as_str(),
                seed_hex: entry.seed_hex.expose_secret(),
            })
            .collect()
    }
    chio_core_types::canonical::canonical_json_bytes_zeroizing(&Custody {
        schema: &keys.schema,
        lease_authority_seeds: project(&keys.lease_authority_seeds),
        governance_authority_seeds: project(&keys.governance_authority_seeds),
        revocation_authority_seed_hex: keys.revocation_authority_seed_hex.expose_secret(),
    })
}
