use super::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PassportSourceManifestIdPreimage<'a> {
    schema: &'a str,
    issuer: &'a str,
    subject: &'a str,
    issued_at: u64,
    expires_at: u64,
    credential_count: u64,
    credential_root: &'a str,
    merkle_roots: &'a [String],
    enterprise_identity_provenance: &'a [EnterpriseIdentityProvenance],
    trust_tier: Option<TrustTier>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PassportCredentialRefPreimage<'a> {
    family: FinancialPassportCredentialFamily,
    credential: &'a FinancialPassportCredential,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PassportPresentationDigestPreimage<'a> {
    source_manifest_digest: &'a str,
    challenge_digest: &'a str,
    credentials: &'a [PassportPresentationDigestEntry<'a>],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PassportPresentationDigestEntry<'a> {
    credential_id: &'a str,
    credential_ref_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PassportPresentationChallengeDigestPreimage<'a> {
    schema: &'a str,
    verifier: &'a str,
    verifier_key_epoch: u64,
    challenge_id: &'a str,
    nonce: &'a str,
    issued_at: &'a str,
    expires_at: &'a str,
    source_passport_id: &'a str,
    selectors: &'a [FinancialPassportCredentialSelector],
}

pub(super) fn financial_passport_presentation_challenge_digest(
    challenge: &FinancialPassportPresentationChallenge,
) -> Result<String, CredentialError> {
    domain_digest(
        PASSPORT_PRESENTATION_CHALLENGE_DIGEST_DOMAIN,
        &PassportPresentationChallengeDigestPreimage {
            schema: &challenge.schema,
            verifier: &challenge.verifier,
            verifier_key_epoch: challenge.verifier_key_epoch,
            challenge_id: &challenge.challenge_id,
            nonce: &challenge.nonce,
            issued_at: &challenge.issued_at,
            expires_at: &challenge.expires_at,
            source_passport_id: &challenge.source_passport_id,
            selectors: &challenge.selectors,
        },
    )
}

pub(super) fn financial_passport_manifest_leaf(
    credential: &FinancialPassportCredential,
) -> Result<FinancialPassportManifestLeaf, CredentialError> {
    let family = match credential {
        FinancialPassportCredential::Reputation(_) => FinancialPassportCredentialFamily::Reputation,
        FinancialPassportCredential::Financial(credential) => match credential.family {
            FinancialCredentialFamilyV1::CreditScorecard => {
                FinancialPassportCredentialFamily::CreditScorecard
            }
            FinancialCredentialFamilyV1::ExposureHistory => {
                FinancialPassportCredentialFamily::ExposureHistory
            }
            FinancialCredentialFamilyV1::SettlementReliability => {
                FinancialPassportCredentialFamily::SettlementReliability
            }
            FinancialCredentialFamilyV1::PremiumHistory => {
                FinancialPassportCredentialFamily::PremiumHistory
            }
            FinancialCredentialFamilyV1::LossHistory => FinancialPassportCredentialFamily::LossHistory,
        },
    };
    let credential_ref_digest = domain_digest(
        PASSPORT_CREDENTIAL_REF_DOMAIN,
        &PassportCredentialRefPreimage {
            family: family.clone(),
            credential,
        },
    )?;
    let credential_id = match credential {
        FinancialPassportCredential::Reputation(_) => credential_ref_digest.clone(),
        FinancialPassportCredential::Financial(credential) => credential.credential_id.clone(),
    };
    Ok(FinancialPassportManifestLeaf {
        credential_id,
        family,
        credential_ref_digest,
    })
}

pub(super) fn recompute_source_passport_id(
    body: &FinancialPassportSourceManifest,
) -> Result<String, CredentialError> {
    domain_digest(
        PASSPORT_SOURCE_MANIFEST_ID_DOMAIN,
        &PassportSourceManifestIdPreimage {
            schema: &body.schema,
            issuer: &body.issuer,
            subject: &body.subject,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            credential_count: body.credential_count,
            credential_root: &body.credential_root,
            merkle_roots: &body.merkle_roots,
            enterprise_identity_provenance: &body.enterprise_identity_provenance,
            trust_tier: body.trust_tier,
        },
    )
}

pub(super) fn recompute_presentation_digest(
    manifest: &SignedFinancialPassportSourceManifest,
    challenge_digest: &str,
    proofs: &[FinancialPassportMembershipProof],
) -> Result<String, CredentialError> {
    let source_manifest_digest = sha256_hex(&canonical_json_bytes(manifest)?);
    let entries = proofs
        .iter()
        .map(|proof| PassportPresentationDigestEntry {
            credential_id: &proof.leaf.credential_id,
            credential_ref_digest: &proof.leaf.credential_ref_digest,
        })
        .collect::<Vec<_>>();
    domain_digest(
        PASSPORT_PRESENTATION_DIGEST_DOMAIN,
        &PassportPresentationDigestPreimage {
            source_manifest_digest: &source_manifest_digest,
            challenge_digest,
            credentials: &entries,
        },
    )
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, CredentialError> {
    let canonical = canonical_json_bytes(value)?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}
