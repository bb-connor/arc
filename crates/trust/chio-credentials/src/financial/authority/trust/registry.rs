use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerTrustKey {
    pub issuer_did: String,
    pub verification_method: String,
    pub key_epoch: u64,
    pub public_key: PublicKey,
    pub status: TrustedKeyStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifierTrustKey {
    pub verifier_id: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub public_key: PublicKey,
    pub status: TrustedKeyStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MigrationAttesterTrustKey {
    pub attester_id: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub public_key: PublicKey,
    pub status: TrustedKeyStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleResolverTrustKey {
    pub resolver_identity: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub public_key: PublicKey,
    pub status: TrustedKeyStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleGenerationAnchorTrustKey {
    pub anchor_id: String,
    pub signer_key_epoch: u64,
    pub public_key: PublicKey,
    pub status: TrustedKeyStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleHighWaterTrustKey {
    pub store_id: String,
    pub signer_key_epoch: u64,
    pub public_key: PublicKey,
    pub status: TrustedKeyStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerActivationMetadata {
    pub issuer_did: String,
    pub profile_family: String,
    pub source_kind: CrossIssuerPortfolioEntryKind,
    pub certification_refs: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CrossIssuerTrustRegistryConfig {
    pub issuer_keys: Vec<IssuerTrustKey>,
    pub verifier_keys: Vec<VerifierTrustKey>,
    pub migration_attester_keys: Vec<MigrationAttesterTrustKey>,
    pub lifecycle_resolver_keys: Vec<LifecycleResolverTrustKey>,
    pub lifecycle_generation_anchor_keys: Vec<LifecycleGenerationAnchorTrustKey>,
    pub lifecycle_high_water_keys: Vec<LifecycleHighWaterTrustKey>,
    pub activation_metadata: Vec<IssuerActivationMetadata>,
}

#[derive(Debug, Clone, Default)]
pub struct CrossIssuerTrustRegistry {
    issuer_keys: BTreeMap<(String, String, u64), IssuerTrustKey>,
    verifier_keys: BTreeMap<(String, String, u64), VerifierTrustKey>,
    migration_attester_keys: BTreeMap<(String, String, u64), MigrationAttesterTrustKey>,
    lifecycle_resolver_keys: BTreeMap<(String, String, u64), LifecycleResolverTrustKey>,
    lifecycle_generation_anchor_keys: BTreeMap<(String, u64), LifecycleGenerationAnchorTrustKey>,
    lifecycle_high_water_keys: BTreeMap<(String, u64), LifecycleHighWaterTrustKey>,
    activation_metadata: BTreeMap<String, IssuerActivationMetadata>,
}

impl CrossIssuerTrustRegistry {
    pub fn new(config: CrossIssuerTrustRegistryConfig) -> Result<Self, CredentialError> {
        let mut registry = Self::default();
        for entry in config.issuer_keys {
            DidChio::from_str(&entry.issuer_did)?;
            validate_text("issuerTrust.verificationMethod", &entry.verification_method)?;
            validate_epoch("issuerTrust.keyEpoch", entry.key_epoch)?;
            insert_unique(
                &mut registry.issuer_keys,
                (
                    entry.issuer_did.clone(),
                    entry.verification_method.clone(),
                    entry.key_epoch,
                ),
                entry,
                "duplicate issuer trust key",
            )?;
        }
        for entry in config.verifier_keys {
            validate_text("verifierTrust.verifierId", &entry.verifier_id)?;
            validate_text("verifierTrust.signerKeyId", &entry.signer_key_id)?;
            validate_epoch("verifierTrust.signerKeyEpoch", entry.signer_key_epoch)?;
            insert_unique(
                &mut registry.verifier_keys,
                (
                    entry.verifier_id.clone(),
                    entry.signer_key_id.clone(),
                    entry.signer_key_epoch,
                ),
                entry,
                "duplicate verifier trust key",
            )?;
        }
        for entry in config.migration_attester_keys {
            validate_text("migrationTrust.attesterId", &entry.attester_id)?;
            validate_text("migrationTrust.signerKeyId", &entry.signer_key_id)?;
            validate_epoch("migrationTrust.signerKeyEpoch", entry.signer_key_epoch)?;
            insert_unique(
                &mut registry.migration_attester_keys,
                (
                    entry.attester_id.clone(),
                    entry.signer_key_id.clone(),
                    entry.signer_key_epoch,
                ),
                entry,
                "duplicate migration attester trust key",
            )?;
        }
        for entry in config.lifecycle_resolver_keys {
            validate_text(
                "lifecycleResolver.resolverIdentity",
                &entry.resolver_identity,
            )?;
            validate_text("lifecycleResolver.signerKeyId", &entry.signer_key_id)?;
            validate_epoch("lifecycleResolver.signerKeyEpoch", entry.signer_key_epoch)?;
            insert_unique(
                &mut registry.lifecycle_resolver_keys,
                (
                    entry.resolver_identity.clone(),
                    entry.signer_key_id.clone(),
                    entry.signer_key_epoch,
                ),
                entry,
                "duplicate lifecycle resolver key",
            )?;
        }
        for entry in config.lifecycle_generation_anchor_keys {
            validate_text("lifecycleAnchor.anchorId", &entry.anchor_id)?;
            validate_epoch("lifecycleAnchor.signerKeyEpoch", entry.signer_key_epoch)?;
            insert_unique(
                &mut registry.lifecycle_generation_anchor_keys,
                (entry.anchor_id.clone(), entry.signer_key_epoch),
                entry,
                "duplicate lifecycle generation anchor key",
            )?;
        }
        for entry in config.lifecycle_high_water_keys {
            validate_text("lifecycleHighWater.storeId", &entry.store_id)?;
            validate_epoch("lifecycleHighWater.signerKeyEpoch", entry.signer_key_epoch)?;
            insert_unique(
                &mut registry.lifecycle_high_water_keys,
                (entry.store_id.clone(), entry.signer_key_epoch),
                entry,
                "duplicate lifecycle high-water key",
            )?;
        }
        for mut entry in config.activation_metadata {
            DidChio::from_str(&entry.issuer_did)?;
            validate_text("activationMetadata.profileFamily", &entry.profile_family)?;
            normalize_strings(&mut entry.certification_refs, "certificationRefs")?;
            if registry
                .activation_metadata
                .insert(entry.issuer_did.clone(), entry)
                .is_some()
            {
                return Err(authority_error("duplicate issuer activation metadata"));
            }
        }
        Ok(registry)
    }

    #[must_use]
    pub fn verifier_keys(&self) -> Vec<VerifierTrustKey> {
        self.verifier_keys.values().cloned().collect()
    }

    #[must_use]
    pub fn lifecycle_resolver_identities(&self) -> BTreeSet<String> {
        self.lifecycle_resolver_keys
            .values()
            .filter(|entry| entry.status == TrustedKeyStatus::Active)
            .map(|entry| entry.resolver_identity.clone())
            .collect()
    }

    pub(in crate::financial_authority) fn issuer_key(
        &self,
        issuer: &str,
        verification_method: &str,
        epoch: u64,
    ) -> Result<&IssuerTrustKey, CredentialError> {
        active_key(
            self.issuer_keys
                .get(&(issuer.to_string(), verification_method.to_string(), epoch)),
            "trusted issuer key is unknown or inactive",
        )
    }

    pub(in crate::financial_authority) fn manifest_issuer_key(
        &self,
        issuer: &str,
        signer_key: &PublicKey,
    ) -> Result<&IssuerTrustKey, CredentialError> {
        let matches = self
            .issuer_keys
            .values()
            .filter(|entry| {
                entry.status == TrustedKeyStatus::Active
                    && entry.issuer_did == issuer
                    && &entry.public_key == signer_key
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(authority_error(
                "source manifest signer does not resolve to one active local issuer key",
            ));
        }
        Ok(matches[0])
    }

    pub(super) fn verifier_key(
        &self,
        verifier_id: &str,
        signer_key_id: &str,
        epoch: u64,
    ) -> Result<&VerifierTrustKey, CredentialError> {
        active_key(
            self.verifier_keys
                .get(&(verifier_id.to_string(), signer_key_id.to_string(), epoch)),
            "trusted verifier key is unknown or inactive",
        )
    }

    pub(super) fn migration_key(
        &self,
        attester_id: &str,
        signer_key_id: &str,
        epoch: u64,
    ) -> Result<&MigrationAttesterTrustKey, CredentialError> {
        active_key(
            self.migration_attester_keys.get(&(
                attester_id.to_string(),
                signer_key_id.to_string(),
                epoch,
            )),
            "trusted migration attester key is unknown or inactive",
        )
    }

    pub(in crate::financial_authority) fn resolver_key(
        &self,
        resolver_identity: &str,
        signer_key_id: &str,
        epoch: u64,
    ) -> Result<&LifecycleResolverTrustKey, CredentialError> {
        active_key(
            self.lifecycle_resolver_keys.get(&(
                resolver_identity.to_string(),
                signer_key_id.to_string(),
                epoch,
            )),
            "trusted lifecycle resolver key is unknown or inactive",
        )
    }

    pub(in crate::financial_authority) fn generation_anchor_key(
        &self,
        anchor_id: &str,
        epoch: u64,
    ) -> Result<&LifecycleGenerationAnchorTrustKey, CredentialError> {
        active_key(
            self.lifecycle_generation_anchor_keys
                .get(&(anchor_id.to_string(), epoch)),
            "trusted lifecycle generation anchor key is unknown or inactive",
        )
    }

    pub(in crate::financial_authority) fn high_water_key(
        &self,
        store_id: &str,
        epoch: u64,
    ) -> Result<&LifecycleHighWaterTrustKey, CredentialError> {
        active_key(
            self.lifecycle_high_water_keys
                .get(&(store_id.to_string(), epoch)),
            "trusted lifecycle high-water key is unknown or inactive",
        )
    }

    pub(in crate::financial_authority) fn activation_metadata(
        &self,
        issuer: &str,
    ) -> Result<&IssuerActivationMetadata, CredentialError> {
        self.activation_metadata
            .get(issuer)
            .ok_or_else(|| authority_error("issuer activation metadata is unavailable"))
    }

}
