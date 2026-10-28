//! Root tags under the deployment's tenant index key set.

use chio_core::root_authority::Sha256Digest;
use chio_core::tenant_index::{IndexDomain, TenantBindingError, TenantIndexKeySet};

use super::{Result, RootExchangeStoreError, RootTags, SqliteRootExchangeStore};

/// The plaintext a root's tags are derived from. It is held only for the
/// derivation and never stored.
#[derive(Clone, Copy)]
pub struct RootTagInputs<'a> {
    pub issuer: &'a str,
    /// The raw value of the record's `subject_mapping.principal_source`.
    pub principal: &'a str,
    pub tenant_value: &'a str,
}

impl std::fmt::Debug for RootTagInputs<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RootTagInputs")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl RootTagInputs<'_> {
    fn preimages(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        for (field, value) in [
            ("issuer", self.issuer),
            ("principal", self.principal),
            ("tenant_value", self.tenant_value),
        ] {
            if value.contains('\0') {
                return Err(RootExchangeStoreError::TagInputContainsNul { field });
            }
        }
        let joined = |value: &str| {
            let mut bytes = Vec::with_capacity(self.issuer.len() + 1 + value.len());
            bytes.extend_from_slice(self.issuer.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(value.as_bytes());
            bytes
        };
        Ok((joined(self.principal), joined(self.tenant_value)))
    }
}

/// The tenant index of one state directory: a key set that holds every
/// generation the stored roots reference.
pub struct RootTenantIndex<'a> {
    keys: &'a TenantIndexKeySet,
}

impl<'a> RootTenantIndex<'a> {
    /// Refuses `TagGenerationMissing` when a stored root's tags name a
    /// generation the key set does not hold.
    pub fn open(keys: &'a TenantIndexKeySet, store: &SqliteRootExchangeStore) -> Result<Self> {
        let loaded: Vec<Sha256Digest> = keys.key_ids().copied().collect();
        store.verify_tag_generations(&loaded)?;
        Ok(Self { keys })
    }

    /// The tags a new root carries, under the active generation.
    pub fn derive_tags(&self, inputs: &RootTagInputs<'_>) -> Result<RootTags> {
        self.tags_in(self.keys.active_key_id(), inputs)
    }

    /// The tags under every loaded generation, active first, for matching
    /// against revocation entries recorded under any of them.
    pub fn candidate_tags(&self, inputs: &RootTagInputs<'_>) -> Result<Vec<RootTags>> {
        self.keys
            .key_ids()
            .map(|key_id| self.tags_in(key_id, inputs))
            .collect()
    }

    /// Verifies presented tags under the generation their `key_id` names.
    pub fn verify_tags(&self, inputs: &RootTagInputs<'_>, tags: &RootTags) -> Result<()> {
        if tags.tenant.key_id != tags.subject.key_id {
            return Err(RootExchangeStoreError::TagMismatch);
        }
        let expected = self.tags_in(&tags.key_id(), inputs)?;
        if expected != *tags {
            return Err(RootExchangeStoreError::TagMismatch);
        }
        Ok(())
    }

    fn tags_in(&self, key_id: &Sha256Digest, inputs: &RootTagInputs<'_>) -> Result<RootTags> {
        let (subject, tenant) = inputs.preimages()?;
        let derive = |domain: IndexDomain, preimage: &[u8]| {
            self.keys
                .derive_in(key_id, domain, preimage)
                .map_err(|error| match error {
                    TenantBindingError::TenantIndexKeyUnknown { key_id } => {
                        RootExchangeStoreError::TenantIndexKeyUnknown { key_id }
                    }
                    other => RootExchangeStoreError::Invalid(other.to_string()),
                })
        };
        Ok(RootTags {
            subject: derive(IndexDomain::SubjectTag, &subject)?,
            tenant: derive(IndexDomain::TenantTag, &tenant)?,
        })
    }
}
