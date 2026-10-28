use chio_core::crypto::PublicKey;

pub const MAX_SETTLEMENT_DRAIN_KEYS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementDrainTrust {
    keys: Vec<PublicKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SettlementDrainTrustError {
    #[error("settlement drain trust requires at least one receipt key")]
    Empty,
    #[error("settlement drain trust exceeds the receipt key limit")]
    TooManyKeys,
    #[error("settlement drain trust repeats a receipt key")]
    DuplicateKey,
}

impl SettlementDrainTrust {
    pub fn new(keys: Vec<PublicKey>) -> Result<Self, SettlementDrainTrustError> {
        if keys.is_empty() {
            return Err(SettlementDrainTrustError::Empty);
        }
        if keys.len() > MAX_SETTLEMENT_DRAIN_KEYS {
            return Err(SettlementDrainTrustError::TooManyKeys);
        }
        for (index, key) in keys.iter().enumerate() {
            if keys.iter().take(index).any(|previous| previous == key) {
                return Err(SettlementDrainTrustError::DuplicateKey);
            }
        }
        Ok(Self { keys })
    }

    pub(crate) fn keys(&self) -> &[PublicKey] {
        &self.keys
    }
}

impl From<PublicKey> for SettlementDrainTrust {
    fn from(key: PublicKey) -> Self {
        Self { keys: vec![key] }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::crypto::{Keypair, HYBRID_ED25519_MLDSA65, ML_DSA_65_PUBLIC_KEY_LEN};

    #[test]
    fn drain_trust_requires_nonempty_bounded_distinct_keys(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            SettlementDrainTrust::new(Vec::new()),
            Err(SettlementDrainTrustError::Empty)
        );
        let key = Keypair::from_seed(&[1; 32]).public_key();
        assert_eq!(
            SettlementDrainTrust::new(vec![key.clone(), key.clone()]),
            Err(SettlementDrainTrustError::DuplicateKey)
        );
        assert_eq!(
            SettlementDrainTrust::new(vec![key.clone(); MAX_SETTLEMENT_DRAIN_KEYS + 1]),
            Err(SettlementDrainTrustError::TooManyKeys)
        );
        assert_eq!(SettlementDrainTrust::from(key.clone()).keys(), &[key]);
        let keys = (0..MAX_SETTLEMENT_DRAIN_KEYS)
            .map(|index| {
                u8::try_from(index).map(|seed| Keypair::from_seed(&[seed; 32]).public_key())
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(SettlementDrainTrust::new(keys.clone())?.keys(), keys);
        Ok(())
    }

    #[test]
    fn drain_trust_preserves_full_hybrid_key_identity() -> Result<(), Box<dyn std::error::Error>> {
        let classical = Keypair::from_seed(&[2; 32]).public_key();
        let first = PublicKey::from_hybrid_parts(
            classical.clone(),
            &[3; ML_DSA_65_PUBLIC_KEY_LEN],
            HYBRID_ED25519_MLDSA65,
        )?;
        let second = PublicKey::from_hybrid_parts(
            classical.clone(),
            &[4; ML_DSA_65_PUBLIC_KEY_LEN],
            HYBRID_ED25519_MLDSA65,
        )?;
        let keys = vec![classical, first.clone(), second];
        assert_eq!(SettlementDrainTrust::new(keys.clone())?.keys(), keys);
        assert_eq!(
            SettlementDrainTrust::new(vec![first.clone(), first]),
            Err(SettlementDrainTrustError::DuplicateKey)
        );
        Ok(())
    }
}
