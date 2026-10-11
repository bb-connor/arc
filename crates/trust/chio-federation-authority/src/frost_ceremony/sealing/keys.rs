use super::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct X25519PublicKey([u8; 32]);

impl X25519PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, FrostCeremonyError> {
        let key = Self(bytes);
        key.validate()?;
        Ok(key)
    }

    pub(in crate::frost_ceremony) fn validate(&self) -> Result<(), FrostCeremonyError> {
        // Require the canonical field encoding, then reject all low-order inputs
        // through the provider's all-zero shared-secret check.
        let mut modulus = [0xff; 32];
        modulus[0] = 0xed;
        modulus[31] = 0x7f;
        if self.0.iter().rev().cmp(modulus.iter().rev()) != std::cmp::Ordering::Less {
            return Err(FrostSealingError::SealingKey.into());
        }
        let validation_key = FrostSealingKey(Zeroizing::new([0x42; 32]));
        validation_key
            .agree(self)
            .map_err(|_| FrostSealingError::SealingKey)?;
        Ok(())
    }
}

pub struct FrostSealingKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for FrostSealingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrostSealingKey")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl FrostSealingKey {
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self, FrostCeremonyError> {
        let mut bytes = Zeroizing::new([0; 32]);
        rng.try_fill_bytes(&mut *bytes)
            .map_err(|_| FrostSealingError::Random)?;
        Ok(Self(bytes))
    }

    pub fn from_custody_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
    pub fn custody_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn private_key(&self) -> Result<agreement::PrivateKey, FrostCeremonyError> {
        agreement::PrivateKey::from_private_key(&agreement::X25519, &*self.0)
            .map_err(|_| FrostSealingError::SealingKey.into())
    }

    pub fn public_key(&self) -> Result<X25519PublicKey, FrostCeremonyError> {
        let public = self
            .private_key()?
            .compute_public_key()
            .map_err(|_| FrostSealingError::SealingKey)?;
        let bytes = public
            .as_ref()
            .try_into()
            .map_err(|_| FrostSealingError::SealingKey)?;
        Ok(X25519PublicKey(bytes))
    }

    pub fn validate_for(&self, config: &FrostCeremonyConfig) -> Result<(), FrostCeremonyError> {
        let context = ValidatedCeremony::new_without_key(config)?;
        if self.public_key()? != context.local_participant()?.sealing_public_key {
            return Err(FrostSealingError::SealingKey.into());
        }
        Ok(())
    }

    pub(super) fn agree(
        &self,
        peer: &X25519PublicKey,
    ) -> Result<Zeroizing<Vec<u8>>, FrostCeremonyError> {
        agreement::agree(
            &self.private_key()?,
            agreement::UnparsedPublicKey::new(&agreement::X25519, peer.0),
            FrostSealingError::Agreement,
            |shared| Ok(Zeroizing::new(shared.to_vec())),
        )
        .map_err(Into::into)
    }
}
