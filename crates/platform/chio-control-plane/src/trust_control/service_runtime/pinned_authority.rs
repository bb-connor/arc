use chio_core::PublicKey;

use crate::CliError;

const MAX_TRUSTED_ROOT_ISSUERS: usize = 256;

/// Independently pinned control-authority state for remote root resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedControlAuthority {
    current_signer: PublicKey,
    trusted_root_issuers: Vec<PublicKey>,
}

impl PinnedControlAuthority {
    /// Build a bounded trust bundle with one exact current signer.
    pub fn new(
        current_signer: PublicKey,
        trusted_root_issuers: Vec<PublicKey>,
    ) -> Result<Self, CliError> {
        let mut trusted = Vec::with_capacity(
            trusted_root_issuers
                .len()
                .saturating_add(1)
                .min(MAX_TRUSTED_ROOT_ISSUERS),
        );
        for issuer in trusted_root_issuers {
            if !trusted.contains(&issuer) {
                trusted.push(issuer);
                validate_trusted_root_issuer_count(trusted.len())?;
            }
        }
        if !trusted.contains(&current_signer) {
            trusted.push(current_signer.clone());
            validate_trusted_root_issuer_count(trusted.len())?;
        }
        if trusted.is_empty() {
            return Err(CliError::cli_other_error(
                "pinned control-authority trust bundle must not be empty".to_string(),
            ));
        }

        Ok(Self {
            current_signer,
            trusted_root_issuers: trusted,
        })
    }

    /// Exact authority key allowed to sign fresh lookup envelopes.
    #[must_use]
    pub fn current_signer(&self) -> &PublicKey {
        &self.current_signer
    }

    /// Bounded authority-key history allowed to authenticate durable roots.
    #[must_use]
    pub fn trusted_root_issuers(&self) -> &[PublicKey] {
        &self.trusted_root_issuers
    }
}

fn validate_trusted_root_issuer_count(count: usize) -> Result<(), CliError> {
    if count <= MAX_TRUSTED_ROOT_ISSUERS {
        return Ok(());
    }
    Err(CliError::cli_other_error(format!(
        "pinned control-authority trust bundle supports at most {MAX_TRUSTED_ROOT_ISSUERS} unique keys"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::Keypair;
    use chio_test_support::prelude::*;

    fn public_key(index: u16) -> PublicKey {
        let mut seed = [0_u8; 32];
        seed[..2].copy_from_slice(&index.to_be_bytes());
        Keypair::from_seed(&seed).public_key()
    }

    #[test]
    fn pinned_control_authority_deduplicates_and_includes_current() {
        let current = public_key(1);
        let historical = public_key(2);
        let bundle = PinnedControlAuthority::new(
            current.clone(),
            vec![
                historical.clone(),
                historical.clone(),
                current.clone(),
                current.clone(),
            ],
        )
        .test_unwrap();

        assert_eq!(bundle.current_signer(), &current);
        assert_eq!(bundle.trusted_root_issuers().len(), 2);
        assert_eq!(
            bundle
                .trusted_root_issuers()
                .iter()
                .filter(|issuer| *issuer == &historical)
                .count(),
            1
        );
        assert!(bundle.trusted_root_issuers().contains(&current));
    }

    #[test]
    fn pinned_control_authority_accepts_empty_history_with_current() {
        let current = public_key(3);
        let bundle = PinnedControlAuthority::new(current.clone(), Vec::new()).test_unwrap();

        assert_eq!(bundle.current_signer(), &current);
        assert_eq!(bundle.trusted_root_issuers(), &[current]);
    }

    #[test]
    fn pinned_control_authority_rejects_more_than_256_unique_keys() {
        let accepted =
            PinnedControlAuthority::new(public_key(255), (0_u16..255).map(public_key).collect())
                .test_unwrap();
        assert_eq!(
            accepted.trusted_root_issuers().len(),
            MAX_TRUSTED_ROOT_ISSUERS
        );

        let error =
            PinnedControlAuthority::new(public_key(256), (0_u16..256).map(public_key).collect())
                .test_unwrap_err();
        assert!(error.to_string().contains("at most 256 unique keys"));
    }
}
