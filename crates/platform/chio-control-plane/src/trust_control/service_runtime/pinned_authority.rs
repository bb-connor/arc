use chio_core::PublicKey;

use crate::CliError;

const MAX_TRUSTED_ROOT_ISSUERS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedAuthoritySuccessor {
    pub generation: u64,
    pub public_key: PublicKey,
}

/// Independently pinned control-authority state for remote root resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedControlAuthority {
    current_signer: PublicKey,
    trusted_root_issuers: Vec<PublicKey>,
    successors: Vec<PinnedAuthoritySuccessor>,
}

impl PinnedControlAuthority {
    /// Build a bounded trust bundle with one exact current signer.
    pub fn new(
        current_signer: PublicKey,
        trusted_root_issuers: Vec<PublicKey>,
    ) -> Result<Self, CliError> {
        Self::with_successors(current_signer, trusted_root_issuers, Vec::new())
    }

    /// Build a bundle with an operator-pinned contiguous successor schedule.
    /// Status responses may report liveness, but they cannot add or reorder
    /// these trust roots.
    pub fn with_successors(
        current_signer: PublicKey,
        trusted_root_issuers: Vec<PublicKey>,
        mut successors: Vec<PinnedAuthoritySuccessor>,
    ) -> Result<Self, CliError> {
        successors.sort_by_key(|pin| pin.generation);
        if successors.iter().any(|pin| pin.generation == 0)
            || successors
                .windows(2)
                .any(|pair| pair[0].generation == pair[1].generation)
        {
            return Err(CliError::cli_other_error(
                "pinned control-authority successor generations must be unique and non-zero"
                    .to_string(),
            ));
        }
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
        let mut scheduled_keys = Vec::with_capacity(successors.len());
        for successor in &successors {
            if trusted.contains(&successor.public_key)
                || scheduled_keys.contains(&successor.public_key)
            {
                return Err(CliError::cli_other_error(
                    "pinned control-authority successor keys must be distinct from current and historical keys"
                        .to_string(),
                ));
            }
            scheduled_keys.push(successor.public_key.clone());
        }
        validate_trusted_root_issuer_count(trusted.len().saturating_add(successors.len()))?;
        if trusted.is_empty() {
            return Err(CliError::cli_other_error(
                "pinned control-authority trust bundle must not be empty".to_string(),
            ));
        }

        Ok(Self {
            current_signer,
            trusted_root_issuers: trusted,
            successors,
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

    #[must_use]
    pub fn successor_for_generation(&self, generation: u64) -> Option<&PublicKey> {
        self.successors
            .iter()
            .find(|pin| pin.generation == generation)
            .map(|pin| &pin.public_key)
    }

    #[must_use]
    pub fn successors(&self) -> &[PinnedAuthoritySuccessor] {
        &self.successors
    }

    #[must_use]
    pub fn trusted_roots_through_generation(&self, generation: u64) -> Vec<PublicKey> {
        let mut trusted = self.trusted_root_issuers.clone();
        for successor in self
            .successors
            .iter()
            .filter(|successor| successor.generation <= generation)
        {
            if !trusted.contains(&successor.public_key) {
                trusted.push(successor.public_key.clone());
            }
        }
        trusted
    }

    pub fn validate_successor_schedule_from(
        &self,
        current_generation: u64,
    ) -> Result<(), CliError> {
        let mut expected = current_generation;
        for successor in &self.successors {
            expected = expected.checked_add(1).ok_or_else(|| {
                CliError::cli_other_error(
                    "pinned control-authority successor generation overflows".to_string(),
                )
            })?;
            if successor.generation != expected {
                return Err(CliError::cli_other_error(
                    "pinned control-authority successor schedule must begin at the next generation and remain contiguous"
                        .to_string(),
                ));
            }
        }
        Ok(())
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
    fn future_successors_are_scheduled_but_not_pretrusted() {
        let current = public_key(10);
        let successor = public_key(11);
        let bundle = PinnedControlAuthority::with_successors(
            current.clone(),
            Vec::new(),
            vec![PinnedAuthoritySuccessor {
                generation: 8,
                public_key: successor.clone(),
            }],
        )
        .test_unwrap();

        assert_eq!(bundle.trusted_root_issuers(), &[current]);
        assert!(!bundle.trusted_root_issuers().contains(&successor));
        assert_eq!(bundle.successor_for_generation(8), Some(&successor));
        bundle.validate_successor_schedule_from(7).test_unwrap();
    }

    #[test]
    fn successor_schedule_must_start_next_and_remain_contiguous() {
        let bundle = PinnedControlAuthority::with_successors(
            public_key(20),
            Vec::new(),
            vec![
                PinnedAuthoritySuccessor {
                    generation: 9,
                    public_key: public_key(21),
                },
                PinnedAuthoritySuccessor {
                    generation: 11,
                    public_key: public_key(22),
                },
            ],
        )
        .test_unwrap();

        let error = bundle.validate_successor_schedule_from(8).test_unwrap_err();
        assert!(error.to_string().contains("remain contiguous"));
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
