impl FindingChallengeCoordinator {
    /// Commit the exact resolved evidence branch into the signed outcome.
    pub(crate) fn evidence_bundle_digest(
        &self,
        challenge: &FindingChallenge,
        evidence: &FindingChallengeClassEvidence<'_>,
    ) -> Result<String, ChallengeCoordinatorError> {
        let bytes = chio_core::canonical_json_bytes(&challenge.evidence)
            .map_err(|_| ChallengeCoordinatorError::Canonical)?;
        let (branch, supplemental_digests) = match evidence {
            FindingChallengeClassEvidence::EvidenceInvalid(resolved) => {
                let mut digests = vec![self.envelope_digest(resolved.purchase_record)?];
                for receipt in resolved.challenged_receipts {
                    digests.push(self.resolved_receipt_digest(
                        &receipt.canonical_receipt_bytes,
                        &receipt.inclusion_proof,
                    )?);
                }
                digests.push(self.canonical_digest(resolved.challenged_checkpoint)?);
                digests.push(self.canonical_digest(resolved.checkpoint_transparency)?);
                for proof in resolved.revoked_keys {
                    digests.push(self.envelope_digest(proof.statement)?);
                }
                ("evidence_invalid", digests)
            }
            FindingChallengeClassEvidence::DigestMismatch(resolved) => (
                "digest_mismatch",
                vec![
                    self.envelope_digest(resolved.failed_delivery)?,
                    self.envelope_digest(resolved.failed_delivery_authority_status)?,
                    self.envelope_digest(resolved.delivery_authority_status)?,
                    self.resolved_receipt_digest(
                        &resolved.deny_receipt.canonical_receipt_bytes,
                        &resolved.deny_receipt.inclusion_proof,
                    )?,
                    self.canonical_digest(resolved.deny_checkpoint)?,
                    self.canonical_digest(resolved.checkpoint_transparency)?,
                ],
            ),
            FindingChallengeClassEvidence::ReplayContradiction(resolved) => {
                let mut digests = vec![
                    self.envelope_digest(resolved.purchase_record)?,
                    self.envelope_digest(resolved.replay_authority_status)?,
                ];
                for reproduction in resolved.reproductions {
                    let reproduction_digest = self.canonical_digest(&(
                        self.resolved_receipt_digest(
                            &reproduction.receipt.canonical_receipt_bytes,
                            &reproduction.receipt.inclusion_proof,
                        )?,
                        self.canonical_digest(reproduction.checkpoint)?,
                        self.canonical_digest(reproduction.checkpoint_transparency)?,
                    ))?;
                    digests.push(reproduction_digest);
                }
                ("replay_contradiction", digests)
            }
        };
        let resolved_bytes = self.canonical_bytes(&(branch, supplemental_digests))?;
        let mut preimage = Vec::with_capacity(
            EVIDENCE_BUNDLE_DOMAIN.len() + 1 + bytes.len() + 1 + resolved_bytes.len(),
        );
        preimage.extend_from_slice(EVIDENCE_BUNDLE_DOMAIN.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&bytes);
        preimage.push(0);
        preimage.extend_from_slice(&resolved_bytes);
        Ok(sha256_hex(&preimage))
    }

    fn resolved_receipt_digest<T: Serialize>(
        &self,
        canonical_receipt_bytes: &[u8],
        inclusion_proof: &T,
    ) -> Result<String, ChallengeCoordinatorError> {
        self.canonical_digest(&(sha256_hex(canonical_receipt_bytes), inclusion_proof))
    }

    fn canonical_digest<T: Serialize>(
        &self,
        value: &T,
    ) -> Result<String, ChallengeCoordinatorError> {
        Ok(sha256_hex(&self.canonical_bytes(value)?))
    }

    fn canonical_bytes<T: Serialize>(
        &self,
        value: &T,
    ) -> Result<Vec<u8>, ChallengeCoordinatorError> {
        canonical_json_bytes(value).map_err(|_| ChallengeCoordinatorError::Canonical)
    }
}
