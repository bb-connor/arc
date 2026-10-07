//! Canonical admission request binding inputs and their existing hash derivation.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRequestBindingInput {
    action_hash: String,
    policy_hash: String,
    governed_intent_hash: Option<String>,
    threshold_proposal_hash: Option<String>,
    verified_approval_set_hash: Option<String>,
    approval_token_digests: Vec<String>,
    budget_hold_reference: Option<String>,
    supplemental_authorization_reference: Option<String>,
    supplemental_authorization_digest: Option<String>,
    execution_nonce_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRequestBindingParts {
    pub action_hash: String,
    pub policy_hash: String,
    pub governed_intent_hash: Option<String>,
    pub threshold_proposal_hash: Option<String>,
    pub verified_approval_set_hash: Option<String>,
    pub approval_token_digests: Vec<String>,
    pub budget_hold_reference: Option<String>,
    pub supplemental_authorization_reference: Option<String>,
    pub supplemental_authorization_digest: Option<String>,
    pub execution_nonce_reference: Option<String>,
}

impl AdmissionRequestBindingInput {
    pub fn new(parts: AdmissionRequestBindingParts) -> Result<Self, AdmissionOperationError> {
        let AdmissionRequestBindingParts {
            action_hash,
            policy_hash,
            governed_intent_hash,
            threshold_proposal_hash,
            verified_approval_set_hash,
            approval_token_digests,
            budget_hold_reference,
            supplemental_authorization_reference,
            supplemental_authorization_digest,
            execution_nonce_reference,
        } = parts;
        validate_digest(&action_hash, "action_hash")?;
        validate_digest(&policy_hash, "policy_hash")?;
        validate_optional_digest(governed_intent_hash.as_deref(), "governed_intent_hash")?;
        validate_optional_digest(
            threshold_proposal_hash.as_deref(),
            "threshold_proposal_hash",
        )?;
        validate_optional_digest(
            verified_approval_set_hash.as_deref(),
            "verified_approval_set_hash",
        )?;
        if approval_token_digests.len() > MAX_APPROVAL_TOKEN_DIGESTS_PER_OPERATION {
            return Err(AdmissionOperationError::Invalid(format!(
                "approval token digest count exceeds {MAX_APPROVAL_TOKEN_DIGESTS_PER_OPERATION}"
            )));
        }
        for digest in &approval_token_digests {
            validate_digest(digest, "approval_token_digest")?;
        }
        if approval_token_digests
            .array_windows::<2>()
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(AdmissionOperationError::Invalid(
                "approval token digests must be strictly sorted".to_string(),
            ));
        }
        validate_optional_identifier(budget_hold_reference.as_deref(), "budget_hold_reference")?;
        validate_optional_identifier(
            supplemental_authorization_reference.as_deref(),
            "supplemental_authorization_reference",
        )?;
        validate_optional_digest(
            supplemental_authorization_digest.as_deref(),
            "supplemental_authorization_digest",
        )?;
        if supplemental_authorization_reference.is_some()
            != supplemental_authorization_digest.is_some()
        {
            return Err(AdmissionOperationError::Invalid(
                "supplemental authorization reference and digest must be supplied together"
                    .to_string(),
            ));
        }
        validate_optional_identifier(
            execution_nonce_reference.as_deref(),
            "execution_nonce_reference",
        )?;
        Ok(Self {
            action_hash,
            policy_hash,
            governed_intent_hash,
            threshold_proposal_hash,
            verified_approval_set_hash,
            approval_token_digests,
            budget_hold_reference,
            supplemental_authorization_reference,
            supplemental_authorization_digest,
            execution_nonce_reference,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_unordered_approval_token_digests(
        mut parts: AdmissionRequestBindingParts,
    ) -> Result<Self, AdmissionOperationError> {
        parts.approval_token_digests.sort_unstable();
        Self::new(parts)
    }

    pub fn approval_token_digests(&self) -> &[String] {
        &self.approval_token_digests
    }

    pub fn derive_hash(&self) -> Result<String, AdmissionOperationError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct BindingBody<'a> {
            action_hash: &'a str,
            policy_hash: &'a str,
            governed_intent_hash: Option<&'a str>,
            threshold_proposal_hash: Option<&'a str>,
            verified_approval_set_hash: Option<&'a str>,
            approval_token_digests: &'a [String],
            budget_hold_reference: Option<&'a str>,
            supplemental_authorization_reference: Option<&'a str>,
            supplemental_authorization_digest: Option<&'a str>,
            execution_nonce_reference: Option<&'a str>,
        }

        let canonical = canonical_json_bytes(&BindingBody {
            action_hash: &self.action_hash,
            policy_hash: &self.policy_hash,
            governed_intent_hash: self.governed_intent_hash.as_deref(),
            threshold_proposal_hash: self.threshold_proposal_hash.as_deref(),
            verified_approval_set_hash: self.verified_approval_set_hash.as_deref(),
            approval_token_digests: &self.approval_token_digests,
            budget_hold_reference: self.budget_hold_reference.as_deref(),
            supplemental_authorization_reference: self
                .supplemental_authorization_reference
                .as_deref(),
            supplemental_authorization_digest: self.supplemental_authorization_digest.as_deref(),
            execution_nonce_reference: self.execution_nonce_reference.as_deref(),
        })
        .map_err(|error| {
            AdmissionOperationError::Invalid(format!(
                "failed to canonicalize admission request binding: {error}"
            ))
        })?;
        let mut bytes =
            Vec::with_capacity(ADMISSION_REQUEST_BINDING_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(ADMISSION_REQUEST_BINDING_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(sha256_hex(&bytes))
    }
}
