//! `chio.capability-presentation.v1`: a leaf capability with its signed ancestors,
//! and the chain digest over them.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_bytes;
use crate::capability::token::CapabilityToken;
use crate::error::Result;
use crate::receipt::commitment::CHAIN_DIGEST_DOMAIN;

use super::delegation_context::DelegationContext;
use super::wire::{check_items, check_schema, validated_type, Sha256Digest};
use super::RootAuthorityShapeError;

pub const CHIO_CAPABILITY_PRESENTATION_SCHEMA: &str = "chio.capability-presentation.v1";

/// Most signed ancestors one presentation carries.
pub const MAX_PRESENTATION_ANCESTORS: usize = 16;

/// The members of [`CapabilityPresentation`]; [`CapabilityPresentation::new`] validates them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPresentationFields {
    pub schema: String,
    pub leaf: CapabilityToken,
    /// Signed ancestors ordered root to parent; empty when the leaf is the root.
    pub ancestors: Vec<CapabilityToken>,
    /// Present when the presenter is not the session holder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_context: Option<DelegationContext>,
}

validated_type!(
    /// `chio.capability-presentation.v1`. Unsigned; every member it carries is
    /// verified on its own.
    #[derive(Debug, Clone)]
    CapabilityPresentation(CapabilityPresentationFields)
);

impl CapabilityPresentationFields {
    pub fn validate(&self) -> core::result::Result<(), RootAuthorityShapeError> {
        check_schema(&self.schema, CHIO_CAPABILITY_PRESENTATION_SCHEMA)?;
        check_items(
            "ancestors",
            self.ancestors.len(),
            0,
            MAX_PRESENTATION_ANCESTORS,
        )
    }
}

impl CapabilityPresentation {
    /// [`chain_digest`] over this presentation's ancestors and leaf.
    pub fn chain_digest(&self) -> Result<Sha256Digest> {
        chain_digest(&self.ancestors, &self.leaf)
    }
}

/// `SHA-256("chio.receipt.chain-digest.v1\0" || canonical_json([root, ..., parent, leaf]))`
/// over the full signed tokens, with `ancestors` ordered root to parent.
pub fn chain_digest(ancestors: &[CapabilityToken], leaf: &CapabilityToken) -> Result<Sha256Digest> {
    let chain: Vec<&CapabilityToken> = ancestors.iter().chain(core::iter::once(leaf)).collect();
    let canonical = canonical_json_bytes(&chain)?;
    Ok(Sha256Digest::of_domain(CHAIN_DIGEST_DOMAIN, &canonical))
}
