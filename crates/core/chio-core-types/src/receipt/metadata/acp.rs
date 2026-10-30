//! Signed metadata block `acp`: an ACP-Client session update receipt with every member
//! committed except the session id.
//!
//! The session id stays plaintext: it is the join key of the session certificate and the
//! compliance verifier, which require it to equal `receipt_context.session_id` and
//! `protocol_refusal.session_id` when present. It links receipts within one session, is minted
//! by the ACP agent and may be low-entropy, so it is not secret. Every other member is
//! committed under `metadata.acp.<member>`; the authorization resource shares the
//! `metadata.receipt_context.authorization_resource` commitment with its `receipt_context`
//! alias when both blocks are built through one `MetadataCommitter`.

use alloc::string::String;

use serde::{Deserialize, Serialize};

use crate::receipt::metadata::{
    metadata_salt_ref, MetadataCommitment, MetadataCommitmentError, MetadataCommitter,
};

/// The raw members of one ACP-Client session update receipt.
#[derive(Clone, Copy, Debug)]
pub struct AcpReceiptFields<'a> {
    pub session_id: &'a str,
    pub tool_call_id: &'a str,
    pub capability_id: Option<&'a str>,
    pub authorization_receipt_id: Option<&'a str>,
    pub authorization_request_id: Option<&'a str>,
    pub authorization_tool_call_id: Option<&'a str>,
    pub authorization_correlation_id: Option<&'a str>,
    pub authorization_operation: Option<&'a str>,
    pub authorization_resource: Option<&'a str>,
    pub authorization_parameter_hash: Option<&'a str>,
    /// The enforcement mode's wire code.
    pub enforcement_mode: &'a str,
}

/// Signed metadata block `acp`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcpReceiptProjection {
    pub session_id: String,
    pub tool_call_id: MetadataCommitment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<MetadataCommitment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_receipt_id: Option<MetadataCommitment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_request_id: Option<MetadataCommitment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_tool_call_id: Option<MetadataCommitment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_correlation_id: Option<MetadataCommitment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_operation: Option<MetadataCommitment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_resource: Option<MetadataCommitment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_parameter_hash: Option<MetadataCommitment>,
    pub enforcement_mode: MetadataCommitment,
}

impl AcpReceiptProjection {
    /// True when this projection is the projection of `fields` under `committer`. The
    /// receipt's other blocks share `committer`, and the caller calls `finish` once per
    /// receipt.
    #[must_use]
    pub fn matches_with(
        &self,
        fields: &AcpReceiptFields<'_>,
        committer: &mut MetadataCommitter<'_>,
    ) -> bool {
        Self::project_with(fields, committer).is_ok_and(|rebuilt| rebuilt == *self)
    }

    /// The projection of `fields`, committing every member through `committer`, which the
    /// receipt's other blocks share.
    pub fn project_with(
        fields: &AcpReceiptFields<'_>,
        committer: &mut MetadataCommitter<'_>,
    ) -> Result<Self, MetadataCommitmentError> {
        let mut acp =
            |field: &str, value: &str| committer.commit(metadata_salt_ref("acp", field)?, &value);
        let tool_call_id = acp("tool_call_id", fields.tool_call_id)?;
        let enforcement_mode = acp("enforcement_mode", fields.enforcement_mode)?;
        let mut optional = |field: &str, value: Option<&str>| {
            value
                .map(|value| committer.commit(metadata_salt_ref("acp", field)?, &value))
                .transpose()
        };
        let capability_id = optional("capability_id", fields.capability_id)?;
        let authorization_receipt_id =
            optional("authorization_receipt_id", fields.authorization_receipt_id)?;
        let authorization_request_id =
            optional("authorization_request_id", fields.authorization_request_id)?;
        let authorization_tool_call_id = optional(
            "authorization_tool_call_id",
            fields.authorization_tool_call_id,
        )?;
        let authorization_correlation_id = optional(
            "authorization_correlation_id",
            fields.authorization_correlation_id,
        )?;
        let authorization_operation =
            optional("authorization_operation", fields.authorization_operation)?;
        let authorization_parameter_hash = optional(
            "authorization_parameter_hash",
            fields.authorization_parameter_hash,
        )?;
        let authorization_resource = fields
            .authorization_resource
            .map(|resource| {
                committer.commit(
                    metadata_salt_ref("receipt_context", "authorization_resource")?,
                    &resource,
                )
            })
            .transpose()?;
        Ok(Self {
            session_id: fields.session_id.into(),
            tool_call_id,
            capability_id,
            authorization_receipt_id,
            authorization_request_id,
            authorization_tool_call_id,
            authorization_correlation_id,
            authorization_operation,
            authorization_resource,
            authorization_parameter_hash,
            enforcement_mode,
        })
    }
}
