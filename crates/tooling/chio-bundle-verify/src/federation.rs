//! Signed federation policies and the export scope they bound.

use chio_core_types::receipt::evidence::{
    EvidenceExportQuery, FederationPolicyDocument, ReceiptReadBoundary, FEDERATION_POLICY_SCHEMA,
};

use crate::error::BundleVerifyError;

/// Check a federation policy's schema, validity window, signature and read
/// boundary.
pub fn verify_federation_policy(
    policy: &FederationPolicyDocument,
) -> Result<(), BundleVerifyError> {
    if policy.body.schema != FEDERATION_POLICY_SCHEMA {
        return Err(BundleVerifyError::schema(format!(
            "unsupported federation policy schema: expected {}, got {}",
            FEDERATION_POLICY_SCHEMA, policy.body.schema
        )));
    }
    if policy.body.created_at > policy.body.expires_at {
        return Err(BundleVerifyError::inconsistent(
            "federation policy created_at must be less than or equal to expires_at",
        ));
    }
    let signed = policy
        .body
        .signer_public_key
        .verify_canonical(&policy.body, &policy.signature)
        .map_err(|error| {
            BundleVerifyError::signature(format!(
                "federation policy signature verification failed: {error}"
            ))
        })?;
    if !signed {
        return Err(BundleVerifyError::signature(
            "federation policy signature verification failed",
        ));
    }
    match &policy.body.query.read_boundary {
        Some(ReceiptReadBoundary::TenantScoped { tenant }) => {
            if tenant.trim().is_empty() {
                return Err(BundleVerifyError::inconsistent(
                    "federation policy tenant read boundary requires a non-empty tenant",
                ));
            }
            if policy
                .body
                .query
                .tenant
                .as_deref()
                .is_some_and(|query_tenant| query_tenant != tenant)
            {
                return Err(BundleVerifyError::inconsistent(
                    "federation policy tenant scope must match its read boundary",
                ));
            }
        }
        Some(ReceiptReadBoundary::AdminAll) => {
            if policy
                .body
                .query
                .tenant
                .as_deref()
                .is_some_and(|tenant| !tenant.trim().is_empty())
            {
                return Err(BundleVerifyError::inconsistent(
                    "federation policy admin-all read boundary must not include tenant scope",
                ));
            }
        }
        None => {
            return Err(BundleVerifyError::inconsistent(
                "federation policy must bind an explicit receipt read boundary",
            ));
        }
    }
    Ok(())
}

/// The read boundary an export under a signed policy may use: the policy's
/// own, never a wider one the request chose.
pub fn merge_read_boundary(
    policy_value: Option<&ReceiptReadBoundary>,
    request_value: Option<&ReceiptReadBoundary>,
) -> Result<Option<ReceiptReadBoundary>, BundleVerifyError> {
    match (policy_value, request_value) {
        (
            Some(ReceiptReadBoundary::TenantScoped { tenant: policy }),
            Some(ReceiptReadBoundary::TenantScoped { tenant: request }),
        ) if policy != request => Err(BundleVerifyError::inconsistent(format!(
            "requested export tenant scope '{request}' falls outside the signed federation policy \
             tenant scope '{policy}'"
        ))),
        (Some(ReceiptReadBoundary::TenantScoped { .. }), Some(ReceiptReadBoundary::AdminAll)) => {
            Err(BundleVerifyError::inconsistent(
                "requested admin-all export exceeds tenant-scoped federation policy",
            ))
        }
        (Some(boundary), _) => Ok(Some(boundary.clone())),
        (None, Some(_)) | (None, None) => Err(BundleVerifyError::inconsistent(
            "signed federation policy must bind an explicit receipt read boundary",
        )),
    }
}

/// An exported query stays inside the scope its federation policy signed.
pub fn ensure_query_within_federation_policy(
    policy_query: &EvidenceExportQuery,
    export_query: &EvidenceExportQuery,
) -> Result<(), BundleVerifyError> {
    let merged_boundary = merge_read_boundary(
        policy_query.read_boundary.as_ref(),
        export_query.read_boundary.as_ref(),
    )?;
    if merged_boundary != export_query.read_boundary {
        return Err(BundleVerifyError::inconsistent(
            "evidence package read boundary exceeds federation policy scope",
        ));
    }
    if let Some(ReceiptReadBoundary::TenantScoped { tenant }) = &export_query.read_boundary {
        if export_query
            .tenant
            .as_deref()
            .is_some_and(|query_tenant| query_tenant != tenant)
        {
            return Err(BundleVerifyError::inconsistent(
                "evidence package read boundary tenant conflicts with query tenant",
            ));
        }
    }
    if policy_query.capability_id.is_some()
        && policy_query.capability_id != export_query.capability_id
    {
        return Err(BundleVerifyError::inconsistent(
            "evidence package query exceeds federation policy capability scope",
        ));
    }
    if policy_query.agent_subject.is_some()
        && policy_query.agent_subject != export_query.agent_subject
    {
        return Err(BundleVerifyError::inconsistent(
            "evidence package query exceeds federation policy agent scope",
        ));
    }
    if policy_query.tenant.is_some() && policy_query.tenant != export_query.tenant {
        return Err(BundleVerifyError::inconsistent(
            "evidence package query exceeds federation policy tenant scope",
        ));
    }
    if let Some(policy_since) = policy_query.since {
        if export_query.since.unwrap_or(0) < policy_since {
            return Err(BundleVerifyError::inconsistent(
                "evidence package query starts before the federation policy window",
            ));
        }
    }
    if let Some(policy_until) = policy_query.until {
        if export_query.until.unwrap_or(u64::MAX) > policy_until {
            return Err(BundleVerifyError::inconsistent(
                "evidence package query ends after the federation policy window",
            ));
        }
    }
    Ok(())
}
