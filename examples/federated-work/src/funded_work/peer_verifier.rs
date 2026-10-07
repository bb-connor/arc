//! Authenticated delivery to the original enrolled verifier.
use super::{
    checkpoint_files, evidence,
    native::Native,
    process::SocketSource,
    verification, verifier_handoff,
    verifier_operator::{self, Enrollment},
};
use crate::common::{self, Result};
use chio_core_types::canonical_json_bytes;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::Path, sync::Arc};

pub const SCHEMA: &str = "chio.experimental.funded-verifier-call.v1";
pub const ROUTE: &str = "/v1/funded-work/verify";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallBody {
    pub schema: String,
    pub origin: String,
    pub enrollment_sha256: String,
    pub request: verifier_handoff::Request,
}
pub type Call = evidence::Signed<CallBody>;

pub(super) fn origin(value: &str) -> Result<url::Url> {
    let url = url::Url::parse(value)?;
    let port = url
        .port_or_known_default()
        .filter(|p| *p != 0)
        .ok_or("concrete HTTPS port required")?;
    crate::https::origin(value, SocketAddr::from(([127, 0, 0, 1], port)))?;
    Ok(url)
}

pub(super) fn authenticate(
    raw: &[u8],
    enrollment: &Enrollment,
    expected_origin: &str,
) -> Result<Call> {
    origin(expected_origin)?;
    let call: Call = evidence::decode(raw)?;
    if call.body.schema != SCHEMA
        || call.body.origin != expected_origin
        || call.body.enrollment_sha256 != common::digest(enrollment)?
        || !enrollment
            .policy
            .provider_key
            .verify_strict(&canonical_json_bytes(&call.body)?, &call.signature)
    {
        return Err("verifier call changed provider, enrollment or selected origin".into());
    }
    Ok(call)
}

pub fn export(
    state: &Path,
    request_id: &str,
    socket: &Path,
    selected_origin: &str,
    output: &Path,
) -> Result<serde_json::Value> {
    origin(selected_origin)?;
    let native = Native::open_for_checkpoint(state, Arc::new(SocketSource(socket.to_owned())))?;
    let entry = native
        .journal
        .by_request(request_id)?
        .ok_or("original funded request missing")?;
    let enrollment = Enrollment {
        schema: verifier_operator::ENROLLMENT_SCHEMA.into(),
        policy: native.policy.clone(),
        agreement: entry.agreement,
    };
    let call = if let Some(retained) = native
        .journal
        .retained::<Call>(&entry.allocation, "verifier-call")?
    {
        authenticate(
            &canonical_json_bytes(&retained)?,
            &enrollment,
            selected_origin,
        )?
    } else {
        let request = verifier_handoff::export(&native, &entry.request)?;
        let call = evidence::sign(
            CallBody {
                schema: SCHEMA.into(),
                origin: selected_origin.into(),
                enrollment_sha256: common::digest(&enrollment)?,
                request,
            },
            &common::key(state)?,
        )?;
        // Bind the first transport destination before any publication. An
        // operator migration requires an explicit future protocol, not retry.
        authenticate(&canonical_json_bytes(&call)?, &enrollment, selected_origin)?;
        native
            .journal
            .retain_before(&entry.allocation, "verifier-call", &call, &["decision"])?;
        call
    };
    let original: verifier_handoff::Request = native
        .journal
        .retained(&entry.allocation, "verifier-request")?
        .ok_or("original verifier request missing")?;
    if canonical_json_bytes(&original)? != canonical_json_bytes(&call.body.request)? {
        return Err("transport call changed original verifier request custody".into());
    }
    checkpoint_files::write(output, &call)?;
    Ok(serde_json::json!({"callSha256":common::digest(&call)?}))
}

pub(super) fn verify_response(
    enrollment: &Enrollment,
    call: &Call,
    raw: &[u8],
) -> Result<verification::Decision> {
    let decision: verification::Decision = evidence::decode(raw)?;
    let request = &call.body.request;
    verifier_handoff::original(
        enrollment,
        request,
        decision.body.finding_assessment.evaluated_at,
    )?;
    super::settlement::validate(
        &request.claim,
        &verifier_handoff::action(enrollment, request)?,
        &enrollment.policy,
    )?;
    verification::verify_public_decision(
        &decision,
        &request.submission,
        &enrollment.policy,
        Some(&request.execution),
    )?;
    if decision.body.claim_transaction_hash != request.claim.transaction_hash {
        return Err("peer response changed the original claim transaction".into());
    }
    // Provider import still requires its own fresh claim/block observation.
    Ok(decision)
}
