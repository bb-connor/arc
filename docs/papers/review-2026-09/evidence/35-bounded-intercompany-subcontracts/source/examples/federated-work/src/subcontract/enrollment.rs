use crate::common::*;
use chio_core_types::{
    capability::token::CapabilityToken, receipt::lineage::SignedExportEnvelope, PublicKey,
};
use serde_json::{json, Value};

/// Activate only operator-selected peers, origin and supported credential shape.
/// The signed artifact cannot choose the expected keys or endpoint.
pub fn verify(
    value: &Value,
    provider: &chio_core_types::PublicKey,
    buyer: &chio_core_types::PublicKey,
    origin: &str,
) -> Result<()> {
    let envelope: SignedExportEnvelope<Value> = serde_json::from_value(value.clone())?;
    if &envelope.signer_key != provider
        || !envelope.verify_signature()?
        || serde_json::to_value(&envelope)? != *value
    {
        return Err("specialist enrollment does not verify under the selected key".into());
    }
    let body = &envelope.body;
    let schema = body["schema"]
        .as_str()
        .ok_or("enrollment schema is absent")?;
    let profiles = if schema == "chio.example.https-enrollment.v3" {
        let profiles = body["profiles"].clone();
        if profiles != json!([WORK_PROFILE]) && profiles != json!([WORK_PROFILE, super::PROFILE]) {
            return Err("unsupported enrollment profiles".into());
        }
        profiles
    } else if [
        "chio.example.https-enrollment.v1",
        "chio.example.https-enrollment.v2",
    ]
    .contains(&schema)
        && body["profile"] == WORK_PROFILE
    {
        json!([WORK_PROFILE])
    } else {
        return Err("unsupported specialist enrollment".into());
    };
    let mut expected = json!({"schema":schema,"buyer":buyer,"provider":provider,"origin":origin,
        "caPem":body["caPem"],"session":body["session"]});
    if schema.ends_with(".v3") {
        expected["profiles"] = profiles;
        expected["subcontractPromisor"] = body["subcontractPromisor"].clone();
        if !body["subcontractPromisor"].is_null() {
            let promisor: PublicKey = serde_json::from_value(body["subcontractPromisor"].clone())?;
            if &promisor == buyer || &promisor == provider {
                return Err("enrollment confuses procurement and issuer authority".into());
            }
        }
    } else {
        expected["profile"] = json!(WORK_PROFILE);
    }
    if *body != expected {
        return Err("enrollment changes the selected relationship or shape".into());
    }
    let ca = body["caPem"]
        .as_str()
        .ok_or("enrollment has no TLS certificates")?;
    if ca.len() > 64 * 1024 {
        return Err("specialist trust material exceeds bounds".into());
    }
    crate::https::public_certificates(ca.as_bytes())?;
    let cap: CapabilityToken = serde_json::from_value(body["session"].clone())?;
    let count = if schema.ends_with(".v1") { 4 } else { 5 };
    let names = ["quote", "accept", "status", "delivery", "resolve"];
    let grants: Vec<Value> = names[..count].iter().map(|name| {
        json!({"server_id":SERVER,"tool_name":name,"operations":["invoke"],"constraints":[{"type":"max_args_size","value":256*1024}],"dpop_required":true})
    }).collect();
    if &cap.issuer != provider
        || &cap.subject != buyer
        || !cap.verify_signature()?
        || serde_json::to_value(&cap)? != body["session"]
        || serde_json::to_value(&cap.scope)? != json!({"grants":grants})
        || cap.issued_at == 0
        || cap.id.is_empty()
        || cap.id.chars().count() > 256
        || body["session"]["schema"] != "chio.capability.v1"
        || cap.expires_at <= cap.issued_at
    {
        return Err("specialist session widens the selected proof-of-possession authority".into());
    }
    Ok(())
}
