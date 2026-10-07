pub mod enrollment;
pub mod permit;
#[cfg(test)]
mod tests;
pub mod worker;

// An exact disclosure and child-work contract selected by the original buyer.
use crate::{common::*, review};
use chio_core_types::PublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const PROFILE: &str = "chio.example.security-review-agreement.v4";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub specialist: PublicKey,
    pub delegate: PublicKey,
    pub paths: Vec<String>,
    pub input_sha256: String,
    pub price_ceiling: u64,
}

impl Policy {
    pub fn validate(&self, parent: &Agreement) -> Result<()> {
        if self.specialist == parent.buyer
            || self.specialist == parent.provider
            || self.delegate == parent.buyer
            || self.delegate == parent.provider
            || self.delegate == self.specialist
            || self.paths.is_empty()
            || self.paths.len() > 16
            || self
                .paths
                .iter()
                .any(|path| !path.starts_with('/') || path.len() > 256)
            || self.paths.windows(2).any(|pair| pair[0] >= pair[1])
            || self.price_ceiling != 100
            || self.price_ceiling > parent.price_ceiling
            || self.input_sha256.len() != 64
            || !self
                .input_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(
                "subcontract policy exceeds the supported disclosure or spending boundary".into(),
            );
        }
        Ok(())
    }
}

/// Reconstruct only selected paths' effective authentication declarations.
/// Descriptions, parameters, examples, extensions and unselected paths never
/// enter the child document, even when nested beneath an approved path.
pub fn project(input: &str, paths: &[String]) -> Result<String> {
    review::check_openapi(input)?;
    let document: Value = serde_json::from_str(input)?;
    let mut selected = BTreeMap::new();
    let mut referenced = BTreeSet::new();
    for path in paths {
        let item = document["paths"]
            .get(path)
            .and_then(Value::as_object)
            .ok_or("approved path is absent")?;
        let mut operations = BTreeMap::new();
        for method in [
            "get", "put", "post", "delete", "options", "head", "patch", "trace",
        ] {
            let Some(operation) = item.get(method) else {
                continue;
            };
            let security = operation
                .get("security")
                .or_else(|| document.get("security"))
                .cloned()
                .unwrap_or_else(|| json!([]));
            for requirement in security.as_array().ok_or("security is not an array")? {
                for name in requirement
                    .as_object()
                    .ok_or("security requirement is not an object")?
                    .keys()
                {
                    referenced.insert(name.clone());
                }
            }
            operations.insert(method.to_string(), json!({"security":security}));
        }
        if operations.is_empty() {
            return Err("approved path has no supported operations".into());
        }
        selected.insert(path.clone(), operations);
    }
    let mut schemes = BTreeMap::new();
    for name in referenced {
        let original = &document["components"]["securitySchemes"][&name];
        let keys = if original["type"] == "http" {
            vec!["type", "scheme"]
        } else {
            vec!["type", "name", "in"]
        };
        let scheme = keys
            .into_iter()
            .map(|key| (key.to_string(), original[key].clone()))
            .collect::<BTreeMap<_, _>>();
        schemes.insert(name, scheme);
    }
    let projected =
        json!({"openapi":"3.1.0","paths":selected,"components":{"securitySchemes":schemes}});
    let bytes = chio_core_types::canonical_json_bytes(&projected)?;
    let text = String::from_utf8(bytes)?;
    review::check_openapi(&text)?;
    Ok(text)
}

pub fn child_agreement(parent: &Agreement) -> Result<Agreement> {
    let policy = parent
        .subcontract
        .as_ref()
        .ok_or("no subcontract permission")?;
    policy.validate(parent)?;
    if parent.profile != PROFILE || !parent.subcontracting {
        return Err("parent does not permit this subcontract".into());
    }
    Ok(Agreement {
        profile: WORK_PROFILE.into(),
        job_id: format!("child-{}", digest(parent)?),
        input_sha256: policy.input_sha256.clone(),
        buyer: policy.delegate.clone(),
        provider: policy.specialist.clone(),
        price_ceiling: policy.price_ceiling,
        deadline: parent.deadline,
        checker: parent.checker.clone(),
        subcontracting: false,
        subcontract: None,
        credit_profile: parent.credit_profile.clone(),
    })
}

pub fn disclosure(request: &review::ReviewRequest) -> Result<String> {
    let parent = &request.acceptance.quote.agreement;
    let policy = parent
        .subcontract
        .as_ref()
        .ok_or("no subcontract permission")?;
    policy.validate(parent)?;
    let input = project(&request.input, &policy.paths)?;
    if chio_core_types::sha256_hex(input.as_bytes()) != policy.input_sha256 {
        return Err("subcontract disclosure differs from buyer-approved bytes".into());
    }
    Ok(input)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildDelivery {
    pub request: review::ReviewRequest,
    pub delivery: Value,
}

pub fn verify_child(parent: &review::ReviewRequest, value: &Value) -> Result<()> {
    let child: ChildDelivery = serde_json::from_value(value.clone())?;
    let expected = child_agreement(&parent.acceptance.quote.agreement)?;
    if digest(&child.request.acceptance.quote.agreement)? != digest(&expected)?
        || child.request.input != disclosure(parent)?
    {
        return Err(
            "specialist evidence changes the permitted child agreement or disclosure".into(),
        );
    }
    permit::verify_parent(parent, &child.request.acceptance.quote)?;
    child.request.validate(&Peers {
        buyer: expected.buyer,
        provider: expected.provider,
    })?;
    if review::verify_terminal(&child.request, &child.delivery)?.0 {
        return Err("specialist did not deliver an accepted result".into());
    }
    Ok(())
}
