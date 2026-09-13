//! Validate real signed codec output against locally pinned wire schemas.
use super::*;
use std::collections::BTreeMap;

struct LocalSchemas(BTreeMap<String, serde_json::Value>);

impl jsonschema::Retrieve for LocalSchemas {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        self.0
            .get(uri.as_str())
            .cloned()
            .ok_or_else(|| format!("unregistered local caller schema: {uri}").into())
    }
}

#[test]
fn signed_caller_artifacts_match_the_registered_schemas() -> TestResult {
    let fixture = fixture()?;
    let resources = [
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../spec/schemas/chio-wire/v1/kernel/caller_dispatch_authorization.schema.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../spec/schemas/chio-wire/v1/kernel/caller_delivery_report.schema.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../spec/schemas/chio-wire/v1/kernel/execution_nonce.schema.json"
        )),
    ];
    let schemas = resources
        .into_iter()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let registry = schemas
        .iter()
        .map(|schema| {
            Ok((
                schema["$id"].as_str().ok_or("schema id")?.to_owned(),
                schema.clone(),
            ))
        })
        .collect::<TestResult<BTreeMap<_, _>>>()?;
    for (schema, value, body_key) in [
        (
            &schemas[0],
            serde_json::to_value(&fixture.authorization)?,
            "authorization",
        ),
        (
            &schemas[1],
            serde_json::to_value(report(&fixture)?)?,
            "report",
        ),
    ] {
        let validator = jsonschema::options()
            .with_retriever(LocalSchemas(registry.clone()))
            .build(schema)?;
        assert!(
            validator.is_valid(&value),
            "{:?}",
            validator.iter_errors(&value).collect::<Vec<_>>()
        );
        let mut extra = value.clone();
        extra[body_key]["unqualified_authority"] = true.into();
        assert!(!validator.is_valid(&extra));
        let mut missing = value.clone();
        missing
            .as_object_mut()
            .ok_or("signed object")?
            .remove("signature");
        assert!(!validator.is_valid(&missing));
        let mut epoch = value.clone();
        epoch[body_key]["executor"]["key_epoch"] = 0.into();
        assert!(!validator.is_valid(&epoch));
    }
    Ok(())
}
