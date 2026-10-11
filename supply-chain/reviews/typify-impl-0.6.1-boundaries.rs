#![cfg(test)]

use serde_json::json;
use typify::{TypeSpace, TypeSpaceSettings};

mod constrained {
    typify::import_types!(schema = "boundaries.schema.json", struct_builder = true);
}

mod nono_manifest {
    typify::import_types!(
        schema = "nono-capability.schema.json",
        struct_builder = true
    );
}

#[test]
fn generated_string_enum_and_required_field_checks_reject_invalid_values() {
    let good =
        json!({"name": "abc", "mode": "read", "port": 443, "version": "fixed", "items": [1]});
    assert!(serde_json::from_value::<constrained::Boundary>(good.clone()).is_ok());
    for (field, value) in [
        ("name", json!("!")),
        ("name", json!("abcde")),
        ("mode", json!("execute")),
    ] {
        let mut bad = good.clone();
        bad[field] = value;
        assert!(serde_json::from_value::<constrained::Boundary>(bad).is_err());
    }
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("name");
    assert!(serde_json::from_value::<constrained::Boundary>(missing).is_err());
    let mut extra = good;
    extra["unrecognized"] = json!(true);
    assert!(serde_json::from_value::<constrained::Boundary>(extra).is_err());
    let incomplete = constrained::Boundary::builder();
    assert!(constrained::Boundary::try_from(incomplete).is_err());
}

#[test]
fn generation_is_not_complete_schema_validation() {
    // These accepted values record upstream limits, not permission to trust them.
    let value = json!({"name": "abc", "mode": "read", "port": 65536, "version": "other", "items": [1, 1, 1]});
    assert!(serde_json::from_value::<constrained::Boundary>(value).is_ok());
}

#[test]
fn selected_nono_schema_requires_separate_version_and_port_semantics() {
    let ordinary =
        json!({"version": "0.1.0", "network": {"mode": "blocked", "ports": {"connect": [443]}}});
    assert!(serde_json::from_value::<nono_manifest::NonoCapabilityManifest>(ordinary).is_ok());
    let above_port_limit =
        json!({"version": "9.9.9", "network": {"mode": "blocked", "ports": {"connect": [65536]}}});
    assert!(
        serde_json::from_value::<nono_manifest::NonoCapabilityManifest>(above_port_limit).is_ok()
    );
    let zero_port =
        json!({"version": "0.1.0", "network": {"mode": "blocked", "ports": {"connect": [0]}}});
    assert!(serde_json::from_value::<nono_manifest::NonoCapabilityManifest>(zero_port).is_err());
    let bad_mode = json!({"version": "0.1.0", "network": {"mode": "unknown"}});
    assert!(serde_json::from_value::<nono_manifest::NonoCapabilityManifest>(bad_mode).is_err());
}

#[test]
fn invalid_pattern_and_numeric_default_reject_generation() {
    for schema in [
        json!({"title": "InvalidPattern", "type": "string", "pattern": "["}),
        json!({"title": "InvalidDefault", "type": "integer", "minimum": 1, "maximum": 10, "default": 11}),
    ] {
        let mut types = TypeSpace::default();
        assert!(types
            .add_root_schema(serde_json::from_value(schema).unwrap())
            .is_err());
    }
}

#[test]
fn external_references_fail_without_fetching_and_deny_is_not_an_allowlist() {
    let schema = json!({"title": "External", "$ref": "https://invalid.example/schema.json"});
    assert!(std::panic::catch_unwind(|| {
        TypeSpace::default().add_root_schema(serde_json::from_value(schema).unwrap())
    })
    .is_err());
    let schema = json!({"title": "Fallback", "type": "string", "x-rust-type": {
        "crate": "absent", "version": "*", "path": "absent::Foreign"
    }});
    let mut settings = TypeSpaceSettings::default();
    settings.with_unknown_crates(typify::UnknownPolicy::Deny);
    let mut types = TypeSpace::new(&settings);
    types
        .add_root_schema(serde_json::from_value(schema).unwrap())
        .unwrap();
    let output = types.to_stream().to_string();
    assert!(output.contains("pub struct Fallback"));
    assert!(!output.contains(":: absent :: Foreign"));
}
