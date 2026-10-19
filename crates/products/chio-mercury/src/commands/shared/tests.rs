#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::utils::read_json_file_bounded;
use super::*;
use chio_control_plane::CliError;
use std::fs;

#[test]
fn write_bundle_manifests_rejects_bundle_id_path_separator() {
    let dir = unique_temp_dir("mercury-bundle-manifest-stem");
    let mut safe = chio_mercury_core::sample_mercury_bundle_manifest();
    safe.bundle_id = "safe-bundle".to_string();
    let mut unsafe_manifest = chio_mercury_core::sample_mercury_bundle_manifest();
    unsafe_manifest.bundle_id = "unsafe/bundle".to_string();

    let error = write_bundle_manifests(&dir, &[safe, unsafe_manifest]).unwrap_err();

    assert!(error.to_string().contains("bundle_id"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn write_bundle_manifests_rejects_bundle_id_control_character() {
    let dir = unique_temp_dir("mercury-bundle-manifest-stem");
    let mut safe = chio_mercury_core::sample_mercury_bundle_manifest();
    safe.bundle_id = "safe-bundle".to_string();
    let mut unsafe_manifest = chio_mercury_core::sample_mercury_bundle_manifest();
    unsafe_manifest.bundle_id = "unsafe\tbundle".to_string();

    let error = write_bundle_manifests(&dir, &[safe, unsafe_manifest]).unwrap_err();

    assert!(error.to_string().contains("bundle_id"));
    let _ = fs::remove_dir_all(dir);
}

fn bounded_read_error_code(result: Result<serde_json::Value, CliError>) -> String {
    result
        .expect_err("read must be refused")
        .report()
        .code
        .to_string()
}

#[test]
fn read_json_file_accepts_input_at_the_bound() {
    let dir = unique_temp_dir("mercury-read-at-bound");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("input.json");
    let mut text = String::from(r#"{"valid":true}"#);
    text.push_str(&" ".repeat(64 - text.len()));
    fs::write(&path, &text).unwrap();

    let value: serde_json::Value = read_json_file_bounded(&path, 64).unwrap();

    assert_eq!(value["valid"], true);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn read_json_file_refuses_input_over_the_bound() {
    let dir = unique_temp_dir("mercury-read-over-bound");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("input.json");
    let mut text = String::from(r#"{"valid":true}"#);
    text.push_str(&" ".repeat(65 - text.len()));
    fs::write(&path, &text).unwrap();

    assert_eq!(
        bounded_read_error_code(read_json_file_bounded(&path, 64)),
        "urn:chio:error:attest:signed-json-too-large"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn read_json_file_refuses_non_utf8_input() {
    let dir = unique_temp_dir("mercury-read-non-utf8");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("input.json");
    fs::write(&path, [0xff, 0xfe]).unwrap();

    assert_eq!(
        bounded_read_error_code(read_json_file_bounded(&path, 64)),
        "urn:chio:error:attest:signed-json-not-utf8"
    );
    let _ = fs::remove_dir_all(dir);
}
