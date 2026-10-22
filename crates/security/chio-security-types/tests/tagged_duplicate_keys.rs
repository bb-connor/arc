//! Adjacently tagged response records refuse a repeated tag or content key on raw input.

use chio_security_types::response_simulation::ResponseSimulationState;
use chio_security_types::ResponseMutationRecord;
use serde::de::DeserializeOwned;

fn assert_refused<T: DeserializeOwned>(raw: &str, key: &str, column: usize) {
    let expected = format!("duplicate field `{key}` at line 1 column {column}");
    for (path, result) in [
        ("from_str", serde_json::from_str::<T>(raw)),
        ("from_slice", serde_json::from_slice::<T>(raw.as_bytes())),
    ] {
        match result {
            Ok(_) => panic!("{path} accepted a repeated `{key}`: {raw}"),
            Err(error) => assert_eq!(error.to_string(), expected, "{path}: {raw}"),
        }
    }
}

fn assert_repeated_tag_and_content_refused<T: DeserializeOwned>(
    tag: &str,
    variant: &str,
    content: &str,
) {
    let head = format!(r#"{{"{tag}":"{variant}","{tag}""#);
    assert_refused::<T>(&format!(r#"{head}:"{variant}"}}"#), tag, head.len());
    let head = format!(r#"{{"{content}":null,"{content}""#);
    assert_refused::<T>(
        &format!(r#"{head}:null,"{tag}":"{variant}"}}"#),
        content,
        head.len(),
    );
}

#[test]
fn response_records_refuse_a_repeated_tag_or_content_key() {
    assert_repeated_tag_and_content_refused::<ResponseMutationRecord>(
        "record_type",
        "requested",
        "record",
    );
    assert_repeated_tag_and_content_refused::<ResponseSimulationState>(
        "kind",
        "suspension",
        "snapshot",
    );
}
