use chio_test_support::ctx::TestUnwrap;
use reqwest::blocking::Client;
use std::path::Path;
use std::process::Output;

pub(super) fn assert_remote_replay_rejected(
    client: &Client,
    challenge: &serde_json::Value,
    response_path: &Path,
    replay: &Output,
) {
    let stderr = String::from_utf8_lossy(&replay.stderr);
    assert!(
        stderr.contains("urn:chio:error:transport:http-failed"),
        "{stderr}"
    );
    let challenge_id = challenge["challengeId"]
        .as_str()
        .test_unwrap("challenge identifier");
    assert!(!stderr.contains(challenge_id), "{stderr}");
    let presentation: serde_json::Value = serde_json::from_slice(
        &std::fs::read(response_path).test_unwrap("read holder presentation"),
    )
    .test_unwrap("decode holder presentation");
    let response = client
        .post(
            challenge["transport"]["submitUrl"]
                .as_str()
                .test_unwrap("public submit URL"),
        )
        .json(&serde_json::json!({"presentation": presentation}))
        .send()
        .test_unwrap("inspect the service's replay rejection");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response
        .text()
        .test_unwrap("read public replay rejection")
        .contains("already been consumed"));
}
