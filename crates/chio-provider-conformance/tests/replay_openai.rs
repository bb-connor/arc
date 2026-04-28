#![cfg(feature = "fixtures-openai")]

use chio_provider_conformance::{openai_fixture_paths, replay_openai_fixture, ReplayMode};

#[test]
fn replays_all_openai_fixtures_with_canonical_byte_assertions() {
    let paths = match openai_fixture_paths() {
        Ok(paths) => paths,
        Err(error) => panic!("load OpenAI fixture paths: {error}"),
    };
    assert_eq!(
        paths.len(),
        12,
        "OpenAI corpus must contain exactly 12 NDJSON fixtures"
    );

    let mut total_invocations = 0;
    let mut total_verdicts = 0;
    let mut total_lowered = 0;
    let mut batch = 0;
    let mut stream = 0;
    let mut no_tool_call = 0;

    for path in paths {
        let outcome = match replay_openai_fixture(&path) {
            Ok(outcome) => outcome,
            Err(error) => panic!("replay {}: {error}", path.display()),
        };

        total_invocations += outcome.invocations;
        total_verdicts += outcome.verdicts;
        total_lowered += outcome.lowered_responses;

        match outcome.mode {
            ReplayMode::Batch => batch += 1,
            ReplayMode::Stream => stream += 1,
            ReplayMode::NoToolCall => no_tool_call += 1,
        }
    }

    assert_eq!(total_invocations, 13);
    assert_eq!(total_verdicts, 13);
    assert_eq!(total_lowered, 6);
    assert_eq!(batch, 7);
    assert_eq!(stream, 4);
    assert_eq!(no_tool_call, 1);
}
