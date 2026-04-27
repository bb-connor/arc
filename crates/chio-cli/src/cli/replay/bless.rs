// `chio replay --bless --into <fixture-dir>` dispatcher.

fn cmd_replay_bless(args: &ReplayArgs, log: &Path) -> Result<(), CliError> {
    let into = args.into.as_ref().ok_or_else(|| {
        CliError::Other("chio replay --bless requires --into <fixture-dir>".to_string())
    })?;

    require_replay_bless_capability()?;
    let scenario = validate_replay_bless_into_path(into)?;

    let iter = open_ndjson(log).map_err(|error| {
        CliError::Other(format!(
            "failed to open TEE capture {}: {error}",
            log.display()
        ))
    })?;
    let mut frames = Vec::new();
    for record in iter {
        let record = record.map_err(|error| {
            CliError::Other(format!(
                "failed to parse TEE capture {}: {error}",
                log.display()
            ))
        })?;
        frames.push(record.frame);
    }

    let summary = chio_replay_corpus::write_m04_fixture(into, frames)
        .map_err(|error| CliError::Other(format!("replay bless failed: {error}")))?;

    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "chio replay bless: wrote {}/{} to {}",
        scenario.family,
        scenario.name,
        summary.dir.display(),
    )
    .map_err(|error| CliError::Other(format!("write stdout: {error}")))?;
    writeln!(
        stdout,
        "  frames:        {} input, {} after dedupe",
        summary.frames_in, summary.frames_after_dedupe,
    )
    .map_err(|error| CliError::Other(format!("write stdout: {error}")))?;
    writeln!(stdout, "  receipts:      {}", summary.receipt_count)
        .map_err(|error| CliError::Other(format!("write stdout: {error}")))?;
    writeln!(stdout, "  root:          {}", summary.root_hex)
        .map_err(|error| CliError::Other(format!("write stdout: {error}")))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_bless_tests {
    use super::*;
    use chio_tee_frame::{Frame, FrameInputs, Otel, Provenance, Upstream, UpstreamSystem, Verdict};
    use serde_json::json;

    fn frame_json() -> String {
        let frame = Frame::build(FrameInputs {
            event_id: "01H7ZZZZZZZZZZZZZZZZZZZZZA".to_string(),
            ts: "2026-04-25T18:02:11.418Z".to_string(),
            tee_id: "tee-test-1".to_string(),
            upstream: Upstream {
                system: UpstreamSystem::Openai,
                operation: "responses.create".to_string(),
                api_version: "2025-10-01".to_string(),
            },
            invocation: json!({"tool":"send","email":"alice@example.com"}),
            provenance: Provenance {
                otel: Otel {
                    trace_id: "0".repeat(32),
                    span_id: "0".repeat(16),
                },
                supply_chain: None,
            },
            request_blob_sha256: "a".repeat(64),
            response_blob_sha256: "b".repeat(64),
            redaction_pass_id: "m06-redactors@1.4.0+default".to_string(),
            verdict: Verdict::Allow,
            deny_reason: None,
            would_have_blocked: false,
            tenant_sig: format!("ed25519:{}", "A".repeat(86)),
        })
        .unwrap();
        serde_json::to_string(&frame).unwrap()
    }

    #[test]
    fn bless_dispatch_writes_fixture_when_capability_is_present() {
        let tmp = tempfile::TempDir::new().unwrap();
        let capture = tmp.path().join("capture.ndjson");
        fs::write(&capture, format!("{}\n", frame_json())).unwrap();
        let into = tmp.path().join("family").join("name");
        std::env::set_var(REPLAY_BLESS_CAPABILITY_ENV, REPLAY_BLESS_CAPABILITY);

        let args = ReplayArgs {
            log: Some(capture.clone()),
            from_tee: false,
            expect_root: None,
            json: false,
            bless: true,
            into: Some(into.clone()),
            command: None,
        };

        cmd_replay_bless(&args, &capture).unwrap();
        std::env::remove_var(REPLAY_BLESS_CAPABILITY_ENV);

        assert!(into.join(chio_replay_corpus::RECEIPTS_FILENAME).is_file());
        let receipts =
            fs::read_to_string(into.join(chio_replay_corpus::RECEIPTS_FILENAME)).unwrap();
        assert!(!receipts.contains("tenant_sig"));
        assert!(!receipts.contains("alice@example.com"));
    }

}
