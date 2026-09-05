use super::*;
use std::os::unix::fs::PermissionsExt;

fn executable(directory: &std::path::Path, body: &str) -> Result<PathBuf> {
    let path = directory.join("model-client");
    std::fs::write(&path, format!("#!/usr/bin/env python3\n{body}\n"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

#[test]
fn rejects_failed_or_incomplete_client_results() -> Result<()> {
    let result = json!({"type":"result","subtype":"success","is_error":false,
        "structured_output":{"content":[{"type":"text","text":"done"}],"stop_reason":"end_turn"},
        "usage":{"input_tokens":20,"output_tokens":10},"permission_denials":[]});
    assert_eq!(parse_result(&result)?.input_tokens, 20);
    for (key, value) in [
        ("type", json!("assistant")),
        ("subtype", json!("error_max_budget_usd")),
        ("is_error", json!(true)),
        ("structured_output", json!({})),
        ("usage", json!({})),
        ("permission_denials", json!([{"tool_name":"Read"}])),
    ] {
        let mut changed = result.clone();
        changed[key] = value;
        assert!(parse_result(&changed).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn sends_only_proposals_from_a_private_directory_with_client_tools_disabled() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let program = executable(
        directory.path(),
        r#"
import json,os,sys
details={'args':sys.argv[1:],'cwd':os.getcwd(),'request':json.load(sys.stdin)}
json.dump({'type':'result','subtype':'success','is_error':False,
 'structured_output':{'content':[{'type':'text','text':json.dumps(details)}],'stop_reason':'end_turn'},
 'usage':{'input_tokens':12,'output_tokens':5}},sys.stdout)
"#,
    )?;
    let provider = ClaudeCode::new(program, "chosen-model".into(), 0.25)?;
    let messages = vec![json!({"role":"user","content":"inspect the supplied task"})];
    let definitions = crate::tools::definitions(&["read_file"]);
    let turn = provider
        .turn("role instructions", &messages, &definitions)
        .await?;
    let details: Value = serde_json::from_str(
        turn.content[0]["text"]
            .as_str()
            .ok_or_else(|| Error::Invalid("test client omitted details".into()))?,
    )?;
    assert_eq!(details["request"]["messages"], json!(messages));
    let arguments = details["args"]
        .as_array()
        .ok_or_else(|| Error::Invalid("test client omitted arguments".into()))?;
    for flag in [
        "--safe-mode",
        "--restricted",
        "--strict-mcp-config",
        "--no-session-persistence",
    ] {
        assert!(arguments.contains(&json!(flag)));
    }
    for pair in [
        ["--tools", ""],
        ["--mcp-config", "{\"mcpServers\":{}}"],
        ["--settings", "{\"disableAllHooks\":true}"],
        ["--model", "chosen-model"],
        ["--max-budget-usd", "0.25"],
    ] {
        assert!(arguments
            .windows(2)
            .any(|window| window == [json!(pair[0]), json!(pair[1])]));
    }
    let cwd = details["cwd"]
        .as_str()
        .ok_or_else(|| Error::Invalid("test client omitted cwd".into()))?;
    assert!(
        !std::path::Path::new(cwd).exists(),
        "private model directory was not removed"
    );
    assert_eq!(provider.model(), "claude-code:chosen-model");
    Ok(())
}

#[tokio::test]
async fn rejects_large_output_and_does_not_expose_client_stderr() -> Result<()> {
    let directory = tempfile::tempdir()?;
    for body in [
        "import sys; sys.stdout.write('x' * (256 * 1024 + 1))",
        "import sys; sys.stderr.write('PRIVATE_TEST_CREDENTIAL'); sys.exit(3)",
    ] {
        let program = executable(directory.path(), body)?;
        let provider = ClaudeCode::new(program, "test".into(), 0.25)?;
        let result = provider.turn("role", &[], &[]).await;
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(!error.to_string().contains("PRIVATE_TEST_CREDENTIAL"));
        }
    }
    Ok(())
}

#[tokio::test]
async fn cancellation_kills_client_descendants() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let ready = directory.path().join("ready");
    let effect = directory.path().join("late-effect");
    let worker = format!(
        "import time; time.sleep(1); open({}, 'w').write('escaped')",
        serde_json::to_string(&effect)?
    );
    let body = format!("import json,subprocess,sys,time\nsubprocess.Popen([sys.executable,'-c',{}])\nopen({},'w').write('ready')\ntime.sleep(30)", serde_json::to_string(&worker)?, serde_json::to_string(&ready)?);
    let provider = ClaudeCode::new(executable(directory.path(), &body)?, "test".into(), 0.25)?;
    let task = tokio::spawn(async move { provider.turn("role", &[], &[]).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| Error::Invalid("test client did not start".into()))?;
    task.abort();
    assert!(task.await.is_err());
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        !effect.exists(),
        "a model descendant survived turn cancellation"
    );
    Ok(())
}

#[tokio::test]
async fn timeout_terminates_a_stalled_model_request() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let program = executable(directory.path(), "import time; time.sleep(30)")?;
    let mut provider = ClaudeCode::new(program, "test".into(), 0.25)?;
    provider.timeout = Duration::from_millis(50);
    assert!(provider.turn("role", &[], &[]).await.is_err());
    Ok(())
}
