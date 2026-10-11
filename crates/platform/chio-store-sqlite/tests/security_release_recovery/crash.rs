//! A separate process executes and syncs an effect, then dies at a release cutpoint.
use super::*;
use chio_kernel::DurableFinalizationCutpoint;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;

const CHILD_POINT: &str = "CHIO_SECURITY_RELEASE_CRASH_POINT";
const DIRECTORY: &str = "CHIO_SECURITY_RELEASE_CRASH_DIRECTORY";
const SIGNER: &str = "CHIO_SECURITY_RELEASE_CRASH_SIGNER";
const AGENT: &str = "CHIO_SECURITY_RELEASE_CRASH_AGENT";

struct EffectServer(PathBuf);

#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for EffectServer {
    fn server_id(&self) -> &str {
        SERVER_ID
    }
    fn tool_names(&self) -> Vec<String> {
        vec![TOOL_NAME.into()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: serde_json::Value,
        _: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.0)
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        writeln!(file, "effect")
            .and_then(|_| file.sync_all())
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        Ok(arguments)
    }
}

fn install_effect_server(fixture: &mut Fixture) {
    let path = fixture.directory.path().join("effect.log");
    fixture.tool_server = Some(Box::new(move || Ok(Box::new(EffectServer(path.clone())))));
    fixture.nonce_enabled = false;
}

fn run_child() -> TestResult {
    let point =
        DurableFinalizationCutpoint::parse(&std::env::var(CHILD_POINT)?).ok_or("child cutpoint")?;
    let directory = PathBuf::from(std::env::var(DIRECTORY)?);
    let mut fixture = Fixture::attach(
        directory.clone(),
        &std::env::var(SIGNER)?,
        &std::env::var(AGENT)?,
    )?;
    install_effect_server(&mut fixture);
    fixture.finalization_cutpoint = Some(point);
    let request: ToolCallRequest =
        serde_json::from_slice(&std::fs::read(directory.join("request.json"))?)?;
    let hook = Arc::new(ReleaseHook {
        allowed: true,
        releases: Arc::new(AtomicUsize::new(0)),
    });
    let runtime = open(&fixture, hook, true)?;
    runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request)?)?;
    Err("child returned without reaching its crash cutpoint".into())
}

fn crash_recovery(
    test_name: &str,
    point: DurableFinalizationCutpoint,
    checkpointed: bool,
) -> TestResult {
    if std::env::var_os(CHILD_POINT).is_some() {
        return run_child();
    }
    let mut fixture = Fixture::new()?;
    install_effect_server(&mut fixture);
    let hook = Arc::new(ReleaseHook {
        allowed: true,
        releases: Arc::new(AtomicUsize::new(0)),
    });
    let request = {
        let runtime = open(&fixture, hook.clone(), true)?;
        fixture.request(&runtime, "release-process-crash")?
    };
    std::fs::write(
        fixture.directory.path().join("request.json"),
        chio_core::canonical_json_bytes(&request)?,
    )?;
    let output = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env(CHILD_POINT, point.name())
        .env(DIRECTORY, fixture.directory.path())
        .env(SIGNER, fixture.signer.seed_hex())
        .env(AGENT, fixture.agent.seed_hex())
        .output()?;
    assert_eq!(
        output.status.signal(),
        Some(libc::SIGABRT),
        "child failed outside cutpoint: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(fixture.directory.path().join("effect.log"))?,
        "effect\n"
    );
    assert_eq!(
        operation_state(&fixture, &request.request_id)?
            .ok_or("retained operation")?
            .1,
        "finalizing"
    );
    let runtime = open(&fixture, hook.clone(), false)?;
    let startup = runtime.kernel.reconcile_durable_admission_startup();
    let replay = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request)?);
    if checkpointed {
        startup?;
        let response = replay?;
        assert_eq!(response.verdict, chio_kernel::Verdict::Allow);
        assert!(response.output.is_some());
        assert_eq!(
            operation_state(&fixture, &request.request_id)?
                .ok_or("completed operation")?
                .1,
            "completed"
        );
    } else {
        assert!(matches!(
            startup,
            Err(KernelError::SecurityDispatchOutcomeRecoveryRequired(_))
        ));
        assert!(replay.is_err());
        assert_eq!(
            operation_state(&fixture, &request.request_id)?
                .ok_or("unreleased operation")?
                .1,
            "finalizing"
        );
    }
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    assert_eq!(
        hook.releases.load(Ordering::SeqCst),
        0,
        "restart must not replace the original release owner"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.directory.path().join("effect.log"))?,
        "effect\n"
    );
    Ok(())
}

#[test]
fn crash_before_release_cannot_publish_resolved_output() -> TestResult {
    crash_recovery(
        "crash::crash_before_release_cannot_publish_resolved_output",
        DurableFinalizationCutpoint::PostReturnResolved,
        false,
    )
}

#[test]
fn crash_after_acknowledgement_requires_the_missing_checkpoint() -> TestResult {
    crash_recovery(
        "crash::crash_after_acknowledgement_requires_the_missing_checkpoint",
        DurableFinalizationCutpoint::SecurityReleaseAcknowledged,
        false,
    )
}

#[test]
fn crash_after_checkpoint_recovers_without_a_second_release_or_effect() -> TestResult {
    crash_recovery(
        "crash::crash_after_checkpoint_recovers_without_a_second_release_or_effect",
        DurableFinalizationCutpoint::SecurityReleaseCheckpointed,
        true,
    )
}
