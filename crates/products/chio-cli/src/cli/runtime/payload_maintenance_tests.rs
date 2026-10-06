use super::*;
use chio_kernel::admission_operation::DurableAdmissionMode;

#[test]
fn terminal_payload_maintenance_environment_starts_actual_owner_or_reports_missing_config(
) -> Result<(), Box<dyn std::error::Error>> {
    const MARKER: &str = "CHIO_PAYLOAD_MAINTENANCE_POSITIVE_TEST_CHILD";
    if let Ok(scenario) = std::env::var(MARKER) {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let database = directory.path().join("configured-fixture.db");
        let runtime = open_cli_durable_admission_runtime(
            DurableAdmissionMode::All,
            Some(&database),
            None,
            None,
            None,
            None,
            None,
            None,
        )?
        .ok_or("missing fixture runtime")?;
        if scenario == "configured" {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while runtime
                .terminal_payload_maintenance_health()
                .ticks_completed
                == 0
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let health = runtime.terminal_payload_maintenance_health();
            assert!(
                health.worker_running && health.ticks_completed > 0,
                "{health:?}"
            );
            assert_eq!(
                health.lifecycle,
                chio_control_plane::TerminalPayloadMaintenanceLifecycle::Ready
            );
            assert!(
                runtime
                    .shutdown_terminal_payload_maintenance()?
                    .worker_joined
            );
        } else {
            let health = runtime.terminal_payload_maintenance_health();
            assert_eq!(
                health.lifecycle,
                chio_control_plane::TerminalPayloadMaintenanceLifecycle::MissingConfiguration
            );
            assert!(!health.worker_running);
            assert_eq!(health.compacted, 0);
            assert_eq!(health.ticks_attempted, 0);
        }
        drop(runtime);
        let reopened = DurableAdmissionRuntime::open(&database)?;
        assert_eq!(
            reopened.terminal_payload_maintenance_health().lifecycle,
            chio_control_plane::TerminalPayloadMaintenanceLifecycle::MissingConfiguration
        );
        return Ok(());
    }
    let name=format!("{}::terminal_payload_maintenance_environment_starts_actual_owner_or_reports_missing_config",module_path!());
    let name = name
        .split_once("::")
        .map_or(name.as_str(), |(_, tail)| tail);
    for scenario in ["configured", "missing"] {
        let mut child = Command::new(std::env::current_exe()?);
        child
            .args(["--exact", name, "--nocapture"])
            .env(MARKER, scenario);
        if scenario == "configured" {
            child
                .env("CHIO_TERMINAL_RAW_PAYLOAD_TTL_SECS", "60")
                .env("CHIO_TERMINAL_RAW_PAYLOAD_MAINTENANCE_INTERVAL_SECS", "1");
        } else {
            child
                .env_remove("CHIO_TERMINAL_RAW_PAYLOAD_TTL_SECS")
                .env_remove("CHIO_TERMINAL_RAW_PAYLOAD_MAINTENANCE_INTERVAL_SECS");
        }
        let output = child.output()?;
        assert!(
            output.status.success(),
            "{scenario}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }
    Ok(())
}

#[test]
fn terminal_payload_maintenance_environment_refuses_before_opening_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    const MARKER: &str = "CHIO_PAYLOAD_MAINTENANCE_TEST_CHILD";
    if let Ok(scenario) = std::env::var(MARKER) {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let database = directory.path().join("must-not-be-created.db");
        let mode = if scenario == "disabled" {
            DurableAdmissionMode::Off
        } else {
            DurableAdmissionMode::All
        };
        let remote = (scenario == "remote").then_some("https://operator.example.test");
        let result = open_cli_durable_admission_runtime(
            mode,
            Some(&database),
            None,
            None,
            None,
            None,
            remote,
            Some("test-control-token"),
        );
        let error = match result {
            Ok(_) => panic!("maintenance configuration must refuse scenario {scenario} before opening authority"),
            Err(error) => error,
        };
        assert!(
            !database.exists(),
            "invalid retention configuration must not create a serving authority"
        );
        let report = error.report();
        assert_eq!(
            report.code,
            chio_errors::_generated::error_codes::CLI_OTHER.urn
        );
        let expected_message = match scenario.as_str() {
            "invalid" => "terminal raw payload maintenance TTL must be positive bounded integer seconds",
            "partial" => "terminal raw payload maintenance requires both TTL and interval environment variables",
            "disabled" => "terminal raw payload maintenance requires enabled durable admission",
            "remote" => "terminal raw payload maintenance for a remote authority belongs to its server owner",
            _ => return Err("unknown fixture scenario".into()),
        };
        assert_eq!(report.message, expected_message);
        if scenario == "invalid" {
            assert!(matches!(&error, CliError::RegisteredSource(_)));
            let source = std::error::Error::source(&error)
                .and_then(std::error::Error::source)
                .and_then(|source| source.downcast_ref::<std::num::ParseIntError>())
                .ok_or("integer parse cause missing")?;
            assert_eq!(source.kind(), &std::num::IntErrorKind::InvalidDigit);
        } else {
            assert!(matches!(&error, CliError::Chio(_)));
        }
        assert!(!format!("{error:?} {error} {report:?}").contains("PRIVATE_ENV_VALUE_CANARY"));
        return Ok(());
    }
    let own_name = format!(
        "{}::terminal_payload_maintenance_environment_refuses_before_opening_authority",
        module_path!()
    );
    let own_name = own_name
        .split_once("::")
        .map_or(own_name.as_str(), |(_, tail)| tail);
    for scenario in ["invalid", "partial", "disabled", "remote"] {
        let mut child = Command::new(std::env::current_exe()?);
        child
            .args(["--exact", own_name, "--nocapture"])
            .env(MARKER, scenario)
            .env(
                "CHIO_TERMINAL_RAW_PAYLOAD_TTL_SECS",
                if scenario == "invalid" {
                    "PRIVATE_ENV_VALUE_CANARY"
                } else {
                    "60"
                },
            );
        if scenario == "partial" {
            child.env_remove("CHIO_TERMINAL_RAW_PAYLOAD_MAINTENANCE_INTERVAL_SECS");
        } else {
            child.env("CHIO_TERMINAL_RAW_PAYLOAD_MAINTENANCE_INTERVAL_SECS", "1");
        }
        let output = child.output()?;
        assert!(
            output.status.success(),
            "{scenario}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "the isolated environment test must actually run"
        );
    }
    Ok(())
}
