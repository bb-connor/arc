use super::*;
use crate::{LocalTerminalPayloadMaintenance, TerminalPayloadMaintenanceConfig};

pub(super) fn validate_requested_authority(
    joint_authority_path: Option<&Path>,
    config: Option<TerminalPayloadMaintenanceConfig>,
) -> Result<(), CliError> {
    if let Some(config) = config {
        config.validate().map_err(|source| {
            CliError::with_public_source(
                &chio_errors::_generated::error_codes::CLI_OTHER,
                "terminal raw payload maintenance server configuration is invalid",
                source,
            )
        })?;
        if joint_authority_path.is_none() {
            return Err(CliError::cli_other_error(
                "terminal raw payload maintenance requires the configured joint serving authority",
            ));
        }
    }
    Ok(())
}

pub(super) fn start_on_existing_authority(
    authority: Option<&Arc<SqliteAuthorityStore>>,
    config: Option<TerminalPayloadMaintenanceConfig>,
) -> Result<Option<LocalTerminalPayloadMaintenance>, CliError> {
    let Some(config) = config else {
        tracing::warn!("terminal raw payload maintenance is disabled on the server because operator TTL and interval are missing");
        return Ok(None);
    };
    let authority = authority.ok_or_else(|| {
        CliError::cli_other_error(
            "terminal raw payload maintenance has no existing joint serving authority",
        )
    })?;
    let owner =
        LocalTerminalPayloadMaintenance::start(authority.clone(), config).map_err(|source| {
            CliError::with_public_source(
                &chio_errors::_generated::error_codes::CLI_OTHER,
                "terminal raw payload maintenance server worker could not start",
                source,
            )
        })?;
    tracing::info!(
        ttl_seconds = config.terminal_raw_payload_ttl.as_secs(),
        interval_seconds = config.interval.as_secs(),
        "server-owned terminal raw payload maintenance configured for supported local value calls"
    );
    Ok(Some(owner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_admission::payload_maintenance_tests::{
        configured_kernel, raw_payload_present, receipt_operation, request_with_credentials,
    };
    use chio_kernel::tool_outcome::ToolOutcomeStore;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn server_payload_maintenance_requires_explicit_existing_authority(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(start_on_existing_authority(None, None)?.is_none());
        let config =
            crate::TerminalPayloadMaintenanceConfig::from_operator_values(Some("10"), Some("1"))?
                .ok_or("missing explicit config")?;
        let error = validate_requested_authority(None, Some(config))
            .err()
            .ok_or("configured server requires authority")?;
        assert!(matches!(&error, CliError::Chio(_)));
        assert_eq!(
            error.report().code,
            chio_errors::_generated::error_codes::CLI_OTHER.urn
        );
        assert_eq!(
            error.report().message,
            "terminal raw payload maintenance requires the configured joint serving authority"
        );
        let error = start_on_existing_authority(None, Some(config))
            .err()
            .ok_or("configured worker requires existing authority")?;
        assert!(matches!(&error, CliError::Chio(_)));
        assert_eq!(
            error.report().code,
            chio_errors::_generated::error_codes::CLI_OTHER.urn
        );
        assert_eq!(
            error.report().message,
            "terminal raw payload maintenance has no existing joint serving authority"
        );
        Ok(())
    }

    #[test]
    fn server_payload_maintenance_uses_existing_clock_and_joins_before_restart(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let initial = chio_test_support::clock::unix_seconds();
        let _time = chio_test_support::clock::scope_unix_secs(initial);
        let directory = crate::durable_admission::private_tempdir()?;
        let database = directory.path().join("server-owner.db");
        let runtime = crate::DurableAdmissionRuntime::open_with_clock(
            &database,
            chio_test_support::clock::clock(),
        )?;
        let authority = runtime.local_authority_store().ok_or("missing authority")?;
        let calls = Arc::new(AtomicU64::new(0));
        let kernel = configured_kernel(&runtime, calls.clone())?;
        let request = request_with_credentials(&kernel, &runtime.kernel_keypair(), "server-owner")?;
        let response = kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(
            response.verdict,
            chio_kernel::Verdict::Allow,
            "{:?}",
            response.reason
        );
        let operation = receipt_operation(&response.receipt)?;
        let outcome = authority
            .tool_outcome_store()
            .lookup_by_operation(&operation.operation_id)?
            .ok_or("missing outcome")?;
        let digest = outcome.raw_output_digest().as_str().to_owned();
        let config = TerminalPayloadMaintenanceConfig {
            terminal_raw_payload_ttl: Duration::from_secs(10),
            interval: Duration::from_millis(10),
            page_limits: chio_store_sqlite::ToolOutcomeCompactionLimits::default(),
        };
        let owner =
            start_on_existing_authority(Some(&authority), Some(config))?.ok_or("missing owner")?;
        assert_eq!(
            runtime.terminal_payload_maintenance_health().lifecycle,
            crate::TerminalPayloadMaintenanceLifecycle::MissingConfiguration
        );
        let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
        let deadline = Instant::now() + Duration::from_secs(3);
        while raw_payload_present(&database, &digest)? && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !raw_payload_present(&database, &digest)?,
            "server worker must use the existing authority's injected clock"
        );
        let stopped = owner.shutdown()?;
        assert!(stopped.worker_joined);
        assert!(!stopped.worker_running);
        assert_eq!(stopped.failures, 0);
        drop(owner);
        drop(kernel);
        drop(authority);
        drop(runtime);
        let reopened = crate::DurableAdmissionRuntime::open_with_clock(
            &database,
            chio_test_support::clock::clock(),
        )?;
        let recovered = configured_kernel(&reopened, calls.clone())?;
        let replay = recovered.evaluate_tool_call_blocking(&request)?;
        assert_eq!(replay.receipt.id, response.receipt.id);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn server_payload_maintenance_preserves_failure_health_through_shutdown(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = crate::durable_admission::private_tempdir()?;
        let database = directory.path().join("server-budget.db");
        let runtime = crate::DurableAdmissionRuntime::open_with_clock(
            &database,
            chio_test_support::clock::clock(),
        )?;
        let authority = runtime.local_authority_store().ok_or("missing authority")?;
        let mut config =
            TerminalPayloadMaintenanceConfig::from_operator_values(Some("10"), Some("1"))?
                .ok_or("config")?;
        config.interval = Duration::from_millis(10);
        config.page_limits.max_sql_steps = 1;
        let owner = start_on_existing_authority(Some(&authority), Some(config))?.ok_or("owner")?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while owner.health().failures == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let stopped = owner.shutdown()?;
        assert!(stopped.failures > 0);
        assert!(stopped
            .last_failure
            .as_deref()
            .is_some_and(|error| error.contains("SQL work budget")));
        assert!(stopped.worker_joined);
        assert!(!stopped.worker_running);
        Ok(())
    }
}
