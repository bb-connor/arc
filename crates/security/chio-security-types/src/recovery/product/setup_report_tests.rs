use super::*;

type TestResult = Result<(), ContractError>;

fn report(qualified_at: u64) -> Result<RecoverySetupReportV1, ContractError> {
    Ok(RecoverySetupReportV1 {
        domain_version: VersionV1,
        probe: RecoverySetupProbeV1 {
            domain_version: VersionV1,
            scope: RecoveryScopeV1 {
                authority_domain: AuthorityDomainId::new("report-authority")?,
                tenant_id: RecoveryTenantId::new("report-tenant")?,
                process_id: ProcessId::new("report-process")?,
            },
            probe_id: ChallengeId::new("report-probe")?,
            native_authority: SourceDigest::from_bytes([1; 32]),
            deployment: DeploymentDigest::from_bytes([2; 32]),
            source_profile: SourceDigest::from_bytes([3; 32]),
            required_coverage: CoverageDigest::from_bytes([4; 32]),
            benign_workflow: WorkflowId::new("report-workflow")?,
            denied_command: CommandId::new("report-denied")?,
            issued_at_unix_ms: SafeInteger::new(1_000)?,
            expires_at_unix_ms: SafeInteger::new(2_000)?,
        },
        benign_operation: OperationId::new("report-operation")?,
        benign_receipt: SourceDigest::from_bytes([5; 32]),
        denied_command_digest: CommandDigest::from_bytes([6; 32]),
        previous_serving_fence: SourceDigest::from_bytes([7; 32]),
        current_serving_fence: SourceDigest::from_bytes([8; 32]),
        qualified_at_unix_ms: SafeInteger::new(qualified_at)?,
    })
}

#[test]
fn setup_writer_reattestation_may_outlive_the_initial_probe() -> TestResult {
    // Native custody must decide whether an initial report was already accepted.
    // Structural report validation must permit a later writer to re-attest it.
    report(3_000)?.validate()?;
    Ok(())
}

#[test]
fn setup_report_still_requires_ordered_time_and_a_different_writer() -> TestResult {
    assert!(report(999)?.validate().is_err());
    let mut same_writer = report(1_500)?;
    same_writer.current_serving_fence = same_writer.previous_serving_fence;
    assert!(same_writer.validate().is_err());
    report(1_500)?.validate()?;
    Ok(())
}
