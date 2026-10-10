//! Foreign protected-record admission keeps the native physical reserve.
use super::command_quotas::{
    prepared_provider_unknown, protected_usage, provider_finality_proof,
    require_live_quota_capability, QuotaTestDiagnostics,
};
use super::*;
use chio_store_sqlite::admission_operation_store::{
    fill_recovery_quota_fixture_intake_events, grow_recovery_quota_fixture_uncheckpointed_history,
    observe_recovery_quota_fixture_clock_work, retain_recovery_quota_fixture_records,
    RecoveryQuotaFixtureRecord,
};

// This exercises the real fenced generic protected writer; typed knowledge and
// semantic lifecycle authorization remain separate owning regressions.
#[tokio::test]
async fn recovery_foreign_intake_cannot_consume_native_physical_reserve() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let (fixture, workflow) = Box::pin(prepared_provider_unknown(&diagnostics)).await?;
    let result: TestResult = Box::pin(async {
        let reader = rusqlite::Connection::open_with_flags(
            fixture.path.join("admission.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        reader.execute_batch("BEGIN")?;
        let _: i64 = reader.query_row(
            "SELECT count(*) FROM admission_operation_recovery_events", [], |row| row.get(0),
        )?;
        let before = protected_usage(&fixture)?;
        diagnostics.phase("real unrelated WAL pressure remains below native settlement hard floor");
        let pressure = grow_recovery_quota_fixture_uncheckpointed_history(
            &fixture.authority.admission_operation_store(),
            &fixture.authority.mutation_fence(), 80 * 1024 * 1024,
        )?;
        assert!((80 * 1024 * 1024..128 * 1024 * 1024).contains(&pressure));
        assert_eq!(protected_usage(&fixture)?, before);
        require_live_quota_capability("current control capability", &fixture.control)?;
        let namespaces = ["semantic-capture", "knowledge-pin", "confined-boundary", "product-report", "protected-setup"];
        for family in namespaces {
            let record = RecoveryQuotaFixtureRecord {
                scope: fixture.runtime.scope().clone(),
                key: format!("{family}:quota-fixture:physical-intake-floor"),
                payload: chio_core::canonical_json_bytes(&serde_json::json!({"fixture":"foreign physical intake floor"}))?,
            };
            diagnostics.phase("foreign fresh protected-record intake preserves the native physical band");
            let refusal = retain_recovery_quota_fixture_records(
                &fixture.authority.admission_operation_store(),
                &fixture.authority.mutation_fence(), &[record],
            );
            assert_eq!(
                refusal.err(),
                Some(chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(
                    "recovery disk headroom exhausted".to_owned(),
                )),
                "{family} bypassed the physical intake floor",
            );
            assert_eq!(protected_usage(&fixture)?, before);
        }
        diagnostics.phase("already captured native finality remains usable in the reserved physical band");
        let settler = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(), &fixture.control, RecoveryPermission::Settle,
        )?;
        let lookup = fixture.kernel.reserve_recovery_provider_lookup(&settler, &workflow)?;
        let proof = provider_finality_proof(&fixture, &lookup)?;
        fixture.kernel.attach_recovery_provider_finality(&settler, &workflow, &proof)?;
        let settled = fixture.runtime.settle(&fixture.control, &workflow)?;
        assert!(settled.effect.is_settled());
        assert_eq!(external_count(&fixture.path)?, 1);
        reader.execute_batch("COMMIT")?;
        drop(reader);
        diagnostics.phase("production fresh-command checkpoint restores normal intake without operator truncation");
        let cancel = fixture.command(
            "fresh-control-restores-foreign-intake-after-reader",
            RecoveryCommandBodyV1::CancelWorkflow {
                workflow_id: workflow.clone(), expected_revision: fixture.record(&workflow)?.revision,
            },
        )?;
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(), &fixture.control, RecoveryPermission::Cancel,
        )?;
        fixture.kernel.execute_recovery_command(&actor, &cancel)?;
        let record = RecoveryQuotaFixtureRecord {
            scope: fixture.runtime.scope().clone(),
            key:"knowledge-pin:quota-fixture:physical-intake-floor".to_owned(),
            payload:chio_core::canonical_json_bytes(&serde_json::json!({"fixture":"foreign physical intake restored"}))?,
        };
        retain_recovery_quota_fixture_records(
            &fixture.authority.admission_operation_store(),
            &fixture.authority.mutation_fence(), &[record],
        )?;
        assert_eq!(external_count(&fixture.path)?, 1);
        Ok(())
    }).await;
    diagnostics.finish(Some(&fixture), result)
}

// The fixture authenticates protected history; it does not qualify the complete
// typed knowledge lifecycle or default-schema history filling throughput.
#[tokio::test]
async fn recovery_authority_clock_observation_has_bounded_work_after_retained_history() -> TestResult
{
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = Box::new(diagnostics.finish(None, RecoveryFixture::new(false))?);
    let result: TestResult = (|| {
        diagnostics.phase("owning clock observation before retained history growth");
        let first = observe_recovery_quota_fixture_clock_work(
            &fixture.authority.admission_operation_store(),
            &fixture.authority.mutation_fence(),
        )?;
        assert!(first.sampled_vm_steps <= 4096);
        let first_observed = first.observed_at?;
        diagnostics.phase("bounded authenticated foreign history with canonical schema restored");
        fill_recovery_quota_fixture_intake_events(
            &fixture.authority.admission_operation_store(),
            &fixture.authority.mutation_fence(),
            fixture.runtime.scope(),
            57344,
        )?;
        let before = protected_usage(&fixture)?;
        diagnostics
            .phase("clock observation remains bounded independently of retained event count");
        let measured = observe_recovery_quota_fixture_clock_work(
            &fixture.authority.admission_operation_store(),
            &fixture.authority.mutation_fence(),
        )?;
        eprintln!(
            "RECOVERY_AUTHORITY_CLOCK_WORK retained_events={} sampled_vm_steps={} observed_at={:?}",
            measured.retained_events, measured.sampled_vm_steps, measured.observed_at
        );
        assert!(measured.retained_events >= 57344);
        assert!(
            measured.sampled_vm_steps <= 4096,
            "authority clock exhausted its fixed SQLite work budget over retained history"
        );
        assert!(measured.observed_at? >= first_observed);
        assert_eq!(protected_usage(&fixture)?, before);
        assert_eq!(external_count(&fixture.path)?, 0);
        Ok(())
    })();
    diagnostics.finish(Some(&fixture), result)
}
