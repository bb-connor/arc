use super::*;

#[test]
fn stale_decision_time_cannot_apply_expired_assignment_authority() -> AnchoredTestResult {
    for expiry in [Expiry::Authorization, Expiry::Request, Expiry::Offer] {
        let fixture = fixture();
        let base = now_ms() / 1_000 * 1_000;
        let _clock =
            chio_kernel::scope_fixed_runtime_for_current_thread(base / 1_000, std::iter::empty());
        let receivable = persist_receivable(&fixture, AUTHORITY_A, "delayed-assignment", base)?;
        let factor_store = fixture.store.activate_factor_assignment_authorities(
            registry(&[AUTHORITY_A], &[])?,
            0,
            &fixture.fence,
            base + 1,
        )?;
        let mut times = FactorTimes::new(base + 2, base + 5, Expiry::Live);
        match expiry {
            Expiry::Authorization => times.authorization_expires = base + 1_000,
            Expiry::Request => times.request_expires = base + 1_000,
            Expiry::Offer => times.offer_expires = base + 1_000,
            Expiry::Live => unreachable!("only expiring authority fixtures are selected"),
        }
        let case = FactorCase::new(
            &fixture,
            &receivable,
            AUTHORITY_A,
            "delayed-assignment",
            times,
        )?;
        let recovery = case.recovery(
            &fixture.store,
            &fixture.fence,
            "delayed-worker",
            case.commit_at,
        )?;
        let _expired = chio_kernel::scope_fixed_runtime_for_current_thread(
            base / 1_000 + 1,
            std::iter::empty(),
        );
        let error = case
            .commit(&factor_store, &recovery, &fixture.fence, case.commit_at)
            .expect_err("delayed assignment used expired authority");
        assert!(
            error
                .to_string()
                .contains("expired before authority commit"),
            "{error}"
        );
        assert!(factor_store
            .load_factor_assignment_result(case.operation.binding().operation_id())?
            .is_none());
        assert_eq!(
            fixture
                .store
                .load_obligation(receivable.atom.obligation_id())?
                .ok_or("obligation disappeared")?
                .head_sequence(),
            1
        );
    }
    Ok(())
}
