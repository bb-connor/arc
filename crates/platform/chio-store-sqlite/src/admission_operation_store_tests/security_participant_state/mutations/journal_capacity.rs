use super::*;

#[test]
fn native_journal_capacity_resumes_after_operator_checkpoint() -> TestResult {
    let _fixture_clock = chio_test_support::clock::scope_unix_secs(now_ms().div_ceil(1_000));
    native::with_test_journal_bounds(2, 67_108_864, || {
        let fixture = fixture();
        let source = imported(&fixture, "source")?;
        let initialized = hydrate(&fixture, &source)?;
        let (mut context, _) = request("capacity-initial")?;
        for index in 0..2 {
            let name = format!("capacity-operation-{index}");
            let (_, join) = request(&format!("capacity-join-{index}"))?;
            let (operation, lease) = setup(&fixture, &name, &context)?;
            let result = fixture.store.join_security_participant_flow(
                &operation,
                &lease,
                &initialized,
                &context,
                &join,
                now_ms(),
            )?;
            context = SecurityInvocationContext::v1(
                context
                    .as_v1()
                    .clone()
                    .with_flow_state_generation(result.context_generation),
            );
        }
        let before = {
            let connection = fixture.store.connection()?;
            let mut statement = connection.prepare("SELECT canonical_record FROM security_participant_state_mutations ORDER BY sequence")?;
            let rows = statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let (_, join) = request("capacity-join-2")?;
        let (operation, lease) = setup(&fixture, "capacity-operation-2", &context)?;
        let denied = fixture.store.join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &join,
            now_ms(),
        );
        assert!(denied.as_ref().is_err_and(|error| error
            .to_string()
            .contains("combined native journal exceeds bounds")));
        assert_eq!(count(&fixture)?, 2);
        let checkpoint = fixture.store.checkpoint_security_participant_history(
            &initialized,
            &fixture.fence,
            now_ms(),
        )?;
        assert_eq!(
            fixture.store.checkpoint_security_participant_history(
                &initialized,
                &fixture.fence,
                now_ms()
            )?,
            checkpoint
        );
        fixture.store.join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &join,
            now_ms(),
        )?;
        assert_eq!(count(&fixture)?, 3);
        let connection = fixture.store.connection()?;
        let mut statement = connection.prepare("SELECT canonical_record FROM security_participant_state_mutations WHERE sequence <= 3 ORDER BY sequence")?;
        assert_eq!(
            statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?,
            before
        );
        drop(statement);
        drop(connection);
        assert_eq!(
            fixture.store.load_security_participant_state(
                initialized.security_authority_id(),
                &fixture.fence,
                now_ms()
            )?,
            Some(initialized)
        );
        Ok(())
    })
}
