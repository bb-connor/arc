use super::*;

#[test]
fn verified_epochs_and_lineage_copy_never_borrow_another_authority() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let a = FlowMutation::native_for_test(&tx, A);
        let b = FlowMutation::native_for_test(&tx, B);
        let mut initial = request("initial")?;
        initial.principal_join = label("principal")?;
        initial.lineage_join = label("lineage-a")?;
        a.join(&initial)?;
        initial.lineage_join = label("lineage-b")?;
        b.join(&initial)?;
        let transition = IsolationEpochTransition {
            tenant_id: initial.key.tenant_id.clone(),
            principal_id: initial.key.principal_id.clone(),
            lineage_id: initial.key.lineage_id.clone(),
            previous_isolation_epoch_id: initial.key.isolation_epoch_id.clone(),
            new_isolation_epoch_id: IsolationEpochId::new("new-epoch")?,
            new_session_id: SessionId::new("new-session")?,
            verification_evidence_hash: Digest32::new([7; 32]),
            transition_id: RecordId::new("same-epoch-transition")?,
            effective_at_unix_ms: 1_000,
        };
        let verified_a = VerifiedIsolationEvidence {
            verifier_id: RecordId::new("verifier-a")?,
            receipt_ref: OpaqueReceiptRef::new("receipt-a")?,
        };
        let verified_b = VerifiedIsolationEvidence {
            verifier_id: RecordId::new("verifier-b")?,
            receipt_ref: OpaqueReceiptRef::new("receipt-b")?,
        };
        let opened_a = a.open_isolation_epoch(&transition, &verified_a)?;
        let opened_b = b.open_isolation_epoch(&transition, &verified_b)?;
        assert_eq!(opened_a.principal_label, InformationLabel::bottom());
        assert_eq!(opened_b.principal_label, InformationLabel::bottom());
        assert_eq!(opened_a.session_label, label("lineage-a")?);
        assert_eq!(opened_b.session_label, label("lineage-b")?);
        assert_eq!(a.open_isolation_epoch(&transition, &verified_a)?, opened_a);
        assert_eq!(b.open_isolation_epoch(&transition, &verified_b)?, opened_b);

        let mut extend = request("same-copy-transition")?;
        extend.key = opened_a.key.clone();
        extend.key.lineage_id = LineageId::new("extended-lineage")?;
        a.join(&extend)?;
        b.join(&extend)?;
        for (authority, receipt) in [(A, "receipt-a"), (B, "receipt-b")] {
            let stored: String = tx.query_row("SELECT evidence_receipt_ref FROM security_participant_state_isolation_epochs WHERE security_authority_id = ?1 AND lineage_id = 'extended-lineage'", [authority], |row| row.get(0))?;
            assert_eq!(stored, receipt);
            verify_native_flow_state(&tx, authority)?;
        }
        // A principal with a prior epoch cannot acquire a fresh bootstrap epoch.
        extend.transition_id = RecordId::new("unverified-epoch")?;
        extend.key.isolation_epoch_id = IsolationEpochId::new("unverified")?;
        assert!(a.join(&extend).is_err());
        assert!(b.join(&extend).is_err());
        tx.rollback()?;
        Ok(())
    })
}

#[test]
fn native_reader_cannot_fill_missing_principal_from_colliding_authority() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let join = request("initial")?;
        FlowMutation::native_for_test(&tx, A).join(&join)?;
        FlowMutation::native_for_test(&tx, B).join(&join)?;
        tx.execute("DELETE FROM security_participant_state_principal_flow_state WHERE security_authority_id = ?1", [A])?;
        assert!(load_scoped_flow_snapshot(FlowReader::native(&tx, A), &join.key).is_err());
        assert!(load_observed_flow_snapshot(FlowReader::native(&tx, A), &join.key).is_err());
        assert!(verify_native_flow_state(&tx, A).is_err());
        verify_native_flow_state(&tx, B)?;
        tx.rollback()?;
        Ok(())
    })
}

#[test]
fn native_inherited_observation_requires_its_own_epoch_and_never_creates_context() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut first = request("first-inherited-source")?;
        first.principal_join = label("principal")?;
        let original = FlowMutation::native_for_test(&tx, A).join(&first)?;
        let mut second = first.key.clone();
        second.lineage_id = LineageId::new("new-authenticated-lineage")?;
        let before = tx.total_changes();
        assert!(!isolation_epoch_exists(
            FlowReader::native(&tx, A),
            &second
        )?);
        assert_eq!(
            load_context_generation(FlowReader::native(&tx, A), &second)?,
            None
        );
        let inherited = load_observed_flow_snapshot(FlowReader::native(&tx, A), &second)?
            .ok_or("inherited source absent")?;
        assert_eq!(inherited.principal_label, original.principal_label);
        assert_eq!(inherited.lineage_label, InformationLabel::bottom());
        assert_eq!(inherited.session_label, original.session_label);
        assert_eq!(inherited.context_generation, original.context_generation);
        assert_eq!(
            load_observed_flow_snapshot(FlowReader::native(&tx, B), &second)?,
            None
        );
        assert_eq!(
            load_context_generation(FlowReader::native(&tx, A), &second)?,
            None
        );
        assert!(!isolation_epoch_exists(
            FlowReader::native(&tx, A),
            &second
        )?);
        assert_eq!(tx.total_changes(), before);
        // The strict custody reader still refuses an unjoined lineage. A
        // conservative observation cannot authorize egress or create a fence.
        assert!(load_scoped_flow_snapshot(FlowReader::native(&tx, A), &second).is_err());
        verify_native_flow_state(&tx, A)?;
        tx.rollback()?;
        Ok(())
    })
}
