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
        assert!(verify_native_flow_state(&tx, A).is_err());
        verify_native_flow_state(&tx, B)?;
        tx.rollback()?;
        Ok(())
    })
}
