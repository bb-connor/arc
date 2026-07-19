    #[test]
    fn bound_apply_rolls_back_authoritative_mutation_before_result_persistence() {
        let database_path = path("atomic-apply-rollback");
        drop(open_capture_authority(&test_config(&database_path)).expect("initialize authority"));
        let genesis =
            capture_admission_genesis_projection(&database_path).expect("capture genesis");
        let membership = AdmissionMembership::new_with_genesis(
            vec!["https://node-a".to_string(), "https://node-b".to_string()],
            genesis,
        )
        .expect("membership");
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus store");
        store.bind_membership(&membership).expect("bind membership");
        let election = store
            .begin_election(&membership, "https://node-a")
            .expect("election");
        let entry = entry(&election, "atomic-apply-rollback");
        store.append_local(&election, &entry).expect("append");
        let commit_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: election.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };

        let error = store
            .commit_local(
                &membership,
                &election,
                &commit_proof,
                |transaction, _, _| {
                    SqliteAdmissionCaptureAuthority::upsert_revocation_in_transaction(
                        transaction,
                        &RevocationRecord {
                            capability_id: "capability-atomic-rollback".to_string(),
                            revoked_at: 1,
                        },
                    )
                    .map_err(|error| error.to_string())?;
                    Err("injected failure before result persistence".to_string())
                },
            )
            .expect_err("apply failure");
        assert!(error.to_string().contains("injected failure"));
        let connection = Connection::open(&database_path).expect("inspect database");
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM revoked_capabilities WHERE capability_id = ?1",
                params!["capability-atomic-rollback"],
                |row| row.get(0),
            )
            .expect("rolled-back row count");
        assert_eq!(count, 0);
        assert_eq!(store.meta().expect("meta").commit_index, 1);
        assert_eq!(store.meta().expect("meta").last_applied, 0);
        assert!(store
            .result_for_operation("atomic-apply-rollback")
            .expect("result lookup")
            .is_none());
        store
            .validate_integrity()
            .expect("rolled-back unapplied state is valid");

        store
            .apply_committed(&mut |transaction, _, _| {
                SqliteAdmissionCaptureAuthority::upsert_revocation_in_transaction(
                    transaction,
                    &RevocationRecord {
                        capability_id: "capability-atomic-rollback".to_string(),
                        revoked_at: 1,
                    },
                )
                .map_err(|error| error.to_string())?;
                Ok("{\"applied\":true}".to_string())
            })
            .expect("replay apply");
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM revoked_capabilities WHERE capability_id = ?1",
                params!["capability-atomic-rollback"],
                |row| row.get(0),
            )
            .expect("committed row count");
        assert_eq!(count, 1);
        assert_eq!(store.meta().expect("meta").last_applied, 1);
        assert!(store
            .result_for_operation("atomic-apply-rollback")
            .expect("result lookup")
            .is_some());
        store.validate_integrity().expect("atomic replay is valid");

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn authenticated_result_mismatch_rolls_back_successful_authoritative_mutation() {
        let source_path = path("atomic-expected-source");
        let target_path = path("atomic-expected-target");
        for database_path in [&source_path, &target_path] {
            drop(
                open_capture_authority(&test_config(database_path)).expect("initialize authority"),
            );
        }
        let genesis = capture_admission_genesis_projection(&source_path).expect("source genesis");
        assert_eq!(
            capture_admission_genesis_projection(&target_path).expect("target genesis"),
            genesis
        );
        let membership = AdmissionMembership::new_with_genesis(
            vec!["https://node-a".to_string(), "https://node-b".to_string()],
            genesis,
        )
        .expect("membership");
        let source = AdmissionConsensusStore::open(&source_path).expect("source store");
        source.bind_membership(&membership).expect("bind source");
        let election = source
            .begin_election(&membership, "https://node-a")
            .expect("source election");
        let entry = entry(&election, "atomic-authenticated-mismatch");
        source
            .append_local(&election, &entry)
            .expect("source append");
        let commit_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: election.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };
        source
            .commit_local(
                &membership,
                &election,
                &commit_proof,
                |transaction, _, _| {
                    SqliteAdmissionCaptureAuthority::upsert_revocation_in_transaction(
                        transaction,
                        &RevocationRecord {
                            capability_id: "capability-authenticated-mismatch".to_string(),
                            revoked_at: 1,
                        },
                    )
                    .map_err(|error| error.to_string())?;
                    Ok("{\"source\":true}".to_string())
                },
            )
            .expect("source commit");
        let snapshot = source.snapshot().expect("authenticated snapshot");

        let target = AdmissionConsensusStore::open(&target_path).expect("target store");
        target.bind_membership(&membership).expect("bind target");
        let before = target.snapshot().expect("target before install");
        let error = target
            .install_snapshot(&membership, &snapshot, |transaction, _, _| {
                SqliteAdmissionCaptureAuthority::upsert_revocation_in_transaction(
                    transaction,
                    &RevocationRecord {
                        capability_id: "capability-authenticated-mismatch".to_string(),
                        revoked_at: 1,
                    },
                )
                .map_err(|error| error.to_string())?;
                Ok("{\"target\":true}".to_string())
            })
            .expect_err("authenticated replay mismatch");
        assert!(error.to_string().contains("authenticated snapshot"));
        let connection = Connection::open(&target_path).expect("inspect target");
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM revoked_capabilities WHERE capability_id = ?1",
                params!["capability-authenticated-mismatch"],
                |row| row.get(0),
            )
            .expect("rolled-back mutation count");
        assert_eq!(count, 0);
        let meta = target.meta().expect("target meta");
        assert_eq!(meta.current_term, snapshot.meta.current_term);
        assert_eq!(meta.voted_for, None);
        assert_eq!(meta.commit_index, 0);
        assert_eq!(meta.last_applied, 0);
        assert!(target
            .result_for_operation("atomic-authenticated-mismatch")
            .expect("result lookup")
            .is_none());
        target
            .validate_integrity()
            .expect("mismatched replay left no projection drift");
        drop(connection);
        drop(target);

        let reopened = AdmissionConsensusStore::open(&target_path).expect("reopen target");
        let mut expected = before;
        expected.meta.current_term = snapshot.meta.current_term;
        expected.meta.voted_for = None;
        assert_eq!(reopened.snapshot().expect("target after restart"), expected);
        let replayed = AtomicUsize::new(0);
        assert_eq!(
            reopened
                .apply_committed(&mut |_, _, _| {
                    replayed.fetch_add(1, Ordering::SeqCst);
                    Ok("{\"unexpected\":true}".to_string())
                })
                .expect("plain replay after restart"),
            0
        );
        assert_eq!(replayed.load(Ordering::SeqCst), 0);

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn concurrent_unrelated_projection_write_cannot_be_blessed() {
        let database_path = path("atomic-apply-concurrent-write");
        drop(open_capture_authority(&test_config(&database_path)).expect("initialize authority"));
        let genesis =
            capture_admission_genesis_projection(&database_path).expect("capture genesis");
        let membership = AdmissionMembership::new_with_genesis(
            vec!["https://node-a".to_string(), "https://node-b".to_string()],
            genesis,
        )
        .expect("membership");
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus store");
        store.bind_membership(&membership).expect("bind membership");
        let election = store
            .begin_election(&membership, "https://node-a")
            .expect("election");
        let entry = entry(&election, "atomic-apply-concurrent-write");
        store.append_local(&election, &entry).expect("append");
        let commit_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: election.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };

        store
            .commit_local(&membership, &election, &commit_proof, |_, _, _| {
                let path = database_path.clone();
                let write = std::thread::spawn(move || {
                    let connection = Connection::open(path)?;
                    connection.busy_timeout(std::time::Duration::from_millis(50))?;
                    connection.execute(
                        r#"
                            INSERT INTO capability_grant_budgets (
                                capability_id, grant_index, invocation_count,
                                updated_at, seq, total_cost_exposed,
                                total_cost_realized_spend
                            ) VALUES (?1, 0, 1, 1, 1, 0, 0)
                            "#,
                        params!["capability-concurrent-drift"],
                    )
                })
                .join()
                .expect("concurrent writer thread");
                assert!(matches!(
                    write,
                    Err(rusqlite::Error::SqliteFailure(ref failure, _))
                        if matches!(
                            failure.code,
                            rusqlite::ErrorCode::DatabaseBusy
                                | rusqlite::ErrorCode::DatabaseLocked
                        )
                ));
                Ok("{\"applied\":true}".to_string())
            })
            .expect("atomic commit");

        let connection = Connection::open(&database_path).expect("inspect database");
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM capability_grant_budgets WHERE capability_id = ?1",
                params!["capability-concurrent-drift"],
                |row| row.get(0),
            )
            .expect("unrelated row count");
        assert_eq!(count, 0);
        assert_eq!(store.meta().expect("meta").last_applied, 1);
        store
            .validate_integrity()
            .expect("concurrent write was not blessed");

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn live_security_projection_drift_is_rejected_but_timestamp_drift_is_ignored() {
        let database_path = path("bound-genesis-integrity");
        drop(open_capture_authority(&test_config(&database_path)).expect("initialize authority"));
        let genesis =
            capture_admission_genesis_projection(&database_path).expect("capture genesis");
        let membership = AdmissionMembership::new_with_genesis(
            vec!["https://node-a".to_string(), "https://node-b".to_string()],
            genesis,
        )
        .expect("membership");
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus store");
        store.bind_membership(&membership).expect("bind membership");

        let election = store
            .begin_election(&membership, "https://node-a")
            .expect("election");
        let entry = entry(&election, "post-genesis-operation");
        store.append_local(&election, &entry).expect("append");
        let commit_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: election.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };
        store
            .commit_local(
                &membership,
                &election,
                &commit_proof,
                |transaction, _, _| {
                    transaction
                        .execute(
                            r#"
                        INSERT INTO capability_grant_budgets (
                            capability_id, grant_index, invocation_count,
                            updated_at, seq, total_cost_exposed,
                            total_cost_realized_spend
                        ) VALUES (?1, 0, 2, 1, 1, 0, 0)
                        "#,
                            params!["capability-after-genesis"],
                        )
                        .map_err(|error| error.to_string())?;
                    Ok("{\"applied\":true}".to_string())
                },
            )
            .expect("commit post-genesis mutation");
        store
            .validate_integrity()
            .expect("consensus-applied projection is valid");

        let tamper = Connection::open(&database_path).expect("tamper connection");
        tamper
            .execute(
                r#"
                UPDATE capability_grant_budgets
                SET updated_at = updated_at + 100
                WHERE capability_id = 'capability-after-genesis'
                "#,
                [],
            )
            .expect("change nondeterministic timestamp");
        store
            .validate_integrity()
            .expect("timestamp-only drift is outside the security projection");
        tamper
            .execute(
                r#"
                UPDATE capability_grant_budgets
                SET invocation_count = invocation_count + 1
                WHERE capability_id = 'capability-after-genesis'
                "#,
                [],
            )
            .expect("tamper security projection");
        assert!(matches!(
            store.validate_integrity(),
            Err(AdmissionConsensusError::Protocol(message))
                if message.contains("security projection")
        ));

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn bound_genesis_record_is_revalidated() {
        let database_path = path("bound-genesis-record-integrity");
        drop(open_capture_authority(&test_config(&database_path)).expect("initialize authority"));
        let genesis =
            capture_admission_genesis_projection(&database_path).expect("capture genesis");
        let membership = AdmissionMembership::new_with_genesis(
            vec!["https://node-a".to_string(), "https://node-b".to_string()],
            genesis,
        )
        .expect("membership");
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus store");
        store.bind_membership(&membership).expect("bind membership");

        Connection::open(&database_path)
            .expect("tamper connection")
            .execute(
                "UPDATE admission_consensus_genesis SET projection_json = '{}' WHERE singleton = 1",
                [],
            )
            .expect("tamper persisted genesis");
        assert!(store.validate_integrity().is_err());

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn quorum_loss_after_election_leaves_projections_unchanged() {
        let a_path = path("quorum-loss-a");
        let b_path = path("quorum-loss-b");
        let a = AdmissionConsensusStore::open(&a_path).expect("a");
        let b = AdmissionConsensusStore::open(&b_path).expect("b");
        let election = a
            .begin_election(&membership(), "https://node-a")
            .expect("election");
        assert!(
            b.request_vote(
                &membership(),
                &AdmissionRequestVoteRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: election.term,
                    candidate_id: election.candidate_id.clone(),
                    last_log_index: election.last_log_index,
                    last_log_term: election.last_log_term,
                    commit_index: election.commit_index,
                }
            )
            .expect("vote")
            .vote_granted
        );
        let entry = entry(&election, "operation-quorum-loss");
        a.append_local(&election, &entry).expect("local append");
        let applied = AtomicUsize::new(0);
        let invalid_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership().digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: election.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec![election.candidate_id.clone()],
        };
        assert!(a
            .commit_local(&membership(), &election, &invalid_proof, |_, _, _| {
                applied.fetch_add(1, Ordering::SeqCst);
                Ok("{\"ok\":true}".to_string())
            })
            .is_err());
        let outsider_proof = AdmissionCommitProof {
            witness_urls: vec![election.candidate_id.clone(), "https://node-c".to_string()],
            ..invalid_proof
        };
        assert!(a
            .commit_local(&membership(), &election, &outsider_proof, |_, _, _| {
                applied.fetch_add(1, Ordering::SeqCst);
                Ok("{\"ok\":true}".to_string())
            })
            .is_err());
        assert_eq!(a.meta().expect("meta").commit_index, 0);
        assert_eq!(a.meta().expect("meta").last_applied, 0);
        assert_eq!(applied.load(Ordering::SeqCst), 0);

        let _ = std::fs::remove_file(a_path);
        let _ = std::fs::remove_file(b_path);
    }

    #[test]
    fn leader_change_requires_a_current_term_entry_before_committing_the_replicated_tail() {
        let a_path = path("leader-change-a");
        let b_path = path("leader-change-b");
        let a = AdmissionConsensusStore::open(&a_path).expect("a");
        let b = AdmissionConsensusStore::open(&b_path).expect("b");
        let first = a
            .begin_election(&membership(), "https://node-a")
            .expect("first election");
        let old_entry = entry(&first, "operation-old-uncommitted");
        a.append_local(&first, &old_entry)
            .expect("append old locally");
        assert!(
            b.append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: first.term,
                    leader_id: first.candidate_id.clone(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(old_entry.clone()),
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{\"old\":true}".to_string()),
            )
            .expect("replicate old")
            .accepted
        );

        let second = b
            .begin_election(&membership(), "https://node-b")
            .expect("second election");
        assert!(
            a.request_vote(
                &membership(),
                &AdmissionRequestVoteRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: second.term,
                    candidate_id: second.candidate_id.clone(),
                    last_log_index: second.last_log_index,
                    last_log_term: second.last_log_term,
                    commit_index: second.commit_index,
                }
            )
            .expect("a votes b")
            .vote_granted
        );
        let old_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership().digest().to_string(),
            index: old_entry.index,
            leader_epoch: second.term,
            current_term_commit_index: old_entry.index,
            leader_id: second.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };
        assert!(b
            .commit_local(&membership(), &second, &old_proof, |_, _, _| {
                Ok("{\"old\":true}".to_string())
            })
            .is_err());
        assert_eq!(b.meta().expect("uncommitted meta").commit_index, 0);

        let new_entry = AdmissionConsensusStore::build_entry(
            &second,
            "operation-new-leader",
            AdmissionCommandKind::Revoke,
            &serde_json::json!({"capabilityId":"capability-new","revokedAt":9}),
        )
        .expect("new entry");
        b.append_local(&second, &new_entry).expect("append new");
        let replace = AdmissionAppendEntriesRequest {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership().digest().to_string(),
            term: second.term,
            leader_id: second.candidate_id.clone(),
            previous_log_index: old_entry.index,
            previous_log_term: old_entry.leader_epoch,
            entry: Some(new_entry.clone()),
            leader_commit: 0,
            commit_proof: None,
        };
        assert!(
            a.append_entries(&membership(), &replace, |_, _, _| Ok(
                "{\"new\":true}".to_string()
            ))
            .expect("replace tail")
            .accepted
        );
        let old_proof = AdmissionCommitProof {
            current_term_commit_index: new_entry.index,
            ..old_proof
        };
        b.commit_local(&membership(), &second, &old_proof, |_, _, _| {
            Ok("{\"old\":true}".to_string())
        })
        .expect("commit inherited entry after current-term replication");
        assert!(
            a.append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: second.term,
                    leader_id: second.candidate_id.clone(),
                    previous_log_index: new_entry.index,
                    previous_log_term: new_entry.leader_epoch,
                    entry: None,
                    leader_commit: old_entry.index,
                    commit_proof: Some(old_proof),
                },
                |_, _, _| Ok("{\"old\":true}".to_string()),
            )
            .expect("apply inherited entry after current-term replication")
            .accepted
        );
        let proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership().digest().to_string(),
            index: new_entry.index,
            leader_epoch: new_entry.leader_epoch,
            current_term_commit_index: new_entry.index,
            leader_id: second.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };
        b.commit_local(&membership(), &second, &proof, |_, _, _| {
            Ok("{\"new\":true}".to_string())
        })
        .expect("commit new");
        assert!(
            a.append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: second.term,
                    leader_id: second.candidate_id.clone(),
                    previous_log_index: new_entry.index,
                    previous_log_term: new_entry.leader_epoch,
                    entry: None,
                    leader_commit: new_entry.index,
                    commit_proof: Some(proof),
                },
                |_, _, _| Ok("{\"new\":true}".to_string()),
            )
            .expect("apply new")
            .accepted
        );
        assert!(a
            .result_for_operation("operation-old-uncommitted")
            .expect("old result")
            .is_some());
        assert!(b
            .result_for_operation("operation-old-uncommitted")
            .expect("old result")
            .is_some());
        assert!(a
            .result_for_operation("operation-new-leader")
            .expect("new result")
            .is_some());

        let _ = std::fs::remove_file(a_path);
        let _ = std::fs::remove_file(b_path);
    }

    #[test]
    fn new_leader_relays_historical_commit_proofs_to_a_lagging_follower() {
        let source_path = path("historical-proof-source");
        let follower_path = path("historical-proof-follower");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        let follower = AdmissionConsensusStore::open(&follower_path).expect("follower");
        let membership = three_member_membership();

        let first = source
            .begin_election(&membership, "https://node-a")
            .expect("first election");
        let old_entry = entry(&first, "operation-historical-proof");
        source.append_local(&first, &old_entry).expect("old append");
        let old_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: old_entry.index,
            leader_epoch: first.term,
            current_term_commit_index: old_entry.index,
            leader_id: first.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };
        source
            .commit_local(&membership, &first, &old_proof, |_, _, _| {
                Ok("{\"old\":true}".to_string())
            })
            .expect("old commit");

        let second = source
            .begin_election(&membership, "https://node-b")
            .expect("second election");
        let current_entry = entry(&second, "operation-current-proof");
        source
            .append_local(&second, &current_entry)
            .expect("current append");
        for entry in [&old_entry, &current_entry] {
            let previous_log_index = entry.index.checked_sub(1).expect("previous index");
            let previous_log_term = if previous_log_index == 0 {
                0
            } else {
                old_entry.leader_epoch
            };
            assert!(
                follower
                    .append_entries(
                        &membership,
                        &AdmissionAppendEntriesRequest {
                            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                            membership_digest: membership.digest().to_string(),
                            term: second.term,
                            leader_id: second.candidate_id.clone(),
                            previous_log_index,
                            previous_log_term,
                            entry: Some(entry.clone()),
                            leader_commit: 0,
                            commit_proof: None,
                        },
                        |_, _, _| Ok("{}".to_string()),
                    )
                    .expect("follower append")
                    .accepted
            );
        }
        assert!(
            follower
                .append_entries(
                    &membership,
                    &AdmissionAppendEntriesRequest {
                        protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                        membership_digest: membership.digest().to_string(),
                        term: second.term,
                        leader_id: second.candidate_id,
                        previous_log_index: current_entry.index,
                        previous_log_term: current_entry.leader_epoch,
                        entry: None,
                        leader_commit: old_entry.index,
                        commit_proof: Some(old_proof),
                    },
                    |_, _, _| Ok("{\"old\":true}".to_string()),
                )
                .expect("historical proof relay")
                .accepted
        );
        assert_eq!(follower.meta().expect("follower meta").commit_index, 1);
        assert_eq!(follower.meta().expect("follower meta").last_applied, 1);

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(follower_path);
    }

    fn clustered_test_config(
        database_path: &Path,
        self_url: &str,
        peer_urls: Vec<String>,
    ) -> TrustServiceConfig {
        let mut config = test_config(database_path);
        config.advertise_url = Some(self_url.to_string());
        config.peer_urls = peer_urls.clone();
        let self_key = deterministic_cluster_test_key(self_url);
        let database_parent = database_path.parent().expect("cluster test database parent");
        let database_file_name = database_path
            .file_name()
            .expect("cluster test database file name");
        let secure_database_path = std::fs::canonicalize(database_parent)
            .expect("canonical cluster test database parent")
            .join(database_file_name);
        let mut seed_path = secure_database_path.as_os_str().to_os_string();
        seed_path.push(".cluster-node.seed");
        let seed_path = PathBuf::from(seed_path);
        crate::persist_authority_keypair(&seed_path, &self_key)
            .expect("persist cluster test identity");
        config.cluster_node_seed_path = Some(seed_path);
        let mut replay_db_path = secure_database_path.as_os_str().to_os_string();
        replay_db_path.push(".cluster-replay.sqlite3");
        let replay_db_path = PathBuf::from(replay_db_path);
        crate::trust_control::cluster_replay::initialize_cluster_peer_replay_ledger(
            &replay_db_path,
        )
        .expect("initialize cluster test replay database");
        config.cluster_replay_db_path = Some(replay_db_path);
        config.cluster_members = std::iter::once(self_url.to_string())
            .chain(peer_urls)
            .map(|node_url| ClusterMemberIdentity {
                public_key: deterministic_cluster_test_key(&node_url).public_key(),
                node_url,
            })
            .collect();
        config
    }

    fn deterministic_cluster_test_key(node_url: &str) -> Keypair {
        let digest = hex::decode(sha256_hex(node_url.as_bytes())).expect("cluster key digest");
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&digest);
        Keypair::from_seed(&seed)
    }

    fn clustered_test_state(
        config: TrustServiceConfig,
        local_addr: SocketAddr,
    ) -> TrustServiceState {
        let cluster = build_cluster_state(&config, local_addr).expect("cluster state");
        TrustServiceState {
            config,
            dashboard_sessions: dashboard_auth::DashboardSessionStore::production(),
            dashboard_report_bridge: None,
            authority_keyring: None,
            authority_test_backend: None,
            active_defense: service_runtime::TrustControlActiveDefenseService::disabled(),
            enterprise_provider_registry: None,
            verifier_policy_registry: None,
            federation_admission_rate_limiter: Arc::new(Mutex::new(
                FederationAdmissionRateLimiter::default(),
            )),
            authority_issuance_rotation_lock: Arc::new(Mutex::new(())),
            cluster,
            cluster_progress: Some(Arc::new(ClusterProgress::new())),
        }
    }

    #[test]
    fn clustered_service_without_combined_authority_storage_starts_without_consensus() {
        let database_path = path("optional-consensus-storage");
        let mut config = clustered_test_config(
            &database_path,
            "http://127.0.0.1:38101",
            vec![
                "http://127.0.0.1:38102".to_string(),
                "http://127.0.0.1:38103".to_string(),
            ],
        );
        config.budget_db_path = None;
        config.revocation_db_path = None;
        let state = clustered_test_state(config, SocketAddr::from(([127, 0, 0, 1], 38101)));
        initialize_admission_consensus(&state).expect("optional consensus initialization");
        assert!(!database_path.exists());
    }

    fn consensus_test_router(state: TrustServiceState) -> axum::Router {
        axum::Router::new()
            .route(
                BUDGET_INCREMENT_PATH,
                axum::routing::post(
                    super::super::super::budget_handlers::handle_try_increment_budget,
                ),
            )
            .route(
                BUDGET_AUTHORIZE_EXPOSURE_PATH,
                axum::routing::post(super::super::super::budget_handlers::handle_try_charge_cost),
            )
            .route(
                INTERNAL_ADMISSION_REQUEST_VOTE_PATH,
                axum::routing::post(handle_internal_admission_request_vote),
            )
            .route(
                INTERNAL_ADMISSION_APPEND_ENTRIES_PATH,
                axum::routing::post(handle_internal_admission_append_entries),
            )
            .route(
                INTERNAL_ADMISSION_PROPOSAL_PATH,
                axum::routing::post(handle_internal_admission_proposal),
            )
            .route(
                INTERNAL_ADMISSION_CAPTURE_QUERY_PATH,
                axum::routing::post(handle_internal_admission_capture_query),
            )
            .route(
                INTERNAL_ADMISSION_SNAPSHOT_PATH,
                axum::routing::get(handle_internal_admission_snapshot),
            )
            .with_state(state)
    }

    fn service_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer consensus-test-token"),
        );
        headers
    }

    async fn invoke_composite_authorize(
        state: TrustServiceState,
        request: CompositeBudgetAuthorizeRequest,
    ) -> Result<CompositeBudgetAuthorizeResponse, String> {
        let response =
            super::super::super::budget_handlers::handle_authorize_composite_budget_hold(
                State(state),
                service_headers(),
                Json(request),
            )
            .await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .map_err(|error| error.to_string())?;
        if status != StatusCode::OK {
            return Err(format!(
                "{status}: {}",
                String::from_utf8_lossy(body.as_ref())
            ));
        }
        serde_json::from_slice(&body).map_err(|error| error.to_string())
    }

    async fn invoke_increment(
        state: TrustServiceState,
        request: TryIncrementBudgetRequest,
    ) -> Result<Value, String> {
        decode_http_response(
            super::super::super::budget_handlers::handle_try_increment_budget(
                State(state),
                service_headers(),
                Json(request),
            )
            .await,
        )
        .await
    }

    async fn decode_http_response<T: DeserializeOwned>(response: Response) -> Result<T, String> {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .map_err(|error| error.to_string())?;
        if status != StatusCode::OK {
            return Err(format!(
                "{status}: {}",
                String::from_utf8_lossy(body.as_ref())
            ));
        }
        serde_json::from_slice(&body).map_err(|error| error.to_string())
    }

    async fn invoke_reverse_exposure(
        state: TrustServiceState,
        request: ReverseChargeCostRequest,
    ) -> Result<ReverseChargeCostResponse, String> {
        decode_http_response(
            super::super::super::budget_handlers::handle_reverse_charge_cost(
                State(state),
                service_headers(),
                Json(request),
            )
            .await,
        )
        .await
    }

    async fn invoke_reduce_exposure(
        state: TrustServiceState,
        request: ReduceChargeCostRequest,
    ) -> Result<ReduceChargeCostResponse, String> {
        decode_http_response(
            super::super::super::budget_handlers::handle_reduce_charge_cost(
                State(state),
                service_headers(),
                Json(request),
            )
            .await,
        )
        .await
    }

    async fn invoke_capture_exposure(
        state: TrustServiceState,
        request: ReduceChargeCostRequest,
    ) -> Result<ReduceChargeCostResponse, String> {
        decode_http_response(
            super::super::super::budget_handlers::handle_capture_budget_hold(
                State(state),
                service_headers(),
                Json(request),
            )
            .await,
        )
        .await
    }

    async fn invoke_admission_command<T: Serialize>(
        state: &TrustServiceState,
        operation_id: &str,
        command_kind: AdmissionCommandKind,
        command: &T,
    ) -> Result<AdmissionConsensusResult, String> {
        match propose_admission_command(state, operation_id.to_string(), command_kind, command)
            .await
        {
            Ok(result) => Ok(result),
            Err(response) => {
                let status = response.status();
                let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .map_err(|error| error.to_string())?;
                Err(format!(
                    "{status}: {}",
                    String::from_utf8_lossy(body.as_ref())
                ))
            }
        }
    }

    struct ThreeNodeCluster {
        paths: [PathBuf; 3],
        states: [TrustServiceState; 3],
        servers: [tokio::task::JoinHandle<()>; 3],
    }

    impl ThreeNodeCluster {
        async fn start(label: &str) -> Self {
            let paths = [
                path(&format!("{label}-a")),
                path(&format!("{label}-b")),
                path(&format!("{label}-c")),
            ];
            let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listener a");
            let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listener b");
            let listener_c = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listener c");
            let addresses = [
                listener_a.local_addr().expect("address a"),
                listener_b.local_addr().expect("address b"),
                listener_c.local_addr().expect("address c"),
            ];
            let urls = addresses
                .iter()
                .map(|address| format!("http://{address}"))
                .collect::<Vec<_>>();
            let states = [
                clustered_test_state(
                    clustered_test_config(
                        &paths[0],
                        &urls[0],
                        vec![urls[1].clone(), urls[2].clone()],
                    ),
                    addresses[0],
                ),
                clustered_test_state(
                    clustered_test_config(
                        &paths[1],
                        &urls[1],
                        vec![urls[0].clone(), urls[2].clone()],
                    ),
                    addresses[1],
                ),
                clustered_test_state(
                    clustered_test_config(
                        &paths[2],
                        &urls[2],
                        vec![urls[0].clone(), urls[1].clone()],
                    ),
                    addresses[2],
                ),
            ];
            for state in &states {
                initialize_admission_consensus(state).expect("initialize consensus");
            }
            let state_a = states[0].clone();
            let state_b = states[1].clone();
            let state_c = states[2].clone();
            let servers = [
                tokio::spawn(async move {
                    axum::serve(listener_a, consensus_test_router(state_a))
                        .await
                        .expect("serve a");
                }),
                tokio::spawn(async move {
                    axum::serve(listener_b, consensus_test_router(state_b))
                        .await
                        .expect("serve b");
                }),
                tokio::spawn(async move {
                    axum::serve(listener_c, consensus_test_router(state_c))
                        .await
                        .expect("serve c");
                }),
            ];
            tokio::time::sleep(Duration::from_millis(10)).await;
            Self {
                paths,
                states,
                servers,
            }
        }

        fn snapshots(&self) -> [AdmissionConsensusSnapshot; 3] {
            std::array::from_fn(|index| {
                configured_admission_consensus_store(&self.states[index].config)
                    .expect("consensus store")
                    .snapshot()
                    .expect("consensus snapshot")
            })
        }

        async fn stop(self) {
            for server in self.servers {
                server.abort();
                let _ = server.await;
            }
            for path in self.paths {
                let _ = std::fs::remove_file(&path);
                let _ = std::fs::remove_file(format!("{}-wal", path.display()));
                let _ = std::fs::remove_file(format!("{}-shm", path.display()));
            }
        }
    }

    fn assert_same_committed_state(
        left: &AdmissionConsensusSnapshot,
        right: &AdmissionConsensusSnapshot,
    ) {
        assert_eq!(left.protocol_version, right.protocol_version);
        assert_eq!(left.meta.membership_digest, right.meta.membership_digest);
        assert_eq!(left.meta.last_log_index, right.meta.last_log_index);
        assert_eq!(left.meta.last_log_term, right.meta.last_log_term);
        assert_eq!(left.meta.commit_index, right.meta.commit_index);
        assert_eq!(left.meta.last_applied, right.meta.last_applied);
        assert_eq!(
            left.meta.applied_state_digest,
            right.meta.applied_state_digest
        );
        assert_eq!(left.entries, right.entries);
        assert_eq!(left.commit_proofs, right.commit_proofs);
        assert_eq!(left.results, right.results);
    }

    #[test]
    fn proposal_serializers_are_scoped_to_one_member() {
        let first = admission_proposal_serializer("https://node-a");
        let first_again = admission_proposal_serializer("https://node-a");
        let second = admission_proposal_serializer("https://node-b");
        assert!(Arc::ptr_eq(&first, &first_again));
        assert!(!Arc::ptr_eq(&first, &second));

        let _first_guard = first.lock().expect("first serializer");
        let (sent, received) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let _second_guard = second.lock().expect("second serializer");
            sent.send(()).expect("notify independent acquisition");
        });
        received
            .recv_timeout(Duration::from_millis(100))
            .expect("another member must not share the held serializer");
        worker.join().expect("serializer worker");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn remote_last_unit_race_converges_to_exactly_one_allow() {
        let cluster = ThreeNodeCluster::start("remote-last-unit").await;

        let first_request = composite_request(
            "capability-remote-last-unit",
            "hold-remote-a",
            "event-remote-a",
            1,
        );
        let second_request = composite_request(
            "capability-remote-last-unit",
            "hold-remote-b",
            "event-remote-b",
            1,
        );
        let (first, second) = tokio::join!(
            invoke_composite_authorize(cluster.states[1].clone(), first_request.clone()),
            invoke_composite_authorize(cluster.states[2].clone(), second_request.clone()),
        );
        let first = first.expect("first response");
        let second = second.expect("second response");
        assert_eq!(usize::from(first.allowed) + usize::from(second.allowed), 1);
        assert_eq!(first.invocation_count_after, 1);
        assert_eq!(second.invocation_count_after, 1);

        let snapshots = cluster.snapshots();
        assert_same_committed_state(&snapshots[0], &snapshots[1]);
        assert_same_committed_state(&snapshots[1], &snapshots[2]);
        assert_eq!(snapshots[0].meta.commit_index, 2);
        assert_eq!(snapshots[0].meta.last_applied, 2);
        assert_eq!(snapshots[0].results.len(), 2);

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn remote_increment_from_follower_converges() {
        let cluster = ThreeNodeCluster::start("remote-increment-replay").await;
        let response = invoke_increment(
            cluster.states[2].clone(),
            TryIncrementBudgetRequest {
                capability_id: "capability-increment-replay".to_string(),
                grant_index: 0,
                max_invocations: Some(2),
            },
        )
        .await
        .expect("follower increment response");
        assert_eq!(response["allowed"].as_bool(), Some(true));
        assert_eq!(response["invocationCount"].as_u64(), Some(1));
        assert_eq!(
            response["budgetAuthority"]["guaranteeLevel"].as_str(),
            Some("ha_linearizable")
        );
        assert_eq!(
            response["budgetCommit"]["quorumCommitted"].as_bool(),
            Some(true)
        );

        let snapshots = cluster.snapshots();
        assert_same_committed_state(&snapshots[0], &snapshots[1]);
        assert_same_committed_state(&snapshots[1], &snapshots[2]);
        assert_eq!(snapshots[0].meta.commit_index, 1);
        assert_eq!(snapshots[0].meta.last_applied, 1);
        assert_eq!(snapshots[0].entries.len(), 1);
        assert_eq!(
            serde_json::to_value(snapshots[0].entries[0].command_kind)
                .expect("serialize increment command kind"),
            Value::String("increment_invocation".to_string())
        );

        for path in &cluster.paths {
            let store = SqliteBudgetStore::open(path).expect("increment projection");
            let usage = store
                .get_usage("capability-increment-replay", 0)
                .expect("increment usage")
                .expect("increment usage row");
            assert_eq!(usage.invocation_count, 1);
            assert_eq!(
                store
                    .list_mutation_events(10, Some("capability-increment-replay"), Some(0))
                    .expect("increment mutation events")
                    .len(),
                1
            );
        }

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn admission_managed_legacy_exposure_rejects_without_mutation() {
        let cluster = ThreeNodeCluster::start("legacy-exposure-rejection").await;
        let response = super::super::super::budget_handlers::handle_try_charge_cost(
            State(cluster.states[2].clone()),
            service_headers(),
            Json(TryChargeCostRequest {
                capability_id: "capability-legacy-exposure".to_string(),
                grant_index: 0,
                max_invocations: Some(2),
                cost_units: 5,
                max_cost_per_invocation: Some(10),
                max_total_cost_units: Some(20),
                hold_id: Some("legacy-exposure-hold".to_string()),
                event_id: Some("legacy-exposure-event".to_string()),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("legacy exposure rejection body");
        assert!(
            String::from_utf8_lossy(body.as_ref()).contains("composite"),
            "legacy exposure rejection should direct callers to composite admission"
        );
        for path in &cluster.paths {
            let store = SqliteBudgetStore::open(path).expect("legacy exposure projection");
            assert!(store
                .get_usage("capability-legacy-exposure", 0)
                .expect("legacy exposure usage")
                .is_none());
            assert!(store
                .list_mutation_events(10, Some("capability-legacy-exposure"), Some(0))
                .expect("legacy exposure mutation events")
                .is_empty());
        }

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn remote_authorization_survives_coordinator_unavailability() {
        let cluster = ThreeNodeCluster::start("remote-coordinator-unavailable").await;
        let mut members = cluster
            .states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                let (self_url, _, _) = admission_members(state).expect("member identity");
                (self_url, index)
            })
            .collect::<Vec<_>>();
        members.sort();
        let coordinator_index = members[0].1;
        cluster.servers[coordinator_index].abort();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let caller_index = members[1].1;
        let response = invoke_composite_authorize(
            cluster.states[caller_index].clone(),
            composite_request(
                "capability-coordinator-unavailable",
                "hold-coordinator-unavailable",
                "event-coordinator-unavailable",
                1,
            ),
        )
        .await
        .expect("fallback authorization");
        assert!(response.allowed);
        for (_, index) in members.iter().skip(1) {
            let snapshot = configured_admission_consensus_store(&cluster.states[*index].config)
                .expect("live consensus store")
                .snapshot()
                .expect("live consensus snapshot");
            assert_eq!(snapshot.meta.commit_index, 1);
            assert_eq!(snapshot.meta.last_applied, 1);
        }

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn ca_free_admission_capture_and_revocation_survive_coordinator_loss() {
        let cluster = ThreeNodeCluster::start("ca-free-admission-failover").await;
        for state in &cluster.states {
            assert!(state.config.authority_seed_path.is_none());
            assert!(state.config.authority_db_path.is_none());
        }

        let mut members = cluster
            .states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                let (self_url, _, _) = admission_members(state).expect("member identity");
                (self_url, index)
            })
            .collect::<Vec<_>>();
        members.sort();
        let coordinator_index = members[0].1;
        let first_survivor_index = members[1].1;
        let second_survivor_index = members[2].1;

        let mut capturable_request = composite_request(
            "capability-capture-after-failover",
            "hold-capture-after-failover",
            "authorize-capture-after-failover",
            1,
        );
        capturable_request.operation_id = "operation-capture-after-failover".to_string();
        let capturable = invoke_composite_authorize(
            cluster.states[coordinator_index].clone(),
            capturable_request,
        )
        .await
        .expect("pre-failover capturable authorization");
        assert!(capturable.allowed);

        let mut revocable_request = composite_request(
            "capability-revoke-after-failover",
            "hold-revoke-after-failover",
            "authorize-revoke-after-failover",
            1,
        );
        revocable_request.operation_id = "operation-revoke-after-failover".to_string();
        let revocable = invoke_composite_authorize(
            cluster.states[coordinator_index].clone(),
            revocable_request,
        )
        .await
        .expect("pre-failover revocable authorization");
        assert!(revocable.allowed);

        cluster.servers[coordinator_index].abort();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let capture_request = combined_request(
            &capturable,
            "operation-capture-after-failover",
            "capture-after-failover",
        );
        let capture = invoke_admission_command(
            &cluster.states[first_survivor_index],
            "operation-capture-after-failover",
            AdmissionCommandKind::CombinedCapture,
            &capture_request,
        )
        .await
        .expect("capture after coordinator loss");
        let capture_response: CombinedAdmissionCaptureResponse =
            serde_json::from_str(&capture.response_json).expect("capture response");
        assert_eq!(
            capture_response.outcome,
            AdmissionCaptureOutcomeView::Captured
        );

        invoke_admission_command(
            &cluster.states[second_survivor_index],
            "revocation:capability-revoke-after-failover",
            AdmissionCommandKind::Revoke,
            &ConsensusRevocationProposal {
                capability_id: "capability-revoke-after-failover".to_string(),
            },
        )
        .await
        .expect("revocation after coordinator loss");
        let denied_request = combined_request(
            &revocable,
            "operation-revoke-after-failover",
            "capture-revoked-after-failover",
        );
        let denied = invoke_admission_command(
            &cluster.states[first_survivor_index],
            "operation-revoke-after-failover",
            AdmissionCommandKind::CombinedCapture,
            &denied_request,
        )
        .await
        .expect("revoked capture after coordinator loss");
        let denied_response: CombinedAdmissionCaptureResponse =
            serde_json::from_str(&denied.response_json).expect("denied capture response");
        assert_eq!(
            denied_response.outcome,
            AdmissionCaptureOutcomeView::DeniedRevoked
        );

        let first_survivor = configured_admission_consensus_store(
            &cluster.states[first_survivor_index].config,
        )
        .expect("first survivor store")
        .snapshot()
        .expect("first survivor snapshot");
        let second_survivor = configured_admission_consensus_store(
            &cluster.states[second_survivor_index].config,
        )
        .expect("second survivor store")
        .snapshot()
        .expect("second survivor snapshot");
        assert_same_committed_state(&first_survivor, &second_survivor);
        assert_eq!(first_survivor.meta.commit_index, 5);
        assert_eq!(first_survivor.meta.last_applied, 5);

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn stale_survivor_forwards_to_fresh_quorum_after_coordinator_loss() {
        let mut cluster = ThreeNodeCluster::start("remote-stale-survivor").await;
        let mut members = cluster
            .states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                let (self_url, _, _) = admission_members(state).expect("member identity");
                (self_url, index)
            })
            .collect::<Vec<_>>();
        members.sort();
        let coordinator_index = members[0].1;
        let fresh_survivor_index = members[1].1;
        let stale_survivor_index = members[2].1;
        let stale_address = members[2]
            .0
            .strip_prefix("http://")
            .expect("local member URL")
            .parse::<SocketAddr>()
            .expect("local member address");

        cluster.servers[stale_survivor_index].abort();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let first = invoke_composite_authorize(
            cluster.states[coordinator_index].clone(),
            composite_request(
                "capability-stale-survivor",
                "hold-before-coordinator-loss",
                "event-before-coordinator-loss",
                2,
            ),
        )
        .await
        .expect("initial quorum authorization");
        assert!(first.allowed);
        assert_eq!(
            configured_admission_consensus_store(&cluster.states[stale_survivor_index].config)
                .expect("stale store")
                .snapshot()
                .expect("stale snapshot")
                .meta
                .commit_index,
            0
        );

        cluster.servers[coordinator_index].abort();
        let stale_listener = tokio::net::TcpListener::bind(stale_address)
            .await
            .expect("restart stale survivor listener");
        let stale_state = cluster.states[stale_survivor_index].clone();
        cluster.servers[stale_survivor_index] = tokio::spawn(async move {
            axum::serve(stale_listener, consensus_test_router(stale_state))
                .await
                .expect("serve restarted stale survivor");
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let second = invoke_composite_authorize(
            cluster.states[stale_survivor_index].clone(),
            composite_request(
                "capability-stale-survivor",
                "hold-after-coordinator-loss",
                "event-after-coordinator-loss",
                2,
            ),
        )
        .await
        .expect("fresh survivor forwarding");
        assert!(second.allowed);
        let fresh =
            configured_admission_consensus_store(&cluster.states[fresh_survivor_index].config)
                .expect("fresh survivor store")
                .snapshot()
                .expect("fresh survivor snapshot");
        let stale =
            configured_admission_consensus_store(&cluster.states[stale_survivor_index].config)
                .expect("recovered survivor store")
                .snapshot()
                .expect("recovered survivor snapshot");
        assert_same_committed_state(&fresh, &stale);
        assert_eq!(fresh.meta.commit_index, 2);

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn cross_node_proposals_converge_after_preferred_coordinator_loss() {
        let cluster = ThreeNodeCluster::start("remote-competing-elections").await;
        let mut members = cluster
            .states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                let (self_url, _, _) = admission_members(state).expect("member identity");
                (self_url, index)
            })
            .collect::<Vec<_>>();
        members.sort();
        cluster.servers[members[0].1].abort();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for (rank, (_, index)) in members.iter().skip(1).enumerate() {
            let state = cluster.states[*index].clone();
            let barrier = barrier.clone();
            workers.push(tokio::task::spawn_blocking(move || {
                barrier.wait();
                propose_admission_command_blocking(
                    &state,
                    format!("competing-election-{rank}"),
                    AdmissionCommandKind::Revoke,
                    serde_json::to_value(ConsensusRevocationProposal {
                        capability_id: format!("capability-competing-{rank}"),
                    })
                    .expect("serialize revocation"),
                )
            }));
        }
        barrier.wait();
        for worker in workers {
            worker
                .await
                .expect("proposal worker")
                .expect("competing proposal converges");
        }
        let left = configured_admission_consensus_store(&cluster.states[members[1].1].config)
            .expect("left store")
            .snapshot()
            .expect("left snapshot");
        let right = configured_admission_consensus_store(&cluster.states[members[2].1].config)
            .expect("right store")
            .snapshot()
            .expect("right snapshot");
        assert_same_committed_state(&left, &right);
        assert_eq!(left.meta.last_log_index, left.meta.commit_index);
        assert_eq!(left.meta.commit_index, left.meta.last_applied);
        assert_eq!(left.entries.len(), left.commit_proofs.len());
        assert_eq!(left.commit_proofs.len(), left.results.len());
        assert!(left.meta.current_term >= left.meta.last_log_term);
        assert!(right.meta.current_term >= right.meta.last_log_term);
        for snapshot in [&left, &right] {
            assert!(snapshot
                .meta
                .voted_for
                .as_ref()
                .is_none_or(|candidate| { members.iter().any(|(member, _)| member == candidate) }));
        }
        let committed_entries = left
            .entries
            .iter()
            .take(usize_index(left.meta.commit_index, "committed entry count").expect("count"))
            .collect::<Vec<_>>();
        assert_eq!(
            committed_entries
                .iter()
                .filter(|entry| entry.command_kind == AdmissionCommandKind::Revoke)
                .count(),
            2
        );
        assert!(committed_entries.iter().all(|entry| matches!(
            entry.command_kind,
            AdmissionCommandKind::Revoke | AdmissionCommandKind::LeadershipBarrier
        )));
        for proof in &left.commit_proofs {
            assert!(proof.current_term_commit_index <= left.meta.commit_index);
            let offset = usize_index(
                checked_predecessor(
                    proof.current_term_commit_index,
                    "current-term commit target",
                )
                .expect("target predecessor"),
                "current-term commit target offset",
            )
            .expect("target offset");
            assert_eq!(left.entries[offset].leader_epoch, proof.leader_epoch);
        }
        for rank in 0..2 {
            let operation_id = scoped_operation_id(
                AdmissionCommandKind::Revoke,
                &format!("competing-election-{rank}"),
            )
            .expect("scoped operation");
            assert_eq!(
                committed_entries
                    .iter()
                    .filter(|entry| entry.operation_id == operation_id)
                    .count(),
                1
            );
            assert!(left
                .results
                .iter()
                .any(|result| result.operation_id == operation_id));
        }
        for (_, index) in members.iter().skip(1) {
            let path = cluster.states[*index]
                .config
                .revocation_db_path
                .as_deref()
                .expect("revocation database");
            let connection = Connection::open(path).expect("revocation projection");
            for rank in 0..2 {
                assert_eq!(
                    connection
                        .query_row(
                            "SELECT COUNT(*) FROM revoked_capabilities WHERE capability_id = ?1",
                            params![format!("capability-competing-{rank}")],
                            |row| row.get::<_, i64>(0),
                        )
                        .expect("revocation count"),
                    1
                );
            }
        }

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn remote_proposal_commits_through_the_preferred_coordinator() {
        let cluster = ThreeNodeCluster::start("remote-preferred-coordinator").await;
        let mut members = cluster
            .states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                let (self_url, _, _) = admission_members(state).expect("member identity");
                (self_url, index)
            })
            .collect::<Vec<_>>();
        members.sort();
        let coordinator_url = members[0].0.clone();
        let caller_index = members[2].1;
        let response = invoke_composite_authorize(
            cluster.states[caller_index].clone(),
            composite_request(
                "capability-preferred-coordinator",
                "hold-preferred-coordinator",
                "event-preferred-coordinator",
                1,
            ),
        )
        .await
        .expect("coordinated authorization");
        assert!(response.allowed);
        let snapshot = configured_admission_consensus_store(&cluster.states[caller_index].config)
            .expect("consensus store")
            .snapshot()
            .expect("consensus snapshot");
        assert_eq!(snapshot.commit_proofs.len(), 1);
        assert_eq!(snapshot.commit_proofs[0].leader_id, coordinator_url);

        cluster.stop().await;
    }
