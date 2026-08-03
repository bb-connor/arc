    use super::*;
    use serde::de::DeserializeOwned;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn membership() -> AdmissionMembership {
        AdmissionMembership::new(vec![
            "https://node-a".to_string(),
            "https://node-b".to_string(),
        ])
        .expect("membership")
    }

    fn three_member_membership() -> AdmissionMembership {
        AdmissionMembership::new(vec![
            "https://node-a".to_string(),
            "https://node-b".to_string(),
            "https://node-c".to_string(),
        ])
        .expect("three-member membership")
    }

    fn single_member() -> AdmissionMembership {
        AdmissionMembership::new(vec!["https://node-a".to_string()]).expect("single membership")
    }

    fn path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("chio-admission-consensus-{label}-{nonce}.db"))
    }

    #[test]
    fn election_term_and_vote_are_persisted_and_stale_terms_are_rejected() {
        let path = path("vote");
        let store = AdmissionConsensusStore::open(&path).expect("open consensus");
        let election = store
            .begin_election(&membership(), "https://node-a")
            .expect("elect");
        assert_eq!(election.term, 1);
        drop(store);

        let reopened = AdmissionConsensusStore::open(&path).expect("reopen consensus");
        assert_eq!(reopened.meta().expect("meta").current_term, 1);
        assert_eq!(
            reopened.meta().expect("meta").voted_for.as_deref(),
            Some("https://node-a")
        );
        let stale = reopened
            .request_vote(
                &membership(),
                &AdmissionRequestVoteRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 0,
                    candidate_id: "https://node-b".to_string(),
                    last_log_index: 0,
                    last_log_term: 0,
                    commit_index: 0,
                },
            )
            .expect("stale vote response");
        assert!(!stale.vote_granted);
        assert_eq!(stale.term, 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn request_vote_persists_representable_higher_term_before_later_failure() {
        let path = path("vote-higher-term-failure");
        let store = AdmissionConsensusStore::open(&path).expect("open consensus");
        store
            .begin_election(&membership(), "https://node-a")
            .expect("initial election");
        Connection::open(&path)
            .expect("trigger connection")
            .execute_batch(
                r#"
                CREATE TRIGGER reject_admission_vote
                BEFORE UPDATE OF voted_for ON admission_consensus_meta
                WHEN NEW.voted_for IS NOT NULL
                BEGIN
                    SELECT RAISE(ABORT, 'injected vote persistence failure');
                END;
                "#,
            )
            .expect("install vote trigger");
        let request = AdmissionRequestVoteRequest {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership().digest().to_string(),
            term: 5,
            candidate_id: "https://node-b".to_string(),
            last_log_index: 0,
            last_log_term: 0,
            commit_index: 0,
        };
        store
            .request_vote(&membership(), &request)
            .expect_err("injected vote failure");
        let meta = store.meta().expect("meta after vote failure");
        assert_eq!(meta.current_term, 5);
        assert_eq!(meta.voted_for, None);
        Connection::open(&path)
            .expect("trigger connection")
            .execute_batch("DROP TRIGGER reject_admission_vote")
            .expect("drop vote trigger");

        let stale = store
            .request_vote(
                &membership(),
                &AdmissionRequestVoteRequest {
                    term: 4,
                    ..request.clone()
                },
            )
            .expect("stale vote response");
        assert!(!stale.vote_granted);
        assert_eq!(stale.term, 5);
        let unrepresentable = store
            .request_vote(
                &membership(),
                &AdmissionRequestVoteRequest {
                    term: u64::MAX,
                    ..request
                },
            )
            .expect("unrepresentable vote response");
        assert!(!unrepresentable.vote_granted);
        assert_eq!(unrepresentable.term, 5);
        assert_eq!(store.meta().expect("durable vote term").current_term, 5);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn operation_scope_separates_caller_events_revocations_and_barriers() {
        let external = "revocation:capability-a";
        let authorize = scoped_operation_id(AdmissionCommandKind::CompositeAuthorize, external)
            .expect("authorize scope");
        let revoke =
            scoped_operation_id(AdmissionCommandKind::Revoke, external).expect("revocation scope");
        let barrier = scoped_operation_id(AdmissionCommandKind::LeadershipBarrier, external)
            .expect("barrier scope");

        assert_ne!(authorize, revoke);
        assert_ne!(authorize, barrier);
        assert_ne!(revoke, barrier);
        assert!(is_lower_sha256(&authorize));
        assert!(is_lower_sha256(&revoke));
        assert!(is_lower_sha256(&barrier));
    }

    #[test]
    fn same_term_candidate_accepts_the_majority_leaders_log() {
        let path = path("same-term-step-down");
        let store = AdmissionConsensusStore::open(&path).expect("open consensus");
        let election = store
            .begin_election(&membership(), "https://node-b")
            .expect("begin competing election");
        let leader = AdmissionElection {
            candidate_id: "https://node-a".to_string(),
            ..election
        };
        let entry = entry(&leader, "operation-majority-leader");

        let response = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: leader.term,
                    leader_id: leader.candidate_id.clone(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(entry.clone()),
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{}".to_string()),
            )
            .expect("append from elected leader");

        assert!(response.accepted);
        assert_eq!(response.match_index, entry.index);
        assert_eq!(
            store.meta().expect("meta").voted_for.as_deref(),
            Some(leader.candidate_id.as_str())
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejected_higher_term_append_persists_term_but_no_leader_or_log_mutation() {
        let path = path("rejected-higher-term");
        let store = AdmissionConsensusStore::open(&path).expect("open consensus");
        store
            .begin_election(&membership(), "https://node-a")
            .expect("initial election");
        let rejected = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 5,
                    leader_id: "https://node-b".to_string(),
                    previous_log_index: 1,
                    previous_log_term: 4,
                    entry: None,
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{}".to_string()),
            )
            .expect("higher-term rejection");
        assert!(!rejected.accepted);
        assert_eq!(rejected.term, 5);
        let meta = store.meta().expect("meta after rejection");
        assert_eq!(meta.current_term, 5);
        assert_eq!(meta.voted_for, None);
        assert_eq!(meta.last_log_index, 0);
        assert_eq!(meta.commit_index, 0);

        let stale = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 4,
                    leader_id: "https://node-a".to_string(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: None,
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{}".to_string()),
            )
            .expect("stale append rejection");
        assert!(!stale.accepted);
        assert_eq!(stale.term, 5);
        assert_eq!(store.meta().expect("durable term").current_term, 5);

        let oversized_previous = AdmissionAppendEntriesRequest {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership().digest().to_string(),
            term: 7,
            leader_id: "https://node-b".to_string(),
            previous_log_index: u64::try_from(i64::MAX).expect("i64 max") + 1,
            previous_log_term: 6,
            entry: None,
            leader_commit: 0,
            commit_proof: None,
        };
        store
            .append_entries(&membership(), &oversized_previous, |_, _, _| {
                Ok("{}".to_string())
            })
            .expect_err("oversized previous index");
        assert_eq!(
            store
                .meta()
                .expect("term after oversized index")
                .current_term,
            7
        );

        let election = AdmissionElection {
            term: 8,
            candidate_id: "https://node-a".to_string(),
            last_log_index: 0,
            last_log_term: 0,
            commit_index: 0,
        };
        let entry = entry(&election, "oversized-proof-target");
        let mut oversized_proof = proof(&entry);
        oversized_proof.current_term_commit_index = u64::try_from(i64::MAX).expect("i64 max") + 1;
        store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 8,
                    leader_id: "https://node-a".to_string(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(entry),
                    leader_commit: 1,
                    commit_proof: Some(oversized_proof),
                },
                |_, _, _| Ok("{}".to_string()),
            )
            .expect_err("oversized proof target");
        let meta = store.meta().expect("term after oversized proof");
        assert_eq!(meta.current_term, 8);
        assert_eq!(meta.voted_for, None);
        assert_eq!(meta.last_log_index, 0);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn newer_leader_repairs_a_higher_term_uncommitted_follower_tail() {
        let path = path("repair-higher-term-tail");
        let store = AdmissionConsensusStore::open(&path).expect("open consensus");
        let stale_election = AdmissionElection {
            term: 3,
            candidate_id: "https://node-b".to_string(),
            last_log_index: 0,
            last_log_term: 0,
            commit_index: 0,
        };
        let stale_entry = entry(&stale_election, "operation-stale-tail");
        assert!(
            store
                .append_entries(
                    &membership(),
                    &AdmissionAppendEntriesRequest {
                        protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                        membership_digest: membership().digest().to_string(),
                        term: stale_election.term,
                        leader_id: stale_election.candidate_id,
                        previous_log_index: 0,
                        previous_log_term: 0,
                        entry: Some(stale_entry),
                        leader_commit: 0,
                        commit_proof: None,
                    },
                    |_, _, _| Ok("{}".to_string()),
                )
                .expect("append stale tail")
                .accepted
        );

        let winning_election = AdmissionElection {
            term: 4,
            candidate_id: "https://node-a".to_string(),
            last_log_index: 0,
            last_log_term: 0,
            commit_index: 0,
        };
        let replacement_entry = AdmissionLogEntry {
            leader_epoch: 2,
            ..entry(&winning_election, "operation-majority-tail")
        };
        let repaired = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: winning_election.term,
                    leader_id: winning_election.candidate_id,
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(replacement_entry.clone()),
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{}".to_string()),
            )
            .expect("repair follower tail");

        assert!(repaired.accepted);
        assert_eq!(store.entry_at(1).expect("replacement"), replacement_entry);
        assert!(store
            .entry_for_operation("operation-stale-tail")
            .expect("stale lookup")
            .is_none());

        let _ = std::fs::remove_file(path);
    }

    fn entry(election: &AdmissionElection, operation_id: &str) -> AdmissionLogEntry {
        AdmissionConsensusStore::build_entry(
            election,
            operation_id,
            AdmissionCommandKind::Revoke,
            &serde_json::json!({"capabilityId":"capability-a","revokedAt":7}),
        )
        .expect("entry")
    }

    fn proof(entry: &AdmissionLogEntry) -> AdmissionCommitProof {
        AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership().digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: "https://node-a".to_string(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        }
    }

    const MERGE_RESULT_JSON: &str = "{\"merged\":true}";

    fn commit_merge_entry(store: &AdmissionConsensusStore, operation_id: &str) {
        let election = store
            .begin_election(&membership(), "https://node-a")
            .expect("merge election");
        let entry = entry(&election, operation_id);
        store.append_local(&election, &entry).expect("merge append");
        store
            .commit_local(&membership(), &election, &proof(&entry), |_, _, _| {
                Ok(MERGE_RESULT_JSON.to_string())
            })
            .expect("merge commit");
    }

    fn commit_merge_sequence(store: &AdmissionConsensusStore, operation_ids: &[&str]) {
        for operation_id in operation_ids {
            commit_merge_entry(store, operation_id);
        }
    }

    fn rewrite_snapshot_result(
        snapshot: &mut AdmissionConsensusSnapshot,
        offset: usize,
        response_json: &str,
    ) {
        let result = snapshot.results.get_mut(offset).expect("snapshot result");
        result.response_json = response_json.to_string();
        result.response_digest = sha256_hex(response_json.as_bytes());
        let mut applied_state_digest = initial_applied_state_digest();
        for result in &snapshot.results {
            applied_state_digest = next_applied_state_digest(
                &applied_state_digest,
                &result.response_digest,
                &result.security_projection_digest,
            )
            .expect("snapshot applied digest");
        }
        snapshot.meta.applied_state_digest = applied_state_digest;
    }

    fn assert_merge_rejected_without_mutation(
        target: &AdmissionConsensusStore,
        candidate: &AdmissionConsensusSnapshot,
    ) {
        validate_snapshot_for_membership(candidate, &membership()).expect("valid candidate");
        let before = target.snapshot().expect("target before rejected merge");
        let error = target
            .merge_committed_snapshot(&membership(), candidate, |_, _, _| {
                Ok(MERGE_RESULT_JSON.to_string())
            })
            .expect_err("divergent merge must reject");
        assert!(error.to_string().contains("diverge"));
        assert_eq!(
            target.snapshot().expect("target after rejected merge"),
            before
        );
    }

    #[test]
    fn merge_matching_equal_and_stale_snapshots_are_noops() {
        let target_path = path("merge-noop-target");
        let stale_path = path("merge-noop-stale");
        let target = AdmissionConsensusStore::open(&target_path).expect("target");
        let stale = AdmissionConsensusStore::open(&stale_path).expect("stale");
        commit_merge_sequence(&target, &["merge-noop-a", "merge-noop-b"]);
        commit_merge_sequence(&stale, &["merge-noop-a"]);
        let before = target.snapshot().expect("target snapshot");

        for candidate in [before.clone(), stale.snapshot().expect("stale snapshot")] {
            assert!(!target
                .merge_committed_snapshot(
                    &membership(),
                    &candidate,
                    |_, _, _| -> Result<_, String> {
                        panic!("an already-applied prefix must not replay")
                    },
                )
                .expect("matching snapshot no-op"));
            assert_eq!(target.snapshot().expect("unchanged target"), before);
        }

        let _ = std::fs::remove_file(target_path);
        let _ = std::fs::remove_file(stale_path);
    }

    #[test]
    fn merge_divergent_equal_and_stale_committed_components_reject_without_mutation() {
        let target_path = path("merge-divergent-target");
        let equal_entry_path = path("merge-divergent-equal-entry");
        let stale_entry_path = path("merge-divergent-stale-entry");
        let stale_path = path("merge-divergent-stale");
        let target = AdmissionConsensusStore::open(&target_path).expect("target");
        let equal_entry =
            AdmissionConsensusStore::open(&equal_entry_path).expect("equal entry source");
        let stale_entry =
            AdmissionConsensusStore::open(&stale_entry_path).expect("stale entry source");
        let stale = AdmissionConsensusStore::open(&stale_path).expect("stale source");
        commit_merge_sequence(&target, &["merge-shared-a", "merge-shared-b"]);
        commit_merge_sequence(&equal_entry, &["merge-other-a", "merge-shared-b"]);
        commit_merge_sequence(&stale_entry, &["merge-other-a"]);
        commit_merge_sequence(&stale, &["merge-shared-a"]);

        let equal = target.snapshot().expect("equal base");
        let stale = stale.snapshot().expect("stale base");
        let mut equal_proof = equal.clone();
        equal_proof.commit_proofs[0].leader_id = "https://node-b".to_string();
        let mut stale_proof = stale.clone();
        stale_proof.commit_proofs[0].leader_id = "https://node-b".to_string();
        let mut equal_result = equal;
        rewrite_snapshot_result(&mut equal_result, 0, "{\"merged\":false}");
        let mut stale_result = stale;
        rewrite_snapshot_result(&mut stale_result, 0, "{\"merged\":false}");

        for candidate in [
            equal_entry.snapshot().expect("equal entry divergence"),
            stale_entry.snapshot().expect("stale entry divergence"),
            equal_proof,
            stale_proof,
            equal_result,
            stale_result,
        ] {
            assert_merge_rejected_without_mutation(&target, &candidate);
        }

        let _ = std::fs::remove_file(target_path);
        let _ = std::fs::remove_file(equal_entry_path);
        let _ = std::fs::remove_file(stale_entry_path);
        let _ = std::fs::remove_file(stale_path);
    }

    #[test]
    fn merge_higher_snapshot_advances_only_the_missing_committed_prefix() {
        let source_path = path("merge-higher-source");
        let target_path = path("merge-higher-target");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        let target = AdmissionConsensusStore::open(&target_path).expect("target");
        commit_merge_sequence(
            &source,
            &["merge-higher-a", "merge-higher-b", "merge-higher-c"],
        );
        commit_merge_sequence(&target, &["merge-higher-a"]);
        let source_snapshot = source.snapshot().expect("source snapshot");
        let applied = AtomicUsize::new(0);

        assert!(target
            .merge_committed_snapshot(&membership(), &source_snapshot, |_, _, _| {
                applied.fetch_add(1, Ordering::SeqCst);
                Ok(MERGE_RESULT_JSON.to_string())
            })
            .expect("advance committed prefix"));
        assert_eq!(applied.load(Ordering::SeqCst), 2);
        let merged = target.snapshot().expect("merged target");
        assert_same_committed_state(&merged, &source_snapshot);
        assert_eq!(merged.meta.current_term, source_snapshot.meta.current_term);
        assert_eq!(merged.meta.voted_for, None);

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn merge_higher_snapshot_discards_a_local_uncommitted_tail() {
        let source_path = path("merge-tail-source");
        let target_path = path("merge-tail-target");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        let target = AdmissionConsensusStore::open(&target_path).expect("target");
        commit_merge_sequence(&source, &["merge-tail-shared", "merge-tail-source"]);
        commit_merge_sequence(&target, &["merge-tail-shared"]);
        let tail_election = target
            .begin_election(&membership(), "https://node-a")
            .expect("tail election");
        let tail = entry(&tail_election, "merge-tail-local");
        target
            .append_local(&tail_election, &tail)
            .expect("append uncommitted tail");

        assert!(target
            .merge_committed_snapshot(
                &membership(),
                &source.snapshot().expect("source snapshot"),
                |_, _, _| Ok(MERGE_RESULT_JSON.to_string()),
            )
            .expect("replace uncommitted tail"));
        assert!(target
            .entry_for_operation("merge-tail-local")
            .expect("tail lookup")
            .is_none());
        assert!(target
            .result_for_operation("merge-tail-source")
            .expect("source result lookup")
            .is_some());
        let meta = target.meta().expect("target meta");
        assert_eq!(meta.last_log_index, 2);
        assert_eq!(meta.commit_index, 2);
        assert_eq!(meta.last_applied, 2);

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn merge_replay_result_mismatch_restores_the_exact_pre_merge_state() {
        let source_path = path("merge-result-source");
        let target_path = path("merge-result-target");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        let target = AdmissionConsensusStore::open(&target_path).expect("target");
        commit_merge_sequence(&source, &["merge-result-mismatch"]);
        let source_snapshot = source.snapshot().expect("source snapshot");
        target
            .bind_membership(&membership())
            .expect("bind target membership");
        let mut expected = target.snapshot().expect("target before merge");
        expected.meta.current_term = source_snapshot.meta.current_term;
        expected.meta.voted_for = None;

        for _attempt in 0..2 {
            let error = target
                .merge_committed_snapshot(&membership(), &source_snapshot, |_, _, _| {
                    Ok("{\"merged\":false}".to_string())
                })
                .expect_err("mismatched replay must reject");
            assert!(error.to_string().contains("authenticated snapshot"));
            assert_eq!(target.meta().expect("target meta").commit_index, 0);
            assert_eq!(target.meta().expect("target meta").last_applied, 0);
            assert!(target
                .result_for_operation("merge-result-mismatch")
                .expect("result lookup")
                .is_none());
            assert_eq!(
                target.snapshot().expect("target after rejected merge"),
                expected
            );
        }
        target
            .validate_integrity()
            .expect("restored state integrity");
        let applied = AtomicUsize::new(0);
        assert_eq!(
            target
                .apply_committed(&mut |_, _, _| {
                    applied.fetch_add(1, Ordering::SeqCst);
                    Ok("{\"unexpected\":true}".to_string())
                })
                .expect("plain replay after rejected merge"),
            0
        );
        assert_eq!(applied.load(Ordering::SeqCst), 0);

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn equal_merge_mismatch_preserves_replication_state_but_observes_higher_term() {
        let source_path = path("merge-equal-term-source");
        let target_path = path("merge-equal-term-target");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        commit_merge_entry(&source, "merge-equal-term");
        let base_snapshot = source.snapshot().expect("base snapshot");
        let target = AdmissionConsensusStore::open(&target_path).expect("target");
        target
            .install_snapshot(&membership(), &base_snapshot, |_, _, _| {
                Ok(MERGE_RESULT_JSON.to_string())
            })
            .expect("seed target");
        let connection = Connection::open(&target_path).expect("target connection");
        connection
            .execute("DELETE FROM admission_consensus_results", [])
            .expect("remove applied result");
        connection
            .execute(
                r#"
                UPDATE admission_consensus_meta
                SET last_applied = 0, applied_state_digest = ?1
                WHERE singleton = 1
                "#,
                params![initial_applied_state_digest()],
            )
            .expect("rewind target apply state");
        drop(connection);
        source
            .begin_election(&membership(), "https://node-b")
            .expect("advance source term");
        let higher_snapshot = source.snapshot().expect("higher-term snapshot");
        let entry_before = target.entry_at(1).expect("target entry");
        let proof_before = target.proof_at(1).expect("target proof");

        let error = target
            .merge_committed_snapshot(&membership(), &higher_snapshot, |_, _, _| {
                Ok("{\"merged\":false}".to_string())
            })
            .expect_err("equal merge mismatch");
        assert!(error.to_string().contains("authenticated snapshot"));
        let meta = target.meta().expect("target meta");
        assert_eq!(meta.current_term, higher_snapshot.meta.current_term);
        assert_eq!(meta.voted_for, None);
        assert_eq!(meta.commit_index, 1);
        assert_eq!(meta.last_applied, 0);
        assert_eq!(target.entry_at(1).expect("target entry"), entry_before);
        assert_eq!(target.proof_at(1).expect("target proof"), proof_before);
        assert!(target
            .result_for_operation("merge-equal-term")
            .expect("result lookup")
            .is_none());

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn snapshot_rejects_a_proof_target_beyond_the_final_commit() {
        let source_path = path("snapshot-proof-beyond-commit");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        commit_merge_sequence(&source, &["proof-committed"]);
        let meta = source.meta().expect("source meta");
        let election = AdmissionElection {
            term: meta.current_term,
            candidate_id: "https://node-a".to_string(),
            last_log_index: meta.last_log_index,
            last_log_term: meta.last_log_term,
            commit_index: meta.commit_index,
        };
        let uncommitted = entry(&election, "proof-uncommitted-target");
        source
            .append_local(&election, &uncommitted)
            .expect("append uncommitted proof target");
        let mut snapshot = source.snapshot().expect("valid source snapshot");
        snapshot.commit_proofs[0].current_term_commit_index = uncommitted.index;

        assert!(validate_snapshot(&snapshot).is_err());
        assert!(validate_snapshot_for_membership(&snapshot, &membership()).is_err());

        let _ = std::fs::remove_file(source_path);
    }

    #[test]
    fn snapshot_enforces_term_log_and_vote_invariants() {
        let source_path = path("snapshot-term-log-vote");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        commit_merge_sequence(&source, &["snapshot-invariant-a", "snapshot-invariant-b"]);
        let snapshot = source.snapshot().expect("valid snapshot");

        let mut term_behind_log = snapshot.clone();
        term_behind_log.meta.current_term = term_behind_log.meta.last_log_term - 1;
        assert!(validate_snapshot(&term_behind_log).is_err());

        let mut wrong_log_head = snapshot.clone();
        wrong_log_head.meta.last_log_term += 1;
        wrong_log_head.meta.current_term = wrong_log_head.meta.last_log_term;
        assert!(validate_snapshot(&wrong_log_head).is_err());

        let mut decreasing_terms = snapshot.clone();
        decreasing_terms.entries[0].leader_epoch = decreasing_terms.entries[1].leader_epoch + 1;
        decreasing_terms.meta.current_term = decreasing_terms.entries[0].leader_epoch;
        assert!(validate_snapshot(&decreasing_terms).is_err());

        let mut outsider_vote = snapshot;
        outsider_vote.meta.voted_for = Some("https://node-c".to_string());
        validate_snapshot(&outsider_vote).expect("structurally valid outsider vote");
        assert!(validate_snapshot_for_membership(&outsider_vote, &membership()).is_err());

        let _ = std::fs::remove_file(source_path);
    }

    #[test]
    fn follower_accepts_one_exact_entry_but_never_applies_it_before_commit() {
        let path = path("append");
        let store = AdmissionConsensusStore::open(&path).expect("open consensus");
        let election = AdmissionElection {
            term: 3,
            candidate_id: "https://node-a".to_string(),
            last_log_index: 0,
            last_log_term: 0,
            commit_index: 0,
        };
        let entry = entry(&election, "operation-a");
        let applied = AtomicUsize::new(0);
        let append = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 3,
                    leader_id: "https://node-a".to_string(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(entry.clone()),
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| {
                    applied.fetch_add(1, Ordering::SeqCst);
                    Ok("{\"ok\":true}".to_string())
                },
            )
            .expect("append response");
        assert!(append.accepted);
        assert_eq!(append.applied_index, 0);
        assert_eq!(applied.load(Ordering::SeqCst), 0);
        let exact_retry = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 3,
                    leader_id: "https://node-a".to_string(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(entry.clone()),
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{\"unexpected\":true}".to_string()),
            )
            .expect("exact append retry");
        assert!(exact_retry.accepted);
        assert_eq!(exact_retry.match_index, 1);
        assert_eq!(exact_retry.applied_index, 0);

        let mut conflicting = entry.clone();
        conflicting.operation_id = "operation-conflict".to_string();
        conflicting.canonical_command =
            "{\"capabilityId\":\"capability-b\",\"revokedAt\":7}".to_string();
        conflicting.command_digest = sha256_hex(conflicting.canonical_command.as_bytes());
        let rejected = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 3,
                    leader_id: "https://node-a".to_string(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(conflicting),
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{\"ok\":true}".to_string()),
            )
            .expect("conflict response");
        assert!(!rejected.accepted);
        assert_eq!(store.meta().expect("meta").last_log_index, 1);
        assert_eq!(applied.load(Ordering::SeqCst), 0);

        let committed = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 3,
                    leader_id: "https://node-a".to_string(),
                    previous_log_index: 1,
                    previous_log_term: 3,
                    entry: None,
                    leader_commit: 1,
                    commit_proof: Some(proof(&entry)),
                },
                |_, _, _| {
                    applied.fetch_add(1, Ordering::SeqCst);
                    Ok("{\"ok\":true}".to_string())
                },
            )
            .expect("commit response");
        assert!(committed.accepted);
        assert_eq!(committed.applied_index, 1);
        assert_eq!(applied.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mixed_version_peers_cannot_vote_or_witness_and_restart_snapshot_replays_exactly() {
        let source_path = path("snapshot-source");
        let target_path = path("snapshot-target");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        let election = source
            .begin_election(&membership(), "https://node-a")
            .expect("election");
        let entry = entry(&election, "operation-snapshot");
        source
            .append_local(&election, &entry)
            .expect("append local");
        let mixed_vote = source
            .request_vote(
                &membership(),
                &AdmissionRequestVoteRequest {
                    protocol_version: "chio.admission-consensus.v0".to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: election.term + 1,
                    candidate_id: "https://old-node".to_string(),
                    last_log_index: entry.index,
                    last_log_term: entry.leader_epoch,
                    commit_index: 0,
                },
            )
            .expect("mixed vote");
        assert!(!mixed_vote.vote_granted);
        assert_eq!(source.meta().expect("meta").current_term, election.term);

        let result = source
            .commit_local(&membership(), &election, &proof(&entry), |_, _, _| {
                Ok("{\"outcome\":\"revoked\"}".to_string())
            })
            .expect("commit local");
        drop(source);
        let reopened = AdmissionConsensusStore::open(&source_path).expect("reopen");
        assert_eq!(reopened.meta().expect("meta").commit_index, 1);
        assert_eq!(reopened.meta().expect("meta").last_applied, 1);
        assert_eq!(
            reopened
                .result_for_operation("operation-snapshot")
                .expect("result"),
            Some(result)
        );
        let snapshot = reopened.snapshot().expect("snapshot");

        let target = AdmissionConsensusStore::open(&target_path).expect("target");
        target
            .install_snapshot(&membership(), &snapshot, |_, _, _| {
                Ok("{\"outcome\":\"revoked\"}".to_string())
            })
            .expect("install snapshot");
        let source_snapshot = snapshot.clone();
        let mut expected = snapshot;
        expected.meta.voted_for = None;
        assert_eq!(target.snapshot().expect("target snapshot"), expected);
        let installed = target.snapshot().expect("installed snapshot");
        target
            .install_snapshot(&membership(), &source_snapshot, |_, _, _| {
                panic!("an exact snapshot retry must not replay")
            })
            .expect("exact snapshot install retry");
        assert_eq!(
            target.snapshot().expect("retried target snapshot"),
            installed
        );

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn snapshot_rejects_proof_gaps_and_result_corruption() {
        let path = path("snapshot-integrity");
        let store = AdmissionConsensusStore::open(&path).expect("open consensus");
        for operation_id in ["operation-snapshot-a", "operation-snapshot-b"] {
            let election = store
                .begin_election(&membership(), "https://node-a")
                .expect("snapshot election");
            let entry = entry(&election, operation_id);
            store
                .append_local(&election, &entry)
                .expect("snapshot append");
            store
                .commit_local(&membership(), &election, &proof(&entry), |_, _, _| {
                    Ok(format!("{{\"operation\":\"{operation_id}\"}}"))
                })
                .expect("snapshot commit");
        }
        let snapshot = store.snapshot().expect("snapshot");

        let mut duplicate_proof = snapshot.clone();
        duplicate_proof.commit_proofs[1] = duplicate_proof.commit_proofs[0].clone();
        assert!(validate_snapshot(&duplicate_proof).is_err());

        let mut changed_body = snapshot.clone();
        changed_body.results[0].response_json = "{\"changed\":true}".to_string();
        assert!(validate_snapshot(&changed_body).is_err());

        let mut changed_digest = snapshot;
        changed_digest.results[0].response_digest = "11".repeat(32);
        assert!(validate_snapshot(&changed_digest).is_err());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn asymmetric_membership_digests_cannot_vote_in_the_same_log() {
        let b_path = path("asymmetric-b");
        let b = AdmissionConsensusStore::open(&b_path).expect("b");
        let full = AdmissionMembership::new(vec![
            "https://node-a".to_string(),
            "https://node-b".to_string(),
            "https://node-c".to_string(),
        ])
        .expect("full membership");
        let asymmetric = AdmissionMembership::new(vec![
            "https://node-a".to_string(),
            "https://node-b".to_string(),
        ])
        .expect("asymmetric membership");
        b.bind_membership(&full).expect("bind full membership");
        let a_vote = AdmissionRequestVoteRequest {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: asymmetric.digest().to_string(),
            term: 1,
            candidate_id: "https://node-a".to_string(),
            last_log_index: 0,
            last_log_term: 0,
            commit_index: 0,
        };
        assert!(
            !b.request_vote(&full, &a_vote)
                .expect("membership rejection")
                .vote_granted
        );
        assert_eq!(b.meta().expect("b meta").current_term, 0);
        drop(b);
        let reopened = AdmissionConsensusStore::open(&b_path).expect("reopen");
        assert!(matches!(
            reopened.request_vote(
                &asymmetric,
                &AdmissionRequestVoteRequest {
                    membership_digest: asymmetric.digest().to_string(),
                    ..a_vote
                }
            ),
            Err(AdmissionConsensusError::Protocol(_))
        ));
        let _ = std::fs::remove_file(b_path);
    }

    #[test]
    fn divergent_initial_projection_cannot_share_consensus_membership() {
        let clean_path = path("baseline-clean");
        let drifted_path = path("baseline-drifted");
        let clean_config = test_config(&clean_path);
        let drifted_config = test_config(&drifted_path);
        drop(open_capture_authority(&clean_config).expect("clean authority"));
        drop(open_capture_authority(&drifted_config).expect("drifted authority"));
        let clean_store = AdmissionConsensusStore::open(&clean_path).expect("clean consensus");
        let drifted_store =
            AdmissionConsensusStore::open(&drifted_path).expect("drifted consensus");
        SqliteBudgetStore::open(&drifted_path)
            .expect("drifted budget")
            .try_increment("capability-baseline-drift", 0, Some(3))
            .expect("seed drifted usage");
        let clean_projection =
            capture_admission_genesis_projection(&clean_path).expect("clean projection");
        let drifted_projection =
            capture_admission_genesis_projection(&drifted_path).expect("drifted projection");
        let clean_baseline =
            admission_genesis_projection_digest(&clean_projection).expect("clean baseline");
        let drifted_baseline =
            admission_genesis_projection_digest(&drifted_projection).expect("drifted baseline");
        assert_ne!(clean_baseline, drifted_baseline);
        let members = vec![
            "https://node-a".to_string(),
            "https://node-b".to_string(),
            "https://node-c".to_string(),
        ];
        let clean_membership =
            AdmissionMembership::new_with_genesis(members.clone(), clean_projection)
                .expect("clean membership");
        let drifted_membership = AdmissionMembership::new_with_genesis(members, drifted_projection)
            .expect("drifted membership");
        assert_ne!(clean_membership.digest(), drifted_membership.digest());
        clean_store
            .bind_membership(&clean_membership)
            .expect("bind clean membership");
        let response = drifted_store
            .request_vote(
                &drifted_membership,
                &AdmissionRequestVoteRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: clean_membership.digest().to_string(),
                    term: 1,
                    candidate_id: "https://node-a".to_string(),
                    last_log_index: 0,
                    last_log_term: 0,
                    commit_index: 0,
                },
            )
            .expect("drifted vote response");
        assert!(!response.vote_granted);
        assert_eq!(response.membership_digest, drifted_membership.digest());

        let _ = std::fs::remove_file(clean_path);
        let _ = std::fs::remove_file(drifted_path);
    }

    #[test]
    fn security_projection_excludes_only_qualified_clock_metadata() {
        assert_eq!(ADMISSION_SECURITY_PROJECTION_EXCLUSIONS.len(), 11);
        for (table, column) in ADMISSION_SECURITY_PROJECTION_EXCLUSIONS {
            let specification = ADMISSION_GENESIS_TABLES
                .iter()
                .find(|specification| specification.name == *table)
                .expect("excluded table exists");
            assert!(specification
                .columns
                .iter()
                .any(|(candidate, _)| candidate == column));
            assert!(admission_security_projection_ignores(table, column));
        }
        for specification in ADMISSION_GENESIS_TABLES {
            for (column, _) in specification.columns {
                assert_eq!(
                    admission_security_projection_ignores(specification.name, column),
                    ADMISSION_SECURITY_PROJECTION_EXCLUSIONS
                        .contains(&(specification.name, *column))
                );
            }
        }
        for column in ["revoked_at", "requested_revoked_at", "effective_revoked_at"] {
            assert!(!ADMISSION_GENESIS_TABLES.iter().any(|specification| {
                specification.columns.iter().any(|(candidate, _)| {
                    candidate == &column
                        && admission_security_projection_ignores(specification.name, candidate)
                })
            }));
        }
    }

    #[test]
    fn admission_operation_ownership_is_committed_by_consensus_projections() {
        for table in [
            "admission_capture_events",
            "budget_authorization_holds",
            "budget_composite_authorizations",
            "budget_composite_holds",
            "budget_composite_mutation_snapshots",
            "budget_mutation_events",
        ] {
            let specification = ADMISSION_GENESIS_TABLES
                .iter()
                .find(|specification| specification.name == table)
                .expect("admission-owned table is authoritative");
            for column in ["operation_id", "request_binding_hash"] {
                assert!(
                    specification.columns.iter().any(|(candidate, value_type)| {
                        *candidate == column && *value_type == GenesisText
                    }),
                    "{table}.{column} is absent from the canonical genesis projection"
                );
                assert!(
                    !admission_security_projection_ignores(table, column),
                    "{table}.{column} is absent from the committed security projection"
                );
            }
        }
    }

    #[test]
    fn legacy_consensus_result_schema_fails_during_open() {
        let database_path = path("legacy-consensus-result-schema");
        let connection = Connection::open(&database_path).expect("legacy database");
        connection
            .execute_batch(
                r#"
                CREATE TABLE admission_consensus_meta (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
                    current_term INTEGER NOT NULL,
                    baseline_state_digest TEXT,
                    membership_digest TEXT,
                    voted_for TEXT,
                    last_log_index INTEGER NOT NULL,
                    last_log_term INTEGER NOT NULL,
                    commit_index INTEGER NOT NULL,
                    last_applied INTEGER NOT NULL,
                    applied_state_digest TEXT NOT NULL
                );
                CREATE TABLE admission_consensus_results (
                    operation_id TEXT PRIMARY KEY,
                    log_index INTEGER NOT NULL UNIQUE,
                    response_json TEXT NOT NULL,
                    response_digest TEXT NOT NULL
                );
                "#,
            )
            .expect("legacy schema");
        connection
            .execute(
                r#"
                INSERT INTO admission_consensus_meta (
                    singleton, schema_version, current_term, baseline_state_digest,
                    membership_digest, voted_for, last_log_index, last_log_term,
                    commit_index, last_applied, applied_state_digest
                ) VALUES (1, 1, 0, NULL, NULL, NULL, 0, 0, 0, 0, ?1)
                "#,
                params![initial_applied_state_digest()],
            )
            .expect("legacy meta");
        drop(connection);

        assert!(AdmissionConsensusStore::open(&database_path).is_err());

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn volatile_transport_cache_does_not_change_genesis_membership() {
        let clean_path = path("baseline-cache-clean");
        let cache_path = path("baseline-cache-drift");
        {
            let config = test_config(&clean_path);
            drop(open_capture_authority(&config).expect("capture authority"));
            drop(AdmissionConsensusStore::open(&clean_path).expect("consensus store"));
            SqliteBudgetStore::open(&clean_path)
                .expect("budget store")
                .try_increment("capability-cache-baseline", 0, Some(4))
                .expect("seed authoritative usage");
        }
        Connection::open(&clean_path)
            .expect("checkpoint database")
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint clean database");
        std::fs::copy(&clean_path, &cache_path).expect("clone authoritative baseline");
        let cache = Connection::open(&cache_path).expect("cache database");
        cache
            .execute_batch(
                r#"
                UPDATE budget_replication_meta SET next_seq = 900 WHERE singleton = 1;
                INSERT INTO budget_import_floors (authority_id, floor_seq)
                VALUES ('https://history-only', 700);
                UPDATE budget_ack_head_watermark SET head_seq = 500 WHERE singleton = 1;
                INSERT INTO budget_origin_ack_heads (authority_id, head_seq)
                VALUES ('https://history-only', 500);
                INSERT INTO budget_abandoned_event_seqs (seq) VALUES (800);
                INSERT INTO budget_abandoned_event_ranges (start_seq, end_seq)
                VALUES (801, 899);
                "#,
            )
            .expect("seed volatile transport cache");

        let clean = capture_admission_genesis_projection(&clean_path).expect("clean genesis");
        let cache = capture_admission_genesis_projection(&cache_path).expect("cache genesis");
        assert_eq!(clean, cache);
        let members = vec![
            "https://node-a".to_string(),
            "https://node-b".to_string(),
            "https://node-c".to_string(),
        ];
        let clean_membership = AdmissionMembership::new_with_genesis(members.clone(), clean)
            .expect("clean membership");
        let cache_membership =
            AdmissionMembership::new_with_genesis(members, cache).expect("cache membership");
        assert_eq!(clean_membership.digest(), cache_membership.digest());

        let _ = std::fs::remove_file(clean_path);
        let _ = std::fs::remove_file(cache_path);
    }

    #[test]
    fn migrated_column_order_has_the_same_logical_genesis() {
        let clean_path = path("logical-schema-clean");
        let migrated_path = path("logical-schema-migrated");
        Connection::open(&migrated_path)
            .expect("migrated database")
            .execute_batch(
                r#"
                CREATE TABLE capability_grant_budgets (
                    capability_id TEXT NOT NULL,
                    grant_index INTEGER NOT NULL,
                    invocation_count INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    total_cost_exposed INTEGER NOT NULL DEFAULT 0,
                    total_cost_realized_spend INTEGER NOT NULL DEFAULT 0,
                    seq INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (capability_id, grant_index)
                );
                "#,
            )
            .expect("legacy physical column order");
        for database_path in [&clean_path, &migrated_path] {
            drop(
                open_capture_authority(&test_config(database_path)).expect("initialize authority"),
            );
            Connection::open(database_path)
                .expect("seed database")
                .execute(
                    r#"
                    INSERT INTO capability_grant_budgets (
                        capability_id, grant_index, invocation_count, updated_at, seq,
                        total_cost_exposed, total_cost_realized_spend
                    ) VALUES ('capability-logical-schema', 0, 2, 17, 4, 9, 3)
                    "#,
                    [],
                )
                .expect("seed logical row");
        }

        assert_eq!(
            capture_admission_genesis_projection(&clean_path).expect("clean genesis"),
            capture_admission_genesis_projection(&migrated_path).expect("migrated genesis")
        );

        let _ = std::fs::remove_file(clean_path);
        let _ = std::fs::remove_file(migrated_path);
    }

    #[test]
    fn genesis_capture_reads_one_atomic_sqlite_snapshot() {
        let database_path = path("atomic-genesis");
        drop(open_capture_authority(&test_config(&database_path)).expect("initialize authority"));
        Connection::open(&database_path)
            .expect("seed database")
            .execute(
                r#"
                INSERT INTO capability_grant_budgets (
                    capability_id, grant_index, invocation_count, updated_at, seq,
                    total_cost_exposed, total_cost_realized_spend
                ) VALUES ('capability-atomic-genesis', 0, 1, 1, 1, 0, 0)
                "#,
                [],
            )
            .expect("seed usage");

        let mut reader = Connection::open(&database_path).expect("reader");
        configure_connection(&reader).expect("reader pragmas");
        let transaction = reader
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .expect("reader transaction");
        let mut wrote = false;
        let projection =
            capture_admission_genesis_projection_from_connection(&transaction, |table_name| {
                if table_name == "admission_authority_meta" && !wrote {
                    Connection::open(&database_path)?.execute_batch(
                        r#"
                        PRAGMA journal_mode = WAL;
                        BEGIN IMMEDIATE;
                        UPDATE admission_authority_meta
                        SET authority_commit_index = 1 WHERE singleton = 1;
                        UPDATE capability_grant_budgets
                        SET invocation_count = 2 WHERE capability_id = 'capability-atomic-genesis';
                        COMMIT;
                        "#,
                    )?;
                    wrote = true;
                }
                Ok(())
            })
            .expect("atomic projection");
        transaction.commit().expect("reader commit");
        assert!(wrote);

        let authority_meta = projection
            .tables
            .iter()
            .find(|table| table.name == "admission_authority_meta")
            .expect("authority meta");
        let usage = projection
            .tables
            .iter()
            .find(|table| table.name == "capability_grant_budgets")
            .expect("budget usage");
        assert_eq!(authority_meta.rows[0][2], AdmissionGenesisValue::Integer(0));
        assert_eq!(usage.rows[0][2], AdmissionGenesisValue::Integer(1));

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn snapshot_seeds_fresh_replacement_from_nonempty_genesis() {
        let source_path = path("genesis-source");
        let target_path = path("genesis-target");
        for database_path in [&source_path, &target_path] {
            drop(
                open_capture_authority(&test_config(database_path))
                    .expect("initialize admission authority"),
            );
        }
        SqliteBudgetStore::open(&source_path)
            .expect("source budget store")
            .try_increment("capability-genesis", 0, Some(7))
            .expect("seed source genesis");

        let members = vec![
            "https://node-a".to_string(),
            "https://node-b".to_string(),
            "https://node-c".to_string(),
        ];
        let source_genesis =
            capture_admission_genesis_projection(&source_path).expect("source genesis");
        let source_membership =
            AdmissionMembership::new_with_genesis(members.clone(), source_genesis.clone())
                .expect("source membership");
        let source = AdmissionConsensusStore::open(&source_path).expect("source consensus");
        source
            .bind_membership(&source_membership)
            .expect("bind source membership");
        let election = source
            .begin_election(&source_membership, "https://node-a")
            .expect("source election");
        let entry = entry(&election, "replacement-replay");
        source
            .append_local(&election, &entry)
            .expect("source append");
        let commit_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: source_membership.digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: election.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };
        source
            .commit_local(&source_membership, &election, &commit_proof, |_, _, _| {
                Ok("{\"replayed\":true}".to_string())
            })
            .expect("source commit");
        let snapshot = source.snapshot().expect("source snapshot");

        let target_genesis =
            capture_admission_genesis_projection(&target_path).expect("empty target genesis");
        let target_membership = AdmissionMembership::new_with_genesis(members, target_genesis)
            .expect("target membership");
        let target = AdmissionConsensusStore::open(&target_path).expect("target consensus");
        target
            .bind_membership(&target_membership)
            .expect("bind initial target membership");
        let replayed = AtomicUsize::new(0);
        target
            .install_snapshot(&source_membership, &snapshot, |_, _, _| {
                replayed.fetch_add(1, Ordering::SeqCst);
                Ok("{\"replayed\":true}".to_string())
            })
            .expect("seed replacement from snapshot");
        assert_eq!(replayed.load(Ordering::SeqCst), 1);

        assert_eq!(
            capture_admission_genesis_projection(&target_path).expect("installed genesis"),
            source_genesis
        );
        assert_eq!(
            target.meta().expect("target meta").membership_digest,
            Some(source_membership.digest().to_string())
        );

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn partial_genesis_snapshot_is_rejected_before_target_mutation() {
        let source_path = path("partial-genesis-source");
        let target_path = path("partial-genesis-target");
        for database_path in [&source_path, &target_path] {
            drop(
                open_capture_authority(&test_config(database_path))
                    .expect("initialize admission authority"),
            );
        }
        SqliteBudgetStore::open(&source_path)
            .expect("source budget store")
            .try_increment("capability-partial-genesis", 0, Some(3))
            .expect("seed source genesis");
        let members = vec!["https://node-a".to_string(), "https://node-b".to_string()];
        let source_genesis =
            capture_admission_genesis_projection(&source_path).expect("source genesis");
        let source_membership = AdmissionMembership::new_with_genesis(members, source_genesis)
            .expect("source membership");
        let source = AdmissionConsensusStore::open(&source_path).expect("source store");
        source
            .bind_membership(&source_membership)
            .expect("bind source");
        let mut snapshot = source.snapshot().expect("snapshot");
        snapshot
            .genesis_projection
            .as_mut()
            .expect("snapshot genesis")
            .tables
            .pop();

        let target_before =
            capture_admission_genesis_projection(&target_path).expect("target before");
        let target = AdmissionConsensusStore::open(&target_path).expect("target store");
        assert!(target
            .install_snapshot(&source_membership, &snapshot, |_, _, _| {
                Ok("{}".to_string())
            })
            .is_err());
        assert_eq!(
            capture_admission_genesis_projection(&target_path).expect("target after"),
            target_before
        );
        assert_eq!(target.meta().expect("target meta").commit_index, 0);

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn snapshot_install_preserves_monotonic_node_local_term_and_vote() {
        let source_path = path("snapshot-hard-state-source");
        let retained_path = path("snapshot-hard-state-retained");
        let advanced_path = path("snapshot-hard-state-advanced");
        let membership = membership();
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        source.bind_membership(&membership).expect("bind source");
        source
            .begin_election(&membership, "https://node-a")
            .expect("source term one");
        let lower_snapshot = source.snapshot().expect("lower snapshot");

        let retained = AdmissionConsensusStore::open(&retained_path).expect("retained target");
        retained
            .bind_membership(&membership)
            .expect("bind retained target");
        retained
            .begin_election(&membership, "https://node-a")
            .expect("retained term one");
        retained
            .begin_election(&membership, "https://node-b")
            .expect("retained term two");
        retained
            .install_snapshot(&membership, &lower_snapshot, |_, _, _| Ok("{}".to_string()))
            .expect("install lower-term snapshot");
        let retained_meta = retained.meta().expect("retained meta");
        assert_eq!(retained_meta.current_term, 2);
        assert_eq!(retained_meta.voted_for.as_deref(), Some("https://node-b"));
        assert_eq!(retained_meta.last_log_index, 0);
        let retained_after_first_install = retained.snapshot().expect("retained snapshot");
        retained
            .install_snapshot(&membership, &lower_snapshot, |_, _, _| Ok("{}".to_string()))
            .expect("retry lower-term snapshot install");
        assert_eq!(
            retained.snapshot().expect("retained retry snapshot"),
            retained_after_first_install
        );

        source
            .begin_election(&membership, "https://node-b")
            .expect("source term two");
        source
            .begin_election(&membership, "https://node-a")
            .expect("source term three");
        let higher_snapshot = source.snapshot().expect("higher snapshot");
        let advanced = AdmissionConsensusStore::open(&advanced_path).expect("advanced target");
        advanced
            .bind_membership(&membership)
            .expect("bind advanced target");
        advanced
            .begin_election(&membership, "https://node-a")
            .expect("advanced term one");
        advanced
            .begin_election(&membership, "https://node-b")
            .expect("advanced term two");
        advanced
            .install_snapshot(
                &membership,
                &higher_snapshot,
                |_, _, _| Ok("{}".to_string()),
            )
            .expect("install higher-term snapshot");
        let advanced_meta = advanced.meta().expect("advanced meta");
        assert_eq!(advanced_meta.current_term, 3);
        assert_eq!(advanced_meta.voted_for, None);
        assert_eq!(advanced_meta.last_log_index, 0);

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(retained_path);
        let _ = std::fs::remove_file(advanced_path);
    }
