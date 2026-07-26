#[cfg(test)]
mod tests {
    use std::error::Error as StdError;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use chio_core::capability::aggregate_budget::{
        issue_aggregate_family_root, verify_aggregate_invocation_authority,
        verify_direct_aggregate_family_root, AggregateFamilyRootResolution,
        AggregateFamilyRootResolutionError, AggregateFamilyRootResolver,
        AggregateInvocationAuthorityError, AggregateInvocationBudget, AggregateInvocationScope,
        MAX_AGGREGATE_FAMILY_ROOT_ID_BYTES,
    };
    use chio_core::capability::attenuation::{
        compute_attenuation_witness, scope_hash, AttenuationProof, DelegationLink,
        DelegationLinkBody,
    };
    use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
    use chio_core::capability::token::{
        CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody,
    };
    use chio_core::{canonical_json_bytes, Keypair, PublicKey, SigningAlgorithm};
    use rusqlite::{params, Connection};
    use crate::SqliteReceiptStore;

    type TestResult = Result<(), Box<dyn StdError>>;

    fn tempdir() -> std::io::Result<tempfile::TempDir> {
        chio_test_support::private_fs::private_tempdir("aggregate-family-root-")
    }

    fn delegable_scope() -> ChioScope {
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "family-server".to_string(),
                tool_name: "family-tool".to_string(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        }
    }

    fn root_body(id: &str, issuer: PublicKey, subject: PublicKey) -> CapabilityTokenBody {
        CapabilityTokenBody {
            id: id.to_string(),
            issuer,
            subject,
            scope: delegable_scope(),
            issued_at: 1_000,
            expires_at: 2_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        }
    }

    fn family_root(
        id: &str,
        max_invocations: u32,
    ) -> Result<(Keypair, Keypair, CapabilityToken), chio_core::Error> {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let token = family_root_with_keys(id, max_invocations, &issuer, &subject)?;
        Ok((issuer, subject, token))
    }

    fn family_root_with_keys(
        id: &str,
        max_invocations: u32,
        issuer: &Keypair,
        subject: &Keypair,
    ) -> Result<CapabilityToken, chio_core::Error> {
        let token = issue_aggregate_family_root(
            root_body(id, issuer.public_key(), subject.public_key()),
            max_invocations,
            issuer,
        )?;
        Ok(token)
    }

    fn legacy_root(id: &str) -> Result<(Keypair, Keypair, CapabilityToken), chio_core::Error> {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let token = CapabilityToken::sign(
            root_body(id, issuer.public_key(), subject.public_key()),
            &issuer,
        )?;
        Ok((issuer, subject, token))
    }

    fn omitted_family_descendant(
        root: &CapabilityToken,
        root_subject: &Keypair,
        child_subject: &Keypair,
    ) -> Result<CapabilityToken, chio_core::Error> {
        let link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: root.id.clone(),
                delegator: root_subject.public_key(),
                delegatee: child_subject.public_key(),
                attenuations: Vec::new(),
                timestamp: 1_100,
                scope_hash: Some(scope_hash(&root.scope)?),
                aggregate_budget: None,
                cumulative_approval: None,
                aggregate_family_preservation: None,
            },
            root_subject,
        )?;
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "family-omission-child".to_string(),
                issuer: root_subject.public_key(),
                subject: child_subject.public_key(),
                scope: root.scope.clone(),
                issued_at: 1_100,
                expires_at: 1_900,
                delegation_chain: vec![link],
                aggregate_invocation_budget: None,
            },
            root_subject,
        )
    }

    fn row_count(path: &std::path::Path) -> Result<i64, rusqlite::Error> {
        let connection = Connection::open(path)?;
        connection.query_row(
            "SELECT COUNT(*) FROM chio_aggregate_family_roots",
            [],
            |row| row.get(0),
        )
    }

    fn replication_record(
        seq: u64,
        token: &CapabilityToken,
    ) -> Result<super::StoredAggregateFamilyRoot, Box<dyn StdError>> {
        let canonical_token_json = String::from_utf8(canonical_json_bytes(token)?)?;
        Ok(super::StoredAggregateFamilyRoot {
            seq,
            token_digest: super::aggregate_family_root_token_digest(
                canonical_token_json.as_bytes(),
            ),
            canonical_token_json,
        })
    }

    fn drop_update_guard(connection: &Connection) -> Result<(), rusqlite::Error> {
        connection.execute_batch("DROP TRIGGER chio_aggregate_family_roots_immutable_update;")
    }

    fn restore_update_guard(connection: &Connection) -> Result<(), rusqlite::Error> {
        connection.execute_batch(super::AGGREGATE_FAMILY_ROOT_UPDATE_TRIGGER_SQL)
    }

    #[test]
    fn aggregate_family_root_empty_database_is_missing_not_legacy() -> TestResult {
        let directory = tempdir()?;
        let store = SqliteReceiptStore::open(directory.path().join("receipts.db"))?;

        assert_eq!(
            store.resolve_aggregate_family_root("never-registered"),
            Err(AggregateFamilyRootResolutionError::Missing)
        );
        Ok(())
    }

    #[test]
    fn aggregate_family_root_family_record_reopens_and_resolves() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let (issuer, _subject, token) = family_root("family-reopen", 7)?;
        {
            let store = SqliteReceiptStore::open(&path)?;
            let status =
                store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
            assert_eq!(status, super::AggregateFamilyRootRecordStatus::Inserted);
        }

        let reopened = SqliteReceiptStore::open(&path)?;
        let resolved = reopened.resolve_aggregate_family_root(&token.id)?;
        match resolved {
            AggregateFamilyRootResolution::FamilyBound(root) => {
                assert_eq!(root.root_capability_id(), token.id);
                assert_eq!(root.max_invocations(), 7);
            }
            other => panic!("expected family-bound root, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn aggregate_family_root_explicit_legacy_record_reopens_and_resolves() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let (issuer, _subject, token) = legacy_root("legacy-reopen")?;
        {
            let store = SqliteReceiptStore::open(&path)?;
            store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        }

        let reopened = SqliteReceiptStore::open(&path)?;
        let resolved = reopened.resolve_aggregate_family_root(&token.id)?;
        match resolved {
            AggregateFamilyRootResolution::LegacyUnbound(root) => {
                assert_eq!(root.root_capability_id(), token.id);
                assert_eq!(root.root_subject(), &token.subject);
                assert_eq!(root.root_expires_at(), token.expires_at);
            }
            other => panic!("expected explicit legacy root, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn aggregate_family_root_descendant_omission_denies_after_restart() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let (issuer, root_subject, root) = family_root("family-omission-root", 5)?;
        let child_subject = Keypair::generate();
        let descendant = omitted_family_descendant(&root, &root_subject, &child_subject)?;
        {
            let store = SqliteReceiptStore::open(&path)?;
            store.record_aggregate_family_root(&root, &[issuer.public_key()], 1_100)?;
        }

        let reopened = SqliteReceiptStore::open(&path)?;
        let error = match verify_aggregate_invocation_authority(
            &descendant,
            &[],
            &[root_subject.public_key()],
            &reopened,
        ) {
            Err(error) => error,
            Ok(_) => panic!("family omission must deny after restart"),
        };
        assert!(matches!(
            error,
            AggregateInvocationAuthorityError::Verification(
                chio_core::Error::AttenuationViolation { .. }
            )
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_identical_retry_is_already_present() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-retry", 5)?;
        let trusted = [issuer.public_key()];

        assert_eq!(
            store.record_aggregate_family_root(&token, &trusted, 1_100)?,
            super::AggregateFamilyRootRecordStatus::Inserted
        );
        assert_eq!(
            store.record_aggregate_family_root(&token, &trusted, 1_100)?,
            super::AggregateFamilyRootRecordStatus::AlreadyPresent
        );
        assert_eq!(row_count(&path)?, 1);
        Ok(())
    }

    #[test]
    fn issued_aggregate_family_root_records_exact_lineage_idempotently() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-issued-lineage", 5)?;
        let trusted = [issuer.public_key()];

        assert_eq!(
            store.record_issued_aggregate_family_root(&token, &trusted, 1_100)?,
            super::AggregateFamilyRootRecordStatus::Inserted
        );
        assert_eq!(
            store.record_issued_aggregate_family_root(&token, &trusted, 1_200)?,
            super::AggregateFamilyRootRecordStatus::AlreadyPresent
        );

        let lineage = match store.get_lineage(&token.id)? {
            Some(lineage) => lineage,
            None => panic!("issued root lineage is missing"),
        };
        assert_eq!(lineage.capability_id, token.id);
        assert_eq!(lineage.subject_key, token.subject.to_hex());
        assert_eq!(lineage.issuer_key, token.issuer.to_hex());
        assert_eq!(lineage.issued_at, token.issued_at);
        assert_eq!(lineage.expires_at, token.expires_at);
        assert_eq!(lineage.grants_json, serde_json::to_string(&token.scope)?);
        assert_eq!(lineage.delegation_depth, 0);
        assert_eq!(lineage.parent_capability_id, None);
        assert_eq!(row_count(&path)?, 1);
        Ok(())
    }

    #[test]
    fn issued_aggregate_family_root_lineage_failure_rolls_back_root() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "CREATE TRIGGER reject_issued_root_lineage
             BEFORE INSERT ON capability_lineage
             BEGIN
                 SELECT RAISE(ABORT, 'lineage rejected');
             END;",
        )?;
        let (issuer, _subject, token) = family_root("family-lineage-rollback", 5)?;

        let error = match store.record_issued_aggregate_family_root(
            &token,
            &[issuer.public_key()],
            1_100,
        ) {
            Err(error) => error,
            Ok(_) => panic!("lineage rejection must fail root capture"),
        };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Unavailable(_)
        ));
        assert_eq!(row_count(&path)?, 0);
        assert!(store.get_lineage(&token.id)?.is_none());
        Ok(())
    }

    #[test]
    fn issued_aggregate_family_root_conflicting_lineage_rolls_back_root() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-lineage-conflict", 5)?;
        let conflicting_subject = Keypair::generate();
        let conflicting = CapabilityToken::sign(
            root_body(
                &token.id,
                issuer.public_key(),
                conflicting_subject.public_key(),
            ),
            &issuer,
        )?;
        store.record_capability_snapshot(&conflicting, None)?;

        let error = match store.record_issued_aggregate_family_root(
            &token,
            &[issuer.public_key()],
            1_100,
        ) {
            Err(error) => error,
            Ok(_) => panic!("conflicting lineage must fail root capture"),
        };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Conflict { ref root_capability_id }
                if root_capability_id == &token.id
        ));
        assert_eq!(row_count(&path)?, 0);
        let lineage = match store.get_lineage(&token.id)? {
            Some(lineage) => lineage,
            None => panic!("conflicting lineage was removed"),
        };
        assert_eq!(lineage.subject_key, conflicting.subject.to_hex());
        Ok(())
    }

    #[test]
    fn aggregate_family_root_replication_round_trips_full_tokens_in_order() -> TestResult {
        let source_directory = tempdir()?;
        let source_path = source_directory.path().join("source.db");
        let source = SqliteReceiptStore::open(&source_path)?;
        let (family_issuer, _family_subject, family) = family_root("replicated-family-root", 5)?;
        let (legacy_issuer, _legacy_subject, legacy) = legacy_root("replicated-legacy-root")?;
        let trusted = [family_issuer.public_key(), legacy_issuer.public_key()];
        source.record_aggregate_family_root(&family, &trusted, 1_100)?;
        source.record_aggregate_family_root(&legacy, &trusted, 1_200)?;

        assert_eq!(source.max_aggregate_family_root_seq()?, 2);
        let first = source.list_aggregate_family_roots_after_seq(0, 1)?;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].seq, 1);
        assert_eq!(
            serde_json::from_str::<CapabilityToken>(&first[0].canonical_token_json)?.id,
            family.id
        );
        let second = source.list_aggregate_family_roots_after_seq(first[0].seq, 8)?;
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].seq, 2);
        assert_eq!(
            serde_json::from_str::<CapabilityToken>(&second[0].canonical_token_json)?.id,
            legacy.id
        );

        let mut records = first;
        records.extend(second);
        let target_directory = tempdir()?;
        let target_path = target_directory.path().join("target.db");
        {
            let target = SqliteReceiptStore::open(&target_path)?;
            assert_eq!(
                target.import_aggregate_family_roots(&records, &trusted, 1_300)?,
                vec![
                    super::AggregateFamilyRootRecordStatus::Inserted,
                    super::AggregateFamilyRootRecordStatus::Inserted,
                ]
            );
        }

        let reopened = SqliteReceiptStore::open(&target_path)?;
        assert!(matches!(
            reopened.resolve_aggregate_family_root(&family.id),
            Ok(AggregateFamilyRootResolution::FamilyBound(root))
                if root.max_invocations() == 5
        ));
        assert!(matches!(
            reopened.resolve_aggregate_family_root(&legacy.id),
            Ok(AggregateFamilyRootResolution::LegacyUnbound(_))
        ));
        let reopened_ids = reopened
            .list_aggregate_family_roots_after_seq(0, 8)?
            .into_iter()
            .map(|record| {
                serde_json::from_str::<CapabilityToken>(&record.canonical_token_json)
                    .map(|token| token.id)
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(reopened_ids, vec![family.id, legacy.id]);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_registration_enforces_id_byte_bound() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("registration-bound.db");
        let store = SqliteReceiptStore::open(&path)?;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let trusted = [issuer.public_key()];

        let accepted_id = "a".repeat(MAX_AGGREGATE_FAMILY_ROOT_ID_BYTES);
        let accepted = family_root_with_keys(&accepted_id, 5, &issuer, &subject)?;
        assert_eq!(
            store.record_aggregate_family_root(&accepted, &trusted, 1_100)?,
            super::AggregateFamilyRootRecordStatus::Inserted
        );

        for rejected_id in [
            String::new(),
            "b".repeat(MAX_AGGREGATE_FAMILY_ROOT_ID_BYTES + 1),
        ] {
            let rejected = family_root_with_keys(&rejected_id, 5, &issuer, &subject)?;
            assert!(matches!(
                store.record_aggregate_family_root(&rejected, &trusted, 1_100),
                Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
            ));
        }
        assert_eq!(row_count(&path)?, 1);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_import_enforces_id_byte_bound() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("import-bound.db");
        let store = SqliteReceiptStore::open(&path)?;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let trusted = [issuer.public_key()];

        let accepted_id = "a".repeat(MAX_AGGREGATE_FAMILY_ROOT_ID_BYTES);
        let accepted = family_root_with_keys(&accepted_id, 5, &issuer, &subject)?;
        assert_eq!(
            store.import_aggregate_family_roots(
                &[replication_record(1, &accepted)?],
                &trusted,
                1_100,
            )?,
            vec![super::AggregateFamilyRootRecordStatus::Inserted]
        );

        for (seq, rejected_id) in [
            (2, String::new()),
            (3, "b".repeat(MAX_AGGREGATE_FAMILY_ROOT_ID_BYTES + 1)),
        ] {
            let rejected = family_root_with_keys(&rejected_id, 5, &issuer, &subject)?;
            assert!(matches!(
                store.import_aggregate_family_roots(
                    &[replication_record(seq, &rejected)?],
                    &trusted,
                    1_100,
                ),
                Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
            ));
        }
        assert_eq!(row_count(&path)?, 1);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_lookup_returns_token_and_head_from_one_snapshot() -> TestResult {
        let directory = tempdir()?;
        let store = SqliteReceiptStore::open(directory.path().join("roots.db"))?;
        let (issuer, _subject, token) = family_root("lookup-family-root", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;

        let found = store.lookup_aggregate_family_root(&token.id)?;
        assert_eq!(found.high_watermark, 1);
        let record = match found.record {
            Some(record) => record,
            None => panic!("recorded root must be returned"),
        };
        assert_eq!(record.seq, 1);
        assert_eq!(
            serde_json::from_str::<CapabilityToken>(&record.canonical_token_json)?.id,
            token.id
        );
        assert_eq!(
            record.token_digest,
            super::aggregate_family_root_token_digest(record.canonical_token_json.as_bytes())
        );

        let missing = store.lookup_aggregate_family_root("missing-root")?;
        assert_eq!(missing.high_watermark, 1);
        assert!(missing.record.is_none());
        Ok(())
    }

    #[test]
    fn aggregate_family_root_replication_preserves_the_exact_canonical_artifact() -> TestResult {
        let source_directory = tempdir()?;
        let source = SqliteReceiptStore::open(source_directory.path().join("source.db"))?;
        let (issuer, _subject, token) = family_root("replication-canonical-root", 5)?;
        source.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let exported = source.list_aggregate_family_roots_after_seq(0, 1)?;
        let original = match exported.first() {
            Some(record) => record,
            None => panic!("source root must be exported"),
        };

        let mut value = serde_json::to_value(&token)?;
        let object = match value.as_object_mut() {
            Some(object) => object,
            None => panic!("capability token must serialize as an object"),
        };
        object.insert("unknownRootField".to_string(), serde_json::json!(true));
        let canonical_with_unknown = chio_core::canonicalize(&value)?;
        let noncanonical = serde_json::to_string_pretty(&token)?;
        let duplicate_id = format!(
            "{{\"id\":\"duplicate\",{}",
            original
                .canonical_token_json
                .strip_prefix('{')
                .unwrap_or(&original.canonical_token_json)
        );
        let cases = [
            super::StoredAggregateFamilyRoot {
                seq: 1,
                token_digest: super::aggregate_family_root_token_digest(noncanonical.as_bytes()),
                canonical_token_json: noncanonical,
            },
            super::StoredAggregateFamilyRoot {
                seq: 1,
                token_digest: super::aggregate_family_root_token_digest(
                    canonical_with_unknown.as_bytes(),
                ),
                canonical_token_json: canonical_with_unknown,
            },
            super::StoredAggregateFamilyRoot {
                seq: 1,
                token_digest: super::aggregate_family_root_token_digest(duplicate_id.as_bytes()),
                canonical_token_json: duplicate_id,
            },
            super::StoredAggregateFamilyRoot {
                seq: 1,
                token_digest: "0".repeat(64),
                canonical_token_json: original.canonical_token_json.clone(),
            },
        ];

        let target_directory = tempdir()?;
        let target_path = target_directory.path().join("target.db");
        let target = SqliteReceiptStore::open(&target_path)?;
        for record in cases {
            assert!(matches!(
                target.import_aggregate_family_roots(&[record], &[issuer.public_key()], 1_200),
                Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
            ));
            assert_eq!(row_count(&target_path)?, 0);
        }
        Ok(())
    }

    #[test]
    fn aggregate_family_root_replication_rejects_unrepresentable_pagination() -> TestResult {
        let directory = tempdir()?;
        let store = SqliteReceiptStore::open(directory.path().join("roots.db"))?;

        assert!(matches!(
            store.list_aggregate_family_roots_after_seq(u64::MAX, 1),
            Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
        ));
        assert!(matches!(
            store.list_aggregate_family_roots_after_seq(0, usize::MAX),
            Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_replication_authenticates_batch_before_mutation() -> TestResult {
        let source_directory = tempdir()?;
        let source = SqliteReceiptStore::open(source_directory.path().join("source.db"))?;
        let (trusted_issuer, _trusted_subject, trusted_root) =
            family_root("replication-trusted-root", 5)?;
        let (untrusted_issuer, _untrusted_subject, untrusted_root) =
            family_root("replication-untrusted-root", 6)?;
        source.record_aggregate_family_root(
            &trusted_root,
            &[trusted_issuer.public_key()],
            1_100,
        )?;
        source.record_aggregate_family_root(
            &untrusted_root,
            &[untrusted_issuer.public_key()],
            1_200,
        )?;
        let records = source.list_aggregate_family_roots_after_seq(0, 8)?;

        let target_directory = tempdir()?;
        let target_path = target_directory.path().join("target.db");
        let target = SqliteReceiptStore::open(&target_path)?;
        let error = match target.import_aggregate_family_roots(
            &records,
            &[trusted_issuer.public_key()],
            1_300,
        ) {
            Err(error) => error,
            Ok(_) => panic!("untrusted replicated root must fail the complete batch"),
        };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Authentication(_)
        ));
        assert_eq!(row_count(&target_path)?, 0);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_replication_conflict_retains_follower_state() -> TestResult {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let original = family_root_with_keys("replication-conflict", 5, &issuer, &subject)?;
        let conflict = family_root_with_keys("replication-conflict", 6, &issuer, &subject)?;

        let source_directory = tempdir()?;
        let source = SqliteReceiptStore::open(source_directory.path().join("source.db"))?;
        source.record_aggregate_family_root(&conflict, &[issuer.public_key()], 1_200)?;
        let records = source.list_aggregate_family_roots_after_seq(0, 8)?;

        let target_directory = tempdir()?;
        let target = SqliteReceiptStore::open(target_directory.path().join("target.db"))?;
        target.record_aggregate_family_root(&original, &[issuer.public_key()], 1_100)?;
        let error =
            match target.import_aggregate_family_roots(&records, &[issuer.public_key()], 1_300) {
                Err(error) => error,
                Ok(_) => panic!("conflicting replicated root must fail"),
            };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Conflict { .. }
        ));
        assert!(matches!(
            target.resolve_aggregate_family_root(&original.id),
            Ok(AggregateFamilyRootResolution::FamilyBound(root))
                if root.max_invocations() == 5
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_explicit_default_algorithm_is_canonical_retry() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-default-algorithm", 5)?;
        let mut explicit_default = token.clone();
        explicit_default.algorithm = Some(SigningAlgorithm::Ed25519);
        let trusted = [issuer.public_key()];

        assert_eq!(
            store.record_aggregate_family_root(&token, &trusted, 1_100)?,
            super::AggregateFamilyRootRecordStatus::Inserted
        );
        assert_eq!(
            store.record_aggregate_family_root(&explicit_default, &trusted, 1_100)?,
            super::AggregateFamilyRootRecordStatus::AlreadyPresent
        );
        assert_eq!(row_count(&path)?, 1);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_conflicting_valid_max_retains_original() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let original = family_root_with_keys("family-conflict", 5, &issuer, &subject)?;
        let conflict = family_root_with_keys("family-conflict", 6, &issuer, &subject)?;
        let trusted = [issuer.public_key()];
        store.record_aggregate_family_root(&original, &trusted, 1_100)?;

        let error = match store.record_aggregate_family_root(&conflict, &trusted, 1_100) {
            Err(error) => error,
            Ok(_) => panic!("changed maximum must conflict"),
        };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Conflict { ref root_capability_id }
                if root_capability_id == "family-conflict"
        ));
        match store.resolve_aggregate_family_root("family-conflict")? {
            AggregateFamilyRootResolution::FamilyBound(root) => {
                assert_eq!(root.max_invocations(), 5);
            }
            other => panic!("expected original family root, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn aggregate_family_root_two_store_handles_race_first_writer() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let first_store = SqliteReceiptStore::open(&path)?;
        let second_store = SqliteReceiptStore::open(&path)?;
        let (first_issuer, _first_subject, first_token) = family_root("family-race", 5)?;
        let (second_issuer, _second_subject, second_token) = family_root("family-race", 6)?;
        let barrier = Arc::new(Barrier::new(2));
        let first_barrier = Arc::clone(&barrier);
        let second_barrier = Arc::clone(&barrier);
        let first_key = first_issuer.public_key();
        let second_key = second_issuer.public_key();
        let first = thread::spawn(move || {
            first_barrier.wait();
            first_store.record_aggregate_family_root(&first_token, &[first_key], 1_100)
        });
        let second = thread::spawn(move || {
            second_barrier.wait();
            second_store.record_aggregate_family_root(&second_token, &[second_key], 1_100)
        });
        let first_result = match first.join() {
            Ok(result) => result,
            Err(_) => panic!("first aggregate family-root writer panicked"),
        };
        let second_result = match second.join() {
            Ok(result) => result,
            Err(_) => panic!("second aggregate family-root writer panicked"),
        };
        assert!(matches!(
            (first_result, second_result),
            (
                Ok(super::AggregateFamilyRootRecordStatus::Inserted),
                Err(super::AggregateFamilyRootStoreError::Conflict { .. })
            ) | (
                Err(super::AggregateFamilyRootStoreError::Conflict { .. }),
                Ok(super::AggregateFamilyRootRecordStatus::Inserted)
            )
        ));
        assert_eq!(row_count(&path)?, 1);
        let resolver = SqliteReceiptStore::open(&path)?;
        match resolver.resolve_aggregate_family_root("family-race")? {
            AggregateFamilyRootResolution::FamilyBound(root) => {
                assert!(matches!(root.max_invocations(), 5 | 6));
            }
            other => panic!("expected the immutable race winner, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn aggregate_family_root_insert_or_replace_cannot_bypass_immutability() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-replace-guard", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let connection = Connection::open(&path)?;

        let replaced = connection.execute(
            r#"
            INSERT OR REPLACE INTO chio_aggregate_family_roots (
                seq, root_capability_id, root_kind, canonical_token_json,
                token_digest, issuer_key, subject_key, root_scope_hash,
                issued_at, expires_at, family_binding_digest, family_owner,
                family_max_invocations, recorded_at
            )
            SELECT
                seq, root_capability_id, root_kind, canonical_token_json,
                token_digest, issuer_key, subject_key, root_scope_hash,
                issued_at, expires_at, family_binding_digest, family_owner,
                family_max_invocations, recorded_at + 1
            FROM chio_aggregate_family_roots
            WHERE root_capability_id = ?1
            "#,
            params![token.id],
        );
        assert!(replaced.is_err());
        assert_eq!(row_count(&path)?, 1);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_update_and_delete_triggers_are_immutable() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-immutable", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let connection = Connection::open(&path)?;

        assert!(connection
            .execute(
                "UPDATE chio_aggregate_family_roots SET recorded_at = 1200 WHERE root_capability_id = ?1",
                params![token.id],
            )
            .is_err());
        assert!(connection
            .execute(
                "DELETE FROM chio_aggregate_family_roots WHERE root_capability_id = ?1",
                params![token.id],
            )
            .is_err());
        assert_eq!(row_count(&path)?, 1);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_untrusted_signer_rejects_before_mutation() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (_issuer, _subject, token) = family_root("family-untrusted", 5)?;
        let untrusted = Keypair::generate();

        let error =
            match store.record_aggregate_family_root(&token, &[untrusted.public_key()], 1_100) {
                Err(error) => error,
                Ok(_) => panic!("untrusted signer must reject"),
            };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Authentication(_)
        ));
        assert_eq!(row_count(&path)?, 0);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_algorithm_envelope_mismatch_rejects_before_mutation() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, mut token) = legacy_root("legacy-algorithm-mismatch")?;
        token.algorithm = Some(SigningAlgorithm::P256);

        let error = match store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)
        {
            Err(error) => error,
            Ok(_) => panic!("unsigned algorithm envelope mismatch must reject"),
        };

        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Authentication(_)
        ));
        assert_eq!(row_count(&path)?, 0);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_batch_conflict_is_all_or_nothing() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let original = family_root_with_keys("family-batch-existing", 5, &issuer, &subject)?;
        let conflict = family_root_with_keys("family-batch-existing", 6, &issuer, &subject)?;
        let (new_issuer, _new_subject, new_root) = family_root("family-batch-new", 4)?;
        let trusted = [issuer.public_key(), new_issuer.public_key()];
        store.record_aggregate_family_root(&original, &trusted, 1_100)?;

        let error = match store.record_aggregate_family_roots(
            &[new_root.clone(), conflict],
            &trusted,
            1_100,
        ) {
            Err(error) => error,
            Ok(_) => panic!("batch conflict must roll back every insert"),
        };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Conflict { .. }
        ));
        assert_eq!(
            store.resolve_aggregate_family_root(&new_root.id),
            Err(AggregateFamilyRootResolutionError::Missing)
        );
        assert_eq!(row_count(&path)?, 1);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_batch_authenticates_all_before_mutation() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (trusted_issuer, _trusted_subject, trusted_root) =
            family_root("family-batch-trusted", 4)?;
        let (_untrusted_issuer, _untrusted_subject, untrusted_root) =
            family_root("family-batch-untrusted", 4)?;

        let error = match store.record_aggregate_family_roots(
            &[trusted_root, untrusted_root],
            &[trusted_issuer.public_key()],
            1_100,
        ) {
            Err(error) => error,
            Ok(_) => panic!("untrusted batch member must reject before the write transaction"),
        };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Authentication(_)
        ));
        assert_eq!(row_count(&path)?, 0);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_batch_conflicting_duplicate_ids_roll_back() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let first = family_root_with_keys("family-batch-duplicate", 5, &issuer, &subject)?;
        let second = family_root_with_keys("family-batch-duplicate", 6, &issuer, &subject)?;

        let error = match store.record_aggregate_family_roots(
            &[first, second],
            &[issuer.public_key()],
            1_100,
        ) {
            Err(error) => error,
            Ok(_) => panic!("conflicting duplicate IDs in one batch must roll back"),
        };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Conflict { .. }
        ));
        assert_eq!(row_count(&path)?, 0);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_malformed_canonical_json_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-malformed", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET canonical_token_json = '{' WHERE root_capability_id = ?1",
            params![token.id],
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root(&token.id),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_noncanonical_json_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-noncanonical", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let noncanonical = serde_json::to_string_pretty(&token)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET canonical_token_json = ?1 WHERE root_capability_id = ?2",
            params![noncanonical, token.id],
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root(&token.id),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_canonical_unknown_token_field_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-unknown-field", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let mut value = serde_json::to_value(&token)?;
        let object = match value.as_object_mut() {
            Some(object) => object,
            None => panic!("capability token must serialize as an object"),
        };
        object.insert("unknownRootField".to_string(), serde_json::json!(true));
        let canonical_with_unknown = chio_core::canonicalize(&value)?;
        let matching_digest =
            super::aggregate_family_root_token_digest(canonical_with_unknown.as_bytes());
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET canonical_token_json = ?1, token_digest = ?2 WHERE root_capability_id = ?3",
            params![canonical_with_unknown, matching_digest, token.id],
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root(&token.id),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_explicit_default_algorithm_row_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-explicit-default-row", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let mut value = serde_json::to_value(&token)?;
        let object = match value.as_object_mut() {
            Some(object) => object,
            None => panic!("capability token must serialize as an object"),
        };
        object.insert("algorithm".to_string(), serde_json::json!("ed25519"));
        let explicit_default = chio_core::canonicalize(&value)?;
        let matching_digest =
            super::aggregate_family_root_token_digest(explicit_default.as_bytes());
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET canonical_token_json = ?1, token_digest = ?2 WHERE root_capability_id = ?3",
            params![explicit_default, matching_digest, token.id],
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root(&token.id),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_token_digest_mismatch_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-digest-corrupt", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET token_digest = ?1 WHERE root_capability_id = ?2",
            params!["0".repeat(64), token.id],
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root(&token.id),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_projection_column_mismatch_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-column-corrupt", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET subject_key = issuer_key WHERE root_capability_id = ?1",
            params![token.id],
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root(&token.id),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_same_token_corrupt_projection_is_not_idempotent() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-corrupt-retry", 5)?;
        let trusted = [issuer.public_key()];
        store.record_aggregate_family_root(&token, &trusted, 1_100)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET subject_key = issuer_key WHERE root_capability_id = ?1",
            params![token.id],
        )?;
        restore_update_guard(&connection)?;

        assert!(matches!(
            store.record_aggregate_family_root(&token, &trusted, 1_100),
            Err(super::AggregateFamilyRootStoreError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_kind_mismatch_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-kind-corrupt", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET root_kind = 'legacy_unbound', family_binding_digest = NULL, family_owner = NULL, family_max_invocations = NULL WHERE root_capability_id = ?1",
            params![token.id],
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root(&token.id),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_invalid_time_shape_and_integer_overflow_do_not_mutate() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let mut invalid_time_body = root_body(
            "legacy-invalid-time",
            issuer.public_key(),
            subject.public_key(),
        );
        invalid_time_body.issued_at = 2_000;
        invalid_time_body.expires_at = 2_000;
        let invalid_time = CapabilityToken::sign(invalid_time_body, &issuer)?;
        let mut overflow_body = root_body(
            "legacy-overflow-time",
            issuer.public_key(),
            subject.public_key(),
        );
        overflow_body.issued_at = i64::MAX as u64 + 1;
        overflow_body.expires_at = i64::MAX as u64 + 2;
        let overflow = CapabilityToken::sign(overflow_body, &issuer)?;
        let trusted = [issuer.public_key()];

        for candidate in [&invalid_time, &overflow] {
            assert!(matches!(
                store.record_aggregate_family_root(candidate, &trusted, 1_100),
                Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
            ));
        }
        let (valid_issuer, _valid_subject, valid) = legacy_root("legacy-recorded-at-overflow")?;
        assert!(matches!(
            store.record_aggregate_family_root(&valid, &[valid_issuer.public_key()], u64::MAX),
            Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
        ));
        assert_eq!(row_count(&path)?, 0);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_rejects_nonroot_shapes() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let nondelegable = CapabilityToken::sign(
            CapabilityTokenBody {
                scope: ChioScope::default(),
                ..root_body(
                    "plain-nondelegable",
                    issuer.public_key(),
                    subject.public_key(),
                )
            },
            &issuer,
        )?;
        let capability_scoped = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "capability-scoped-not-root".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 1_000,
                expires_at: 2_000,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: Some(AggregateInvocationBudget {
                    scope: AggregateInvocationScope::Capability,
                    max_invocations: 5,
                    root_binding: None,
                }),
            },
            &issuer,
        )?;
        let nondelegable_family = issue_aggregate_family_root(
            CapabilityTokenBody {
                id: "family-nondelegable".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 1_000,
                expires_at: 2_000,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            5,
            &issuer,
        )?;
        let delegable_family =
            family_root_with_keys("delegated-token-parent", 5, &issuer, &subject)?;
        let child_subject = Keypair::generate();
        let delegated = omitted_family_descendant(&delegable_family, &subject, &child_subject)?;
        let legacy_proof = AttenuationProof {
            parent_scope_hash: scope_hash(&delegable_family.scope)?,
            child_scope_hash: scope_hash(&delegable_family.scope)?,
            normalized_subset_proof: compute_attenuation_witness(
                &delegable_family.scope,
                &delegable_family.scope,
            )?,
            aggregate_family_preservation: None,
        };
        let constrained_legacy = CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: root_body(
                    "legacy-constrained-root",
                    issuer.public_key(),
                    subject.public_key(),
                ),
                caveats: Vec::new(),
                scope_attenuations: Vec::new(),
                attenuation_proof: legacy_proof,
                budget_share_bps: Some(3_000),
            },
            &issuer,
        )?;
        let verified_family =
            verify_direct_aggregate_family_root(&delegable_family, &[issuer.public_key()])?;
        let family_proof = AttenuationProof {
            parent_scope_hash: scope_hash(&delegable_family.scope)?,
            child_scope_hash: scope_hash(&delegable_family.scope)?,
            normalized_subset_proof: compute_attenuation_witness(
                &delegable_family.scope,
                &delegable_family.scope,
            )?,
            aggregate_family_preservation: Some(verified_family.preservation_evidence()),
        };
        let constrained_family = CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: delegable_family.body(),
                caveats: Vec::new(),
                scope_attenuations: Vec::new(),
                attenuation_proof: family_proof,
                budget_share_bps: Some(3_000),
            },
            &issuer,
        )?;
        assert!(constrained_legacy.verify_signature()?);
        assert!(
            verify_direct_aggregate_family_root(&constrained_family, &[issuer.public_key()])
                .is_ok()
        );
        let trusted = [issuer.public_key(), subject.public_key()];

        for candidate in [
            &nondelegable,
            &capability_scoped,
            &nondelegable_family,
            &delegated,
            &constrained_legacy,
            &constrained_family,
        ] {
            assert!(matches!(
                store.record_aggregate_family_root(candidate, &trusted, 1_100),
                Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
            ));
        }
        assert_eq!(row_count(&path)?, 0);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_rejects_token_above_transport_bound() -> TestResult {
        let directory = tempdir()?;
        let store = SqliteReceiptStore::open(directory.path().join("receipts.db"))?;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let mut body = root_body("oversized-root", issuer.public_key(), subject.public_key());
        body.scope.grants[0].server_id =
            "x".repeat(super::MAX_AGGREGATE_FAMILY_ROOT_TOKEN_BYTES + 1);
        let token = CapabilityToken::sign(body, &issuer)?;

        assert!(matches!(
            store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100),
            Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_missing_table_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "DROP TRIGGER chio_aggregate_family_roots_immutable_update;
             DROP TRIGGER chio_aggregate_family_roots_immutable_delete;
             DROP TABLE chio_aggregate_family_roots;",
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root("malformed-table"),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_missing_immutability_trigger_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;

        assert!(matches!(
            store.resolve_aggregate_family_root("trigger-missing"),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_noop_trigger_name_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute_batch(
            "CREATE TRIGGER chio_aggregate_family_roots_immutable_update
             BEFORE UPDATE ON chio_aggregate_family_roots
             BEGIN SELECT 1; END;",
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root("trigger-squatted"),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_unexpected_trigger_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "CREATE TRIGGER chio_aggregate_family_roots_unexpected_insert
             AFTER INSERT ON chio_aggregate_family_roots
             BEGIN SELECT 1; END;",
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root("unexpected-trigger"),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_dropped_table_does_not_recreate_on_restart() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        {
            let store = SqliteReceiptStore::open(&path)?;
            let connection = Connection::open(&path)?;
            connection.execute_batch("DROP TABLE chio_aggregate_family_roots;")?;
            drop(store);
        }

        assert!(SqliteReceiptStore::open(&path).is_err());
        Ok(())
    }

    #[test]
    fn aggregate_family_root_dropped_tables_do_not_erase_migration_history() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        {
            let store = SqliteReceiptStore::open(&path)?;
            let connection = Connection::open(&path)?;
            connection.execute_batch(
                "DROP TABLE chio_aggregate_family_roots;
                 DROP TABLE chio_aggregate_family_root_schema;",
            )?;
            drop(store);
        }

        assert!(SqliteReceiptStore::open(&path).is_err());
        assert!(SqliteReceiptStore::open_existing(&path).is_err());
        Ok(())
    }

    #[test]
    fn aggregate_family_root_open_existing_runs_first_migration() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        {
            let store = SqliteReceiptStore::open(&path)?;
            let connection = Connection::open(&path)?;
            connection.execute_batch(
                "DROP TABLE chio_aggregate_family_roots;
                 DROP TABLE chio_aggregate_family_root_schema;
                 DELETE FROM chio_module_schema_version
                 WHERE module = 'aggregate_family_root_authority';",
            )?;
            drop(store);
        }

        let reopened = SqliteReceiptStore::open_existing(&path)?;
        assert_eq!(
            reopened.resolve_aggregate_family_root("not-registered"),
            Err(AggregateFamilyRootResolutionError::Missing)
        );
        Ok(())
    }

    #[test]
    fn aggregate_family_root_existing_point_lookup_never_runs_migration() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        {
            let store = SqliteReceiptStore::open(&path)?;
            let connection = Connection::open(&path)?;
            connection.execute_batch(
                "DROP TABLE chio_aggregate_family_roots;
                 DROP TABLE chio_aggregate_family_root_schema;
                 DELETE FROM chio_module_schema_version
                 WHERE module = 'aggregate_family_root_authority';",
            )?;
            drop(store);
        }

        assert!(matches!(
            SqliteReceiptStore::lookup_existing_aggregate_family_root(&path, "missing"),
            Err(super::AggregateFamilyRootStoreError::Corrupt(_))
        ));
        assert!(SqliteReceiptStore::open_existing_strict(&path).is_err());
        let connection = Connection::open(&path)?;
        let object_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE name IN (
                'chio_aggregate_family_roots',
                'chio_aggregate_family_root_schema'
             )",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(object_count, 0);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_rejects_oversized_stored_text_before_decoding() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _, token) = legacy_root("oversized-stored-root")?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "DROP TRIGGER chio_aggregate_family_roots_immutable_update;
             UPDATE chio_aggregate_family_roots
             SET canonical_token_json = CAST(zeroblob(524289) AS TEXT)
             WHERE root_capability_id = 'oversized-stored-root';",
        )?;
        connection.execute_batch(super::AGGREGATE_FAMILY_ROOT_UPDATE_TRIGGER_SQL)?;

        assert!(matches!(
            store.lookup_aggregate_family_root(&token.id),
            Err(super::AggregateFamilyRootStoreError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_ignores_database_wide_user_version() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        {
            let store = SqliteReceiptStore::open(&path)?;
            let connection = Connection::open(&path)?;
            connection.execute_batch("PRAGMA user_version = 73;")?;
            drop(store);
        }

        let reopened = SqliteReceiptStore::open_existing(&path)?;
        assert_eq!(
            reopened.resolve_aggregate_family_root("not-registered"),
            Err(AggregateFamilyRootResolutionError::Missing)
        );
        Ok(())
    }

    #[test]
    fn aggregate_family_root_open_existing_rejects_tampered_schema() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        {
            let store = SqliteReceiptStore::open(&path)?;
            let connection = Connection::open(&path)?;
            drop_update_guard(&connection)?;
            drop(store);
        }

        assert!(SqliteReceiptStore::open_existing(&path).is_err());
        Ok(())
    }

    #[test]
    fn aggregate_family_root_malformed_sqlite_schema_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "PRAGMA writable_schema = ON;
             UPDATE sqlite_master
             SET sql = 'malformed'
             WHERE type = 'table' AND name = 'chio_aggregate_family_roots';
             PRAGMA writable_schema = OFF;
             PRAGMA schema_version = 424242;",
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root("corrupt-schema"),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_busy_writer_is_unavailable() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        store.writer_handle().run_write(|connection| {
            connection.execute_batch("PRAGMA busy_timeout = 0;")?;
            Ok(())
        })?;
        let lock = Connection::open(&path)?;
        lock.execute_batch("PRAGMA busy_timeout = 0; BEGIN IMMEDIATE;")?;
        let (issuer, _subject, token) = legacy_root("legacy-busy-store")?;

        assert!(matches!(
            store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100),
            Err(super::AggregateFamilyRootStoreError::Unavailable(_))
        ));
        lock.execute_batch("ROLLBACK;")?;
        Ok(())
    }

    #[test]
    fn aggregate_family_root_sqlite_error_classes_preserve_semantics() {
        for code in [
            rusqlite::ffi::SQLITE_BUSY,
            rusqlite::ffi::SQLITE_LOCKED,
            rusqlite::ffi::SQLITE_IOERR,
            rusqlite::ffi::SQLITE_CANTOPEN,
        ] {
            let resolver_error = super::sqlite_to_resolution_error(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                None,
            ));
            assert!(matches!(
                resolver_error,
                AggregateFamilyRootResolutionError::Unavailable(_)
            ));
            let store_error = super::sqlite_to_store_error(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                None,
            ));
            assert!(matches!(
                store_error,
                super::AggregateFamilyRootStoreError::Unavailable(_)
            ));
        }

        for code in [rusqlite::ffi::SQLITE_CORRUPT, rusqlite::ffi::SQLITE_NOTADB] {
            let resolver_error = super::sqlite_to_resolution_error(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                None,
            ));
            assert!(matches!(
                resolver_error,
                AggregateFamilyRootResolutionError::Corrupt(_)
            ));
            let store_error = super::sqlite_to_store_error(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                None,
            ));
            assert!(matches!(
                store_error,
                super::AggregateFamilyRootStoreError::Corrupt(_)
            ));
        }
    }
}
