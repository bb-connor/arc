#[test]
fn certify_adversarial_multi_operator_open_market_preserves_visibility_without_trust() {
    let scenarios_dir = unique_path("chio-adversarial-open-market-scenarios", "");
    let results_dir = unique_path("chio-adversarial-open-market-results", "");
    let output_path = unique_path("chio-adversarial-open-market-artifact", ".json");
    let seed_path = unique_path("chio-adversarial-open-market-seed", ".txt");
    let receipt_db_path = unique_path("chio-adversarial-open-market-receipts", ".sqlite");
    let authority_db_path = unique_path("chio-adversarial-open-market-authority", ".sqlite");
    let registry_path = unique_path("chio-adversarial-open-market-certifications", ".json");
    let tool_server_id = "demo-server-adversarial-open-market";
    let provider_id = "carrier-adversarial-open-market";
    let service_token = "adversarial-open-market-token";

    write_scenario(&scenarios_dir, "adversarial-open-market");
    write_results(&results_dir, "adversarial-open-market", "pass");
    run_certify_check(
        &scenarios_dir,
        &results_dir,
        &output_path,
        &seed_path,
        tool_server_id,
        Some("Adversarial Open Market Server"),
    );
    issue_local_liability_provider(&receipt_db_path, &authority_db_path, provider_id);

    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let _service = spawn_trust_service_with_public_registry(
        listen,
        service_token,
        Some(&registry_path),
        &base_url,
        &receipt_db_path,
        &authority_db_path,
    );
    let client = Client::new();
    wait_for_trust_service(&client, &base_url);

    let publish = publish_remote_certification(&base_url, service_token, &output_path);
    assert_eq!(publish["toolServerId"], tool_server_id);

    let listing_response = client
        .get(format!("{base_url}/v1/public/registry/listings/search"))
        .query(&[("actorKind", "tool_server"), ("actorId", tool_server_id)])
        .send()
        .expect("fetch public generic listings");
    assert_eq!(listing_response.status(), reqwest::StatusCode::OK);
    let listing_body: serde_json::Value = listing_response
        .json()
        .expect("parse public generic listings");
    let origin_report: GenericListingReport =
        serde_json::from_value(listing_body.clone()).expect("parse origin listing report");
    let generated_at = origin_report.generated_at;
    let valid_until = origin_report.freshness.valid_until;
    let publisher_operator_id = origin_report.publisher.operator_id.clone();
    let tool_server_listing_value = listing_body["listings"]
        .as_array()
        .expect("listing array")
        .iter()
        .find(|listing| {
            listing["body"]["subject"]["actorKind"] == "tool_server"
                && listing["body"]["subject"]["actorId"] == tool_server_id
        })
        .cloned()
        .expect("tool-server listing");
    assert_eq!(
        origin_report.listings.len(),
        1,
        "filtered registry report should contain only the tool server under test"
    );
    let mut tampered_mirror = origin_report.clone();
    tampered_mirror.publisher.role = GenericRegistryPublisherRole::Mirror;
    tampered_mirror.publisher.operator_id = "mirror-a".to_string();
    tampered_mirror.publisher.operator_name = Some("Mirror A".to_string());
    tampered_mirror.publisher.registry_url = "https://mirror-a.chio.example".to_string();
    tampered_mirror.publisher.upstream_registry_urls = vec![base_url.clone()];
    let tampered_listing = tampered_mirror
        .listings
        .iter_mut()
        .find(|listing| {
            listing.body.subject.actor_kind == GenericListingActorKind::ToolServer
                && listing.body.subject.actor_id == tool_server_id
        })
        .expect("tampered mirror listing");
    tampered_listing.body.status = GenericListingStatus::Revoked;

    let mut divergent_indexer = origin_report.clone();
    divergent_indexer.publisher.role = GenericRegistryPublisherRole::Indexer;
    divergent_indexer.publisher.operator_id = "indexer-a".to_string();
    divergent_indexer.publisher.operator_name = Some("Indexer A".to_string());
    divergent_indexer.publisher.registry_url = "https://indexer-a.chio.example".to_string();
    divergent_indexer.publisher.upstream_registry_urls = vec![base_url.clone()];
    let divergent_keypair = Keypair::generate();
    let mut divergent_ownership = divergent_indexer.namespace.clone();
    divergent_ownership.owner_id = "indexer-a".to_string();
    divergent_ownership.registry_url = "https://indexer-a.chio.example".to_string();
    divergent_ownership.signer_public_key = divergent_keypair.public_key();
    divergent_indexer.namespace = divergent_ownership.clone();
    for listing in &mut divergent_indexer.listings {
        let mut divergent_body = listing.body.clone();
        divergent_body.namespace_ownership = divergent_ownership.clone();
        if divergent_body.subject.actor_kind == GenericListingActorKind::ToolServer
            && divergent_body.subject.actor_id == tool_server_id
        {
            divergent_body.compatibility.source_artifact_sha256 =
                "sha256-divergent-source".to_string();
        }
        *listing = SignedGenericListing::sign(divergent_body, &divergent_keypair)
            .expect("sign divergent indexer listing");
    }

    let aggregated = aggregate_generic_listing_reports(
        &[origin_report, tampered_mirror, divergent_indexer],
        &GenericListingQuery {
            actor_kind: Some(GenericListingActorKind::ToolServer),
            actor_id: Some(tool_server_id.to_string()),
            ..GenericListingQuery::default()
        },
        generated_at,
    );
    assert_eq!(aggregated.peer_count, 3);
    assert_eq!(
        aggregated.reachable_count, 2,
        "unexpected aggregation errors: {:#?}",
        aggregated.errors
    );
    assert_eq!(aggregated.stale_peer_count, 0);
    assert_eq!(aggregated.result_count, 0);
    assert_eq!(aggregated.divergence_count, 1);
    assert!(aggregated.errors.iter().any(
        |error| error.operator_id == "mirror-a" && error.error.contains("signature is invalid")
    ));
    assert!(aggregated.divergences.iter().any(|divergence| {
        divergence.actor_id == tool_server_id
            && divergence
                .publisher_operator_ids
                .contains(&publisher_operator_id)
            && divergence
                .publisher_operator_ids
                .contains(&"indexer-a".to_string())
    }));

    let activation_request = serde_json::json!({
        "listing": tool_server_listing_value.clone(),
        "admissionClass": "bond_backed",
        "disposition": "approved",
        "eligibility": {
            "allowedActorKinds": ["tool_server"],
            "allowedPublisherRoles": ["origin"],
            "allowedStatuses": ["active"],
            "requireFreshListing": true,
            "requireBondBacking": true,
            "requiredListingOperatorIds": [publisher_operator_id],
            "policyReference": "policy/adversarial-open-market/default"
        },
        "reviewContext": {
            "publisher": listing_body["publisher"].clone(),
            "freshness": {
                "state": "fresh",
                "ageSecs": 0,
                "maxAgeSecs": 300,
                "validUntil": valid_until,
                "generatedAt": generated_at
            }
        },
        "requestedBy": "ops@chio.example",
        "reviewedBy": "reviewer@chio.example",
        "requestedAt": generated_at,
        "reviewedAt": generated_at + 1,
        "expiresAt": generated_at + 300,
        "note": "bond-backed local activation for adversarial qualification"
    });
    let activation_response = client
        .post(format!("{base_url}/v1/registry/trust-activations/issue"))
        .bearer_auth(service_token)
        .json(&activation_request)
        .send()
        .expect("issue activation");
    assert_eq!(activation_response.status(), reqwest::StatusCode::OK);
    let activation: SignedGenericTrustActivation =
        activation_response.json().expect("parse activation");

    let admitted_activation_response = client
        .post(format!("{base_url}/v1/registry/trust-activations/evaluate"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "listing": tool_server_listing_value.clone(),
            "currentPublisher": listing_body["publisher"].clone(),
            "currentFreshness": {
                "state": "fresh",
                "ageSecs": 0,
                "maxAgeSecs": 300,
                "validUntil": valid_until,
                "generatedAt": generated_at
            },
            "activation": serde_json::to_value(&activation).expect("serialize activation"),
            "evaluatedAt": generated_at + 2
        }))
        .send()
        .expect("evaluate admitted activation");
    assert_eq!(
        admitted_activation_response.status(),
        reqwest::StatusCode::OK
    );
    let admitted_activation: serde_json::Value = admitted_activation_response
        .json()
        .expect("parse admitted activation evaluation");
    assert_eq!(admitted_activation["admitted"], false);
    assert_eq!(
        admitted_activation["findings"][0]["code"],
        "bond_backing_required"
    );

    let divergent_activation_response = client
        .post(format!("{base_url}/v1/registry/trust-activations/evaluate"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "listing": tool_server_listing_value.clone(),
            "currentPublisher": listing_body["publisher"].clone(),
            "currentFreshness": {
                "state": "divergent",
                "ageSecs": 5,
                "maxAgeSecs": 300,
                "validUntil": valid_until,
                "generatedAt": generated_at
            },
            "activation": serde_json::to_value(&activation).expect("serialize activation"),
            "evaluatedAt": generated_at + 2
        }))
        .send()
        .expect("evaluate divergent activation");
    assert_eq!(
        divergent_activation_response.status(),
        reqwest::StatusCode::OK
    );
    let divergent_activation: serde_json::Value = divergent_activation_response
        .json()
        .expect("parse divergent activation evaluation");
    assert_eq!(divergent_activation["admitted"], false);
    assert_eq!(
        divergent_activation["findings"][0]["code"],
        "listing_divergent"
    );

    let charter_request = serde_json::json!({
        "authorityScope": {
            "namespace": tool_server_listing_value["body"]["namespace"].clone(),
            "allowedListingOperatorIds": [publisher_operator_id.clone()],
            "allowedActorKinds": ["tool_server"],
            "policyReference": "policy/adversarial-open-market/governance"
        },
        "allowedCaseKinds": ["sanction", "appeal"],
        "issuedBy": "governance@chio.example",
        "issuedAt": generated_at + 2,
        "expiresAt": generated_at + 600,
        "note": "local open-market governance charter"
    });
    let charter_response = client
        .post(format!("{base_url}/v1/registry/governance/charters/issue"))
        .bearer_auth(service_token)
        .json(&charter_request)
        .send()
        .expect("issue governance charter");
    assert_eq!(charter_response.status(), reqwest::StatusCode::OK);
    let charter: SignedGenericGovernanceCharter =
        charter_response.json().expect("parse governance charter");

    let mut forged_activation_body = activation.body.clone();
    forged_activation_body.local_operator_id = "https://remote-governor.chio.example".to_string();
    forged_activation_body.local_operator_name = Some("Remote Governor".to_string());
    let local_authority_keypair = SqliteCapabilityAuthority::open(&authority_db_path)
        .expect("open local authority")
        .local_keypair()
        .expect("read local authority keypair");
    let forged_activation =
        SignedGenericTrustActivation::sign(forged_activation_body, &local_authority_keypair)
            .expect("sign forged activation");

    let forged_case_issue_response = client
        .post(format!("{base_url}/v1/registry/governance/cases/issue"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "charter": serde_json::to_value(&charter).expect("serialize charter"),
            "listing": tool_server_listing_value.clone(),
            "activation": serde_json::to_value(&forged_activation).expect("serialize forged activation"),
            "kind": "sanction",
            "state": "enforced",
            "subjectOperatorId": publisher_operator_id.clone(),
            "evidenceRefs": [{
                "kind": "trust_activation",
                "referenceId": activation.body.activation_id.clone()
            }],
            "issuedBy": "governance@chio.example",
            "openedAt": generated_at + 3,
            "updatedAt": generated_at + 3,
            "expiresAt": generated_at + 500,
            "note": "forged remote activation should fail"
        }))
        .send()
        .expect("issue forged governance case");
    assert_eq!(
        forged_case_issue_response.status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    assert!(forged_case_issue_response
        .text()
        .expect("read forged governance case error")
        .contains("issued by the governing operator"));

    let sanction_case_response = client
        .post(format!("{base_url}/v1/registry/governance/cases/issue"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "charter": serde_json::to_value(&charter).expect("serialize charter"),
            "listing": tool_server_listing_value.clone(),
            "activation": serde_json::to_value(&activation).expect("serialize activation"),
            "kind": "sanction",
            "state": "enforced",
            "subjectOperatorId": publisher_operator_id.clone(),
            "evidenceRefs": [{
                "kind": "trust_activation",
                "referenceId": activation.body.activation_id.clone()
            }],
            "issuedBy": "governance@chio.example",
            "openedAt": generated_at + 3,
            "updatedAt": generated_at + 3,
            "expiresAt": generated_at + 500,
            "note": "local sanction case"
        }))
        .send()
        .expect("issue local sanction case");
    assert_eq!(sanction_case_response.status(), reqwest::StatusCode::OK);
    let sanction_case: SignedGenericGovernanceCase =
        sanction_case_response.json().expect("parse sanction case");

    let forged_governance_evaluation_response = client
        .post(format!("{base_url}/v1/registry/governance/cases/evaluate"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "listing": tool_server_listing_value.clone(),
            "currentPublisher": listing_body["publisher"].clone(),
            "activation": serde_json::to_value(&forged_activation).expect("serialize forged activation"),
            "charter": serde_json::to_value(&charter).expect("serialize charter"),
            "case": serde_json::to_value(&sanction_case).expect("serialize sanction case"),
            "evaluatedAt": generated_at + 4
        }))
        .send()
        .expect("evaluate sanction with forged activation");
    assert_eq!(
        forged_governance_evaluation_response.status(),
        reqwest::StatusCode::OK
    );
    let forged_governance_evaluation: serde_json::Value = forged_governance_evaluation_response
        .json()
        .expect("parse forged governance evaluation");
    assert_eq!(
        forged_governance_evaluation["findings"][0]["code"],
        "activation_mismatch"
    );

    let fee_schedule_request = serde_json::json!({
        "scope": {
            "namespace": tool_server_listing_value["body"]["namespace"].clone(),
            "allowedListingOperatorIds": [publisher_operator_id.clone()],
            "allowedActorKinds": ["tool_server"],
            "allowedAdmissionClasses": ["bond_backed"],
            "policyReference": "policy/adversarial-open-market/default"
        },
        "publicationFee": {
            "units": 100,
            "currency": "USD"
        },
        "disputeFee": {
            "units": 2500,
            "currency": "USD"
        },
        "marketParticipationFee": {
            "units": 500,
            "currency": "USD"
        },
        "bondRequirements": [{
            "bondClass": "listing",
            "requiredAmount": {
                "units": 5000,
                "currency": "USD"
            },
            "collateralReferenceKind": "credit_bond",
            "slashable": true
        }],
        "issuedBy": "market@chio.example",
        "issuedAt": generated_at + 4,
        "expiresAt": generated_at + 700,
        "note": "adversarial qualification fee schedule"
    });
    let fee_schedule_response = client
        .post(format!("{base_url}/v1/registry/market/fees/issue"))
        .bearer_auth(service_token)
        .json(&fee_schedule_request)
        .send()
        .expect("issue fee schedule");
    assert_eq!(fee_schedule_response.status(), reqwest::StatusCode::OK);
    let fee_schedule: SignedOpenMarketFeeSchedule =
        fee_schedule_response.json().expect("parse fee schedule");

    let forged_penalty_issue_response = client
        .post(format!("{base_url}/v1/registry/market/penalties/issue"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "feeSchedule": serde_json::to_value(&fee_schedule).expect("serialize fee schedule"),
            "charter": serde_json::to_value(&charter).expect("serialize charter"),
            "case": serde_json::to_value(&sanction_case).expect("serialize sanction case"),
            "listing": tool_server_listing_value.clone(),
            "activation": serde_json::to_value(&forged_activation).expect("serialize forged activation"),
            "abuseClass": "unverifiable_listing_behavior",
            "bondClass": "listing",
            "action": "slash_bond",
            "state": "enforced",
            "penaltyAmount": {
                "units": 2500,
                "currency": "USD"
            },
            "evidenceRefs": [{
                "kind": "governance_case",
                "referenceId": sanction_case.body.case_id.clone()
            }],
            "subjectOperatorId": publisher_operator_id.clone(),
            "issuedBy": "market@chio.example",
            "openedAt": generated_at + 5,
            "updatedAt": generated_at + 5,
            "expiresAt": generated_at + 700,
            "note": "forged remote activation should fail"
        }))
        .send()
        .expect("issue forged market penalty");
    assert_eq!(
        forged_penalty_issue_response.status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    assert!(forged_penalty_issue_response
        .text()
        .expect("read forged market penalty error")
        .contains("issued by the governing operator"));

    let penalty_response = client
        .post(format!("{base_url}/v1/registry/market/penalties/issue"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "feeSchedule": serde_json::to_value(&fee_schedule).expect("serialize fee schedule"),
            "charter": serde_json::to_value(&charter).expect("serialize charter"),
            "case": serde_json::to_value(&sanction_case).expect("serialize sanction case"),
            "listing": tool_server_listing_value.clone(),
            "activation": serde_json::to_value(&activation).expect("serialize activation"),
            "abuseClass": "unverifiable_listing_behavior",
            "bondClass": "listing",
            "action": "slash_bond",
            "state": "enforced",
            "penaltyAmount": {
                "units": 2500,
                "currency": "USD"
            },
            "evidenceRefs": [{
                "kind": "governance_case",
                "referenceId": sanction_case.body.case_id.clone()
            }],
            "subjectOperatorId": publisher_operator_id.clone(),
            "issuedBy": "market@chio.example",
            "openedAt": generated_at + 5,
            "updatedAt": generated_at + 5,
            "expiresAt": generated_at + 700,
            "note": "local market penalty"
        }))
        .send()
        .expect("issue local market penalty");
    assert_eq!(penalty_response.status(), reqwest::StatusCode::OK);
    let penalty: SignedOpenMarketPenalty = penalty_response.json().expect("parse penalty");

    let forged_penalty_evaluation_response = client
        .post(format!("{base_url}/v1/registry/market/penalties/evaluate"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "feeSchedule": serde_json::to_value(&fee_schedule).expect("serialize fee schedule"),
            "listing": tool_server_listing_value,
            "currentPublisher": listing_body["publisher"].clone(),
            "activation": serde_json::to_value(&forged_activation).expect("serialize forged activation"),
            "charter": serde_json::to_value(&charter).expect("serialize charter"),
            "case": serde_json::to_value(&sanction_case).expect("serialize sanction case"),
            "penalty": serde_json::to_value(&penalty).expect("serialize penalty"),
            "evaluatedAt": generated_at + 6
        }))
        .send()
        .expect("evaluate market penalty with forged activation");
    assert_eq!(
        forged_penalty_evaluation_response.status(),
        reqwest::StatusCode::OK
    );
    let forged_penalty_evaluation: serde_json::Value = forged_penalty_evaluation_response
        .json()
        .expect("parse forged penalty evaluation");
    assert_eq!(
        forged_penalty_evaluation["findings"][0]["code"],
        "activation_mismatch"
    );

    let subject_key = Keypair::generate().public_key().to_hex();
    let local_summary = SignedPortableReputationSummary::sign(
        build_portable_reputation_summary_artifact(
            &base_url,
            &PortableReputationSummaryIssueRequest {
                subject_key: subject_key.clone(),
                since: Some(generated_at.saturating_sub(600)),
                until: Some(generated_at),
                issued_at: Some(generated_at),
                expires_at: Some(generated_at + 600),
                note: Some("local reputation summary".to_string()),
            },
            &sample_portable_reputation_scorecard(&subject_key, 0.82),
            PortableReputationSummaryArtifactContext {
                issuer_operator_name: Some("Origin Operator".to_string()),
                effective_score: 0.82,
                probationary: false,
                imported_signal_count: Some(0),
                accepted_imported_signal_count: Some(0),
                issued_at: generated_at,
            },
        )
        .expect("build local reputation summary"),
        &Keypair::generate(),
    )
    .expect("sign local reputation summary");
    let remote_negative_event = SignedPortableNegativeEvent::sign(
        build_portable_negative_event_artifact(
            "https://malicious-issuer.chio.example",
            Some("Malicious Issuer".to_string()),
            &PortableNegativeEventIssueRequest {
                subject_key: subject_key.clone(),
                kind: PortableNegativeEventKind::FraudSignal,
                severity: 0.9,
                observed_at: generated_at.saturating_sub(30),
                published_at: Some(generated_at.saturating_sub(10)),
                expires_at: Some(generated_at + 600),
                evidence_refs: vec![PortableNegativeEventEvidenceReference {
                    kind: PortableNegativeEventEvidenceKind::External,
                    reference_id: "fraud-case-1".to_string(),
                    uri: Some("https://malicious-issuer.chio.example/cases/1".to_string()),
                    sha256: None,
                }],
                note: Some("malicious remote negative signal".to_string()),
            },
            generated_at,
        )
        .expect("build remote negative event"),
        &Keypair::generate(),
    )
    .expect("sign remote negative event");
    let reputation_evaluation = evaluate_portable_reputation(
        &PortableReputationEvaluationRequest {
            subject_key: subject_key.clone(),
            summaries: vec![local_summary],
            negative_events: vec![remote_negative_event],
            weighting_profile: PortableReputationWeightingProfile {
                profile_id: "local-only".to_string(),
                allowed_issuer_operator_ids: vec![base_url.clone()],
                issuer_weights: BTreeMap::new(),
                max_summary_age_secs: 3600,
                max_event_age_secs: 3600,
                reject_probationary: false,
                negative_event_weight: 0.5,
                blocking_event_kinds: vec![PortableNegativeEventKind::FraudSignal],
            },
            evaluated_at: Some(generated_at + 10),
        },
        generated_at + 10,
    )
    .expect("evaluate portable reputation");
    assert_eq!(reputation_evaluation.accepted_summary_count, 1);
    assert_eq!(reputation_evaluation.accepted_negative_event_count, 0);
    assert_eq!(reputation_evaluation.rejected_negative_event_count, 1);
    assert_eq!(
        reputation_evaluation.findings[0].code,
        PortableReputationFindingCode::IssuerNotAllowed
    );
    assert!(reputation_evaluation.effective_score.is_some());
}
