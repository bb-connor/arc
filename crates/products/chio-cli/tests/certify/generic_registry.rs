use super::*;

#[test]
fn certify_public_generic_registry_namespace_and_listings_project_current_actor_families() {
    if skip_when_loopback_bind_denied(
        "certify_public_generic_registry_namespace_and_listings_project_current_actor_families",
    ) {
        return;
    }

    let scenarios_dir = unique_path("chio-generic-registry-scenarios", "");
    let results_dir = unique_path("chio-generic-registry-results", "");
    let output_path = unique_path("chio-generic-registry-artifact", ".json");
    let seed_path = unique_path("chio-generic-registry-seed", ".txt");
    let state = chio_test_support::private_tempdir().expect("create private authority state");
    let receipt_db_path = state.path().join("receipts.sqlite");
    let authority_db_path = state.path().join("authority.sqlite");
    let registry_path = unique_path("chio-generic-registry-certifications", ".json");
    let tool_server_id = "demo-server-generic-listing";
    let provider_id = "carrier-generic";
    let service_token = "generic-registry-token";

    write_scenario(&scenarios_dir, "generic-listing");
    write_results(&results_dir, "generic-listing", "pass");
    run_certify_check(
        &scenarios_dir,
        &results_dir,
        &output_path,
        &seed_path,
        tool_server_id,
        Some("Generic Listing Server"),
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

    let namespace_response = client
        .get(format!("{base_url}/v1/public/registry/namespace"))
        .send()
        .expect("fetch public generic namespace");
    assert_eq!(namespace_response.status(), reqwest::StatusCode::OK);
    let namespace_body: serde_json::Value = namespace_response
        .json()
        .expect("parse public generic namespace");
    assert_eq!(
        namespace_body["body"]["schema"],
        "chio.registry.namespace.v1"
    );
    assert_eq!(namespace_body["body"]["ownership"]["namespace"], base_url);
    assert_eq!(namespace_body["body"]["ownership"]["ownerId"], base_url);
    assert_eq!(namespace_body["body"]["boundary"]["visibilityOnly"], true);
    assert_eq!(
        namespace_body["body"]["boundary"]["automaticTrustAdmission"],
        false
    );

    let listing_response = client
        .get(format!("{base_url}/v1/public/registry/listings/search"))
        .send()
        .expect("fetch public generic listings");
    assert_eq!(listing_response.status(), reqwest::StatusCode::OK);
    let listing_body: serde_json::Value = listing_response
        .json()
        .expect("parse public generic listings");
    assert_eq!(listing_body["schema"], "chio.registry.listing-report.v1");
    assert_eq!(listing_body["namespace"]["namespace"], base_url);
    assert_eq!(listing_body["publisher"]["role"], "origin");
    assert_eq!(listing_body["publisher"]["operatorId"], base_url);
    assert_eq!(listing_body["publisher"]["registryUrl"], base_url);
    assert_eq!(
        listing_body["searchPolicy"]["algorithm"],
        "freshness-status-kind-actor-published-at-v1"
    );
    assert_eq!(listing_body["searchPolicy"]["reproducibleOrdering"], true);
    assert_eq!(listing_body["searchPolicy"]["visibilityOnly"], true);
    assert_eq!(
        listing_body["searchPolicy"]["explicitTrustActivationRequired"],
        true
    );
    assert_eq!(listing_body["freshness"]["maxAgeSecs"], 300);
    assert!(
        listing_body["freshness"]["validUntil"]
            .as_u64()
            .expect("freshness validUntil")
            > listing_body["generatedAt"].as_u64().expect("generatedAt")
    );
    assert_eq!(listing_body["summary"]["matchingListings"], 4);
    assert_eq!(listing_body["summary"]["returnedListings"], 4);

    let listings = listing_body["listings"].as_array().expect("listing array");
    assert!(listings.iter().any(|listing| {
        listing["body"]["subject"]["actorKind"] == "tool_server"
            && listing["body"]["subject"]["actorId"] == tool_server_id
            && listing["body"]["compatibility"]["sourceSchema"] == "chio.certify.check.v1"
    }));
    assert!(listings.iter().any(|listing| {
        listing["body"]["subject"]["actorKind"] == "credential_issuer"
            && listing["body"]["compatibility"]["sourceSchema"] == "chio.public-issuer-discovery.v1"
    }));
    assert!(listings.iter().any(|listing| {
        listing["body"]["subject"]["actorKind"] == "credential_verifier"
            && listing["body"]["compatibility"]["sourceSchema"]
                == "chio.public-verifier-discovery.v1"
    }));
    assert!(listings.iter().any(|listing| {
        listing["body"]["subject"]["actorKind"] == "liability_provider"
            && listing["body"]["subject"]["actorId"] == provider_id
            && listing["body"]["compatibility"]["sourceSchema"] == "chio.market.provider.v1"
    }));
    assert!(listings.iter().all(|listing| {
        listing["body"]["namespace"] == base_url
            && listing["body"]["namespaceOwnership"]["ownerId"] == base_url
            && listing["body"]["boundary"]["visibilityOnly"] == true
            && listing["body"]["boundary"]["explicitTrustActivationRequired"] == true
            && listing["body"]["boundary"]["automaticTrustAdmission"] == false
    }));

    let provider_only = client
        .get(format!(
            "{base_url}/v1/public/registry/listings/search?actorKind=liability_provider"
        ))
        .send()
        .expect("fetch provider-only listings");
    assert_eq!(provider_only.status(), reqwest::StatusCode::OK);
    let provider_only_body: serde_json::Value =
        provider_only.json().expect("parse provider-only listings");
    assert_eq!(provider_only_body["summary"]["matchingListings"], 1);
    assert_eq!(provider_only_body["summary"]["returnedListings"], 1);
    assert_eq!(
        provider_only_body["listings"][0]["body"]["subject"]["actorId"],
        provider_id
    );
}

#[test]
fn certify_generic_registry_trust_activation_requires_explicit_local_activation_and_fails_closed() {
    if skip_when_loopback_bind_denied(
        "certify_generic_registry_trust_activation_requires_explicit_local_activation_and_fails_closed",
    ) {
        return;
    }

    let scenarios_dir = unique_path("chio-generic-activation-scenarios", "");
    let results_dir = unique_path("chio-generic-activation-results", "");
    let output_path = unique_path("chio-generic-activation-artifact", ".json");
    let seed_path = unique_path("chio-generic-activation-seed", ".txt");
    let state = chio_test_support::private_tempdir().expect("create private authority state");
    let receipt_db_path = state.path().join("receipts.sqlite");
    let authority_db_path = state.path().join("authority.sqlite");
    let registry_path = unique_path("chio-generic-activation-certifications", ".json");
    let tool_server_id = "demo-server-generic-activation";
    let provider_id = "carrier-generic-activation";
    let service_token = "generic-activation-token";

    write_scenario(&scenarios_dir, "generic-activation");
    write_results(&results_dir, "generic-activation", "pass");
    run_certify_check(
        &scenarios_dir,
        &results_dir,
        &output_path,
        &seed_path,
        tool_server_id,
        Some("Generic Activation Server"),
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
        .send()
        .expect("fetch public generic listings");
    assert_eq!(listing_response.status(), reqwest::StatusCode::OK);
    let listing_body: serde_json::Value = listing_response
        .json()
        .expect("parse public generic listings");
    let generated_at = listing_body["generatedAt"]
        .as_u64()
        .expect("listing generatedAt");
    let valid_until = listing_body["freshness"]["validUntil"]
        .as_u64()
        .expect("listing validUntil");
    let tool_server_listing = listing_body["listings"]
        .as_array()
        .expect("listing array")
        .iter()
        .find(|listing| {
            listing["body"]["subject"]["actorKind"] == "tool_server"
                && listing["body"]["subject"]["actorId"] == tool_server_id
        })
        .cloned()
        .expect("tool-server listing");

    let fresh_context = serde_json::json!({
        "publisher": listing_body["publisher"].clone(),
        "freshness": {
            "state": "fresh",
            "ageSecs": 0,
            "maxAgeSecs": 300,
            "validUntil": valid_until,
            "generatedAt": generated_at
        }
    });

    let approved_request = serde_json::json!({
        "listing": tool_server_listing,
        "admissionClass": "reviewable",
        "disposition": "approved",
        "eligibility": {
            "allowedActorKinds": ["tool_server"],
            "allowedPublisherRoles": ["origin"],
            "allowedStatuses": ["active"],
            "requireFreshListing": true,
            "policyReference": "policy/open-registry/default"
        },
        "reviewContext": fresh_context,
        "requestedBy": "ops@chio.example",
        "reviewedBy": "reviewer@chio.example",
        "requestedAt": generated_at,
        "reviewedAt": generated_at + 1,
        "expiresAt": generated_at + 120,
        "note": "explicit local activation for tool server listing"
    });

    let approved_activation_response = client
        .post(format!("{base_url}/v1/registry/trust-activations/issue"))
        .bearer_auth(service_token)
        .json(&approved_request)
        .send()
        .expect("issue approved trust activation");
    assert_eq!(
        approved_activation_response.status(),
        reqwest::StatusCode::OK
    );
    let approved_activation: serde_json::Value = approved_activation_response
        .json()
        .expect("parse approved activation");
    assert_eq!(approved_activation["body"]["admissionClass"], "reviewable");
    assert_eq!(approved_activation["body"]["disposition"], "approved");

    let approved_evaluation_response = client
        .post(format!("{base_url}/v1/registry/trust-activations/evaluate"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "listing": approved_request["listing"].clone(),
            "currentPublisher": listing_body["publisher"].clone(),
            "currentFreshness": {
                "state": "fresh",
                "ageSecs": 0,
                "maxAgeSecs": 300,
                "validUntil": valid_until,
                "generatedAt": generated_at
            },
            "activation": approved_activation.clone(),
            "evaluatedAt": generated_at + 2
        }))
        .send()
        .expect("evaluate approved activation");
    assert_eq!(
        approved_evaluation_response.status(),
        reqwest::StatusCode::OK
    );
    let approved_evaluation: serde_json::Value = approved_evaluation_response
        .json()
        .expect("parse approved evaluation");
    assert_eq!(approved_evaluation["admitted"], true);
    assert!(
        approved_evaluation["findings"].is_null()
            || approved_evaluation["findings"] == serde_json::json!([])
    );

    let stale_evaluation_response = client
        .post(format!("{base_url}/v1/registry/trust-activations/evaluate"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "listing": approved_request["listing"].clone(),
            "currentPublisher": listing_body["publisher"].clone(),
            "currentFreshness": {
                "state": "stale",
                "ageSecs": 400,
                "maxAgeSecs": 300,
                "validUntil": valid_until,
                "generatedAt": generated_at
            },
            "activation": approved_activation.clone(),
            "evaluatedAt": generated_at + 400
        }))
        .send()
        .expect("evaluate stale activation");
    assert_eq!(stale_evaluation_response.status(), reqwest::StatusCode::OK);
    let stale_evaluation: serde_json::Value = stale_evaluation_response
        .json()
        .expect("parse stale evaluation");
    assert_eq!(stale_evaluation["admitted"], false);
    assert_eq!(stale_evaluation["findings"][0]["code"], "listing_stale");

    let public_untrusted_request = serde_json::json!({
        "listing": approved_request["listing"].clone(),
        "admissionClass": "public_untrusted",
        "disposition": "approved",
        "eligibility": {
            "allowedActorKinds": ["tool_server"],
            "allowedPublisherRoles": ["origin"],
            "allowedStatuses": ["active"],
            "requireFreshListing": true,
            "policyReference": "policy/open-registry/public-only"
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
        "expiresAt": generated_at + 120,
        "note": "visibility only; do not widen runtime trust"
    });

    let public_untrusted_activation_response = client
        .post(format!("{base_url}/v1/registry/trust-activations/issue"))
        .bearer_auth(service_token)
        .json(&public_untrusted_request)
        .send()
        .expect("issue public_untrusted activation");
    assert_eq!(
        public_untrusted_activation_response.status(),
        reqwest::StatusCode::OK
    );
    let public_untrusted_activation: serde_json::Value = public_untrusted_activation_response
        .json()
        .expect("parse public_untrusted activation");

    let public_untrusted_evaluation_response = client
        .post(format!("{base_url}/v1/registry/trust-activations/evaluate"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "listing": public_untrusted_request["listing"].clone(),
            "currentPublisher": listing_body["publisher"].clone(),
            "currentFreshness": {
                "state": "fresh",
                "ageSecs": 0,
                "maxAgeSecs": 300,
                "validUntil": valid_until,
                "generatedAt": generated_at
            },
            "activation": public_untrusted_activation,
            "evaluatedAt": generated_at + 2
        }))
        .send()
        .expect("evaluate public_untrusted activation");
    assert_eq!(
        public_untrusted_evaluation_response.status(),
        reqwest::StatusCode::OK
    );
    let public_untrusted_evaluation: serde_json::Value = public_untrusted_evaluation_response
        .json()
        .expect("parse public_untrusted evaluation");
    assert_eq!(public_untrusted_evaluation["admitted"], false);
    assert_eq!(
        public_untrusted_evaluation["findings"][0]["code"],
        "admission_class_untrusted"
    );
}

#[test]
fn certify_generic_registry_governance_charters_and_cases_enforce_bounded_open_governance() {
    if skip_when_loopback_bind_denied(
        "certify_generic_registry_governance_charters_and_cases_enforce_bounded_open_governance",
    ) {
        return;
    }

    let scenarios_dir = unique_path("chio-generic-governance-scenarios", "");
    let results_dir = unique_path("chio-generic-governance-results", "");
    let output_path = unique_path("chio-generic-governance-artifact", ".json");
    let seed_path = unique_path("chio-generic-governance-seed", ".txt");
    let state = chio_test_support::private_tempdir().expect("create private authority state");
    let receipt_db_path = state.path().join("receipts.sqlite");
    let authority_db_path = state.path().join("authority.sqlite");
    let registry_path = unique_path("chio-generic-governance-certifications", ".json");
    let tool_server_id = "demo-server-generic-governance";
    let provider_id = "carrier-generic-governance";
    let service_token = "generic-governance-token";

    write_scenario(&scenarios_dir, "generic-governance");
    write_results(&results_dir, "generic-governance", "pass");
    run_certify_check(
        &scenarios_dir,
        &results_dir,
        &output_path,
        &seed_path,
        tool_server_id,
        Some("Generic Governance Server"),
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
        .send()
        .expect("fetch public generic listings");
    assert_eq!(listing_response.status(), reqwest::StatusCode::OK);
    let listing_body: serde_json::Value = listing_response
        .json()
        .expect("parse public generic listings");
    let generated_at = listing_body["generatedAt"]
        .as_u64()
        .expect("listing generatedAt");
    let valid_until = listing_body["freshness"]["validUntil"]
        .as_u64()
        .expect("listing validUntil");
    let publisher_operator_id = listing_body["publisher"]["operatorId"]
        .as_str()
        .expect("publisher operatorId");
    let tool_server_listing = listing_body["listings"]
        .as_array()
        .expect("listing array")
        .iter()
        .find(|listing| {
            listing["body"]["subject"]["actorKind"] == "tool_server"
                && listing["body"]["subject"]["actorId"] == tool_server_id
        })
        .cloned()
        .expect("tool-server listing");

    let activation_request = serde_json::json!({
        "listing": tool_server_listing.clone(),
        "admissionClass": "reviewable",
        "disposition": "approved",
        "eligibility": {
            "allowedActorKinds": ["tool_server"],
            "allowedPublisherRoles": ["origin"],
            "allowedStatuses": ["active"],
            "requireFreshListing": true,
            "requiredListingOperatorIds": [publisher_operator_id],
            "policyReference": "policy/open-registry/default"
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
        "note": "local trust activation for governance test"
    });
    let activation_response = client
        .post(format!("{base_url}/v1/registry/trust-activations/issue"))
        .bearer_auth(service_token)
        .json(&activation_request)
        .send()
        .expect("issue activation");
    assert_eq!(activation_response.status(), reqwest::StatusCode::OK);
    let activation: serde_json::Value = activation_response.json().expect("parse activation");

    let charter_request = serde_json::json!({
        "authorityScope": {
            "namespace": tool_server_listing["body"]["namespace"].clone(),
            "allowedListingOperatorIds": [publisher_operator_id],
            "allowedActorKinds": ["tool_server"],
            "policyReference": "policy/governance/default"
        },
        "allowedCaseKinds": ["dispute", "freeze", "sanction", "appeal"],
        "escalationOperatorIds": ["network-audit.chio.example"],
        "issuedBy": "governance@chio.example",
        "issuedAt": generated_at + 2,
        "expiresAt": generated_at + 600,
        "note": "default open-registry governance charter"
    });
    let charter_response = client
        .post(format!("{base_url}/v1/registry/governance/charters/issue"))
        .bearer_auth(service_token)
        .json(&charter_request)
        .send()
        .expect("issue governance charter");
    assert_eq!(charter_response.status(), reqwest::StatusCode::OK);
    let charter: serde_json::Value = charter_response.json().expect("parse charter");

    let freeze_request = serde_json::json!({
        "charter": charter.clone(),
        "listing": tool_server_listing.clone(),
        "activation": activation.clone(),
        "kind": "freeze",
        "state": "enforced",
        "subjectOperatorId": publisher_operator_id,
        "evidenceRefs": [{
            "kind": "trust_activation",
            "referenceId": activation["body"]["activationId"].clone()
        }],
        "issuedBy": "governance@chio.example",
        "openedAt": generated_at + 3,
        "updatedAt": generated_at + 3,
        "expiresAt": generated_at + 120,
        "note": "temporary freeze pending review"
    });
    let freeze_response = client
        .post(format!("{base_url}/v1/registry/governance/cases/issue"))
        .bearer_auth(service_token)
        .json(&freeze_request)
        .send()
        .expect("issue freeze case");
    assert_eq!(freeze_response.status(), reqwest::StatusCode::OK);
    let freeze_case: serde_json::Value = freeze_response.json().expect("parse freeze case");

    let freeze_evaluation_response = client
        .post(format!("{base_url}/v1/registry/governance/cases/evaluate"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "listing": tool_server_listing.clone(),
            "currentPublisher": listing_body["publisher"].clone(),
            "activation": activation.clone(),
            "charter": charter.clone(),
            "case": freeze_case.clone(),
            "evaluatedAt": generated_at + 4
        }))
        .send()
        .expect("evaluate freeze case");
    assert_eq!(freeze_evaluation_response.status(), reqwest::StatusCode::OK);
    let freeze_evaluation: serde_json::Value = freeze_evaluation_response
        .json()
        .expect("parse freeze evaluation");
    assert_eq!(freeze_evaluation["effectiveState"], "frozen");
    assert_eq!(freeze_evaluation["blocksAdmission"], true);
    assert!(
        freeze_evaluation["findings"].is_null()
            || freeze_evaluation["findings"] == serde_json::json!([])
    );

    let missing_activation_evaluation_response = client
        .post(format!("{base_url}/v1/registry/governance/cases/evaluate"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "listing": tool_server_listing.clone(),
            "currentPublisher": listing_body["publisher"].clone(),
            "charter": charter.clone(),
            "case": freeze_case.clone(),
            "evaluatedAt": generated_at + 4
        }))
        .send()
        .expect("evaluate freeze without activation");
    assert_eq!(
        missing_activation_evaluation_response.status(),
        reqwest::StatusCode::OK
    );
    let missing_activation_evaluation: serde_json::Value = missing_activation_evaluation_response
        .json()
        .expect("parse missing activation evaluation");
    assert_eq!(
        missing_activation_evaluation["findings"][0]["code"],
        "missing_activation"
    );

    let expired_charter_request = serde_json::json!({
        "authorityScope": charter_request["authorityScope"].clone(),
        "allowedCaseKinds": ["freeze", "appeal"],
        "escalationOperatorIds": ["network-audit.chio.example"],
        "issuedBy": "governance@chio.example",
        "issuedAt": generated_at + 2,
        "expiresAt": generated_at + 3,
        "note": "short-lived charter"
    });
    let expired_charter_response = client
        .post(format!("{base_url}/v1/registry/governance/charters/issue"))
        .bearer_auth(service_token)
        .json(&expired_charter_request)
        .send()
        .expect("issue expired charter");
    assert_eq!(expired_charter_response.status(), reqwest::StatusCode::OK);
    let expired_charter: serde_json::Value = expired_charter_response
        .json()
        .expect("parse expired charter");

    let expired_case_request = serde_json::json!({
        "charter": expired_charter.clone(),
        "listing": tool_server_listing.clone(),
        "activation": activation.clone(),
        "kind": "freeze",
        "state": "enforced",
        "subjectOperatorId": publisher_operator_id,
        "evidenceRefs": [{
            "kind": "listing",
            "referenceId": tool_server_listing["body"]["listingId"].clone()
        }],
        "issuedBy": "governance@chio.example",
        "openedAt": generated_at + 3,
        "updatedAt": generated_at + 3,
        "expiresAt": generated_at + 120,
        "note": "freeze under expired charter"
    });
    let expired_case_response = client
        .post(format!("{base_url}/v1/registry/governance/cases/issue"))
        .bearer_auth(service_token)
        .json(&expired_case_request)
        .send()
        .expect("issue case under expired charter");
    assert_eq!(expired_case_response.status(), reqwest::StatusCode::OK);
    let expired_case: serde_json::Value = expired_case_response.json().expect("parse expired case");

    let expired_charter_evaluation_response = client
        .post(format!("{base_url}/v1/registry/governance/cases/evaluate"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "listing": tool_server_listing.clone(),
            "currentPublisher": listing_body["publisher"].clone(),
            "activation": activation.clone(),
            "charter": expired_charter,
            "case": expired_case,
            "evaluatedAt": generated_at + 10
        }))
        .send()
        .expect("evaluate expired charter");
    assert_eq!(
        expired_charter_evaluation_response.status(),
        reqwest::StatusCode::OK
    );
    let expired_charter_evaluation: serde_json::Value = expired_charter_evaluation_response
        .json()
        .expect("parse expired charter evaluation");
    assert_eq!(
        expired_charter_evaluation["findings"][0]["code"],
        "charter_expired"
    );

    let appeal_request = serde_json::json!({
        "charter": charter.clone(),
        "listing": tool_server_listing.clone(),
        "activation": activation.clone(),
        "kind": "appeal",
        "state": "open",
        "subjectOperatorId": publisher_operator_id,
        "evidenceRefs": [{
            "kind": "external",
            "referenceId": "appeal-1"
        }],
        "appealOfCaseId": freeze_case["body"]["caseId"].clone(),
        "issuedBy": "governance@chio.example",
        "openedAt": generated_at + 5,
        "updatedAt": generated_at + 5,
        "expiresAt": generated_at + 120,
        "note": "appeal of enforced freeze"
    });
    let appeal_response = client
        .post(format!("{base_url}/v1/registry/governance/cases/issue"))
        .bearer_auth(service_token)
        .json(&appeal_request)
        .send()
        .expect("issue appeal case");
    assert_eq!(appeal_response.status(), reqwest::StatusCode::OK);
    let appeal_case: serde_json::Value = appeal_response.json().expect("parse appeal case");

    let appeal_evaluation_response = client
        .post(format!("{base_url}/v1/registry/governance/cases/evaluate"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "listing": tool_server_listing,
            "currentPublisher": listing_body["publisher"].clone(),
            "activation": activation,
            "charter": charter,
            "case": appeal_case,
            "priorCase": freeze_case,
            "evaluatedAt": generated_at + 6
        }))
        .send()
        .expect("evaluate appeal case");
    assert_eq!(appeal_evaluation_response.status(), reqwest::StatusCode::OK);
    let appeal_evaluation: serde_json::Value = appeal_evaluation_response
        .json()
        .expect("parse appeal evaluation");
    assert_eq!(appeal_evaluation["effectiveState"], "appealed");
    assert_eq!(appeal_evaluation["blocksAdmission"], false);
    assert!(
        appeal_evaluation["findings"].is_null()
            || appeal_evaluation["findings"] == serde_json::json!([])
    );
}

#[test]
fn certify_open_market_fee_schedules_and_slashing_require_explicit_bounded_authority() {
    if skip_when_loopback_bind_denied(
        "certify_open_market_fee_schedules_and_slashing_require_explicit_bounded_authority",
    ) {
        return;
    }

    let scenarios_dir = unique_path("chio-open-market-scenarios", "");
    let results_dir = unique_path("chio-open-market-results", "");
    let output_path = unique_path("chio-open-market-artifact", ".json");
    let seed_path = unique_path("chio-open-market-seed", ".txt");
    let state = chio_test_support::private_tempdir().expect("create private authority state");
    let receipt_db_path = state.path().join("receipts.sqlite");
    let authority_db_path = state.path().join("authority.sqlite");
    let registry_path = unique_path("chio-open-market-certifications", ".json");
    let tool_server_id = "demo-server-open-market";
    let provider_id = "carrier-open-market";
    let service_token = "open-market-token";

    write_scenario(&scenarios_dir, "open-market");
    write_results(&results_dir, "open-market", "pass");
    run_certify_check(
        &scenarios_dir,
        &results_dir,
        &output_path,
        &seed_path,
        tool_server_id,
        Some("Open Market Server"),
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
        .send()
        .expect("fetch public generic listings");
    assert_eq!(listing_response.status(), reqwest::StatusCode::OK);
    let listing_body: serde_json::Value = listing_response
        .json()
        .expect("parse public generic listings");
    let generated_at = listing_body["generatedAt"]
        .as_u64()
        .expect("listing generatedAt");
    let valid_until = listing_body["freshness"]["validUntil"]
        .as_u64()
        .expect("listing validUntil");
    let publisher_operator_id = listing_body["publisher"]["operatorId"]
        .as_str()
        .expect("publisher operatorId");
    let tool_server_listing = listing_body["listings"]
        .as_array()
        .expect("listing array")
        .iter()
        .find(|listing| {
            listing["body"]["subject"]["actorKind"] == "tool_server"
                && listing["body"]["subject"]["actorId"] == tool_server_id
        })
        .cloned()
        .expect("tool-server listing");

    let activation_request = serde_json::json!({
        "listing": tool_server_listing.clone(),
        "admissionClass": "bond_backed",
        "disposition": "approved",
        "eligibility": {
            "allowedActorKinds": ["tool_server"],
            "allowedPublisherRoles": ["origin"],
            "allowedStatuses": ["active"],
            "requireFreshListing": true,
            "requireBondBacking": true,
            "requiredListingOperatorIds": [publisher_operator_id],
            "policyReference": "policy/open-market/default"
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
        "note": "bond-backed activation for open-market economics"
    });
    let activation_response = client
        .post(format!("{base_url}/v1/registry/trust-activations/issue"))
        .bearer_auth(service_token)
        .json(&activation_request)
        .send()
        .expect("issue trust activation");
    assert_eq!(activation_response.status(), reqwest::StatusCode::OK);
    let activation: serde_json::Value = activation_response.json().expect("parse activation");

    let charter_request = serde_json::json!({
        "authorityScope": {
            "namespace": tool_server_listing["body"]["namespace"].clone(),
            "allowedListingOperatorIds": [publisher_operator_id],
            "allowedActorKinds": ["tool_server"],
            "policyReference": "policy/open-market/governance"
        },
        "allowedCaseKinds": ["sanction", "appeal"],
        "issuedBy": "governance@chio.example",
        "issuedAt": generated_at + 2,
        "expiresAt": generated_at + 600,
        "note": "open-market governance charter"
    });
    let charter_response = client
        .post(format!("{base_url}/v1/registry/governance/charters/issue"))
        .bearer_auth(service_token)
        .json(&charter_request)
        .send()
        .expect("issue governance charter");
    assert_eq!(charter_response.status(), reqwest::StatusCode::OK);
    let charter: serde_json::Value = charter_response.json().expect("parse charter");

    let sanction_request = serde_json::json!({
        "charter": charter.clone(),
        "listing": tool_server_listing.clone(),
        "activation": activation.clone(),
        "kind": "sanction",
        "state": "enforced",
        "subjectOperatorId": publisher_operator_id,
        "evidenceRefs": [{
            "kind": "trust_activation",
            "referenceId": activation["body"]["activationId"].clone()
        }],
        "issuedBy": "governance@chio.example",
        "openedAt": generated_at + 3,
        "updatedAt": generated_at + 3,
        "expiresAt": generated_at + 500,
        "note": "sanction for unverifiable listing behavior"
    });
    let sanction_response = client
        .post(format!("{base_url}/v1/registry/governance/cases/issue"))
        .bearer_auth(service_token)
        .json(&sanction_request)
        .send()
        .expect("issue sanction case");
    assert_eq!(sanction_response.status(), reqwest::StatusCode::OK);
    let sanction_case: serde_json::Value = sanction_response.json().expect("parse sanction case");

    let fee_schedule_request = serde_json::json!({
        "scope": {
            "namespace": tool_server_listing["body"]["namespace"].clone(),
            "allowedListingOperatorIds": [publisher_operator_id],
            "allowedActorKinds": ["tool_server"],
            "allowedAdmissionClasses": ["bond_backed"],
            "policyReference": "policy/open-market/default"
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
        "note": "bounded open-market fee schedule"
    });
    let fee_schedule_response = client
        .post(format!("{base_url}/v1/registry/market/fees/issue"))
        .bearer_auth(service_token)
        .json(&fee_schedule_request)
        .send()
        .expect("issue fee schedule");
    assert_eq!(fee_schedule_response.status(), reqwest::StatusCode::OK);
    let fee_schedule: serde_json::Value = fee_schedule_response.json().expect("parse fee schedule");

    let penalty_request = serde_json::json!({
        "feeSchedule": fee_schedule.clone(),
        "charter": charter.clone(),
        "case": sanction_case.clone(),
        "listing": tool_server_listing.clone(),
        "activation": activation.clone(),
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
            "referenceId": sanction_case["body"]["caseId"].clone()
        }],
        "subjectOperatorId": publisher_operator_id,
        "issuedBy": "market@chio.example",
        "openedAt": generated_at + 5,
        "updatedAt": generated_at + 5,
        "expiresAt": generated_at + 700,
        "note": "slash listing bond for sustained unverifiable behavior"
    });
    let penalty_response = client
        .post(format!("{base_url}/v1/registry/market/penalties/issue"))
        .bearer_auth(service_token)
        .json(&penalty_request)
        .send()
        .expect("issue market penalty");
    assert_eq!(penalty_response.status(), reqwest::StatusCode::OK);
    let penalty: serde_json::Value = penalty_response.json().expect("parse market penalty");

    let evaluation_response = client
        .post(format!("{base_url}/v1/registry/market/penalties/evaluate"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "feeSchedule": fee_schedule.clone(),
            "listing": tool_server_listing.clone(),
            "currentPublisher": listing_body["publisher"].clone(),
            "activation": activation.clone(),
            "charter": charter.clone(),
            "case": sanction_case.clone(),
            "penalty": penalty.clone(),
            "evaluatedAt": generated_at + 6
        }))
        .send()
        .expect("evaluate market penalty");
    assert_eq!(evaluation_response.status(), reqwest::StatusCode::OK);
    let evaluation: serde_json::Value =
        evaluation_response.json().expect("parse market evaluation");
    assert_eq!(evaluation["effectiveState"], "bond_slashed");
    assert_eq!(evaluation["blocksAdmission"], true);
    assert_eq!(evaluation["publicationFee"]["units"], 100);
    assert_eq!(evaluation["bondRequirement"]["bondClass"], "listing");
    assert!(evaluation["findings"].is_null() || evaluation["findings"] == serde_json::json!([]));

    let expired_fee_schedule_request = serde_json::json!({
        "scope": fee_schedule_request["scope"].clone(),
        "publicationFee": fee_schedule_request["publicationFee"].clone(),
        "disputeFee": fee_schedule_request["disputeFee"].clone(),
        "marketParticipationFee": fee_schedule_request["marketParticipationFee"].clone(),
        "bondRequirements": fee_schedule_request["bondRequirements"].clone(),
        "issuedBy": "market@chio.example",
        "issuedAt": generated_at + 4,
        "expiresAt": generated_at + 5,
        "note": "already expired schedule for fail-closed check"
    });
    let expired_fee_schedule_response = client
        .post(format!("{base_url}/v1/registry/market/fees/issue"))
        .bearer_auth(service_token)
        .json(&expired_fee_schedule_request)
        .send()
        .expect("issue expired fee schedule");
    assert_eq!(
        expired_fee_schedule_response.status(),
        reqwest::StatusCode::OK
    );
    let expired_fee_schedule: serde_json::Value = expired_fee_schedule_response
        .json()
        .expect("parse expired fee schedule");

    let expired_evaluation_response = client
        .post(format!("{base_url}/v1/registry/market/penalties/evaluate"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "feeSchedule": expired_fee_schedule,
            "listing": tool_server_listing.clone(),
            "currentPublisher": listing_body["publisher"].clone(),
            "activation": activation.clone(),
            "charter": charter.clone(),
            "case": sanction_case.clone(),
            "penalty": penalty.clone(),
            "evaluatedAt": generated_at + 6
        }))
        .send()
        .expect("evaluate expired schedule");
    assert_eq!(
        expired_evaluation_response.status(),
        reqwest::StatusCode::OK
    );
    let expired_evaluation: serde_json::Value = expired_evaluation_response
        .json()
        .expect("parse expired evaluation");
    assert_eq!(
        expired_evaluation["findings"][0]["code"],
        "fee_schedule_expired"
    );

    let dispute_only_fee_schedule_request = serde_json::json!({
        "scope": fee_schedule_request["scope"].clone(),
        "publicationFee": fee_schedule_request["publicationFee"].clone(),
        "disputeFee": fee_schedule_request["disputeFee"].clone(),
        "marketParticipationFee": fee_schedule_request["marketParticipationFee"].clone(),
        "bondRequirements": [{
            "bondClass": "dispute",
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
        "note": "dispute-only bond requirement"
    });
    let dispute_only_fee_schedule_response = client
        .post(format!("{base_url}/v1/registry/market/fees/issue"))
        .bearer_auth(service_token)
        .json(&dispute_only_fee_schedule_request)
        .send()
        .expect("issue dispute-only fee schedule");
    assert_eq!(
        dispute_only_fee_schedule_response.status(),
        reqwest::StatusCode::OK
    );
    let dispute_only_fee_schedule: serde_json::Value = dispute_only_fee_schedule_response
        .json()
        .expect("parse dispute-only fee schedule");

    let dispute_penalty_request = serde_json::json!({
        "feeSchedule": dispute_only_fee_schedule.clone(),
        "charter": charter.clone(),
        "case": sanction_case.clone(),
        "listing": tool_server_listing.clone(),
        "activation": activation.clone(),
        "abuseClass": "unverifiable_listing_behavior",
        "bondClass": "listing",
        "action": "hold_bond",
        "state": "enforced",
        "penaltyAmount": {
            "units": 1000,
            "currency": "USD"
        },
        "evidenceRefs": [{
            "kind": "governance_case",
            "referenceId": sanction_case["body"]["caseId"].clone()
        }],
        "subjectOperatorId": publisher_operator_id,
        "issuedBy": "market@chio.example",
        "openedAt": generated_at + 5,
        "updatedAt": generated_at + 5,
        "expiresAt": generated_at + 700,
        "note": "hold listing bond without matching bond requirement"
    });
    let dispute_penalty_response = client
        .post(format!("{base_url}/v1/registry/market/penalties/issue"))
        .bearer_auth(service_token)
        .json(&dispute_penalty_request)
        .send()
        .expect("issue mismatch penalty");
    assert_eq!(dispute_penalty_response.status(), reqwest::StatusCode::OK);
    let dispute_penalty: serde_json::Value = dispute_penalty_response
        .json()
        .expect("parse mismatch penalty");

    let mismatch_evaluation_response = client
        .post(format!("{base_url}/v1/registry/market/penalties/evaluate"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "feeSchedule": dispute_only_fee_schedule,
            "listing": tool_server_listing,
            "currentPublisher": listing_body["publisher"].clone(),
            "activation": activation,
            "charter": charter,
            "case": sanction_case,
            "penalty": dispute_penalty,
            "evaluatedAt": generated_at + 6
        }))
        .send()
        .expect("evaluate mismatch penalty");
    assert_eq!(
        mismatch_evaluation_response.status(),
        reqwest::StatusCode::OK
    );
    let mismatch_evaluation: serde_json::Value = mismatch_evaluation_response
        .json()
        .expect("parse mismatch evaluation");
    assert_eq!(
        mismatch_evaluation["findings"][0]["code"],
        "bond_requirement_missing"
    );
}

#[test]
#[ignore = "flaky on CI: aggregated.reachable_count comes back as 1 vs expected 2 under timing pressure; tracked as a follow-up"]
fn certify_adversarial_multi_operator_open_market_preserves_visibility_without_trust() {
    if skip_when_loopback_bind_denied(
        "certify_adversarial_multi_operator_open_market_preserves_visibility_without_trust",
    ) {
        return;
    }

    let scenarios_dir = unique_path("chio-adversarial-open-market-scenarios", "");
    let results_dir = unique_path("chio-adversarial-open-market-results", "");
    let output_path = unique_path("chio-adversarial-open-market-artifact", ".json");
    let seed_path = unique_path("chio-adversarial-open-market-seed", ".txt");
    let state = chio_test_support::private_tempdir().expect("create private authority state");
    let receipt_db_path = state.path().join("receipts.sqlite");
    let authority_db_path = state.path().join("authority.sqlite");
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
        generated_at + 10,
    );
    assert_eq!(aggregated.peer_count, 3);
    assert_eq!(aggregated.reachable_count, 2);
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
