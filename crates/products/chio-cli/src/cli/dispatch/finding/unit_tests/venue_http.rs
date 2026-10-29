use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn verify_by_id_runs_the_strict_ingress_over_the_served_bytes() {
    if !loopback_bind_available() {
        eprintln!("skipping finding verify transport test: loopback bind denied");
        return;
    }
    let artifact = canonical_golden_finding();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/v1/findings/{GOLDEN_FINDING_ID}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(artifact),
        )
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    tokio::task::spawn_blocking(move || {
        cmd_finding_verify(
            None,
            Some(GOLDEN_FINDING_ID),
            None,
            None,
            None,
            None,
            true,
            true,
            Some(&uri),
            &NONE,
        )
    })
    .await
    .unwrap()
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_by_id_rejects_a_different_valid_artifact() {
    if !loopback_bind_available() {
        eprintln!("skipping finding verify transport test: loopback bind denied");
        return;
    }
    let requested_id = "a".repeat(64);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/v1/findings/{requested_id}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(canonical_golden_finding()),
        )
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let error = tokio::task::spawn_blocking(move || {
        cmd_finding_verify(
            None,
            Some(&requested_id),
            None,
            None,
            None,
            None,
            true,
            true,
            Some(&uri),
            &NONE,
        )
    })
    .await
    .unwrap()
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("venue returned finding") && error.contains("requested id"),
        "unexpected error: {error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn buy_drives_the_authenticated_live_purchase_roundtrip() {
    if !loopback_bind_available() {
        eprintln!("skipping finding buy transport test: loopback bind denied");
        return;
    }
    let fixture = live_buy_fixture();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/v1/findings/{}", fixture.finding_id)))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(fixture.raw_finding.clone()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let request_body =
        String::from_utf8(chio_core_types::canonical_json_bytes(&fixture.request).unwrap())
            .unwrap();
    let response_body =
        String::from_utf8(chio_core_types::canonical_json_bytes(&fixture.result).unwrap()).unwrap();
    Mock::given(method("POST"))
        .and(path_matcher(format!(
            "/v1/findings/{}/purchase",
            fixture.finding_id
        )))
        .and(header("authorization", "Bearer venue-token"))
        .and(header("content-type", "application/json"))
        .and(body_string(request_body))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(response_body),
        )
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let finding_id = fixture.finding_id;
    let payer = fixture.result.payer;
    tokio::task::spawn_blocking(move || {
        cmd_finding_buy(
            &finding_id,
            400,
            "USD",
            Some(&payer),
            Some(900),
            true,
            Some(&uri),
            Some("venue-token"),
            &NONE,
        )
    })
    .await
    .unwrap()
    .unwrap();
}

#[test]
fn venue_reads_do_not_follow_a_redirect_to_a_second_authority() {
    if !loopback_bind_available() {
        eprintln!("skipping venue redirect test: loopback bind denied");
        return;
    }
    let probe = super::super::redirect_probe::RedirectProbe::start("302 Found");
    assert!(fetch_finding_bytes(&probe.venue_url, GOLDEN_FINDING_ID, &NONE).is_err());
    probe.assert_redirect_not_followed("the finding fetch");

    let probe = super::super::redirect_probe::RedirectProbe::start("302 Found");
    let venue = Some(probe.venue_url.as_str());
    assert!(cmd_finding_search("repo:", None, None, None, true, venue, &NONE).is_err());
    probe.assert_redirect_not_followed("the finding search");
}

#[test]
fn venue_publish_does_not_follow_a_redirect_to_a_second_authority() {
    if !loopback_bind_available() {
        eprintln!("skipping venue redirect test: loopback bind denied");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = write_temp(&dir, "finding.json", &canonical_golden_finding());
    let probe = super::super::redirect_probe::RedirectProbe::start("303 See Other");
    let venue = Some(probe.venue_url.as_str());
    assert!(cmd_finding_publish(&path, true, venue, Some("venue-token"), &NONE).is_err());
    probe.assert_redirect_not_followed("the finding publish");
}
