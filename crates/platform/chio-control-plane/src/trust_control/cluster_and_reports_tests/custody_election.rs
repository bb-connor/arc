//! Election ranks signing custodians ahead of lower custody-less URLs.
use super::*;

struct CustodyCluster {
    directory: tempfile::TempDir,
    custodian: ServedPeer,
    lowest: ServedPeer,
    middle: ServedPeer,
}

/// Two followers hold only the pinned anchor and a signed envelope, and both
/// URLs sort below the custodian. The gate holds custodian authority exports.
fn custody_cluster(gate: Option<Arc<AuthorityGate>>) -> CustodyCluster {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let now = unix_timestamp_now().test_unwrap();
    let custodian = SqliteCapabilityAuthority::open_with_clock(
        directory.path().join("custodian.sqlite3"),
        fixed_clock(now),
    )
    .test_unwrap();
    let anchor = custodian
        .initialize_replication("custody-election")
        .test_unwrap();
    let envelope = custodian.signed_snapshot().test_unwrap();
    for name in ["lowest.sqlite3", "middle.sqlite3"] {
        let follower = SqliteCapabilityAuthority::open_with_clock(
            directory.path().join(name),
            fixed_clock(now),
        )
        .test_unwrap();
        follower.pin_replication_anchor(&anchor).test_unwrap();
        follower.apply_signed_snapshot(&envelope).test_unwrap();
    }
    let (first, second) = (ServedPeer::reserve(), ServedPeer::reserve());
    let ((lowest_listener, lowest_url), (middle_listener, middle_url)) = if first.1 < second.1 {
        (first, second)
    } else {
        (second, first)
    };
    let (custodian_listener, custodian_url) = ServedPeer::reserve_on("127.0.0.2:0");
    assert!(middle_url < custodian_url);
    let node = |listener, url: String, peers: [&str; 2], authority: &str, gate| {
        let mut state = state_with_cluster(&url, &peers, None, None, None);
        state.config.authority_db_path = Some(directory.path().join(authority));
        state.finding_challenge_clock = fixed_clock(now);
        ServedPeer::serve(listener, url, state, gate)
    };
    let custodian = node(
        custodian_listener,
        custodian_url.clone(),
        [&lowest_url, &middle_url],
        "custodian.sqlite3",
        gate,
    );
    let lowest = node(
        lowest_listener,
        lowest_url.clone(),
        [&middle_url, &custodian_url],
        "lowest.sqlite3",
        None,
    );
    let middle = node(
        middle_listener,
        middle_url.clone(),
        [&lowest_url, &custodian_url],
        "middle.sqlite3",
        None,
    );
    CustodyCluster {
        directory,
        custodian,
        lowest,
        middle,
    }
}

#[test]
fn healthy_custodian_leads_over_lower_custody_less_urls() {
    let cluster = custody_cluster(None);
    for follower in [&cluster.lowest, &cluster.middle] {
        let _ = sync_peer(&cluster.custodian.state, &follower.url);
    }
    for follower in [&cluster.lowest, &cluster.middle] {
        let _ = sync_peer(&follower.state, &cluster.custodian.url);
    }
    for node in [&cluster.custodian, &cluster.lowest, &cluster.middle] {
        assert_eq!(
            current_leader_url(&node.state).as_deref(),
            Some(cluster.custodian.url.as_str())
        );
        load_authority_status_for_state(&node.state).test_unwrap();
    }
}

#[test]
fn custody_read_error_ranks_custodian_custody_less() {
    let cluster = custody_cluster(None);
    let _ = sync_peer(&cluster.custodian.state, &cluster.lowest.url);
    assert_eq!(
        current_leader_url(&cluster.custodian.state).as_deref(),
        Some(cluster.custodian.url.as_str())
    );
    std::fs::write(
        cluster.directory.path().join("custodian.sqlite3"),
        b"not an authority database",
    )
    .test_unwrap();
    let _ = sync_peer(&cluster.custodian.state, &cluster.lowest.url);
    assert_eq!(
        current_leader_url(&cluster.custodian.state).as_deref(),
        Some(cluster.lowest.url.as_str())
    );
}

#[test]
fn without_a_reachable_custodian_lowest_url_keeps_budget_liveness_and_refuses_authority() {
    let cluster = custody_cluster(None);
    let _ = sync_peer(&cluster.lowest.state, &cluster.middle.url);
    let _ = sync_peer(&cluster.middle.state, &cluster.lowest.url);
    for node in [&cluster.lowest, &cluster.middle] {
        assert_eq!(
            current_leader_url(&node.state).as_deref(),
            Some(cluster.lowest.url.as_str())
        );
        assert!(current_budget_event_authority(&node.state).is_ok());
    }
    let refused = load_authority_status_for_state(&cluster.lowest.state).test_unwrap_err();
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// The follower samples the elected custodian's status again while the
/// custodian holds its second authority export. That later sample ranks it.
fn rank_after_late_custodian_status(change: impl FnOnce(&mut Value)) {
    let (gate, held) = AuthorityGate::holding(2);
    let cluster = custody_cluster(Some(gate));
    let _ = sync_peer(&cluster.custodian.state, &cluster.lowest.url);
    let _ = sync_peer(&cluster.lowest.state, &cluster.custodian.url);
    assert_eq!(
        current_leader_url(&cluster.lowest.state).as_deref(),
        Some(cluster.custodian.url.as_str())
    );
    let round = {
        let state = cluster.lowest.state.clone();
        let custodian_url = cluster.custodian.url.clone();
        std::thread::spawn(move || sync_peer(&state, &custodian_url))
    };
    held.recv_timeout(Duration::from_secs(30)).test_unwrap();
    let mut status = serde_json::to_value(
        service_runtime::client::build_cluster_peer_client(
            &cluster.lowest.state.config.access,
            &cluster.custodian.url,
        )
        .test_unwrap()
        .cluster_status()
        .test_unwrap(),
    )
    .test_unwrap();
    change(&mut status);
    *cluster
        .custodian
        .cluster_status_override
        .lock()
        .test_unwrap() = Some(status);
    cluster
        .custodian
        .gate
        .as_ref()
        .test_unwrap()
        .release
        .notify_one();
    let _ = round.join().test_unwrap();
    assert_eq!(
        current_leader_url(&cluster.lowest.state).as_deref(),
        Some(cluster.lowest.url.as_str())
    );
}

#[test]
fn late_identity_mismatch_deranks_the_elected_custodian() {
    rank_after_late_custodian_status(|status| {
        status["selfUrl"] = json!("http://127.0.0.3:1");
    });
}

#[test]
fn late_lost_custody_deranks_the_elected_custodian() {
    rank_after_late_custodian_status(|status| {
        status["signingCustody"] = json!(false);
    });
}
