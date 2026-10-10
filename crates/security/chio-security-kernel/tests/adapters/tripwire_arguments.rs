use super::*;

const MARKER: &str = "synthetic-tripwire-marker";

struct ArgumentDetector {
    kind: TripwireKind,
    marker: &'static str,
    unavailable: bool,
    calls: AtomicUsize,
}

impl TripwireDetectorPort for ArgumentDetector {
    fn detect(&self, input: &TripwireInput) -> PortResult<TripwireDecision> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(input.tenant_id.as_str(), "tenant-a");
        assert_eq!(
            input.content_digest,
            Digest32::new(*sha256(input.content.as_bytes()).as_bytes())
        );
        if input.kind == self.kind && input.content.as_bytes() == self.marker.as_bytes() {
            if self.unavailable {
                return Err(PortError::unavailable());
            }
            return Ok(TripwireDecision::Match {
                artifact_id_hash: Digest32::new([61; 32]),
                artifact_version_hash: Digest32::new([62; 32]),
            });
        }
        Ok(TripwireDecision::Clear)
    }
}

fn assert_argument_denied(kind: TripwireKind, arguments: serde_json::Value, unavailable: bool) {
    assert_marker_denied(kind, MARKER, arguments, unavailable);
}

fn assert_marker_denied(
    kind: TripwireKind,
    marker: &'static str,
    arguments: serde_json::Value,
    unavailable: bool,
) {
    let (mut kernel, mut request, invocations) = kernel_with_server();
    request.arguments = arguments;
    let events = Arc::new(FakeEvents::new(false));
    let receipts = Arc::new(FakeSecurityReceipts::new(false));
    kernel.add_guard(Box::new(TripwireGuard::new(
        Arc::new(ArgumentDetector {
            kind,
            marker,
            unavailable,
            calls: AtomicUsize::new(0),
        }),
        tripwire_publisher_with_receipts(events.clone(), receipts.clone()),
        MissingContextPolicy::Deny,
    )));
    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context(&request))
        .test_unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.output, None);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    if unavailable {
        assert_eq!(events.appends.load(Ordering::SeqCst), 0);
        assert_eq!(receipts.bodies().len(), 0);
        assert!(response.receipt.evidence.iter().any(|evidence| {
            evidence
                .details
                .as_deref()
                .is_some_and(|details| details.contains("tripwire detector failed"))
        }));
        return;
    }
    assert_eq!(events.appends.load(Ordering::SeqCst), 1);
    let bodies = receipts.bodies();
    assert_eq!(bodies.len(), 1);
    assert!(!serde_json::to_string(&bodies[0])
        .test_unwrap()
        .contains(marker));
    let ActiveDefenseReceiptBody::TripwireObservation(observation) = &bodies[0] else {
        panic!("argument match must persist a tripwire observation");
    };
    assert_eq!(observation.tripwire_kind, kind);
    assert_eq!(observation.header.tenant_id.as_str(), "tenant-a");
    assert_eq!(observation.artifact_id_hash, Digest32::new([61; 32]));
    assert_eq!(observation.artifact_version_hash, Digest32::new([62; 32]));
}

#[test]
fn credential_argument_is_denied_before_dispatch_with_evidence() {
    assert_argument_denied(
        TripwireKind::CredentialArtifact,
        serde_json::json!({"nested": [null, {"value": MARKER}]}),
        false,
    );
}

#[test]
fn file_marker_argument_is_denied_before_dispatch_with_evidence() {
    assert_argument_denied(
        TripwireKind::FileMarker,
        serde_json::json!({"nested": [[MARKER]]}),
        false,
    );
}

#[test]
fn browser_cookie_argument_is_denied_before_dispatch_with_evidence() {
    assert_argument_denied(
        TripwireKind::BrowserCookie,
        serde_json::json!({"cookie": MARKER}),
        false,
    );
}

#[test]
fn internal_hostname_argument_is_denied_before_dispatch_with_evidence() {
    assert_argument_denied(
        TripwireKind::InternalHostname,
        serde_json::json!({"hostname": MARKER}),
        false,
    );
}

#[test]
fn argument_object_keys_are_inspected() {
    assert_argument_denied(
        TripwireKind::InternalHostname,
        serde_json::json!({(MARKER): "ordinary"}),
        false,
    );
}

#[test]
fn argument_detector_failure_prevents_dispatch_without_fabricating_a_hit() {
    assert_argument_denied(
        TripwireKind::CredentialArtifact,
        serde_json::json!({"credential": MARKER}),
        true,
    );
}

#[test]
fn credential_in_authorization_header_is_denied() {
    assert_argument_denied(
        TripwireKind::CredentialArtifact,
        serde_json::json!({"headers": {"Authorization": format!("Bearer {MARKER}")}}),
        false,
    );
}

#[test]
fn cookie_assignment_is_denied() {
    assert_argument_denied(
        TripwireKind::BrowserCookie,
        serde_json::json!({"Cookie": format!("ordinary=value; session={MARKER}; other=value")}),
        false,
    );
}

#[test]
fn hostname_inside_url_is_denied() {
    assert_argument_denied(
        TripwireKind::InternalHostname,
        serde_json::json!({"url": format!("https://{MARKER}:443/path?value=ordinary")}),
        false,
    );
}

#[test]
fn file_marker_inside_quoted_command_is_denied() {
    assert_argument_denied(
        TripwireKind::FileMarker,
        serde_json::json!({"command": format!("read '{MARKER}'")}),
        false,
    );
}

#[test]
fn oversized_argument_work_is_refused_before_detector_or_dispatch() {
    let deep = (0..34).fold(serde_json::Value::Null, |value, _| {
        serde_json::json!([value])
    });
    let wide = serde_json::Value::Array(vec![serde_json::Value::Null; 4097]);
    let large = serde_json::Value::String("x".repeat(1024 * 1024 + 1));
    let many = serde_json::Value::String("ordinary ".repeat(4097));
    for arguments in [deep, wide, large, many] {
        let (mut kernel, mut request, invocations) = kernel_with_server();
        request.arguments = arguments;
        let detector = Arc::new(ArgumentDetector {
            kind: TripwireKind::CredentialArtifact,
            marker: MARKER,
            unavailable: false,
            calls: AtomicUsize::new(0),
        });
        kernel.add_guard(Box::new(TripwireGuard::new(
            detector.clone(),
            tripwire_publisher(Arc::new(FakeEvents::new(false))),
            MissingContextPolicy::Deny,
        )));
        let response = kernel
            .evaluate_tool_call_blocking_with_security_context(
                &request,
                &security_context(&request),
            )
            .test_unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert_eq!(detector.calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn padded_credentials_preserve_slashes_and_padding() {
    const PADDED: &str = "synthetic/credential+data==";
    for text in [
        format!("Bearer {PADDED}"),
        format!("session={PADDED}; ordinary=value"),
    ] {
        assert_marker_denied(
            TripwireKind::CredentialArtifact,
            PADDED,
            serde_json::json!({"header": text}),
            false,
        );
    }
}

#[test]
fn dotted_hostname_is_preserved_inside_url() {
    assert_marker_denied(
        TripwireKind::InternalHostname,
        "synthetic-decoy.internal",
        serde_json::json!({"url": "https://synthetic-decoy.internal:8443/path?q=ordinary"}),
        false,
    );
}

#[test]
fn clean_arguments_allow_without_fabricating_detection_evidence() {
    for arguments in [
        serde_json::json!({}),
        serde_json::json!({"items": [null, true, 42, ""]}),
        serde_json::json!({"text": "ordinary words; session=ordinary/value==", "url": "https://ordinary.internal/path"}),
    ] {
        let (mut kernel, mut request, invocations) = kernel_with_server();
        request.arguments = arguments;
        let events = Arc::new(FakeEvents::new(false));
        let receipts = Arc::new(FakeSecurityReceipts::new(false));
        kernel.add_guard(Box::new(TripwireGuard::new(
            Arc::new(ArgumentDetector {
                kind: TripwireKind::CredentialArtifact,
                marker: MARKER,
                unavailable: false,
                calls: AtomicUsize::new(0),
            }),
            tripwire_publisher_with_receipts(events.clone(), receipts.clone()),
            MissingContextPolicy::Deny,
        )));
        let response = kernel
            .evaluate_tool_call_blocking_with_security_context(
                &request,
                &security_context(&request),
            )
            .test_unwrap();
        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        assert_eq!(events.appends.load(Ordering::SeqCst), 0);
        assert!(receipts.bodies().is_empty());
    }
}

#[test]
fn padded_credentials_next_to_command_delimiters_are_denied() {
    const PADDED: &str = "synthetic/credential+data==";
    for command in [
        format!("send {PADDED};"),
        format!("send ({PADDED})"),
        format!("send [{PADDED}],ordinary"),
    ] {
        assert_marker_denied(
            TripwireKind::CredentialArtifact,
            PADDED,
            serde_json::json!({"command": command}),
            false,
        );
    }
}
