// Real signed authority RPC, original signed parent and fenced revocation store.
use super::*;
use chio_kernel::RevocationStore;
use chio_secret_broker::authority_ipc::{
    AuthorityRpcClient, AuthorityRpcClientConfig, AuthorityRpcServer, BrokerAdmissionAuthority,
};
use chio_secret_broker::kernel_admission::BrokerKernelAuthorityHandler;
use chio_secret_broker::revocation::{
    BrokerRevocationRequest, BrokerRevocations, CapabilityLiveness, CapabilityLivenessRequest,
};
use std::sync::atomic::AtomicBool;

#[test]
fn native_broker_live_authority_rejects_a_kernel_from_another_authority() -> TestResult {
    for mismatch in ["kernel", "native", "participant", "enforcement"] {
        let mut fixture = super::super::super::super::public_fixture()?;
        let (_, _, registration) = install_broker(&mut fixture)?;
        let other = super::super::super::super::public_fixture()?;
        match mismatch {
            "native" => fixture
                .kernel
                .set_security_pre_dispatch_hook(other.hook.clone()),
            "participant" => fixture.kernel.clear_supplemental_admission_participant(),
            "enforcement" => fixture
                .kernel
                .set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Optional),
            _ => {}
        }
        let kernel = if mismatch == "kernel" {
            other.kernel
        } else {
            fixture.kernel
        };
        assert!(
            BrokerKernelAuthorityHandler::new(
                &fixture.authority,
                fixture.binding.clone(),
                registration.registrar.clone(),
                Arc::new(kernel),
            )
            .is_err(),
            "mismatched {mismatch} supplied parent liveness for this authority"
        );
    }
    Ok(())
}

#[test]
fn native_broker_live_authority_rechecks_original_parent_and_signs_actual_revocation_cut(
) -> TestResult {
    let mut fixture = super::super::super::super::public_fixture()?;
    let (execute, _, registration) = install_broker(&mut fixture)?;
    fixture
        .kernel
        .register_delegation_parent(&fixture.request.capability)?;
    let Fixture {
        kernel,
        authority,
        binding,
        request,
        _directory,
        ..
    } = fixture;
    let handler = Arc::new(BrokerKernelAuthorityHandler::new(
        &authority,
        binding,
        registration.registrar.clone(),
        Arc::new(kernel),
    )?);
    let broker_key = Keypair::from_seed(&[36; 32]);
    let authority_key = Keypair::from_seed(&[34; 32]);
    let socket = _directory.path().join("authority.sock");
    let server = AuthorityRpcServer::bind(
        &socket,
        broker_key.public_key(),
        Arc::new(Ed25519Backend::new(authority_key.clone())),
        handler,
        2,
    )?;
    let mut serving = ServingAuthority::start(server)?;
    let client = AuthorityRpcClient::connect(
        AuthorityRpcClientConfig {
            socket_path: socket,
            trusted_authority: authority_key.public_key(),
            timeout_ms: 1000,
            maximum_clock_skew_seconds: 2,
        },
        Arc::new(Ed25519Backend::new(broker_key)),
    )?;
    let before =
        authority
            .budget_store()
            .list_mutation_events(100, Some(&request.capability.id), None)?;
    let parent_request = CapabilityLivenessRequest {
        parent_capability_id: request.capability.id.clone(),
        expected_subject: request.capability.subject.clone(),
        expected_audience: "native-broker".into(),
        now_unix_seconds: now_ms()? / 1000,
    };
    let parent = client.verify_live_parent(&parent_request)?;
    assert_eq!(parent.capability_id, request.capability.id);
    assert_eq!(parent.subject, request.capability.subject);
    assert_eq!(
        parent.expires_at_unix_seconds,
        request.capability.expires_at
    );
    assert!(parent.delegation_ancestor_ids.is_empty());
    assert!(parent.verified_at_unix_seconds <= now_ms()? / 1000);
    let exchange = client.verify_live_parent_with_audit_evidence(&parent_request)?;
    assert_eq!(exchange.trusted_authority(), &authority_key.public_key());
    for mutation in ["subject", "audience", "absent", "old", "future"] {
        let mut changed = parent_request.clone();
        match mutation {
            "subject" => changed.expected_subject = Keypair::from_seed(&[37; 32]).public_key(),
            "audience" => changed.expected_audience = "other-broker".into(),
            "absent" => changed.parent_capability_id = "absent-parent".into(),
            "old" => changed.now_unix_seconds = 0,
            _ => changed.now_unix_seconds = u64::MAX,
        }
        assert!(client.verify_live_parent(&changed).is_err(), "{mutation}");
    }
    assert!(
        client.prepare_execution(&execute).is_err(),
        "live parent alone cannot authorize execution"
    );
    let mut revocation = BrokerRevocationRequest {
        broker_capability_id: execute.capability.body.capability_id.clone(),
        revocation_id: execute.capability.body.revocation_id.clone(),
        now_unix_seconds: now_ms()? / 1000,
    };
    let revocations = authority.revocation_store();
    let initial = client.check_broker_revocation(&revocation)?;
    assert!(!initial.revoked);
    assert_eq!(initial.authority_domain, "native-broker-domain");
    assert_eq!(initial.commit_index, revocations.latest_revocation_index()?);
    let exchange = client.check_broker_revocation_with_audit_evidence(&revocation)?;
    assert_eq!(exchange.trusted_authority(), &authority_key.public_key());
    assert!(revocations.revoke(&revocation.revocation_id)?);
    assert!(client.check_broker_revocation(&revocation)?.revoked);
    revocation.revocation_id = "other-revocation-id".into();
    assert!(!client.check_broker_revocation(&revocation)?.revoked);
    assert!(revocations.revoke(&revocation.broker_capability_id)?);
    assert!(client.check_broker_revocation(&revocation)?.revoked);
    assert!(revocations.revoke(&request.capability.id)?);
    assert!(client
        .verify_live_parent(&CapabilityLivenessRequest {
            now_unix_seconds: now_ms()? / 1000,
            ..parent_request
        })
        .is_err());
    assert_eq!(
        authority
            .budget_store()
            .list_mutation_events(100, Some(&request.capability.id), None)?,
        before
    );
    serving.stop()?;
    Ok(())
}

struct ServingAuthority {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
}
impl ServingAuthority {
    fn start(server: AuthorityRpcServer) -> TestResult<Self> {
        server.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                if !server.try_serve_one().map_err(|error| error.to_string())? {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            }
            Ok(())
        });
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
    fn stop(&mut self) -> TestResult {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| "authority thread panicked")?
                .map_err(|error| format!("authority server: {error}"))?;
        }
        Ok(())
    }
}
impl Drop for ServingAuthority {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
