//! Portable verdicts must consult the same managed authority as full admission.
use super::*;
use chio_core::{capability::token::CapabilityToken, crypto::Keypair};
use chio_kernel::{ChioKernel, KernelConfig};
use chio_kernel_core::{EvaluationVerdict, PortableToolCallRequest, Verdict};

struct Fixture {
    _root: tempfile::TempDir,
    clock: Arc<AuthorityClock>,
    source: SqliteCapabilityAuthority,
    kernel: ChioKernel,
    token: CapabilityToken,
    issuer: Keypair,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = private_root()?;
        let clock = Arc::new(AuthorityClock(AtomicU64::new(100)));
        let path = root.path().join("issuer.db");
        let source = SqliteCapabilityAuthority::open_with_clock(&path, clock.clone())?;
        source.initialize_replication("portable-lifecycle")?;
        let issuer = source.current_keypair()?;
        let scope = serde_json::from_value(serde_json::json!({"grants":[{
            "server_id":"server", "tool_name":"read", "operations":["invoke"], "constraints":[]
        }], "resource_grants":[], "prompt_grants":[]}))?;
        let token = source.issue_capability(&Keypair::generate().public_key(), scope, 300)?;
        let mut kernel = ChioKernel::new_with_clock(
            KernelConfig {
                keypair: Keypair::generate(),
                // A static pin must not override this managed issuer's lifecycle.
                ca_public_keys: vec![issuer.public_key()],
                max_delegation_depth: 5,
                policy_hash: chio_core::sha256_hex(b"portable-lifecycle"),
                allow_sampling: false,
                allow_sampling_tool_use: false,
                allow_elicitation: false,
                max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
                max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
                require_web3_evidence: false,
                allow_ephemeral_receipt_log: true,
                allow_ephemeral_revocation_store: true,
                checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
                retention_config: None,
                memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
                deadlines: chio_kernel::HotPathDeadlineConfig::default(),
            },
            clock.clone(),
        );
        kernel.set_capability_authority(Box::new(SqliteCapabilityAuthority::open_with_clock(
            &path,
            clock.clone(),
        )?));
        clock.0.store(101, Ordering::SeqCst);
        source.rotate_with_verification_deadline(110)?;
        clock.0.store(105, Ordering::SeqCst);
        let fixture = Self {
            _root: root,
            clock,
            source,
            kernel,
            token,
            issuer,
        };
        assert_eq!(
            fixture.evaluate(&fixture.token, 105).verdict,
            Verdict::Allow
        );
        Ok(fixture)
    }

    fn evaluate(&self, token: &CapabilityToken, now: u64) -> EvaluationVerdict {
        let request = PortableToolCallRequest {
            request_id: "portable-lifecycle".into(),
            server_id: "server".into(),
            tool_name: "read".into(),
            agent_id: token.subject.to_hex(),
            arguments: serde_json::json!({}),
        };
        self.kernel
            .evaluate_portable_verdict(token, &request, &[], &FixedClock::new(now), None)
    }

    fn assert_denied(&self, token: &CapabilityToken, now: u64) {
        let verdict = self.evaluate(token, now);
        assert_eq!(verdict.verdict, Verdict::Deny);
        assert!(
            verdict
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("issuer lifecycle denied")),
            "{:?}",
            verdict.reason
        );
        assert!(verdict.verified.is_none());
    }
}

#[test]
fn kg2_portable_denies_post_rotation_issuance_during_verification_grace() -> TestResult {
    let fixture = Fixture::new()?;
    let mut body = fixture.token.signing_body().body;
    body.issued_at = 102;
    let forged = CapabilityToken::sign(body, &fixture.issuer)?;
    fixture.assert_denied(&forged, 105);
    Ok(())
}

#[test]
fn kg2_portable_static_pin_cannot_override_retirement_or_revocation() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.source.retire_issuer(&fixture.issuer.public_key())?;
    fixture.assert_denied(&fixture.token, 105);
    fixture.source.revoke_issuer(&fixture.issuer.public_key())?;
    fixture.assert_denied(&fixture.token, 105);
    Ok(())
}

#[test]
fn kg2_portable_static_pin_cannot_extend_exact_verification_deadline() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.clock.0.store(110, Ordering::SeqCst);
    fixture.assert_denied(&fixture.token, 110);
    Ok(())
}

#[test]
fn kg2_portable_denies_when_managed_authority_clock_fails() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.clock.0.store(u64::MAX, Ordering::SeqCst);
    fixture.assert_denied(&fixture.token, 105);
    Ok(())
}
