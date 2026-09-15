use crate::{
    common::{self, Result},
    funded_work::{
        settlement::Prepared, verifier_handoff as handoff, verifier_operator as operator,
    },
};
use chio_finding::FindingFacetKind;
use serde_json::json;

fn fixture() -> Result<(
    super::native::Fixture,
    operator::Enrollment,
    handoff::Request,
)> {
    let f = super::native::fixture_profile(
        vec![
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetKind::CheckpointMembership,
            FindingFacetKind::GuaranteeConsistency,
        ],
        true,
    )?;
    let (original, submission, _) = super::wire::candidate(&f)?;
    let enrollment = operator::Enrollment {
        schema: operator::ENROLLMENT_SCHEMA.into(),
        policy: f.native.policy.clone(),
        agreement: f.agreement.clone(),
    };
    let request = handoff::Request {
        schema: handoff::REQUEST_SCHEMA.into(),
        submission,
        execution: original.execution.ok_or("execution missing")?,
        input: original.input,
        original_output: original.output.clone(),
        output: original.output,
        claim: Prepared {
            intent: json!(null),
            nonce: "0".into(),
            raw_transaction: "0x00".into(),
            transaction_hash: format!("0x{}", "ab".repeat(32)),
        },
    };
    Ok((f, enrollment, request))
}

#[test]
fn public_verifier_reconstructs_original_authority_without_private_native_request() -> Result<()> {
    let (_f, enrollment, request) = fixture()?;
    let original = handoff::original(&enrollment, &request, common::now()?)?;
    assert_eq!(original.binding, request.submission.body.binding);
    assert_eq!(original.output, request.original_output);
    let raw = serde_json::to_value(&request)?;
    assert!(raw.get("observation").is_none());
    assert!(raw.get("capability").is_none());
    Ok(())
}

#[test]
fn provider_signed_binding_substitution_cannot_replace_native_execution_authority() -> Result<()> {
    let (f, enrollment, request) = fixture()?;
    for field in [
        "authorityUuid",
        "operationId",
        "holdId",
        "authorizationId",
        "requestSha256",
        "outcomeId",
        "rawOutcomeSha256",
        "allocationId",
    ] {
        let mut body = serde_json::to_value(&request.submission.body)?;
        body["binding"][field] = json!(if field == "allocationId" {
            format!("0x{}", "ab".repeat(32))
        } else {
            "ab".repeat(32)
        });
        let mut changed = request.clone();
        changed.submission = crate::funded_work::evidence::sign(
            serde_json::from_value(body)?,
            &common::key(f.directory.path())?,
        )?;
        assert!(
            handoff::original(&enrollment, &changed, common::now()?).is_err(),
            "{field}"
        );
    }
    let mut changed = request.clone();
    changed.input.push(' ');
    assert!(handoff::original(&enrollment, &changed, common::now()?).is_err());
    changed = request.clone();
    changed.original_output = json!([]);
    assert!(handoff::original(&enrollment, &changed, common::now()?).is_err());
    Ok(())
}

#[test]
#[ignore = "requires owned chain; selected by authority/verifier qualification"]
fn verifier_reobserves_claim_after_checker_before_minting_a_decision() -> Result<()> {
    use crate::funded_work::{evidence, settlement, verification};
    let directory = tempfile::tempdir()?;
    let f = crate::funded_work::smoke::setup(directory.path())?;
    f.native.execute(&f.agreement, &f.request)?;
    let original = f.native.evidence(&f.request)?;
    let allocation = original.binding.allocation_id.clone();
    let submission = evidence::submit(
        &original,
        &original.output,
        &common::key(directory.path())?,
        &f.native.journal,
    )?;
    f.native
        .journal
        .retain(&allocation, "submission", &submission)?;
    let entry = f
        .native
        .journal
        .by_request(&f.request.request_id)?
        .ok_or("entry missing")?;
    let checkpoint: crate::funded_work::Checkpoint = std::sync::Arc::new(|_| Ok(()));
    settlement::drive(
        &entry,
        settlement::Action::Submit,
        &f.native.policy,
        &f.native.journal,
        f.chain.as_ref(),
        &checkpoint,
    )?;
    f.chain
        .request(json!({"method":"advance","allocation":allocation,"phase":"decision"}))?;
    let request = handoff::export(&f.native, &f.request)?;
    let enrollment = operator::Enrollment {
        schema: operator::ENROLLMENT_SCHEMA.into(),
        policy: f.native.policy.clone(),
        agreement: f.agreement,
    };
    let state = directory.path().join("verifier");
    operator::initialize(&state, &enrollment)?;
    struct Checker {
        chain: std::sync::Arc<crate::funded_work::local_chain::LocalChain>,
        allocation: String,
        output: serde_json::Value,
    }
    impl verification::Checker for Checker {
        fn check(&self, _: &str) -> Result<serde_json::Value> {
            self.chain.request(
                json!({"method":"advance","allocation":self.allocation,"phase":"refund"}),
            )?;
            Ok(self.output.clone())
        }
    }
    let checker = Checker {
        chain: f.chain.clone(),
        allocation,
        output: original.output,
    };
    assert!(
        operator::decide(&state, &request, f.chain.as_ref(), &checker).is_err(),
        "a claim that expired while checking must not mint a verifier decision"
    );
    let db = rusqlite::Connection::open(state.join(operator::DATABASE))?;
    let count: i64 = db.query_row(
        "SELECT count(*) FROM custody WHERE decision IS NOT NULL",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn changed_verifier_seed_cannot_consume_pending_original_custody() -> Result<()> {
    use crate::funded_work::{observer, verification};
    let (f, enrollment, request) = fixture()?;
    let state = f.directory.path().join("verifier");
    operator::initialize(&state, &enrollment)?;
    std::fs::write(
        state.join("key.seed"),
        chio_core_types::Keypair::generate().seed_hex(),
    )?;
    struct Unavailable;
    impl observer::FundingSource for Unavailable {
        fn observe(&self, _: &str) -> Result<observer::Observation> {
            Err("unexpected observer invocation".into())
        }
    }
    impl verification::Checker for Unavailable {
        fn check(&self, _: &str) -> Result<serde_json::Value> {
            Err("unexpected checker invocation".into())
        }
    }
    let error = match operator::decide(&state, &request, &Unavailable, &Unavailable) {
        Ok(_) => return Err("changed key authorized pending custody".into()),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("verifier key changed original enrollment"),
        "{error}"
    );
    let db = rusqlite::Connection::open(state.join(operator::DATABASE))?;
    let count: i64 = db.query_row(
        "SELECT count(*) FROM custody WHERE request IS NULL AND decision IS NULL",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(count, 1);
    Ok(())
}
