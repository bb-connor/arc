//! Public-file choreography; coordinator never loads role keys or private requests.
use super::{
    authority_enrollment::Pins,
    checkpoint_files as files, checkpoint_operator, evidence,
    isolated_roles::{Runner, ROLES},
    local_chain::LocalChain,
    observer::Domain,
    process::Server,
    verifier_operator,
    work_consent::{Acceptance, Intent, Proposal, INTENT_SCHEMA},
};
use crate::common::{self, digest, Result};
use chio_core_types::{sha256_hex, PublicKey};
use serde_json::{json, Value};
use std::{fs, path::Path, sync::Arc};

fn generate(r: &Runner, role: &str, path: &str) -> Result<PublicKey> {
    Ok(serde_json::from_value(
        r.run(role, &["init", path], &[], None, false)?.value()?["publicKey"].clone(),
    )?)
}
pub fn run(root: &Path, mode: &str) -> Result<Value> {
    if !["pay", "reject"].contains(&mode) {
        return Err("isolated lifecycle supports pay or reject".into());
    }
    let r = Runner::new(root)?;
    let pins = Pins {
        buyer: generate(&r, "buyer", "/state")?,
        provider: generate(&r, "provider", "/state")?,
        verifier: generate(&r, "verifier", "/state")?,
        governance: generate(&r, "governance", "/state")?,
        checkpoint: generate(&r, "operator", "/state/checkpoint")?,
        status: generate(&r, "operator", "/state/status")?,
    };
    let isolation: Vec<Value> = ROLES
        .iter()
        .map(|role| r.probe(role))
        .collect::<Result<_>>()?;
    let public = r.root.join("public");
    let pinfile = public.join("authorities.json");
    files::write(&pinfile, &pins)?;
    let expires = (common::now()? + 3600).to_string();
    let draft = r.publish(
        &r.run(
            "governance",
            &[
                "experimental-context-draft",
                "/state",
                "/in/pins.json",
                &expires,
                "/out/draft.json",
            ],
            &[("pins.json", &pinfile)],
            None,
            false,
        )?,
        "draft.json",
    )?;
    let context = r.publish(
        &r.run(
            "operator",
            &[
                "experimental-context-attest",
                "/state/status",
                "/in/pins.json",
                "/in/draft.json",
                "/out/context.json",
            ],
            &[("pins.json", &pinfile), ("draft.json", &draft)],
            None,
            false,
        )?,
        "context.json",
    )?;
    let chain = Arc::new(LocalChain::start()?);
    let setup = chain.request(json!({"method":"initialize"}))?;
    let domain: Domain = serde_json::from_value(setup["domain"].clone())?;
    let domainfile = public.join("domain.json");
    files::write(&domainfile, &domain)?;
    let policy: super::agreement::Policy = serde_json::from_value(
        r.run(
            "provider",
            &[
                "experimental-provider-enroll",
                "/state",
                "/in/pins.json",
                "/in/context.json",
                "/in/domain.json",
            ],
            &[
                ("pins.json", &pinfile),
                ("context.json", &context),
                ("domain.json", &domainfile),
            ],
            None,
            false,
        )?
        .value()?,
    )?;
    let input = include_str!("../../fixtures/openapi.json");
    let intent = Intent {
        schema: INTENT_SCHEMA.into(),
        policy_sha256: digest(&policy)?,
        request_id: "isolated-w0".into(),
        input_sha256: sha256_hex(input.as_bytes()),
        work: serde_json::from_value(setup["work"].clone())?,
    };
    let intentfile = public.join("intent.json");
    files::write(&intentfile, &intent)?;
    let inputfile = public.join("input.json");
    files::write(&inputfile, &input)?;
    let proposalfile = r.publish(
        &r.run(
            "provider",
            &[
                "experimental-work-propose",
                "/state",
                "/in/intent.json",
                "/in/input.json",
                "/out/proposal.json",
            ],
            &[("intent.json", &intentfile), ("input.json", &inputfile)],
            None,
            false,
        )?,
        "proposal.json",
    )?;
    let proposal: Proposal = evidence::read(&proposalfile)?;
    let buyer_inputs = [
        ("intent.json", intentfile.as_path()),
        ("proposal.json", proposalfile.as_path()),
    ];
    // Force failed publication after first consent has committed in buyer custody.
    let failed = r.run(
        "buyer",
        &[
            "experimental-work-accept",
            "/state",
            "/in/intent.json",
            "/in/proposal.json",
            "/in/proposal.json",
        ],
        &buyer_inputs,
        None,
        false,
    )?;
    if failed.process.status.success() {
        return Err("read-only consent publication succeeded".into());
    }
    fs::remove_file(r.root.join("buyer/key.seed"))?;
    let acceptancefile = r.publish(
        &r.run(
            "buyer",
            &[
                "experimental-work-accept",
                "/state",
                "/in/intent.json",
                "/in/proposal.json",
                "/out/acceptance.json",
            ],
            &buyer_inputs,
            None,
            false,
        )?,
        "acceptance.json",
    )?;
    let acceptance: Acceptance = evidence::read(&acceptancefile)?;
    let mut tampered = acceptance.clone();
    tampered.body.proposal_sha256 = "ab".repeat(32);
    let tamperfile = public.join("tampered-acceptance.json");
    files::write(&tamperfile, &tampered)?;
    let denied = r.run(
        "provider",
        &[
            "experimental-provider-execute",
            "/state",
            "/observer.sock",
            "/in/acceptance.json",
        ],
        &[("acceptance.json", &tamperfile)],
        None,
        false,
    )?;
    if denied.process.status.success() {
        return Err("tampered buyer acceptance authorized execution".into());
    }
    let agreement = &acceptance.body.agreement;
    let checkpoint_enrollment = public.join("checkpoint-enrollment.json");
    files::write(
        &checkpoint_enrollment,
        &checkpoint_operator::Enrollment {
            schema: checkpoint_operator::ENROLLMENT_SCHEMA.into(),
            authority_uuid: proposal.policy.authority_uuid.clone(),
            context: proposal.policy.finding_context.clone(),
        },
    )?;
    r.run(
        "operator",
        &[
            "experimental-checkpoint-init",
            "/state",
            "/in/enrollment.json",
        ],
        &[("enrollment.json", &checkpoint_enrollment)],
        None,
        false,
    )?
    .value()?;
    let verifier_enrollment = public.join("verifier-enrollment.json");
    files::write(
        &verifier_enrollment,
        &verifier_operator::Enrollment {
            schema: verifier_operator::ENROLLMENT_SCHEMA.into(),
            policy: proposal.policy.clone(),
            agreement: agreement.clone(),
        },
    )?;
    r.run(
        "verifier",
        &[
            "experimental-verifier-init",
            "/state",
            "/in/enrollment.json",
        ],
        &[("enrollment.json", &verifier_enrollment)],
        None,
        false,
    )?
    .value()?;
    let funding = chain.request(json!({"method":"fund","terms":agreement.body.terms()?}))?;
    let allocation = funding["allocationId"]
        .as_str()
        .ok_or("allocation missing")?
        .to_owned();
    chain.request(json!({"method":"pin-verifier","key":pins.verifier.to_hex()}))?;
    let socket = r.root.join("provider.sock");
    let mut provider_server = Server::start(&socket, allocation.clone(), chain.clone())?;
    let first = r
        .run(
            "provider",
            &[
                "experimental-provider-execute",
                "/state",
                "/observer.sock",
                "/in/acceptance.json",
            ],
            &[("acceptance.json", &acceptancefile)],
            Some(&socket),
            false,
        )?
        .value()?;
    let id = intent.request_id.as_str();
    let checkpoint_request = r.publish(
        &r.run(
            "provider",
            &[
                "experimental-checkpoint-export",
                "/state",
                id,
                "/out/checkpoint-request.json",
            ],
            &[],
            None,
            false,
        )?,
        "checkpoint-request.json",
    )?;
    let checkpoint_response = r.publish(
        &r.run(
            "operator",
            &[
                "experimental-checkpoint-sign",
                "/state",
                "/in/request.json",
                "/out/checkpoint-response.json",
            ],
            &[("request.json", &checkpoint_request)],
            None,
            false,
        )?,
        "checkpoint-response.json",
    )?;
    r.run(
        "provider",
        &[
            "experimental-checkpoint-import",
            "/state",
            id,
            "/in/response.json",
        ],
        &[("response.json", &checkpoint_response)],
        None,
        false,
    )?
    .value()?;
    let output = r.publish(
        &r.run(
            "provider",
            &[
                "experimental-provider-output",
                "/state",
                id,
                "/out/output.json",
            ],
            &[],
            None,
            false,
        )?,
        "output.json",
    )?;
    let candidate = public.join("candidate.json");
    files::write(
        &candidate,
        &if mode == "reject" {
            json!([])
        } else {
            evidence::read::<Value>(&output)?
        },
    )?;
    r.run(
        "provider",
        &[
            "experimental-provider-submit",
            "/state",
            id,
            "/observer.sock",
            "/in/candidate.json",
        ],
        &[("candidate.json", &candidate)],
        Some(&socket),
        false,
    )?
    .value()?;
    chain.request(json!({"method":"advance","allocation":allocation,"phase":"decision"}))?;
    let verifier_request = r.publish(
        &r.run(
            "provider",
            &[
                "experimental-verifier-export",
                "/state",
                id,
                "/observer.sock",
                "/out/verifier-request.json",
            ],
            &[],
            Some(&socket),
            false,
        )?,
        "verifier-request.json",
    )?;
    let verifier_socket = r.root.join("verifier.sock");
    let mut verifier_server =
        Server::start_readonly(&verifier_socket, allocation.clone(), chain.clone())?;
    let failed = r.run(
        "verifier",
        &[
            "experimental-verifier-decide",
            "/state",
            "/in/request.json",
            "/observer.sock",
            "/in/request.json",
        ],
        &[("request.json", &verifier_request)],
        Some(&verifier_socket),
        true,
    )?;
    if failed.process.status.success() {
        return Err("read-only verifier publication succeeded".into());
    }
    fs::remove_file(r.root.join("verifier/key.seed"))?;
    verifier_server.finish()?;
    let decisionfile = r.publish(
        &r.run(
            "verifier",
            &[
                "experimental-verifier-decide",
                "/state",
                "/in/request.json",
                "/unavailable",
                "/out/decision.json",
            ],
            &[("request.json", &verifier_request)],
            None,
            false,
        )?,
        "decision.json",
    )?;
    r.run(
        "provider",
        &[
            "experimental-verifier-import",
            "/state",
            id,
            "/observer.sock",
            "/in/decision.json",
        ],
        &[("decision.json", &decisionfile)],
        Some(&socket),
        false,
    )?
    .value()?;
    r.run(
        "provider",
        &[
            "experimental-provider-settle",
            "/state",
            id,
            "/observer.sock",
        ],
        &[],
        Some(&socket),
        false,
    )?
    .value()?;
    let replay = r
        .run(
            "provider",
            &[
                "experimental-provider-execute",
                "/state",
                "/observer.sock",
                "/in/acceptance.json",
            ],
            &[("acceptance.json", &acceptancefile)],
            Some(&socket),
            false,
        )?
        .value()?;
    provider_server.finish()?;
    let request: super::verifier_handoff::Request = evidence::read(&verifier_request)?;
    files::write(
        &public.join("witness.json"),
        &json!({"agreement":agreement,"submission":request.submission,"context":proposal.policy.finding_context,"bundle":request.execution,"output":request.output}),
    )?;
    files::write(
        &public.join("pins.json"),
        &json!({"buyer":pins.buyer,"provider":pins.provider,"verifier":pins.verifier,"allocationId":allocation,"authorityUuid":proposal.policy.authority_uuid}),
    )?;
    let decision: super::verification::Decision = evidence::read(&decisionfile)?;
    Ok(
        json!({"first":first,"replay":replay,"chain":chain.request(json!({"method":"summary","allocation":allocation}))?,"isolation":isolation,
        "buyerConsentReplayWithoutKey":true,"decisionReplayWithoutDependencies":true,"tamperedConsentDenied":true,
        "independentAdministration":false,"evaluatedAt":decision.body.finding_assessment.evaluated_at}),
    )
}
