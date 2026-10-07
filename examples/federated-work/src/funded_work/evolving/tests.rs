use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct FundingProbe(AtomicUsize);
impl super::super::observer::FundingSource for FundingProbe {
    fn observe(&self, _: &str) -> Result<super::super::observer::Observation> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err("funding observation reached".into())
    }
}

#[test]
fn receiver_rejects_signed_wrong_route_missing_treaty_and_foreign_capability_before_funding(
) -> Result<()> {
    for case in ["control", "route", "treaty", "receiver"] {
        let directory = tempfile::tempdir()?;
        let state = directory.path();
        let buyer = Keypair::generate();
        let allocator = Keypair::generate();
        let (domain, terms, _, _) = super::super::tests::observer::fixture()?;
        let now = super::super::now_ms()?;
        Native::provision_composed(
            state,
            buyer.public_key(),
            domain,
            vec![
                chio_finding::FindingFacetKind::ArtifactIntegrity,
                chio_finding::FindingFacetKind::GuaranteeConsistency,
            ],
            false,
            Some(Provision {
                allocator: allocator.public_key(),
                witness: allocator.public_key(),
                program_id: digest(&allocator.public_key())?,
                buyer: buyer.clone(),
                issued: now,
                until: now + 600_000,
            }),
        )?;
        let source = Arc::new(FundingProbe(AtomicUsize::new(0)));
        let work = WorkTerms {
            payer: terms.payer,
            beneficiary: terms.beneficiary,
            verifier: terms.verifier,
            amount: terms.amount,
            submit_by: terms.submit_by,
            challenge_until: terms.challenge_until,
            resolve_by: terms.resolve_by,
            refund_after: terms.refund_after,
        };
        let mut prepared = prepare(
            state,
            Native::open(state, source.clone())?,
            &json!({"work":work}),
            &buyer,
            "test",
        )?;
        let store = DelegationStore::open(state.join("allocator.sqlite"))?;
        let root = WorkSlot {
            id: "program".into(),
            holder: buyer.public_key(),
            contract: WorkContract {
                effects: BTreeSet::from([Effect {
                    server: prepared.request.server_id.clone(),
                    tool: "review".into(),
                }]),
                readers: [
                    buyer.public_key().to_hex(),
                    prepared.native.policy.provider_key.to_hex(),
                ]
                .into_iter()
                .collect(),
                max_units: 100,
                currency: "XTS".into(),
                expires_at: now / 1000 + 600,
                depth: 2,
                acceptance: Acceptance {
                    clauses: vec![Clause::Equals {
                        pointer: "/0/path".into(),
                        value: json!("/accounts"),
                    }],
                },
            },
        };
        store.create_root(root.clone())?;
        let mut leaf = root;
        leaf.id = "test".into();
        subdivide(&store, "program", &buyer, leaf)?;
        seal(&store, &mut prepared, &buyer, &allocator)?;
        let config = prepared
            .native
            .policy
            .composition
            .as_ref()
            .ok_or("config")?;
        let mut bundle = graph::new(config, &prepared.request.capability, &allocator)?;
        graph::add(
            &mut bundle,
            &prepared.request,
            store.allocation_digest("test")?,
            &prepared.request.capability,
            &allocator,
        )?;
        if case == "route" {
            let route = &mut bundle.route_plan_receipts[0];
            route.protocol_target =
                format!("native://{}", Keypair::generate().public_key().to_hex());
            route.signature =
                chio_swarm_authority::sign_swarm_route_plan_receipt(route, &allocator)?;
        }
        chio_swarm_authority::verify_swarm_authority_for_admission(
            &bundle,
            &[allocator.public_key()],
        )?;
        SqliteRuntimeOrchestrationStore::open(state.join("runtime.sqlite"))?
            .insert_swarm_authority_bundle(bundle.clone())?;
        let context = prepared
            .request
            .governed_intent
            .as_mut()
            .and_then(|i| i.context.as_mut())
            .ok_or("context")?;
        context["chioSwarm"] = graph::context(&bundle, "test")?;
        if case == "treaty" {
            context
                .as_object_mut()
                .ok_or("context object")?
                .remove("chioTreaty");
        }
        if case == "receiver" {
            let foreign = Keypair::generate();
            let cap = &prepared.request.capability;
            prepared.request.capability = CapabilityToken::sign(
                CapabilityTokenBody {
                    id: cap.id.clone(),
                    issuer: foreign.public_key(),
                    subject: cap.subject.clone(),
                    scope: cap.scope.clone(),
                    issued_at: cap.issued_at,
                    expires_at: cap.expires_at,
                    delegation_chain: vec![],
                    aggregate_invocation_budget: None,
                },
                &foreign,
            )?;
            prepared.waiver = super::super::waiver_terms::authorize(
                &prepared.native.policy,
                &work,
                &mut prepared.request,
                &common::key(state)?,
                &buyer,
            )?;
        }
        let p = &prepared.native.policy;
        let agreement = Agreement {
            schema: AGREEMENT_SCHEMA.into(),
            policy_sha256: digest(p)?,
            authority_uuid: p.authority_uuid.clone(),
            buyer_key: p.buyer_key.clone(),
            provider_key: p.provider_key.clone(),
            request_id: "test".into(),
            request_sha256: digest(&prepared.request)?,
            finding_context_sha256: digest(&p.finding_context)?,
            required_finding_facets: p.required_finding_facets.clone(),
            domain: p.domain.clone(),
            work,
            capture_waiver_terms: Some(prepared.waiver),
        }
        .sign(&buyer, &common::key(state)?)?;
        // Each adversarial request has valid buyer/provider signatures over its
        // actual bytes. A bad agreement signature cannot satisfy these controls.
        agreement.validate(p, &prepared.request)?;
        let error = prepared
            .native
            .execute(&agreement, &prepared.request)
            .err()
            .ok_or("unexpected admission")?
            .to_string();
        let expected = match case {
            "route" => "composed route does not target this receiver and task",
            "treaty" => "composed admission changed treaty, origin or task identity",
            "receiver" => "original funding capability is expired or invalid",
            _ => "funding observation reached",
        };
        assert_eq!(error, expected, "{case}");
        assert_eq!(
            source.0.load(Ordering::SeqCst),
            usize::from(case == "control")
        );
        assert_eq!(prepared.native.journal.execution_count()?, 0);
        assert!(prepared.native.operation(&prepared.request)?.is_none());
        assert!(prepared.native.journal.by_request("test")?.is_none());
    }
    Ok(())
}
