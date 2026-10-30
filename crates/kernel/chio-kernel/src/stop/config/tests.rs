use super::*;

const AUTHORITY: &str = "store-uuid-1";
const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/stop_operator_config"
);
const WEAK_KEY: &str = "0100000000000000000000000000000000000000000000000000000000000000";

fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn root() -> Keypair {
    key(1)
}

fn pins() -> StopConfigPins {
    StopConfigPins {
        config_root: root().public_key(),
        authority_id: AUTHORITY.to_owned(),
        receipt_signer: key(9).public_key(),
    }
}

fn operator(seed: u8, resume: bool) -> RosterPrincipalV1 {
    let subject_key = key(seed).public_key();
    RosterPrincipalV1 {
        principal: PrincipalId::from_subject_key(&subject_key),
        subject_key,
        permissions: StopPermissions {
            stop: true,
            resume,
            restrict: true,
            relax: resume,
        },
    }
}

fn roster(seeds: &[u8], quorum_k: u16) -> StopRosterV1 {
    let mut principals: Vec<_> = seeds.iter().map(|seed| operator(*seed, true)).collect();
    principals.sort_by(|left, right| left.principal.cmp(&right.principal));
    StopRosterV1 {
        scope: StopScope::Kernel,
        principals,
        quorum_k,
    }
}

fn first_body() -> StopOperatorConfigBodyV1 {
    StopOperatorConfigBodyV1 {
        schema: STOP_OPERATOR_CONFIG_SCHEMA.to_owned(),
        authority_id: AUTHORITY.to_owned(),
        deployment_generation: 1,
        predecessor_digest: None,
        rosters: vec![roster(&[11, 12, 13], 2)],
        stop_quorum_max: DEFAULT_STOP_QUORUM_MAX,
        resume_policy: ResumePolicyV1::OperatorPair,
        same_principal_cooldown_ms: None,
        time_attestation_key: Some(key(21).public_key()),
        config_authority_key: root().public_key(),
    }
}

fn first() -> StopOperatorConfigV1 {
    StopOperatorConfigV1::sign(first_body(), &root()).unwrap()
}

fn second_body() -> StopOperatorConfigBodyV1 {
    StopOperatorConfigBodyV1 {
        deployment_generation: 2,
        predecessor_digest: Some(first().digest().unwrap()),
        rosters: vec![roster(&[11, 12, 13, 14], 2)],
        ..first_body()
    }
}

fn second() -> StopOperatorConfigV1 {
    StopOperatorConfigV1::sign(second_body(), &root()).unwrap()
}

fn approvals(document: &StopOperatorConfigV1, seeds: &[u8]) -> Vec<StopConfigApprovalV1> {
    let digest = document.digest().unwrap();
    seeds
        .iter()
        .map(|seed| StopConfigApprovalV1::sign(&key(*seed), &digest).unwrap())
        .collect()
}

fn installed() -> VerifiedStopOperatorConfig {
    first().verify(&pins(), None).unwrap()
}

fn generated_fixtures() -> Vec<(&'static str, Vec<u8>)> {
    let second = second();
    vec![
        ("generation-1.json", first().canonical_bytes().unwrap()),
        ("generation-2.json", second.canonical_bytes().unwrap()),
        (
            "generation-2-approvals.json",
            chio_core_types::canonical_json_bytes(&approvals(&second, &[11, 12])).unwrap(),
        ),
    ]
}

/// Set `CHIO_WRITE_STOP_CONFIG_FIXTURES=1` to rewrite the committed fixtures
/// from this generator.
#[test]
fn committed_fixtures_are_the_generator_output() {
    let write = std::env::var_os("CHIO_WRITE_STOP_CONFIG_FIXTURES").is_some();
    for (name, bytes) in generated_fixtures() {
        let path = std::path::Path::new(FIXTURES).join(name);
        if write {
            std::fs::create_dir_all(FIXTURES).unwrap();
            std::fs::write(&path, &bytes).unwrap();
        }
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "{name}");
    }
}

#[test]
fn committed_fixtures_verify_as_a_first_document_and_its_successor() {
    let read = |name: &str| std::fs::read(std::path::Path::new(FIXTURES).join(name)).unwrap();
    let first = StopOperatorConfigV1::decode(&read("generation-1.json"))
        .unwrap()
        .verify(&pins(), None)
        .unwrap();
    assert_eq!(first.deployment_generation(), 1);
    assert_eq!(first.kernel_roster().principals.len(), 3);
    assert_eq!(first.kernel_roster().quorum_k, 2);
    assert_eq!(
        first.kernel_roster_digest(),
        first.kernel_roster().digest().unwrap()
    );

    let approvals: Vec<StopConfigApprovalV1> =
        serde_json::from_slice(&read("generation-2-approvals.json")).unwrap();
    let second = StopOperatorConfigV1::decode(&read("generation-2.json"))
        .unwrap()
        .verify(
            &pins(),
            Some(StopConfigSuccession {
                installed: &first,
                approvals: &approvals,
            }),
        )
        .unwrap();
    assert_eq!(second.deployment_generation(), 2);
    assert_eq!(
        second.config().body.predecessor_digest.as_deref(),
        Some(first.digest())
    );
    assert_ne!(second.kernel_roster_digest(), first.kernel_roster_digest());
}

#[test]
fn principal_ids_are_domain_separated_key_digests() {
    let principal = PrincipalId::from_subject_key(&key(11).public_key());
    assert_eq!(principal.as_str().len(), 64);
    assert!(principal
        .as_str()
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')));
    assert_ne!(
        principal.as_str(),
        chio_core_types::sha256_hex(key(11).public_key().to_hex().as_bytes())
    );
    assert_ne!(
        principal,
        PrincipalId::from_subject_key(&key(12).public_key())
    );
    let operator = operator(11, true);
    assert_eq!(operator.principal, principal);
    assert!(roster(&[11, 12], 1).principal(&principal).is_some());
    assert!(roster(&[12, 13], 1).principal(&principal).is_none());
}

fn rejected(body: StopOperatorConfigBodyV1) -> StopConfigError {
    StopOperatorConfigV1::sign(body, &root())
        .unwrap()
        .verify(&pins(), None)
        .unwrap_err()
}

#[test]
fn every_load_time_rejection_is_exact() {
    let weak = PublicKey::from_hex(WEAK_KEY).unwrap();
    let mut weak_operator = operator(11, true);
    weak_operator.subject_key = weak.clone();
    weak_operator.principal = PrincipalId::from_subject_key(&weak);
    let mut mismatched = operator(11, true);
    mismatched.principal = PrincipalId::from_subject_key(&key(12).public_key());
    let mut receipt_signer = operator(9, true);
    receipt_signer.principal = PrincipalId::from_subject_key(&receipt_signer.subject_key);
    let mut one_resumer = roster(&[11, 12, 13], 1);
    for entry in one_resumer.principals.iter_mut().skip(1) {
        entry.permissions.resume = false;
    }
    let mut unordered = roster(&[11, 12], 1);
    unordered.principals.reverse();
    let mut duplicated = roster(&[11], 1);
    duplicated.principals.push(operator(11, true));
    let mut large = roster(&[11], 1);
    large.principals = (0..=MAX_STOP_ROSTER_PRINCIPALS)
        .map(|index| {
            let mut seed = [0xa5; 32];
            seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
            let subject_key = Keypair::from_seed(&seed).public_key();
            RosterPrincipalV1 {
                principal: PrincipalId::from_subject_key(&subject_key),
                subject_key,
                permissions: operator(11, true).permissions,
            }
        })
        .collect();
    large
        .principals
        .sort_by(|left, right| left.principal.cmp(&right.principal));
    assert_eq!(large.principals.len(), MAX_STOP_ROSTER_PRINCIPALS + 1);

    let cases: Vec<(StopOperatorConfigBodyV1, StopConfigError)> = vec![
        (
            StopOperatorConfigBodyV1 {
                schema: "chio.stop-operator-config.v0".into(),
                ..first_body()
            },
            StopConfigError::Schema,
        ),
        (
            StopOperatorConfigBodyV1 {
                authority_id: "another-store".into(),
                ..first_body()
            },
            StopConfigError::AuthorityMismatch,
        ),
        (
            StopOperatorConfigBodyV1 {
                deployment_generation: 0,
                ..first_body()
            },
            StopConfigError::GenerationZero,
        ),
        (
            StopOperatorConfigBodyV1 {
                stop_quorum_max: 0,
                ..first_body()
            },
            StopConfigError::QuorumMaxOutOfRange,
        ),
        (
            StopOperatorConfigBodyV1 {
                stop_quorum_max: STOP_QUORUM_MAX_LIMIT + 1,
                ..first_body()
            },
            StopConfigError::QuorumMaxOutOfRange,
        ),
        (
            StopOperatorConfigBodyV1 {
                time_attestation_key: Some(weak.clone()),
                ..first_body()
            },
            StopConfigError::WeakKey,
        ),
        (
            StopOperatorConfigBodyV1 {
                resume_policy: ResumePolicyV1::SamePrincipalAfter,
                ..first_body()
            },
            StopConfigError::CooldownRequired,
        ),
        (
            StopOperatorConfigBodyV1 {
                resume_policy: ResumePolicyV1::SamePrincipalAfter,
                same_principal_cooldown_ms: Some(MIN_SAME_PRINCIPAL_COOLDOWN_MS - 1),
                ..first_body()
            },
            StopConfigError::CooldownRequired,
        ),
        (
            StopOperatorConfigBodyV1 {
                same_principal_cooldown_ms: Some(MIN_SAME_PRINCIPAL_COOLDOWN_MS),
                ..first_body()
            },
            StopConfigError::UnexpectedCooldown,
        ),
        (
            StopOperatorConfigBodyV1 {
                rosters: Vec::new(),
                ..first_body()
            },
            StopConfigError::MissingKernelRoster,
        ),
        (
            StopOperatorConfigBodyV1 {
                rosters: vec![roster(&[11, 12], 1), roster(&[13, 14], 1)],
                ..first_body()
            },
            StopConfigError::DuplicateScope,
        ),
        (
            StopOperatorConfigBodyV1 {
                rosters: vec![roster(&[], 1)],
                ..first_body()
            },
            StopConfigError::EmptyRoster,
        ),
        (
            StopOperatorConfigBodyV1 {
                rosters: vec![large],
                ..first_body()
            },
            StopConfigError::RosterTooLarge,
        ),
        (
            StopOperatorConfigBodyV1 {
                rosters: vec![unordered],
                ..first_body()
            },
            StopConfigError::PrincipalsUnordered,
        ),
        (
            StopOperatorConfigBodyV1 {
                rosters: vec![duplicated],
                ..first_body()
            },
            StopConfigError::PrincipalsUnordered,
        ),
        (
            StopOperatorConfigBodyV1 {
                rosters: vec![StopRosterV1 {
                    scope: StopScope::Kernel,
                    principals: vec![weak_operator],
                    quorum_k: 1,
                }],
                resume_policy: ResumePolicyV1::Quorum,
                ..first_body()
            },
            StopConfigError::WeakKey,
        ),
        (
            StopOperatorConfigBodyV1 {
                rosters: vec![StopRosterV1 {
                    scope: StopScope::Kernel,
                    principals: vec![mismatched],
                    quorum_k: 1,
                }],
                resume_policy: ResumePolicyV1::Quorum,
                ..first_body()
            },
            StopConfigError::PrincipalMismatch,
        ),
        (
            StopOperatorConfigBodyV1 {
                rosters: vec![StopRosterV1 {
                    scope: StopScope::Kernel,
                    principals: vec![receipt_signer],
                    quorum_k: 1,
                }],
                resume_policy: ResumePolicyV1::Quorum,
                ..first_body()
            },
            StopConfigError::ReceiptSignerOnRoster,
        ),
        (
            StopOperatorConfigBodyV1 {
                rosters: vec![roster(&[11, 12, 13], 0)],
                ..first_body()
            },
            StopConfigError::QuorumOutOfRange,
        ),
        (
            StopOperatorConfigBodyV1 {
                rosters: vec![roster(&[11, 12, 13], 4)],
                ..first_body()
            },
            StopConfigError::QuorumOutOfRange,
        ),
        (
            StopOperatorConfigBodyV1 {
                stop_quorum_max: 2,
                rosters: vec![roster(&[11, 12, 13], 3)],
                ..first_body()
            },
            StopConfigError::QuorumOutOfRange,
        ),
        (
            StopOperatorConfigBodyV1 {
                rosters: vec![one_resumer],
                ..first_body()
            },
            StopConfigError::ResumeQuorumUnreachable,
        ),
        (
            StopOperatorConfigBodyV1 {
                predecessor_digest: Some(first().digest().unwrap()),
                ..first_body()
            },
            StopConfigError::UnexpectedPredecessor,
        ),
    ];
    for (body, expected) in cases {
        assert_eq!(rejected(body), expected);
    }

    let mut quorum_roster = roster(&[11, 12, 13], 3);
    quorum_roster.principals[2].permissions.resume = false;
    assert_eq!(
        rejected(StopOperatorConfigBodyV1 {
            rosters: vec![quorum_roster],
            resume_policy: ResumePolicyV1::Quorum,
            ..first_body()
        }),
        StopConfigError::ResumeQuorumUnreachable
    );
}

#[test]
fn the_root_and_its_signature_are_both_required() {
    let other = key(2);
    let foreign = StopOperatorConfigV1::sign(
        StopOperatorConfigBodyV1 {
            config_authority_key: other.public_key(),
            ..first_body()
        },
        &other,
    )
    .unwrap();
    assert_eq!(
        foreign.verify(&pins(), None),
        Err(StopConfigError::RootMismatch)
    );

    let forged = StopOperatorConfigV1::sign(first_body(), &other).unwrap();
    assert_eq!(
        forged.verify(&pins(), None),
        Err(StopConfigError::Signature)
    );

    let mut tampered = first();
    tampered.body.rosters[0].quorum_k = 1;
    assert_eq!(
        tampered.verify(&pins(), None),
        Err(StopConfigError::Signature)
    );
}

#[test]
fn the_document_and_its_approvals_refuse_unwrapped_and_foreign_id_signatures() {
    for (label, signature) in crate::wrapper_refusals::refused_signatures(&root(), &first_body()) {
        let document = StopOperatorConfigV1 {
            signature,
            body: first_body(),
        };
        assert_eq!(
            document.verify(&pins(), None),
            Err(StopConfigError::Signature),
            "{label}"
        );
    }

    let second = second();
    let digest = second.digest().unwrap();
    let principal = PrincipalId::from_subject_key(&key(12).public_key());
    let body = approval_body(&principal, &digest).unwrap();
    for (label, signature) in crate::wrapper_refusals::refused_signatures_over(&key(12), &body) {
        let mut approvals = approvals(&second, &[11, 12]);
        approvals[1].signature = signature;
        assert_eq!(
            succeed(second.clone(), &approvals),
            Err(StopConfigError::ApprovalSignature),
            "{label}"
        );
    }
}

#[test]
fn documents_decode_only_from_bounded_canonical_bytes() {
    let canonical = first().canonical_bytes().unwrap();
    assert_eq!(StopOperatorConfigV1::decode(&canonical).unwrap(), first());

    let pretty = serde_json::to_vec_pretty(&first()).unwrap();
    assert!(matches!(
        StopOperatorConfigV1::decode(&pretty),
        Err(StopConfigError::Decode(_))
    ));

    let mut value = serde_json::to_value(first()).unwrap();
    value["body"]["unexpected"] = serde_json::json!(true);
    let unknown = chio_core_types::canonical_json_bytes(&value).unwrap();
    assert!(matches!(
        StopOperatorConfigV1::decode(&unknown),
        Err(StopConfigError::Decode(_))
    ));

    let oversized = vec![b' '; MAX_STOP_OPERATOR_CONFIG_BYTES + 1];
    assert!(matches!(
        StopOperatorConfigV1::decode(&oversized),
        Err(StopConfigError::Decode(_))
    ));
}

fn succeed(
    document: StopOperatorConfigV1,
    approvals: &[StopConfigApprovalV1],
) -> Result<VerifiedStopOperatorConfig, StopConfigError> {
    let installed = installed();
    document.verify(
        &pins(),
        Some(StopConfigSuccession {
            installed: &installed,
            approvals,
        }),
    )
}

#[test]
fn a_replacement_needs_the_installed_roster_quorum() {
    assert!(succeed(second(), &approvals(&second(), &[12, 13])).is_ok());

    let stale = StopOperatorConfigV1::sign(
        StopOperatorConfigBodyV1 {
            deployment_generation: 1,
            ..second_body()
        },
        &root(),
    )
    .unwrap();
    assert_eq!(
        succeed(stale.clone(), &approvals(&stale, &[11, 12])),
        Err(StopConfigError::GenerationNotAbove {
            generation: 1,
            installed: 1
        })
    );

    let orphan = StopOperatorConfigV1::sign(
        StopOperatorConfigBodyV1 {
            predecessor_digest: Some("0".repeat(64)),
            ..second_body()
        },
        &root(),
    )
    .unwrap();
    assert_eq!(
        succeed(orphan.clone(), &approvals(&orphan, &[11, 12])),
        Err(StopConfigError::PredecessorMismatch)
    );
    let unlinked = StopOperatorConfigV1::sign(
        StopOperatorConfigBodyV1 {
            predecessor_digest: None,
            ..second_body()
        },
        &root(),
    )
    .unwrap();
    assert_eq!(
        succeed(unlinked.clone(), &approvals(&unlinked, &[11, 12])),
        Err(StopConfigError::PredecessorMismatch)
    );

    assert_eq!(
        succeed(second(), &approvals(&second(), &[11])),
        Err(StopConfigError::ApprovalQuorumShort {
            approved: 1,
            required: 2
        })
    );
    assert_eq!(
        succeed(second(), &[]),
        Err(StopConfigError::ApprovalQuorumShort {
            approved: 0,
            required: 2
        })
    );
    assert_eq!(
        succeed(second(), &approvals(&second(), &[11, 11])),
        Err(StopConfigError::ApprovalDuplicate)
    );
    assert_eq!(
        succeed(second(), &approvals(&second(), &[11, 14])),
        Err(StopConfigError::ApprovalUnknownPrincipal)
    );
    assert_eq!(
        succeed(second(), &approvals(&first(), &[11, 12])),
        Err(StopConfigError::ApprovalInvalid)
    );
    let mut wrong_schema = approvals(&second(), &[11, 12]);
    wrong_schema[0].schema = "chio.stop-operator-config-approval.v0".into();
    assert_eq!(
        succeed(second(), &wrong_schema),
        Err(StopConfigError::ApprovalInvalid)
    );
    let mut forged = approvals(&second(), &[11, 12]);
    forged[1].principal = PrincipalId::from_subject_key(&key(13).public_key());
    assert_eq!(
        succeed(second(), &forged),
        Err(StopConfigError::ApprovalSignature)
    );
    let flood = approvals(&second(), &[11; 17]);
    assert_eq!(
        succeed(second(), &flood),
        Err(StopConfigError::TooManyApprovals)
    );
}
