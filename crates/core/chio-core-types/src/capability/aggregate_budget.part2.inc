#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use crate::capability::attenuation::{scope_hash, DelegationLink, DelegationLinkBody};
    use crate::capability::scope::{Operation, ToolGrant};
    use crate::capability::token::{CapabilityToken, CapabilityTokenBody};
    use crate::crypto::{
        canonical_json_bytes, sha256_hex, Ed25519Backend, Keypair, SigningAlgorithm, SigningBackend,
    };

    const FIXED_ISSUER_SEED: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const FIXED_SUBJECT_SEED: &str =
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const FIXED_COMMITMENT_JSON: &str = concat!(
        "{\"aggregate_scope\":\"delegation_family\",\"max_invocations\":3,",
        "\"root_capability_id\":\"cap-family-root\",\"root_expires_at\":2000,",
        "\"root_issued_at\":1000,\"root_issuer\":",
        "\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",",
        "\"root_scope_hash\":",
        "\"2222222222222222222222222222222222222222222222222222222222222222\",",
        "\"root_subject\":",
        "\"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c\"}"
    );
    const FIXED_COMMITMENT_HASH: &str =
        "17ee61436f0e78da037cdd55094c94eaa30c16f7cdb5ec88ea46bf5892155393";

    fn fixed_issuer() -> Keypair {
        Keypair::from_seed_hex(FIXED_ISSUER_SEED).expect("fixed issuer")
    }

    fn fixed_subject() -> Keypair {
        Keypair::from_seed_hex(FIXED_SUBJECT_SEED).expect("fixed subject")
    }

    fn ordinary_root_body(
        issuer: &PublicKey,
        subject: &PublicKey,
        id: &str,
    ) -> CapabilityTokenBody {
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.clone(),
            subject: subject.clone(),
            scope: ChioScope::default(),
            issued_at: 1_000,
            expires_at: 2_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        }
    }

    fn delegable_root_body(
        issuer: &PublicKey,
        subject: &PublicKey,
        id: &str,
    ) -> CapabilityTokenBody {
        let mut body = ordinary_root_body(issuer, subject, id);
        body.scope.grants.push(ToolGrant {
            server_id: "aggregate-root-server".to_string(),
            tool_name: "aggregate-root-tool".to_string(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        });
        body
    }

    fn valid_root(max_invocations: u32) -> (Keypair, CapabilityToken) {
        let issuer = fixed_issuer();
        let subject = fixed_subject();
        let token = issue_aggregate_family_root(
            ordinary_root_body(
                &issuer.public_key(),
                &subject.public_key(),
                "cap-family-root",
            ),
            max_invocations,
            &issuer,
        )
        .expect("issue aggregate family root");
        (issuer, token)
    }

    fn assert_attenuation_reason(error: Error, expected: &str) {
        match error {
            Error::AttenuationViolation { reason } => assert_eq!(reason, expected),
            other => panic!("expected attenuation violation, got {other:?}"),
        }
    }

    fn assert_invalid_signature(error: Error, expected: &str) {
        match error {
            Error::InvalidSignature(reason) => assert_eq!(reason, expected),
            other => panic!("expected invalid signature, got {other:?}"),
        }
    }

    fn root_binding_mut(body: &mut CapabilityTokenBody) -> &mut AggregateBudgetRootBinding {
        body.aggregate_invocation_budget
            .as_mut()
            .and_then(|budget| budget.root_binding.as_mut())
            .expect("root binding")
    }

    fn root_binding(token: &CapabilityToken) -> &AggregateBudgetRootBinding {
        token
            .aggregate_invocation_budget
            .as_ref()
            .and_then(|budget| budget.root_binding.as_ref())
            .expect("root binding")
    }

    fn resign_binding(binding: &mut AggregateBudgetRootBinding, signer: &Keypair) {
        binding.signature = signer.sign(&binding.body.signing_bytes().expect("binding bytes"));
    }

    fn resign_outer(body: CapabilityTokenBody, signer: &Keypair) -> CapabilityToken {
        CapabilityToken::sign(body, signer).expect("resign outer capability")
    }

    fn domain_hash<T: Serialize>(domain: &str, value: &T) -> String {
        let canonical = canonical_json_bytes(value).expect("canonical value");
        let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
        preimage.extend_from_slice(domain.as_bytes());
        preimage.extend_from_slice(&canonical);
        sha256_hex(&preimage)
    }

    struct InconsistentBackend {
        keypair: Keypair,
    }

    impl SigningBackend for InconsistentBackend {
        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::P256
        }

        fn public_key(&self) -> PublicKey {
            self.keypair.public_key()
        }

        fn sign_bytes(&self, message: &[u8]) -> Result<Signature> {
            Ok(self.keypair.sign(message))
        }
    }

    struct SignatureMismatchBackend {
        keypair: Keypair,
    }

    impl SigningBackend for SignatureMismatchBackend {
        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::Ed25519
        }

        fn public_key(&self) -> PublicKey {
            self.keypair.public_key()
        }

        fn sign_bytes(&self, _message: &[u8]) -> Result<Signature> {
            Ok(Signature::from_p256_der(&[1_u8, 2, 3]))
        }
    }

    struct TwoStageSignatureBackend {
        expected_keypair: Keypair,
        other_keypair: Keypair,
        expected_signature_first: bool,
        sign_calls: AtomicUsize,
    }

    impl SigningBackend for TwoStageSignatureBackend {
        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::Ed25519
        }

        fn public_key(&self) -> PublicKey {
            self.expected_keypair.public_key()
        }

        fn sign_bytes(&self, message: &[u8]) -> Result<Signature> {
            let first_call = self.sign_calls.fetch_add(1, Ordering::SeqCst) == 0;
            if first_call == self.expected_signature_first {
                Ok(self.expected_keypair.sign(message))
            } else {
                Ok(self.other_keypair.sign(message))
            }
        }
    }

    #[test]
    fn aggregate_invocation_root_commitment_matches_fixed_canonical_vector() {
        let commitment = AggregateBudgetRootCommitment {
            root_capability_id: "cap-family-root".to_string(),
            root_issuer: fixed_issuer().public_key(),
            root_subject: fixed_subject().public_key(),
            root_scope_hash: "22".repeat(32),
            root_issued_at: 1_000,
            root_expires_at: 2_000,
            aggregate_scope: AggregateInvocationScope::DelegationFamily,
            max_invocations: 3,
        };

        assert_eq!(
            commitment.canonical_bytes().expect("canonical commitment"),
            FIXED_COMMITMENT_JSON.as_bytes()
        );
        assert_eq!(
            commitment.commitment_hash().expect("commitment hash"),
            FIXED_COMMITMENT_HASH
        );
    }

    #[test]
    fn aggregate_invocation_root_binding_signing_bytes_use_exact_domain_prefix() {
        let body = AggregateBudgetRootBindingBody {
            schema: CHIO_AGGREGATE_BUDGET_ROOT_SCHEMA.to_string(),
            root_capability_id: "cap-family-root".to_string(),
            root_capability_hash: "11".repeat(32),
            root_issuer: fixed_issuer().public_key(),
            root_subject: fixed_subject().public_key(),
            max_invocations: 3,
            root_expires_at: 2_000,
            root_scope_hash: "22".repeat(32),
        };
        let expected_json = concat!(
            "{\"max_invocations\":3,\"root_capability_hash\":",
            "\"1111111111111111111111111111111111111111111111111111111111111111\",",
            "\"root_capability_id\":\"cap-family-root\",\"root_expires_at\":2000,",
            "\"root_issuer\":",
            "\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",",
            "\"root_scope_hash\":",
            "\"2222222222222222222222222222222222222222222222222222222222222222\",",
            "\"root_subject\":",
            "\"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c\",",
            "\"schema\":\"chio.aggregate-budget-root.v1\"}"
        );
        let mut expected = CHIO_AGGREGATE_BUDGET_ROOT_SIGNATURE_DOMAIN
            .as_bytes()
            .to_vec();
        expected.extend_from_slice(expected_json.as_bytes());

        assert_eq!(
            body.signing_bytes().expect("binding signing bytes"),
            expected
        );
    }

    #[test]
    fn aggregate_invocation_root_keypair_issuance_accepts_zero_and_verifies() {
        let (issuer, token) = valid_root(0);
        assert!(token
            .verify_signature()
            .expect("final capability signature"));

        let verified =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).expect("root");
        assert_eq!(verified.root_capability_id(), token.id);
        assert_eq!(verified.root_issuer(), &token.issuer);
        assert_eq!(verified.root_subject(), &token.subject);
        assert_eq!(
            verified.root_scope_hash(),
            scope_hash(&token.scope).unwrap()
        );
        assert_eq!(verified.root_issued_at(), token.issued_at);
        assert_eq!(verified.root_expires_at(), token.expires_at);
        assert_eq!(verified.max_invocations(), 0);
        assert_eq!(verified.root_binding(), root_binding(&token));
        assert_eq!(
            verified.root_binding_digest(),
            verified.root_binding().preservation_digest().unwrap()
        );
        assert_eq!(
            verified.family_owner(),
            verified
                .root_binding()
                .body
                .unverified_family_owner()
                .unwrap()
        );
    }

    #[test]
    fn direct_aggregate_root_record_verifier_authenticates_family_and_legacy_shapes() {
        let issuer = fixed_issuer();
        let subject = fixed_subject();
        let family = issue_aggregate_family_root(
            delegable_root_body(&issuer.public_key(), &subject.public_key(), "family-root"),
            0,
            &issuer,
        )
        .expect("family root");
        let legacy = CapabilityToken::sign(
            delegable_root_body(&issuer.public_key(), &subject.public_key(), "legacy-root"),
            &issuer,
        )
        .expect("legacy root");

        assert!(matches!(
            verify_direct_aggregate_root_record(&family, &[issuer.public_key()]),
            Ok(AggregateFamilyRootResolution::FamilyBound(root))
                if root.root_capability_id() == "family-root" && root.max_invocations() == 0
        ));
        assert!(matches!(
            verify_direct_aggregate_root_record(&legacy, &[issuer.public_key()]),
            Ok(AggregateFamilyRootResolution::LegacyUnbound(root))
                if root.root_capability_id() == "legacy-root"
        ));

        let nondelegable = CapabilityToken::sign(
            ordinary_root_body(&issuer.public_key(), &subject.public_key(), "not-a-root"),
            &issuer,
        )
        .expect("signed direct token");
        assert!(
            verify_direct_aggregate_root_record(&nondelegable, &[issuer.public_key()]).is_err()
        );
    }

    #[test]
    fn direct_aggregate_root_record_verifier_enforces_id_byte_bound_before_issuer_trust() {
        let issuer = fixed_issuer();
        let subject = fixed_subject();
        let accepted_id = "a".repeat(MAX_AGGREGATE_FAMILY_ROOT_ID_BYTES);
        let accepted = CapabilityToken::sign(
            delegable_root_body(&issuer.public_key(), &subject.public_key(), &accepted_id),
            &issuer,
        )
        .expect("512-byte root id");
        assert!(matches!(
            verify_direct_aggregate_root_record(&accepted, &[issuer.public_key()]),
            Ok(AggregateFamilyRootResolution::LegacyUnbound(root))
                if root.root_capability_id() == accepted_id
        ));

        for rejected_id in [
            String::new(),
            "b".repeat(MAX_AGGREGATE_FAMILY_ROOT_ID_BYTES + 1),
        ] {
            let rejected = CapabilityToken::sign(
                delegable_root_body(&issuer.public_key(), &subject.public_key(), &rejected_id),
                &issuer,
            )
            .expect("structurally signed root");
            let error = verify_direct_aggregate_root_record(&rejected, &[])
                .expect_err("invalid root id must fail before issuer trust");
            assert_attenuation_reason(
                error,
                "aggregate root capability id must contain 1 to 512 bytes",
            );
        }
    }

    #[test]
    fn aggregate_invocation_root_backend_issuance_accepts_safe_body() {
        let keypair = fixed_issuer();
        let backend = Ed25519Backend::new(keypair);
        let subject = fixed_subject();
        let token = issue_aggregate_family_root_with_backend(
            ordinary_root_body(
                &backend.public_key(),
                &subject.public_key(),
                "cap-family-backend",
            ),
            3,
            &backend,
        )
        .expect("backend issue");
        let binding = token
            .aggregate_invocation_budget
            .as_ref()
            .and_then(|budget| budget.root_binding.as_ref())
            .expect("root binding");
        assert_eq!(binding.algorithm, None);
        assert!(serde_json::to_value(binding)
            .unwrap()
            .get("algorithm")
            .is_none());
        verify_direct_aggregate_family_root(&token, &[backend.public_key()])
            .expect("verify backend root");
    }

    #[cfg(feature = "fips")]
    #[test]
    fn aggregate_invocation_root_nondefault_backend_records_algorithm_and_verifies() {
        let backend = crate::crypto::P256Backend::generate().expect("P-256 backend");
        let subject = fixed_subject();
        let token = issue_aggregate_family_root_with_backend(
            ordinary_root_body(
                &backend.public_key(),
                &subject.public_key(),
                "cap-family-p256",
            ),
            5,
            &backend,
        )
        .expect("P-256 issue");
        assert_eq!(root_binding(&token).algorithm, Some(SigningAlgorithm::P256));
        verify_direct_aggregate_family_root(&token, &[backend.public_key()])
            .expect("verify P-256 root");
    }

    #[test]
    fn aggregate_invocation_root_issuance_rejects_keypair_and_backend_signer_mismatch() {
        let issuer = fixed_issuer();
        let other = Keypair::from_seed(&[9_u8; 32]);
        let subject = fixed_subject();
        let body = ordinary_root_body(
            &issuer.public_key(),
            &subject.public_key(),
            "cap-keypair-mismatch",
        );
        match issue_aggregate_family_root(body, 3, &other).unwrap_err() {
            Error::InvalidPublicKey(reason) => {
                assert_eq!(
                    reason,
                    "aggregate family root issuer does not match signing key"
                )
            }
            error => panic!("expected invalid public key, got {error:?}"),
        }

        let backend = Ed25519Backend::new(other);
        let body = ordinary_root_body(
            &issuer.public_key(),
            &subject.public_key(),
            "cap-backend-mismatch",
        );
        match issue_aggregate_family_root_with_backend(body, 3, &backend).unwrap_err() {
            Error::InvalidPublicKey(reason) => {
                assert_eq!(
                    reason,
                    "signing backend identity does not match the requested key"
                )
            }
            error => panic!("expected invalid public key, got {error:?}"),
        }
    }

    #[test]
    fn aggregate_invocation_root_issuance_rejects_inconsistent_backend_algorithm() {
        let backend = InconsistentBackend {
            keypair: fixed_issuer(),
        };
        let subject = fixed_subject();
        let body = ordinary_root_body(
            &backend.public_key(),
            &subject.public_key(),
            "cap-inconsistent-backend",
        );
        let error = issue_aggregate_family_root_with_backend(body, 3, &backend).unwrap_err();
        assert_invalid_signature(
            error,
            "signing backend algorithm does not match public key",
        );
    }

    #[test]
    fn aggregate_invocation_root_issuance_rejects_backend_signature_algorithm_mismatch() {
        let backend = SignatureMismatchBackend {
            keypair: fixed_issuer(),
        };
        let subject = fixed_subject();
        let body = ordinary_root_body(
            &backend.public_key(),
            &subject.public_key(),
            "cap-signature-mismatch-backend",
        );
        let error = issue_aggregate_family_root_with_backend(body, 3, &backend).unwrap_err();
        assert_invalid_signature(
            error,
            "signing backend returned a signature from a different identity",
        );
    }

    #[test]
    fn aggregate_invocation_root_issuance_rejects_stateful_second_signature_key_drift() {
        let backend = TwoStageSignatureBackend {
            expected_keypair: fixed_issuer(),
            other_keypair: Keypair::from_seed(&[7_u8; 32]),
            expected_signature_first: true,
            sign_calls: AtomicUsize::new(0),
        };
        let subject = fixed_subject();
        let body = ordinary_root_body(
            &backend.public_key(),
            &subject.public_key(),
            "cap-second-signature-key-drift",
        );

        let error = issue_aggregate_family_root_with_backend(body, 3, &backend).unwrap_err();
        assert_invalid_signature(
            error,
            "signing backend returned a signature from a different identity",
        );
        assert_eq!(backend.sign_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn aggregate_invocation_root_issuance_rejects_same_algorithm_wrong_key_binding_signature() {
        let backend = TwoStageSignatureBackend {
            expected_keypair: fixed_issuer(),
            other_keypair: Keypair::from_seed(&[8_u8; 32]),
            expected_signature_first: false,
            sign_calls: AtomicUsize::new(0),
        };
        let subject = fixed_subject();
        let body = ordinary_root_body(
            &backend.public_key(),
            &subject.public_key(),
            "cap-wrong-key-binding-signature",
        );

        let error = issue_aggregate_family_root_with_backend(body, 3, &backend).unwrap_err();
        assert_invalid_signature(
            error,
            "signing backend returned a signature from a different identity",
        );
        assert_eq!(backend.sign_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn aggregate_invocation_root_issuance_rejects_prepopulated_or_delegated_body() {
        let issuer = fixed_issuer();
        let subject = fixed_subject();
        let mut prepopulated = ordinary_root_body(
            &issuer.public_key(),
            &subject.public_key(),
            "cap-prepopulated",
        );
        prepopulated.aggregate_invocation_budget = Some(AggregateInvocationBudget {
            scope: AggregateInvocationScope::Capability,
            max_invocations: 1,
            root_binding: None,
        });
        let error = issue_aggregate_family_root(prepopulated, 3, &issuer).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root issuance requires aggregate_invocation_budget to be absent",
        );

        let mut delegated = ordinary_root_body(
            &issuer.public_key(),
            &subject.public_key(),
            "cap-delegated-root",
        );
        delegated.delegation_chain.push(
            DelegationLink::sign(
                DelegationLinkBody {
                    capability_id: "parent".to_string(),
                    delegator: issuer.public_key(),
                    delegatee: subject.public_key(),
                    attenuations: vec![],
                    timestamp: 900,
                    scope_hash: None,
                    aggregate_family_preservation: None,
                },
                &issuer,
            )
            .unwrap(),
        );
        let error = issue_aggregate_family_root(delegated, 3, &issuer).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root issuance requires an empty delegation chain",
        );
    }

    #[test]
    fn aggregate_invocation_root_verifier_rejects_untrusted_issuer() {
        let (_issuer, token) = valid_root(3);
        match verify_direct_aggregate_family_root(&token, &[]).unwrap_err() {
            Error::InvalidPublicKey(reason) => {
                assert_eq!(reason, "aggregate family root issuer is not trusted")
            }
            error => panic!("expected invalid public key, got {error:?}"),
        }
    }

    #[test]
    fn aggregate_invocation_root_verifier_requires_delegation_family_scope() {
        let (issuer, mut token) = valid_root(3);
        token
            .aggregate_invocation_budget
            .as_mut()
            .expect("aggregate budget")
            .scope = AggregateInvocationScope::Capability;

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "capability-scoped aggregate budget must not carry a root binding",
        );
    }

    #[test]
    fn aggregate_invocation_root_verifier_rejects_nonempty_chain() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        body.delegation_chain.push(
            DelegationLink::sign(
                DelegationLinkBody {
                    capability_id: "grafted-parent".to_string(),
                    delegator: issuer.public_key(),
                    delegatee: body.subject.clone(),
                    attenuations: vec![],
                    timestamp: 900,
                    scope_hash: None,
                    aggregate_family_preservation: None,
                },
                &issuer,
            )
            .unwrap(),
        );
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root verification requires an empty delegation chain",
        );
    }

    #[test]
    fn aggregate_invocation_root_verifier_rejects_wrong_binding_schema() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.body.schema = "chio.aggregate-budget-root.v2".to_string();
        resign_binding(binding, &issuer);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_invalid_signature(error, "aggregate family root binding schema mismatch");
    }

    #[test]
    fn aggregate_invocation_root_verifier_rejects_binding_algorithm_mismatch() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        root_binding_mut(&mut body).algorithm = Some(SigningAlgorithm::P256);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_invalid_signature(
            error,
            "aggregate family root binding algorithm does not match root issuer and signature",
        );
    }

    #[test]
    fn aggregate_invocation_root_verifier_rejects_wrong_binding_signature() {
        let (issuer, token) = valid_root(3);
        let attacker = Keypair::from_seed(&[17_u8; 32]);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.signature = attacker.sign(&binding.body.signing_bytes().unwrap());
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_invalid_signature(error, "aggregate family root binding signature invalid");
    }

    #[test]
    fn aggregate_invocation_root_owner_hashes_body_and_digest_hashes_complete_envelope() {
        let (_issuer, token) = valid_root(3);
        let binding = root_binding(&token).clone();
        assert_eq!(
            binding.body.unverified_family_owner().unwrap(),
            domain_hash(CHIO_AGGREGATE_BUDGET_FAMILY_KEY_DOMAIN, &binding.body)
        );
        assert_eq!(
            binding.preservation_digest().unwrap(),
            domain_hash(CHIO_AGGREGATE_BUDGET_ROOT_BINDING_DOMAIN, &binding)
        );

        let mut changed_envelope = binding.clone();
        changed_envelope.signature = Keypair::from_seed(&[23_u8; 32]).sign(b"different");
        assert_eq!(
            binding.body.unverified_family_owner().unwrap(),
            changed_envelope.body.unverified_family_owner().unwrap()
        );
        assert_ne!(
            binding.preservation_digest().unwrap(),
            changed_envelope.preservation_digest().unwrap()
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_root_capability_id_mutation() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.body.root_capability_id = "cap-forged-id".to_string();
        resign_binding(binding, &issuer);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_capability_id does not match token id",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_root_commitment_hash_mutation() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.body.root_capability_hash = "00".repeat(32);
        resign_binding(binding, &issuer);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(error, "aggregate family root commitment hash mismatch");
    }

    #[test]
    fn aggregate_invocation_root_rejects_root_issuer_mutation() {
        let (issuer, token) = valid_root(3);
        let other = Keypair::from_seed(&[31_u8; 32]);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.body.root_issuer = other.public_key();
        resign_binding(binding, &other);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_issuer does not match token issuer",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_root_subject_mutation() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.body.root_subject = Keypair::from_seed(&[37_u8; 32]).public_key();
        resign_binding(binding, &issuer);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_subject does not match token subject",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_root_issued_at_mutation_via_commitment_hash() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        body.issued_at = body.issued_at.saturating_add(1);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(error, "aggregate family root commitment hash mismatch");
    }

    #[test]
    fn aggregate_invocation_root_rejects_root_expiry_mutation() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.body.root_expires_at = binding.body.root_expires_at.saturating_add(1);
        resign_binding(binding, &issuer);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_expires_at does not match token expiry",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_root_scope_hash_mutation() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.body.root_scope_hash = "ff".repeat(32);
        resign_binding(binding, &issuer);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_scope_hash does not match token scope",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_maximum_mutation() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        body.aggregate_invocation_budget
            .as_mut()
            .expect("aggregate budget")
            .max_invocations = 2;
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding max_invocations does not match aggregate budget",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_final_capability_signature_mutation() {
        let (issuer, mut token) = valid_root(3);
        token.id.push_str("-tampered");

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_invalid_signature(error, "aggregate family root capability signature invalid");
    }

    #[test]
    fn aggregate_invocation_root_rejects_token_issuer_mutation() {
        let (issuer, token) = valid_root(3);
        let other = Keypair::from_seed(&[41_u8; 32]);
        let mut body = token.body();
        body.issuer = other.public_key();
        let token = resign_outer(body, &other);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key(), other.public_key()])
                .unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_issuer does not match token issuer",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_binding_graft() {
        let issuer = fixed_issuer();
        let subject_a = fixed_subject();
        let subject_b = Keypair::from_seed(&[43_u8; 32]);
        let root_a = issue_aggregate_family_root(
            ordinary_root_body(&issuer.public_key(), &subject_a.public_key(), "cap-root-a"),
            3,
            &issuer,
        )
        .unwrap();
        let root_b = issue_aggregate_family_root(
            ordinary_root_body(&issuer.public_key(), &subject_b.public_key(), "cap-root-b"),
            3,
            &issuer,
        )
        .unwrap();
        let mut body = root_b.body();
        body.aggregate_invocation_budget
            .as_mut()
            .expect("aggregate budget")
            .root_binding = Some(root_binding(&root_a).clone());
        let grafted = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&grafted, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_capability_id does not match token id",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_binding_from_mismatched_authority() {
        let issuer_a = fixed_issuer();
        let issuer_b = Keypair::from_seed(&[47_u8; 32]);
        let subject = fixed_subject();
        let root_a = issue_aggregate_family_root(
            ordinary_root_body(
                &issuer_a.public_key(),
                &subject.public_key(),
                "cap-authority-a",
            ),
            3,
            &issuer_a,
        )
        .unwrap();
        let root_b = issue_aggregate_family_root(
            ordinary_root_body(
                &issuer_b.public_key(),
                &subject.public_key(),
                "cap-authority-b",
            ),
            3,
            &issuer_b,
        )
        .unwrap();
        let mut body = root_a.body();
        body.aggregate_invocation_budget
            .as_mut()
            .expect("aggregate budget")
            .root_binding = Some(root_binding(&root_b).clone());
        let grafted = resign_outer(body, &issuer_a);

        let error = verify_direct_aggregate_family_root(
            &grafted,
            &[issuer_a.public_key(), issuer_b.public_key()],
        )
        .unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_issuer does not match token issuer",
        );
    }
}
