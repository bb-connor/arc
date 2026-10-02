use super::*;

pub(super) fn corpus() -> Vec<Case> {
    vec![
        Case::new("accept"),
        // -- both reject: the envelope alone decides ----------------------
        Case::new("wrong payload type")
            .envelope(|envelope| {
                envelope.payload_type = "application/json".to_string();
            })
            .agree_reject("dsse.malformed", "chio_treaty_unverified_required_evidence"),
        Case::new("payload is not parseable JSON")
            .envelope(|envelope| {
                envelope.payload = base64::engine::general_purpose::STANDARD.encode(b"{\"_type\":");
            })
            .agree_reject(
                "statement.malformed",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("statement type is not in-toto Statement v1")
            .statement(|statement, _fixture| {
                statement.statement_type = "https://in-toto.io/Statement/v0.1".to_string();
            })
            .agree_reject(
                "statement.schema_invalid",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("payload mutated after signing")
            .envelope(|envelope| {
                let mut decoded = base64::engine::general_purpose::STANDARD
                    .decode(envelope.payload.as_bytes())
                    .unwrap_or_default();
                if let Some(position) = decoded.iter().position(|byte| *byte == b'0') {
                    decoded[position] = b'1';
                }
                envelope.payload = base64::engine::general_purpose::STANDARD.encode(&decoded);
            })
            .agree_reject(
                "signature.server_a_invalid",
                "chio_treaty_unverified_required_evidence",
            ),
        // The two signature-isolation cases. Each leaves one signature valid
        // over unmodified bytes and forges the other, which is what separates
        // what each participant's key contributes from what the envelope as a
        // whole contributes.
        Case::new("only the origin's signature is forged")
            .envelope(|envelope| {
                if let Some(signature) = envelope.signatures.first_mut() {
                    signature.sig = forged_signature(&signature.sig);
                }
            })
            .agree_reject(
                "signature.server_a_invalid",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("only the receiver's signature is forged")
            .envelope(|envelope| {
                if let Some(signature) = envelope.signatures.get_mut(1) {
                    signature.sig = forged_signature(&signature.sig);
                }
            })
            .agree_reject(
                "signature.server_b_invalid",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("one signature removed")
            .envelope(|envelope| {
                envelope.signatures.truncate(1);
            })
            .agree_reject("dsse.malformed", "chio_treaty_unverified_required_evidence"),
        Case::new("duplicate signature keyid")
            .envelope(|envelope| {
                if envelope.signatures.len() == 2 {
                    envelope.signatures[1].keyid = envelope.signatures[0].keyid.clone();
                }
            })
            .agree_reject("dsse.malformed", "chio_treaty_unverified_required_evidence"),
        Case::new("predicate type is the compatibility profile")
            .statement(|statement, _fixture| {
                statement.predicate_type = "chio.bilateral-signature-slice.v1".to_string();
            })
            .agree_reject(
                "predicate.type_unrecognised",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("origin kernel renamed to an unpinned identity")
            .statement(|statement, _fixture| {
                statement.predicate.tool_server_a.kernel_id = "kernel.impostor".to_string();
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.signer_kernel_ids[0] = "kernel.impostor".to_string();
                }
            })
            .agree_reject(
                "peer.unpinned_or_keyid_mismatch",
                "chio_treaty_dsse_binding_mismatch",
            ),
        Case::new("declared passport fingerprint disagrees with the pin")
            .statement(|statement, _fixture| {
                statement.predicate.tool_server_a.passport_key_fingerprint =
                    Keyid(sha256_hex(b"conformance:not-the-pinned-key"));
            })
            .agree_reject(
                "peer.unpinned_or_keyid_mismatch",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("the two verdicts disagree")
            .statement(|statement, _fixture| {
                if let Some(summary) = statement.predicate.policy_evaluation_summary.as_mut() {
                    summary.server_b_verdict.verdict = "deny".to_string();
                    summary.joint_disposition = None;
                }
            })
            .agree_reject(
                "policy.verdict_disagreement",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("request hash substituted in the binding reference")
            .statement(|statement, _fixture| {
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.request_sha256 = sha256_hex(b"conformance:other-arguments");
                }
            })
            .agree_reject(
                "predicate.schema_invalid",
                "chio_treaty_dsse_binding_mismatch",
            ),
        Case::new("signer order transposed in the binding reference")
            .statement(|statement, _fixture| {
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.signer_kernel_ids.swap(0, 1);
                }
            })
            .agree_reject(
                "predicate.schema_invalid",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("lease reference substituted in the binding reference")
            .statement(|statement, _fixture| {
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.lease_refs = vec!["lease-conformance-other".to_string()];
                }
            })
            .agree_reject(
                "predicate.schema_invalid",
                "chio_treaty_dsse_binding_mismatch",
            ),
        // -- the field neither decider compares ---------------------------
        Case::new("admission report digest substituted").statement(|statement, _fixture| {
            if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                treaty.admission_report_sha256 = sha256_hex(b"conformance:other-report");
            }
        }),
        // -- the offline verifier checks what the hook does not ------------
        Case::new("subject digest does not match the receipt body")
            .statement(|statement, _fixture| {
                statement.subject[0].digest.sha256 = sha256_hex(b"conformance:other-receipt-body");
            })
            .verifier_only(
                "subject.digest_mismatch",
                "the pre-dispatch hook never resolves the subject receipt and never reads the \
                 statement's subject, so the subject binding of the conforming verifier's steps \
                 17 to 19 has no counterpart on the dispatch path.",
            ),
        Case::new("subject receipt absent from the receiver's receipt store")
            .verifier_state(|state| {
                state.receipt_store = InMemoryReceiptStore::new();
            })
            .verifier_only(
                "subject.digest_mismatch",
                "the hook has no receipt store on this path, so a statement whose subject names \
                 a receipt the receiver does not hold still admits.",
            ),
        Case::new("capability lease absent from the receiver's registry")
            .verifier_state(|state| {
                state.lease_registry = InMemoryLeaseRegistry::new();
            })
            .hook_state(|state| {
                state.missing_lease = true;
                Ok(())
            })
            .agree_reject(
                "capability.lease_expired_or_unknown",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("governance record absent from the receiver's store")
            .verifier_state(|state| {
                state.governance_store = InMemoryGovernanceReceiptStore::new();
            })
            .hook_state(|state| {
                state.missing_governance = true;
                Ok(())
            })
            .agree_reject(
                "governance.receipt_required_missing",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("tool name absent from the verifier's action-class table")
            .verifier_state(|state| {
                state.action_class_table_is_empty = true;
            })
            .verifier_only(
                "governance.unknown_action_class",
                "the verifier's unknown-class policy is reject and its table is verifier-owned. \
                 The hook reads the class out of the ladder intersection it computed itself, so \
                 a table the verifier has not been given does not reach it.",
            ),
        Case::new("peer passport revoked at the pinned epoch")
            .verifier_state(|state| {
                state.revoke_origin = true;
            })
            .verifier_only(
                "peer.revoked_at_epoch",
                "revocation reaches the kernel through its revocation view rather than through \
                 this hook; the hook resolves no revocation oracle.",
            ),
        Case::new("pinned peer has no ladder manifest reference")
            .verifier_state(|state| {
                state.drop_origin_ladder_ref = true;
            })
            .verifier_only(
                "ladder.manifest_missing",
                "the hook activates both manifests itself and stores their intersection, so it \
                 checks the intersection rather than a per-peer manifest reference.",
            ),
        Case::new("pinned peer's ladder manifest reference is stale")
            .verifier_state(|state| {
                state.stale_origin_ladder_ref = true;
            })
            .verifier_only(
                "ladder.manifest_stale",
                "manifest freshness is measured against the verifier's pinned epoch, which the \
                 hook does not hold; the hook bounds the same material through the validity \
                 window of the intersection it stored.",
            ),
        // The divergence axis in the participants' keys themselves: the
        // verifier reads them from its pin set, the hook from the activated
        // agreement. One input, two receiver-owned sources, two answers.
        Case::new("origin passport key rotated in the agreement but not in the pin set")
            .statement(|statement, fixture| {
                statement.predicate.tool_server_a.passport_key_fingerprint =
                    Keyid::from_public_key(&fixture.rotated_origin_key.public_key());
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.treaty_scope_sha256 = fixture.rotated_treaty_scope_sha256.clone();
                }
            })
            .hook_state(|state| {
                state.agreement = Agreement::RotatedOriginKey;
                Ok(())
            })
            .verifier_only(
                "peer.unpinned_or_keyid_mismatch",
                "the two deciders resolve the participants' public keys from two different \
                 receiver-owned stores: the conforming verifier from its pin set, the hook from \
                 the activated agreement. A rotation carried into one and not the other is \
                 admitted by whichever decider holds the newer key. A deployment MUST keep the \
                 two in agreement or run both deciders.",
            ),
        // -- the hook checks what the offline verifier cannot --------------
        Case::new("consistency model downgraded below the class")
            .statement(|statement, _fixture| {
                statement.predicate.consistency_model = "crdt-commutative".to_string();
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.consistency_model = "crdt-commutative".to_string();
                }
            })
            .hook_only(
                "chio_treaty_dsse_binding_mismatch",
                "the offline verifier has no ladder intersection, so it cannot know which \
                 consistency model the action class requires; it accepts any model the predicate \
                 and its binding reference agree on. The hook compares both against the \
                 intersection it computed itself.",
            ),
        Case::new("unanimous deny")
            .statement(|statement, _fixture| {
                if let Some(summary) = statement.predicate.policy_evaluation_summary.as_mut() {
                    summary.server_a_verdict.verdict = "deny".to_string();
                    summary.server_b_verdict.verdict = "deny".to_string();
                    summary.joint_disposition = Some("deny".to_string());
                }
            })
            .hook_only(
                "chio_treaty_policy_denied",
                "a unanimous deny is a valid statement and the conforming verifier returns it \
                 verified for audit and dispute review. Admission is the stricter caller: the \
                 hook requires allow.",
            ),
        Case::new("agreement absent from the receiver's store")
            .hook_state(|state| {
                state.presented.treaty_scope_id = Some(ABSENT_ID.to_string());
                Ok(())
            })
            .hook_only(
                "chio_treaty_missing_scope",
                "the agreement is resolved by identifier out of the receiver's own store; no \
                 agreement record reaches the offline verifier at all.",
            ),
        Case::new("agreement scope digest presented does not match the store")
            .hook_state(|state| {
                state.presented.treaty_scope_sha256 =
                    Some(sha256_hex(b"conformance:other-treaty-scope"));
                Ok(())
            })
            .hook_only(
                "chio_treaty_scope_hash_mismatch",
                "the agreement is resolved by identifier out of the receiver's own store and \
                 compared against the digest the request presented. No agreement record reaches \
                 the offline verifier.",
            ),
        Case::new("action class outside the agreement's allowed classes")
            .statement(|statement, fixture| {
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.treaty_scope_sha256 = fixture.restricted_treaty_scope_sha256.clone();
                }
            })
            .hook_state(|state| {
                state.agreement = Agreement::RestrictedActionClasses;
                Ok(())
            })
            .hook_only(
                "chio_treaty_action_class_not_allowed",
                "which classes the two organizations put in scope is a field of the agreement \
                 the receiver activated. The envelope names a class; nothing in it says whether \
                 this receiver's agreement admits that class.",
            ),
        Case::new("ladder intersection absent from the receiver's store")
            .hook_state(|state| {
                state.presented.ladder_intersection_id = Some(ABSENT_ID.to_string());
                Ok(())
            })
            .hook_only(
                "chio_treaty_missing_intersection",
                "the intersection is computed and stored by the receiver and is never \
                 transferred, so an offline verifier of an envelope has nothing to resolve.",
            ),
        Case::new("presented ladder intersection digest does not match the store")
            .hook_state(|state| {
                state.presented.ladder_intersection_sha256 =
                    Some(sha256_hex(b"conformance:other-intersection"));
                Ok(())
            })
            .hook_only(
                "chio_treaty_intersection_mismatch",
                "the intersection the request names is compared against the one the receiver \
                 stored; the offline verifier holds no intersection to compare.",
            ),
        Case::new("continuation absent from the receiver's store")
            .hook_state(|state| {
                state.presented.continuation_id = Some(ABSENT_ID.to_string());
                Ok(())
            })
            .hook_only(
                "chio_treaty_missing_continuation",
                "the continuation is authenticated by residency in the receiver's own store; \
                 the statement names it only by digest.",
            ),
        Case::new("presented continuation digest does not match the store")
            .hook_state(|state| {
                state.presented.continuation_sha256 =
                    Some(sha256_hex(b"conformance:other-continuation"));
                Ok(())
            })
            .hook_only(
                "chio_treaty_continuation_hash_mismatch",
                "the digest the request presents is compared against the stored continuation; \
                 the offline verifier resolves no continuation.",
            ),
        Case::new("continuation already spent")
            .hook_state(|state| {
                state
                    .store
                    .consume_treaty_continuation(CONTINUATION_ID, "adm-conformance-earlier")?;
                Ok(())
            })
            .hook_only(
                "chio_treaty_continuation_replay",
                "single use is a property of one table in the receiver's store. Nothing in the \
                 envelope records whether the continuation was spent, so an offline verifier \
                 cannot decide it.",
            ),
        Case::new("continuation outside its validity window")
            .hook_state(|state| {
                state.continuation_expires_at_unix_ms = ISSUED_AT_MS + 1;
                Ok(())
            })
            .hook_only(
                "chio_treaty_continuation_stale",
                "the continuation is a receiver-owned record the statement names only by digest; \
                 the offline verifier never resolves it.",
            ),
        Case::new("action class presented disagrees with the stored continuation")
            .hook_state(|state| {
                state.presented.action_class_id = Some(OTHER_ACTION_CLASS.to_string());
                Ok(())
            })
            .hook_only(
                "chio_treaty_continuation_mismatch",
                "the class the request names is checked against the continuation and the \
                 intersection the receiver stored, and the continuation is compared first. The \
                 envelope carries the class identifier and nothing that would let an offline \
                 verifier decide whether the receiver admits that class.",
            ),
        Case::new("presented lineage bundle digest does not match the store")
            .hook_state(|state| {
                state.presented.lineage_bundle_sha256 =
                    Some(sha256_hex(b"conformance:other-lineage-bundle"));
                Ok(())
            })
            .hook_only(
                "chio_treaty_lineage_hash_mismatch",
                "the lineage bundle is resolved out of the receiver's store by identifier and \
                 its stored digest is compared against the presented one; no bundle crosses.",
            ),
        Case::new("lineage bundle does not bind the stored continuation")
            .hook_state(|state| {
                state.unbind_lineage_from_continuation = true;
                Ok(())
            })
            .hook_only(
                "chio_treaty_lineage_mismatch",
                "the walk for a lineage statement that binds this continuation is over records \
                 the receiver wrote; the conforming verifier never sees the bundle.",
            ),
        Case::new("invocation record absent from the receiver's store")
            .hook_state(|state| {
                state.presented.invocation_id = Some(ABSENT_ID.to_string());
                Ok(())
            })
            .hook_only(
                "chio_treaty_missing_bilateral_evidence",
                "a class whose co-signing mode requires two signatures forces the invocation \
                 record into its required-evidence set, and the record lives only in the \
                 receiver's store.",
            ),
        Case::new("presented invocation record digest does not match the store")
            .hook_state(|state| {
                state.presented.invocation_sha256 =
                    Some(sha256_hex(b"conformance:other-invocation"));
                Ok(())
            })
            .hook_only(
                "chio_treaty_bilateral_hash_mismatch",
                "the invocation record is resolved by identifier and its stored digest compared \
                 against the presented one; the record is never carried on the wire.",
            ),
        Case::new("invocation record does not bind the requested dispatch")
            .hook_state(|state| {
                state.unbind_invocation_from_dispatch = true;
                Ok(())
            })
            .hook_only(
                "chio_treaty_bilateral_mismatch",
                "the record is compared against the receiver's own admission bundle, which the \
                 conforming verifier does not hold.",
            ),
        Case::new("envelope reference omitted for a class that requires it")
            .hook_state(|state| {
                state.presented.omit_envelope = true;
                Ok(())
            })
            .hook_only(
                "chio_treaty_missing_required_evidence",
                "which evidence classes a call must carry comes from the action class in the \
                 intersection the receiver stored. An offline verifier handed an envelope is \
                 never in a position to observe that one was not presented.",
            ),
        Case::new("request smuggles a trust root")
            .hook_state(|state| {
                state.smuggle_trust_root = true;
                Ok(())
            })
            .hook_only(
                "request_smuggled_trust_root",
                "the refusal is over the request's own agreement context, which no offline \
                 verifier of an envelope ever sees.",
            ),
    ]
}
