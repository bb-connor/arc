//! Structure-aware corpus exercises the same decoder used after peer admission.
use super::*;
use chio_core::{canonical_json_bytes, Ed25519Backend, Keypair, SigningBackend};

pub fn response_authority_protocol(data: &[u8]) {
    let outcome = drive(data).map_err(|error| error.to_string());
    assert_eq!(outcome, Ok(()), "valid authority corpus failed");
}
fn drive(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let signer = Ed25519Backend::new(Keypair::from_seed(&[23; 32]));
    let config = ActiveResponseAuthorityProtocolServerConfig {
        expected_client_peer: PeerIdentity {
            process_id: 2,
            user_id: 1000,
            group_id: 1000,
        },
        trusted_client: signer.public_key()?,
        deployment_digest: Digest32::new([3; 32]),
        store_digest: Digest32::new([4; 32]),
        timeout_ms: 1000,
        maximum_clock_skew_seconds: 30,
        maximum_replay_entries: 16,
    };
    let body = ActiveResponseAuthorityRequestBody {
        schema: ACTIVE_RESPONSE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        deployment_digest: config.deployment_digest,
        store_digest: config.store_digest,
        request_id: RequestId::new("fuzz-authority-request")?,
        issued_at_unix_seconds: 1000,
        client: signer.public_key()?,
        operation: ActiveResponseAuthorityOperation::Health,
    };
    let signature = signer
        .sign_wrapped(
            ACTIVE_RESPONSE_AUTHORITY_REQUEST_SCHEMA,
            &active_response_authority_request_signing_body(&body)?,
        )?
        .signature;
    let signed = SignedActiveResponseAuthorityRequest { body, signature };
    let valid = canonical_json_bytes(&signed)?;
    let verified = decode_authority_request(&valid, &config, 1000)?;
    assert_eq!(verified.request(), &signed);
    // Present an unchanged, valid signature to a different trust context.
    let mut rebound = config.clone();
    rebound.deployment_digest = Digest32::new([5; 32]);
    let foreign = decode_authority_request(&valid, &rebound, 1000)
        .err()
        .ok_or("foreign deployment minted authority")?;
    assert_eq!(
        foreign.code().as_str(),
        "urn:chio:error:transport:response-authority-deployment"
    );
    let mut changed = signed.clone();
    let reason = match data.first().copied().unwrap_or(0) % 5 {
        0 => {
            changed.body.schema.push('x');
            "schema"
        }
        1 => {
            changed.body.store_digest = Digest32::new([6; 32]);
            "store"
        }
        2 => {
            changed.body.issued_at_unix_seconds = 1031;
            "freshness"
        }
        3 => {
            changed.body.client = Keypair::from_seed(&[24; 32]).public_key();
            "client"
        }
        _ => {
            changed.body.request_id = RequestId::new("substituted-request")?;
            "signature"
        }
    };
    let substituted = decode_authority_request(&canonical_json_bytes(&changed)?, &config, 1000)
        .err()
        .ok_or("substituted envelope minted authority")?;
    assert_eq!(
        substituted.code().as_str(),
        format!("urn:chio:error:transport:response-authority-{reason}")
    );
    // Reach authenticated freshness checks across the full u64 domain, with
    // valid signatures. Overflow must reject instead of widening the window.
    let mut bytes = [0_u8; 8];
    for (byte, input) in bytes.iter_mut().zip(data) {
        *byte = *input;
    }
    let now = u64::from_le_bytes(bytes);
    let freshness =
        super::validation::validate_request_freshness(now, config.maximum_clock_skew_seconds, now);
    if now.checked_add(config.maximum_clock_skew_seconds).is_some() {
        freshness?;
    } else {
        assert_eq!(
            freshness
                .err()
                .ok_or("overflow granted authority")?
                .code()
                .as_str(),
            "urn:chio:error:transport:response-authority-time-overflow"
        );
    }
    // Wire numbers must remain in the canonical codec's I-JSON domain.
    // Full-width arithmetic is exercised above without pretending it is a
    // representable signed wire timestamp.
    let wire_now = now & ((1_u64 << 53) - 1);
    let mut timed = signed.clone();
    timed.body.issued_at_unix_seconds = wire_now;
    timed.signature = signer
        .sign_wrapped(
            ACTIVE_RESPONSE_AUTHORITY_REQUEST_SCHEMA,
            &active_response_authority_request_signing_body(&timed.body)?,
        )?
        .signature;
    let decoded = decode_authority_request(&canonical_json_bytes(&timed)?, &config, wire_now)?;
    assert_eq!(decoded.request(), &timed);
    // Mutate a valid envelope at data-selected byte offsets. This reaches
    // structural and canonical refusal paths that arbitrary JSON rarely reaches.
    let mut wire = valid.clone();
    for edit in data.chunks_exact(3).take(64) {
        let [low, high, mask] = *edit else {
            continue;
        };
        let Some(byte) = usize::from(u16::from_le_bytes([low, high]))
            .checked_rem(wire.len())
            .and_then(|offset| wire.get_mut(offset))
        else {
            continue;
        };
        *byte ^= mask;
    }
    if let Ok(accepted) = decode_authority_request(&wire, &config, 1000) {
        assert_eq!(accepted.request(), &signed);
    }
    if let Ok(verified) = decode_authority_request(data, &config, 1000) {
        assert_eq!(canonical_json_bytes(verified.request())?, data);
        assert_eq!(verified.request().body.client, config.trusted_client);
        assert_eq!(
            verified.request().body.deployment_digest,
            config.deployment_digest
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    #[test]
    fn signed_authority_corpus_rejects_each_binding_substitution() {
        for seed in 0..5 {
            super::response_authority_protocol(&[seed]);
        }
        super::response_authority_protocol(&[u8::MAX; 8]);
    }
}
