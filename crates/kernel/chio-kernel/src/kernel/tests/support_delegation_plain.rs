fn make_chain_bound_plain_capability(
    leaf_signer: &Keypair,
    id: &str,
    subject: PublicKey,
    scope: ChioScope,
    delegation_chain: Vec<DelegationLink>,
) -> CapabilityToken {
    let issued_at = current_unix_timestamp();
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: leaf_signer.public_key(),
            subject,
            scope,
            issued_at,
            expires_at: issued_at.saturating_add(120),
            delegation_chain,
            aggregate_invocation_budget: None,
        },
        leaf_signer,
    )
    .unwrap()
}
