#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationAuthorizationLookupRequest<'a> {
    operation_id: &'a str,
    request_binding_hash: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationAuthorizationRequest<'a> {
    operation_id: &'a str,
    request_binding_hash: &'a str,
    amount_units: u64,
    currency: &'a str,
    payer: &'a str,
    payee: &'a str,
    reference: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    governed: Option<&'a GovernedPaymentContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    commerce: Option<&'a CommercePaymentContext>,
}

impl<'a> OperationAuthorizationRequest<'a> {
    fn new(
        operation_id: &'a str,
        request_binding_hash: &'a str,
        request: &'a PaymentAuthorizeRequest,
    ) -> Self {
        Self {
            operation_id,
            request_binding_hash,
            amount_units: request.amount_units,
            currency: &request.currency,
            payer: &request.payer,
            payee: &request.payee,
            reference: &request.reference,
            governed: request.governed.as_ref(),
            commerce: request.commerce.as_ref(),
        }
    }
}

fn validate_operation_authorization_echo(
    echoed_operation_id: Option<&str>,
    echoed_request_binding_hash: Option<&str>,
    operation_id: &str,
    request_binding_hash: &str,
) -> Result<(), PaymentError> {
    if echoed_operation_id != Some(operation_id)
        || echoed_request_binding_hash != Some(request_binding_hash)
    {
        return Err(PaymentError::RailError(
            "payment rail did not attest the exact authorization operation binding".to_string(),
        ));
    }
    Ok(())
}
