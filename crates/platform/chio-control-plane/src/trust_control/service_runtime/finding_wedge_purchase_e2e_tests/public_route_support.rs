use super::*;

pub(super) struct RoutedPurchaseExecutor {
    pub(super) authority: Arc<SqliteAuthorityStore>,
    pub(super) web: MarketWeb,
    pub(super) witness: VerifiedFindingAdmission,
    pub(super) buyer: Keypair,
    pub(super) kernel_keypair: Keypair,
    pub(super) calls: Arc<PaymentCalls>,
    pub(super) invocations: Arc<AtomicU64>,
    pub(super) attempts: Arc<AtomicU64>,
    pub(super) exchange_now: u64,
    pub(super) now: Arc<AtomicU64>,
    pub(super) status_proof_b64: String,
}

impl RoutedPurchaseExecutor {
    pub(super) fn execution_error(error: impl std::fmt::Display) -> FindingPurchaseExecutionError {
        FindingPurchaseExecutionError::Internal(error.to_string())
    }
}

#[async_trait::async_trait]
impl FindingPurchaseExecutor for RoutedPurchaseExecutor {
    fn mutation_fence(&self) -> chio_kernel::admission_operation::StoreMutationFence {
        self.authority.mutation_fence()
    }

    fn stop_control(&self) -> chio_kernel::stop::StopControl {
        chio_kernel::stop::StopControl::process_local()
    }

    fn authenticate_buyer(
        &self,
        bearer_token: &str,
    ) -> Result<AuthenticatedFindingBuyer, FindingBuyerAuthenticationError> {
        if bearer_token != BUYER_TOKEN {
            return Err(FindingBuyerAuthenticationError);
        }
        let payer = self.buyer.public_key().to_hex();
        AuthenticatedFindingBuyer::new("buyer-agent-1".to_owned(), payer, self.buyer.public_key())
            .map_err(|_| FindingBuyerAuthenticationError)
    }

    async fn execute(
        &self,
        authenticated_buyer: AuthenticatedFindingBuyer,
        request: FindingPurchaseRequest,
    ) -> Result<FindingPurchaseResult, FindingPurchaseExecutionError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let now = self.now.load(Ordering::SeqCst);
        if request.finding_id != self.web.finding_id
            || request.max_price.currency != "USD"
            || request.max_price.units < PRICE_UNITS
        {
            return Err(FindingPurchaseExecutionError::Rejected(
                "finding or price ceiling does not match the admitted offer".to_owned(),
            ));
        }
        let payer_key = self.buyer.public_key();
        let payer_hex = payer_key.to_hex();
        if authenticated_buyer.public_key() != &payer_key
            || authenticated_buyer.payer() != payer_hex
        {
            return Err(FindingPurchaseExecutionError::Rejected(
                "authenticated buyer does not match the executor key".to_owned(),
            ));
        }
        let payer = request
            .payer
            .clone()
            .unwrap_or_else(|| authenticated_buyer.payer().to_owned());
        if payer != payer_hex {
            return Err(FindingPurchaseExecutionError::Rejected(
                "payer is not mapped to the authenticated buyer key".to_owned(),
            ));
        }
        let deadline_secs = request.deadline_secs.unwrap_or(RESERVATION_TTL_SECS);
        let public_request = FindingPublicPurchaseRequestBinding {
            request_id: &request.request_id,
            finding_id: &request.finding_id,
            requested_payer: request.payer.as_deref(),
            resolved_payer: &payer,
            payer_hex: &payer_hex,
            max_price_units: request.max_price.units,
            currency: &request.max_price.currency,
            deadline_secs: request.deadline_secs,
        };
        let exchange = handshake_at(
            &self.web,
            &self.witness,
            &self.buyer,
            BUYER_PAYOUT,
            TOKEN_ID,
            self.exchange_now,
            request.max_price.clone(),
            deadline_secs,
        )
        .map_err(Self::execution_error)?;
        let coordinator = coordinator(&self.authority).map_err(Self::execution_error)?;
        let reservation_receipt = match coordinator.resolve(&exchange.reservation_id) {
            Ok(reservation) => {
                let bid_envelope_sha256 =
                    digest_of(&exchange.bid).map_err(Self::execution_error)?;
                let admission_envelope_sha256 =
                    digest_of(&self.web.admission).map_err(Self::execution_error)?;
                if reservation.state != FindingPurchaseReservationState::Consumed {
                    return Err(FindingPurchaseExecutionError::Pending(
                        "durable reservation has not reached a purchase terminal".to_owned(),
                    ));
                }
                if reservation.purchase_intent_id
                    != derive_purchase_intent_id(&exchange.reservation_id)
                    || reservation.authoritative_payment_operation_id
                        != derive_payment_operation_id(&exchange.reservation_id)
                    || reservation.payer_hex != payer_hex
                    || reservation.agent_id != exchange.ask.body.agent_id
                    || reservation.finding_id != self.web.finding_id
                    || reservation.listing_id != exchange.ask.body.listing_id
                    || reservation.bid_envelope_sha256 != bid_envelope_sha256
                    || reservation.ask_digest != exchange.ask_digest
                    || reservation.admission_envelope_sha256 != admission_envelope_sha256
                    || reservation.amount_units != exchange.ask.body.quoted_price.units
                    || reservation.currency != exchange.ask.body.quoted_price.currency
                    || reservation.created_at != self.exchange_now
                    || reservation.expires_at != self.exchange_now.saturating_add(deadline_secs)
                {
                    return Err(FindingPurchaseExecutionError::Conflict(
                        "durable reservation does not bind the public replay".to_owned(),
                    ));
                }
                self.authority
                    .finding_purchase_store()
                    .verify_public_purchase_reservation(&public_request, &exchange.reservation_id)
                    .map_err(Self::execution_error)?;
                SignedReservationReceipt::sign(
                    ReservationReceipt {
                        schema: RESERVATION_RECEIPT_SCHEMA.to_owned(),
                        receipt_id: exchange.reservation_id.clone(),
                        agent_id: exchange.ask.body.agent_id.clone(),
                        listing_id: exchange.ask.body.listing_id.clone(),
                        ask_digest: exchange.ask_digest.clone(),
                        reserved_amount: exchange.ask.body.quoted_price.clone(),
                    },
                    &keypair(16),
                )
                .map_err(Self::execution_error)?
            }
            Err(PurchaseCoordinatorError::UnknownReservation) => coordinator
                .reserve_for_public_request(
                    &exchange.bid,
                    &exchange.ask,
                    &exchange.buyer_signature_hex,
                    &self.web.admission,
                    &self.web.authorization,
                    EXPOSURE_UNITS,
                    deadline_secs,
                    now,
                    &public_request,
                )
                .map_err(Self::execution_error)?,
            Err(error) => return Err(Self::execution_error(error)),
        };
        let verified = VerifiedReservationReceipt::from_signed(
            &reservation_receipt,
            &keypair(16).public_key(),
        )
        .map_err(Self::execution_error)?;
        let accepted = accept_finding_purchase(
            &exchange.ask,
            &verified,
            &self.buyer,
            self.exchange_now,
            &self.witness,
            &self.web.finding,
        )
        .map_err(Self::execution_error)?;
        let reservation = coordinator
            .resolve(&exchange.reservation_id)
            .map_err(Self::execution_error)?;
        match reservation.state {
            FindingPurchaseReservationState::Open => {
                coordinator
                    .reserve_slot(&exchange.reservation_id, now)
                    .map_err(Self::execution_error)?;
            }
            FindingPurchaseReservationState::SlotReserved
            | FindingPurchaseReservationState::Consumed => {}
            FindingPurchaseReservationState::Released
            | FindingPurchaseReservationState::Expired => {
                return Err(FindingPurchaseExecutionError::Conflict(
                    "reservation is already closed without a purchase record".to_owned(),
                ));
            }
        }
        let context_b64 = purchase_context_b64(&CarrierInputs {
            web: &self.web,
            handshake: &exchange,
            accepted: &accepted,
            reservation_receipt: &reservation_receipt,
        })
        .map_err(Self::execution_error)?;
        let capability = exchange.ask.body.token_offer.clone();
        let reveal = reveal_request_at(
            &RevealRequestInputs {
                request_id: &request.request_id,
                capability: &capability,
                buyer: &self.buyer,
                finding_id: &self.web.finding_id,
                context_b64: Some(&context_b64),
                status_proof_b64: Some(&self.status_proof_b64),
                nonce: &request.request_id,
            },
            self.exchange_now,
        )
        .map_err(Self::execution_error)?;
        let kernel = build_reveal_kernel(&RevealKernelInputs {
            authority: &self.authority,
            kernel_keypair: &self.kernel_keypair,
            web: &self.web,
            rail: Rail::ReversibleHold,
            calls: &self.calls,
            invocations: &self.invocations,
            install_verifier: true,
            install_status_verifier: true,
        })
        .map_err(Self::execution_error)?;
        let response = kernel
            .evaluate_tool_call_blocking(&reveal)
            .map_err(Self::execution_error)?;
        if response.verdict != Verdict::Allow {
            return Err(FindingPurchaseExecutionError::Pending(
                "test adapter received a denial requiring checkpointed finalization".to_owned(),
            ));
        }
        let output = delivered_value(&response).map_err(Self::execution_error)?;
        let media_type = output
            .get("media_type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Self::execution_error("reveal media type missing"))?
            .to_owned();
        let payload_b64 = output
            .get("payload_b64")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Self::execution_error("reveal payload missing"))?
            .to_owned();
        let finalized_at =
            unix_timestamp_now().unwrap_or_else(|error| panic!("trusted fixture clock: {error}"));
        self.authority
            .finding_purchase_store()
            .register_community_fund_destination(
                &self.web.allocation_id,
                COMMUNITY_FUND_DESTINATION,
                finalized_at,
            )
            .map_err(Self::execution_error)?;
        let record = coordinator
            .finalize_delivery(
                &exchange.reservation_id,
                &response.receipt,
                &self.web.admission,
                &self.web.backing,
                finalized_at,
            )
            .map_err(Self::execution_error)?;
        Ok(FindingPurchaseResult {
            schema: FINDING_PURCHASE_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id,
            finding_id: self.web.finding_id.clone(),
            payer,
            payer_key,
            reservation_id: exchange.reservation_id.clone(),
            purchase_intent_id: record.body.purchase_intent_id.clone(),
            authoritative_payment_operation_id: record
                .body
                .authoritative_payment_operation_id
                .clone(),
            verdict: FindingPurchaseVerdict::Allow,
            settlement: FindingPurchaseSettlementTerminal::Captured,
            accepted_price: record.body.accepted_price.clone(),
            realized_spend: record.body.realized_spend.clone(),
            delivery_receipt: response.receipt,
            purchase_record: Some(record),
            failed_delivery: None,
            output: Some(FindingPurchasedOutput {
                media_type,
                payload_b64,
            }),
        })
    }
}

pub(super) struct FixedTerminalExecutor {
    pub(super) authority: Arc<SqliteAuthorityStore>,
    pub(super) result: FindingPurchaseResult,
}

#[async_trait::async_trait]
impl FindingPurchaseExecutor for FixedTerminalExecutor {
    fn mutation_fence(&self) -> chio_kernel::admission_operation::StoreMutationFence {
        self.authority.mutation_fence()
    }

    fn stop_control(&self) -> chio_kernel::stop::StopControl {
        chio_kernel::stop::StopControl::process_local()
    }

    fn authenticate_buyer(
        &self,
        bearer_token: &str,
    ) -> Result<AuthenticatedFindingBuyer, FindingBuyerAuthenticationError> {
        if bearer_token != BUYER_TOKEN {
            return Err(FindingBuyerAuthenticationError);
        }
        AuthenticatedFindingBuyer::new(
            "buyer-agent-1".to_owned(),
            self.result.payer.clone(),
            self.result.payer_key.clone(),
        )
        .map_err(|_| FindingBuyerAuthenticationError)
    }

    async fn execute(
        &self,
        _buyer: AuthenticatedFindingBuyer,
        _request: FindingPurchaseRequest,
    ) -> Result<FindingPurchaseResult, FindingPurchaseExecutionError> {
        Ok(self.result.clone())
    }
}

pub(super) async fn assert_terminal_cannot_rebind_public_request(
    state: &mut TrustServiceState,
    authority: &Arc<SqliteAuthorityStore>,
    path: &str,
    first: &FindingPurchaseResult,
    finding_id: &str,
    payer: &str,
) -> TestResult {
    let other_request = FindingPurchaseRequest::new(
        finding_id.to_owned(),
        PRICE_UNITS + 51,
        "USD".to_owned(),
        Some(payer.to_owned()),
        Some(900),
    )?;
    let mut rebound = first.clone();
    rebound.request_id = other_request.request_id.clone();
    state.finding_purchase_executor = Some(Arc::new(FixedTerminalExecutor {
        authority: authority.clone(),
        result: rebound,
    }));
    let (status, body) = send(
        state,
        buyer_post(path, canonical_json_bytes(&other_request)?)?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        json_body(&body)?["code"],
        serde_json::json!("purchase_terminal_invalid")
    );
    Ok(())
}
