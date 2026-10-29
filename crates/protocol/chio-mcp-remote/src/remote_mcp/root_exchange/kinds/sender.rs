//! The sender constraint (`cnf`) of a presented token.

use axum::http::HeaderMap;
use serde_json::{Map, Value};

use super::super::error::{RootExchangeError, SenderConstraintFailure};
use crate::sender_constraint::{validate_sender_constraint, ConfirmationWire};
use crate::{ChioSenderConstraintClaims, SenderConstraintError, SenderRequest};

/// Check the `cnf` of `claims` against the request presenting the token,
/// returning the constraint it holds.
pub(super) fn check(
    claims: &Map<String, Value>,
    request: SenderRequest<'_>,
) -> Result<Option<ChioSenderConstraintClaims>, RootExchangeError> {
    let constraint = confirmation(claims)?;
    check_constraint(constraint.as_ref(), request)?;
    Ok(constraint)
}

/// Check a sender constraint already read from its grant against the
/// request presenting it.
pub(super) fn check_constraint(
    constraint: Option<&ChioSenderConstraintClaims>,
    request: SenderRequest<'_>,
) -> Result<(), RootExchangeError> {
    validate_sender_constraint(constraint, request).map_err(failure)
}

/// Check the `cnf` of `claims` against a request that holds no proof, so
/// any sender binding refuses.
pub(super) fn refuse_bound(claims: &Map<String, Value>) -> Result<(), RootExchangeError> {
    let headers = HeaderMap::new();
    check(claims, SenderRequest::from(&headers)).map(|_| ())
}

fn failure(error: SenderConstraintError) -> RootExchangeError {
    RootExchangeError::SenderConstraintUnmet(match error {
        SenderConstraintError::DpopUnavailable => SenderConstraintFailure::DpopUnavailable,
        SenderConstraintError::UnsupportedSchema => SenderConstraintFailure::Confirmation,
        SenderConstraintError::MtlsBinding => SenderConstraintFailure::Mtls,
        SenderConstraintError::AttestationBinding => SenderConstraintFailure::Attestation,
    })
}

/// The token's `cnf`, read through the closed confirmation profile.
fn confirmation(
    claims: &Map<String, Value>,
) -> Result<Option<ChioSenderConstraintClaims>, RootExchangeError> {
    let Some(cnf) = claims.get("cnf") else {
        return Ok(None);
    };
    let wire: ConfirmationWire = serde_json::from_value(cnf.clone()).map_err(|_| {
        RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::Confirmation)
    })?;
    ChioSenderConstraintClaims::try_from(wire)
        .map(Some)
        .map_err(|_| {
            RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::Confirmation)
        })
}
