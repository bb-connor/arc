//! One initial predecessor-format restore through the real protected writer.
//! This does not emulate an older executable or rewrite retained history.
use super::*;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

struct LegacyRestoreConstruction {
    scope: RecoveryScopeV1,
    principal: chio_security_types::PrincipalId,
    authorization: ReleaseAuthorizationDigest,
    request: RequestId,
    consumed: bool,
}

thread_local! {
    static LEGACY_RESTORE_CONSTRUCTION: RefCell<Option<LegacyRestoreConstruction>> = const { RefCell::new(None) };
}

/// A thread-bound, one-use initial serialization mode. Dropping the guard
/// clears it before a current-format replay or delivery acknowledgement.
pub struct LegacyCheckpointRestoreFixtureScope {
    _thread_bound: PhantomData<Rc<()>>,
}

impl Drop for LegacyCheckpointRestoreFixtureScope {
    fn drop(&mut self) {
        LEGACY_RESTORE_CONSTRUCTION.with(|state| *state.borrow_mut() = None);
    }
}

pub fn construct_legacy_checkpoint_restore_fixture(
    actor: &AuthenticatedRecoveryActor,
    request: &RequestId,
) -> Result<LegacyCheckpointRestoreFixtureScope, AdmissionOperationStoreError> {
    if actor.permission() != RecoveryPermission::KnowledgeRead {
        return Err(refused("legacy restore fixture authority"));
    }
    let authorization = super::super::release::authority_digest(actor)?;
    LEGACY_RESTORE_CONSTRUCTION.with(|state| {
        let mut state = state.borrow_mut();
        if state.is_some() {
            return Err(refused("legacy restore construction already active"));
        }
        *state = Some(LegacyRestoreConstruction {
            scope: actor.scope().clone(),
            principal: actor.principal().clone(),
            authorization,
            request: request.clone(),
            consumed: false,
        });
        Ok(LegacyCheckpointRestoreFixtureScope {
            _thread_bound: PhantomData,
        })
    })
}

pub(super) fn consume_legacy_restore_construction(
    actor: &AuthenticatedRecoveryActor,
    request: &RequestId,
) -> Result<bool, AdmissionOperationStoreError> {
    LEGACY_RESTORE_CONSTRUCTION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(state) = state.as_mut() else {
            return Ok(false);
        };
        if state.consumed
            || state.scope != *actor.scope()
            || state.principal != *actor.principal()
            || state.request != *request
            || state.authorization != super::super::release::authority_digest(actor)?
        {
            return Err(refused("legacy restore construction identity changed"));
        }
        state.consumed = true;
        Ok(true)
    })
}
