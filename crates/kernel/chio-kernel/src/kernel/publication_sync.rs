use std::cell::RefCell;
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::KernelError;

thread_local! {
    static HELD: RefCell<Vec<(usize, u8)>> = const { RefCell::new(Vec::new()) };
}

/// Lock-order enforcement is per kernel; callbacks between kernels can form cycles.
/// Receipt and projection poison refuse because publication effects may be incomplete.
#[derive(Default)]
pub(super) struct PublicationSync {
    pub(super) fence: RwLock<()>,
    pub(super) receipts: RwLock<()>,
    projection: Mutex<()>,
}

struct RankToken {
    domain: usize,
    rank: u8,
}

impl Drop for RankToken {
    fn drop(&mut self) {
        HELD.with(|held| {
            held.borrow_mut()
                .retain(|entry| *entry != (self.domain, self.rank));
        });
    }
}

pub(super) enum LockGuard<'a> {
    Read { _guard: RwLockReadGuard<'a, ()> },
    Write { _guard: RwLockWriteGuard<'a, ()> },
    Projection { _guard: MutexGuard<'a, ()> },
}

pub(super) struct RankedGuard<'a> {
    _guard: LockGuard<'a>,
    _rank: RankToken,
}

pub(super) struct PublicationGuard<'a> {
    _receipts: RankedGuard<'a>,
    _fence: RankedGuard<'a>,
}

impl PublicationSync {
    fn enter(&self, rank: u8) -> Result<RankToken, KernelError> {
        let domain = std::ptr::from_ref(self).addr();
        HELD.with(|held| {
            let mut held = held.try_borrow_mut().map_err(|_| {
                KernelError::Internal("receipt publication lock tracking reentered".into())
            })?;
            if held
                .iter()
                .any(|(id, prior)| *id == domain && *prior >= rank)
            {
                return Err(KernelError::Internal(
                    "receipt publication lock order violation".into(),
                ));
            }
            held.push((domain, rank));
            Ok(RankToken { domain, rank })
        })
    }

    pub(super) fn fence(
        &self,
        exclusive: bool,
        recover_poison: bool,
    ) -> Result<RankedGuard<'_>, KernelError> {
        let rank = self.enter(1)?;
        let guard = if exclusive {
            let guard = match self.fence.write() {
                Ok(guard) => guard,
                Err(poisoned) if recover_poison => {
                    tracing::warn!(
                        "receipt revocation fence poisoned; recovering publication ordering"
                    );
                    self.fence.clear_poison();
                    poisoned.into_inner()
                }
                Err(_) => {
                    return Err(KernelError::Internal(
                        "receipt revocation fence poisoned".into(),
                    ))
                }
            };
            LockGuard::Write { _guard: guard }
        } else {
            let guard = match self.fence.read() {
                Ok(guard) => guard,
                Err(poisoned) if recover_poison => {
                    tracing::warn!(
                        "receipt revocation fence poisoned; recovering publication ordering"
                    );
                    self.fence.clear_poison();
                    poisoned.into_inner()
                }
                Err(_) => {
                    return Err(KernelError::Internal(
                        "receipt revocation fence poisoned".into(),
                    ))
                }
            };
            LockGuard::Read { _guard: guard }
        };
        Ok(RankedGuard {
            _guard: guard,
            _rank: rank,
        })
    }

    pub(super) fn receipts(&self, exclusive: bool) -> Result<RankedGuard<'_>, KernelError> {
        let rank = self.enter(2)?;
        let error = || KernelError::Internal("receipt store barrier poisoned".into());
        let guard = if exclusive {
            LockGuard::Write {
                _guard: self.receipts.write().map_err(|_| error())?,
            }
        } else {
            LockGuard::Read {
                _guard: self.receipts.read().map_err(|_| error())?,
            }
        };
        Ok(RankedGuard {
            _guard: guard,
            _rank: rank,
        })
    }

    pub(super) fn projection(&self) -> Result<RankedGuard<'_>, KernelError> {
        let rank = self.enter(3)?;
        let guard = self
            .projection
            .lock()
            .map_err(|_| KernelError::Internal("receipt projection lock poisoned".into()))?;
        Ok(RankedGuard {
            _guard: LockGuard::Projection { _guard: guard },
            _rank: rank,
        })
    }

    pub(super) fn publication(
        &self,
        durable: bool,
        replay: bool,
    ) -> Result<PublicationGuard<'_>, KernelError> {
        let fence = self.fence(!durable, true)?;
        let receipts = self.receipts(replay)?;
        Ok(PublicationGuard {
            _receipts: receipts,
            _fence: fence,
        })
    }
}
