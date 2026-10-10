//! One process envelope and one native nonce lifecycle; atomic store steps assumed.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    None,
    FinalizeWithoutCustody,
    PreflightBeforeIntent,
    RenewMissingNonce,
    RewriteProcessEnvelope,
    RequireLiveInitiator,
}

#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
enum Phase {
    #[default]
    Absent,
    Prepared,
    Issued,
    Captured,
    Settled,
    Closed,
}

#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct State {
    envelope: bool,
    finalized: bool,
    intent: bool,
    phase: Phase,
    issuance_count: u8,
    reply_available: bool,
    process_nonce: bool,
    restarted: bool,
    lost_issuance_ack: bool,
    expired: bool,
    cancelled: bool,
    effect: bool,
    rewritten: bool,
}

impl State {
    pub fn invariant(self) -> Result<(), &'static str> {
        if self.finalized && !self.envelope {
            return Err("process finalized without durable exact request custody");
        }
        if self.phase != Phase::Absent && !self.intent {
            return Err("native preflight preceded durable admission intent");
        }
        if self.issuance_count > 1 {
            return Err("missing process acknowledgement minted another native nonce");
        }
        if self.rewritten {
            return Err("native attachment rewrote the frozen process envelope");
        }
        if self.effect && !matches!(self.phase, Phase::Captured | Phase::Settled) {
            return Err("external effect lost its captured native owner");
        }
        Ok(())
    }

    pub fn useful_restart(self) -> bool {
        self.lost_issuance_ack && self.effect && self.phase == Phase::Settled
    }

    pub fn settlement_enabled(self, fault: Fault) -> bool {
        // Check a local enabledness obligation, not eventual scheduling fairness.
        !self.effect
            || self.phase != Phase::Captured
            || self
                .successors(fault)
                .iter()
                .any(|(_, next)| next.phase == Phase::Settled)
    }

    pub fn successors(self, fault: Fault) -> Vec<(&'static str, Self)> {
        let mut out = Vec::new();
        let mut push = |name, edit: fn(&mut Self)| {
            let mut next = self;
            edit(&mut next);
            out.push((name, next));
        };
        if !self.envelope && !self.finalized {
            push("retain exact reviewed envelope", |s| s.envelope = true);
        }
        if !self.finalized && (self.envelope || fault == Fault::FinalizeWithoutCustody) {
            push("finalize process reservation once", |s| s.finalized = true);
        }
        if self.finalized && !self.intent {
            push("retain immutable admission intent", |s| s.intent = true);
        }
        if self.finalized
            && self.phase == Phase::Absent
            && !self.cancelled
            && !self.expired
            && (self.intent || fault == Fault::PreflightBeforeIntent)
        {
            push("begin original native nonce preflight", |s| {
                s.phase = Phase::Prepared;
            });
        }
        if self.phase == Phase::Prepared && !self.cancelled && !self.expired {
            push(
                "native issuance commits before process acknowledgement",
                |s| {
                    s.phase = Phase::Issued;
                    s.issuance_count = 1;
                    s.reply_available = true;
                },
            );
        }
        if self.phase == Phase::Issued && !self.process_nonce && self.reply_available {
            push(
                "retain the exact original issuance in process journal",
                |s| {
                    s.process_nonce = true;
                },
            );
        }
        if self.phase == Phase::Issued && !self.process_nonce && !self.reply_available {
            push("read back original native issuance", |s| {
                s.reply_available = true
            });
            if fault == Fault::RenewMissingNonce && !self.expired && !self.cancelled {
                push("mint replacement after missing process nonce", |s| {
                    s.issuance_count = 2;
                    s.reply_available = true;
                });
            }
        }
        if self.finalized && !self.restarted {
            push("crash and reopen; discard only volatile reply", |s| {
                s.restarted = true;
                s.lost_issuance_ack = s.phase == Phase::Issued && !s.process_nonce;
                s.reply_available = false;
            });
        }
        if self.phase == Phase::Issued && self.process_nonce && !self.expired && !self.cancelled {
            let mut captured = self;
            captured.phase = Phase::Captured;
            captured.rewritten = fault == Fault::RewriteProcessEnvelope;
            out.push((
                "attach original nonce and capture original operation",
                captured,
            ));
        }
        if self.intent && !self.cancelled {
            out.push((
                "persist cancellation",
                Self {
                    cancelled: true,
                    ..self
                },
            ));
        }
        if self.intent && !self.expired {
            out.push((
                "initiating authority expires",
                Self {
                    expired: true,
                    ..self
                },
            ));
        }
        if self.intent
            && (self.expired || self.cancelled)
            && matches!(self.phase, Phase::Absent | Phase::Prepared | Phase::Issued)
        {
            out.push((
                "native participants close before capture",
                Self {
                    phase: Phase::Closed,
                    ..self
                },
            ));
        }
        if self.phase == Phase::Captured && !self.effect {
            out.push((
                "original captured owner applies its one effect",
                Self {
                    effect: true,
                    ..self
                },
            ));
        }
        if self.phase == Phase::Captured
            && self.effect
            && (!self.expired || fault != Fault::RequireLiveInitiator)
        {
            out.push((
                "fenced recovery settles retained effect",
                Self {
                    phase: Phase::Settled,
                    ..self
                },
            ));
        }
        out
    }
}
