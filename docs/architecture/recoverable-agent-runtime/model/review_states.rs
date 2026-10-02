//! Independent finite models of the revision 2 architecture corrections.
use std::hash::Hash;

pub trait Model: Copy + Eq + Hash {
    fn initial() -> Self;
    fn invariant(self) -> Result<(), &'static str>;
    fn successors(self, mutation: Mutation) -> Vec<(&'static str, Self)>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mutation {
    None,
    CloseFromProjection,
    IgnoreAdmissionTombstone,
    IgnoreCancellation,
    ReleaseWithoutJoin,
    IgnoreKnowledgeFence,
    RevisionBeforeReplay,
    CachedResponseAfterRevocation,
    PartialFailureAsNoEffect,
}

#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
enum Native {
    #[default]
    Absent,
    Admitted,
    Captured,
    Applied,
}

#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct Admission {
    intent: bool,
    submitted: bool,
    native: Native,
    projected: bool,
    cancelled: bool,
    closed: bool,
    late_admission: bool,
    captured_after_cancel: bool,
}

impl Model for Admission {
    fn initial() -> Self {
        Self::default()
    }

    fn invariant(self) -> Result<(), &'static str> {
        if self.closed && matches!(self.native, Native::Captured | Native::Applied) {
            return Err("missing projection closed a potentially effective native operation");
        }
        if self.late_admission {
            return Err("late submission reopened a closed admission intent");
        }
        if self.captured_after_cancel {
            return Err("capture followed an earlier committed cancellation");
        }
        Ok(())
    }

    fn successors(self, mutation: Mutation) -> Vec<(&'static str, Self)> {
        let mut out = Vec::new();
        if !self.intent && !self.cancelled {
            out.push((
                "retain immutable admission intent",
                Self {
                    intent: true,
                    ..self
                },
            ));
        }
        if self.intent && !self.submitted && !self.closed && !self.cancelled {
            out.push((
                "submit original request; response may be lost",
                Self {
                    submitted: true,
                    ..self
                },
            ));
        }
        if self.submitted
            && self.native == Native::Absent
            && (!self.closed || mutation == Mutation::IgnoreAdmissionTombstone)
        {
            out.push((
                "native admission commits without projection acknowledgement",
                Self {
                    native: Native::Admitted,
                    late_admission: self.closed,
                    ..self
                },
            ));
        }
        if self.native == Native::Admitted
            && !self.closed
            && (!self.cancelled || mutation == Mutation::IgnoreCancellation)
        {
            out.push((
                "native capture commits",
                Self {
                    native: Native::Captured,
                    captured_after_cancel: self.cancelled,
                    ..self
                },
            ));
        }
        if self.native == Native::Captured {
            out.push((
                "original captured owner produces external effect",
                Self {
                    native: Native::Applied,
                    ..self
                },
            ));
        }
        if self.native != Native::Absent && !self.projected {
            out.push((
                "recover native operation into workflow projection",
                Self {
                    projected: true,
                    ..self
                },
            ));
        }
        if !self.cancelled {
            out.push((
                "commit cancellation intent",
                Self {
                    cancelled: true,
                    ..self
                },
            ));
        }
        if self.intent
            && self.cancelled
            && !self.closed
            && (matches!(self.native, Native::Absent | Native::Admitted)
                || (mutation == Mutation::CloseFromProjection && !self.projected))
        {
            out.push((
                "close no-effect and fence the admission intent",
                Self {
                    closed: true,
                    ..self
                },
            ));
        }
        out
    }
}

#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct Knowledge {
    prepared: bool,
    joined: bool,
    release_record: bool,
    delivered: bool,
    captured: bool,
    stale_capture: bool,
}

impl Model for Knowledge {
    fn initial() -> Self {
        Self::default()
    }

    fn invariant(self) -> Result<(), &'static str> {
        if self.delivered && !self.joined {
            return Err("bytes escaped before native knowledge joined");
        }
        if self.stale_capture {
            return Err("stale public preparation captured after restricted observation");
        }
        Ok(())
    }

    fn successors(self, mutation: Mutation) -> Vec<(&'static str, Self)> {
        let mut out = Vec::new();
        if !self.prepared && !self.joined {
            out.push((
                "prepare exact public dispatch at original flow generation",
                Self {
                    prepared: true,
                    ..self
                },
            ));
        }
        if !self.release_record {
            out.push((
                "commit restricted artifact observation and release record",
                Self {
                    joined: mutation != Mutation::ReleaseWithoutJoin,
                    release_record: true,
                    ..self
                },
            ));
        }
        if self.release_record && !self.delivered {
            out.push((
                "release restricted bytes into recipient context",
                Self {
                    delivered: true,
                    ..self
                },
            ));
        }
        if self.prepared
            && !self.captured
            && (!self.joined || mutation == Mutation::IgnoreKnowledgeFence)
        {
            out.push((
                "capture previously prepared public dispatch",
                Self {
                    captured: true,
                    stale_capture: self.joined,
                    ..self
                },
            ));
        }
        out
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Replay {
    committed: bool,
    revision: u8,
    authorized: bool,
    replayed: bool,
    leaked: bool,
    false_conflict: bool,
}

impl Model for Replay {
    fn initial() -> Self {
        Self {
            committed: false,
            revision: 0,
            authorized: true,
            replayed: false,
            leaked: false,
            false_conflict: false,
        }
    }

    fn invariant(self) -> Result<(), &'static str> {
        if self.leaked {
            return Err("cached protected response escaped after read revocation");
        }
        if self.false_conflict {
            return Err("committed command replay incorrectly conflicted on its old revision");
        }
        Ok(())
    }

    fn successors(self, mutation: Mutation) -> Vec<(&'static str, Self)> {
        let mut out = Vec::new();
        if !self.committed && self.authorized {
            out.push((
                "commit command expecting revision zero; lose acknowledgement",
                Self {
                    committed: true,
                    revision: 1,
                    ..self
                },
            ));
        }
        if self.committed && self.revision == 1 {
            out.push((
                "another authorized transition advances revision",
                Self {
                    revision: 2,
                    ..self
                },
            ));
        }
        if self.authorized {
            out.push((
                "revoke current read authority",
                Self {
                    authorized: false,
                    ..self
                },
            ));
        }
        if self.committed && !self.replayed {
            out.push((
                "replay same command and original expected revision",
                Self {
                    replayed: true,
                    leaked: !self.authorized && mutation == Mutation::CachedResponseAfterRevocation,
                    false_conflict: self.authorized
                        && self.revision != 0
                        && mutation == Mutation::RevisionBeforeReplay,
                    ..self
                },
            ));
        }
        out
    }
}

#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
enum Release {
    #[default]
    Pending,
    Withheld,
    Delivered,
}

#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct PartialEffect {
    effects: u8,
    partial: bool,
    repeat_authorized: bool,
    release: Release,
}

impl Model for PartialEffect {
    fn initial() -> Self {
        Self::default()
    }

    fn invariant(self) -> Result<(), &'static str> {
        if self.effects > 1 {
            return Err("partial failure caused a second external effect for the same step");
        }
        Ok(())
    }

    fn successors(self, mutation: Mutation) -> Vec<(&'static str, Self)> {
        let mut out = Vec::new();
        if self.effects == 0 {
            out.push((
                "settle successful external effect",
                Self { effects: 1, ..self },
            ));
            out.push((
                "settle partial external effect with failed task outcome",
                Self {
                    effects: 1,
                    partial: true,
                    ..self
                },
            ));
        }
        if self.partial && !self.repeat_authorized && mutation == Mutation::PartialFailureAsNoEffect
        {
            out.push((
                "MUTATED classify unsuccessful outcome as retryable no-effect",
                Self {
                    repeat_authorized: true,
                    ..self
                },
            ));
        }
        if self.repeat_authorized && self.effects == 1 {
            out.push((
                "MUTATED perform replacement effect for same step",
                Self { effects: 2, ..self },
            ));
        }
        if self.effects > 0 && self.release == Release::Pending {
            out.push((
                "withhold output without changing effect settlement",
                Self {
                    release: Release::Withheld,
                    ..self
                },
            ));
        }
        if self.effects > 0 && self.release != Release::Delivered {
            out.push((
                "release exact result under separately verified authority",
                Self {
                    release: Release::Delivered,
                    ..self
                },
            ));
        }
        out
    }
}
