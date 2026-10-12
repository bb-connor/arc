//! Finite protocol abstraction. This is not the production recovery runtime.

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Phase {
    Absent,
    Selected,
    Ready,
    Captured,
    Unknown,
    Succeeded,
    ClosedNoEffect,
}

impl Phase {
    fn unresolved(self) -> bool {
        matches!(
            self,
            Self::Selected | Self::Ready | Self::Captured | Self::Unknown
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Claim {
    operation: usize,
    epoch: u8,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct State {
    phases: [Phase; 2],
    active: Option<usize>,
    allocated: usize,
    epochs: [u8; 2],
    claims: [Option<Claim>; 2],
    consumed: [bool; 2],
    effects: [u8; 2],
    stale_capture: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mutation {
    None,
    OverlappingSelection,
    IgnoreOwnerEpoch,
    ReplayUnknown,
    UnknownMeansNoEffect,
}

impl State {
    pub fn initial() -> Self {
        Self {
            phases: [Phase::Absent; 2],
            active: None,
            allocated: 0,
            epochs: [0; 2],
            claims: [None; 2],
            consumed: [false; 2],
            effects: [0; 2],
            stale_capture: false,
        }
    }

    pub fn invariant(self) -> Result<(), &'static str> {
        let open: Vec<usize> = self
            .phases
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.unresolved().then_some(i))
            .collect();
        if open.len() > 1 {
            return Err("more than one unresolved continuation owns the step");
        }
        if open.first().copied() != self.active {
            return Err("active continuation disagrees with durable unresolved state");
        }
        if u16::from(self.effects[0]) + u16::from(self.effects[1]) > 1 {
            return Err("the one modeled effectful step executed more than once");
        }
        if self.phases.contains(&Phase::Succeeded) && !open.is_empty() {
            return Err("a completed step acquired another continuation");
        }
        if self.stale_capture {
            return Err("a stale coordinator epoch captured live ownership");
        }
        for i in 0..2 {
            if self.phases[i] == Phase::ClosedNoEffect && self.effects[i] != 0 {
                return Err("an actual effect was classified as closed without effect");
            }
            if matches!(
                self.phases[i],
                Phase::Captured | Phase::Unknown | Phase::Succeeded
            ) && !self.consumed[i]
            {
                return Err("captured operation lacks consumed authority");
            }
        }
        Ok(())
    }

    pub fn successors(self, mutation: Mutation) -> Vec<(String, Self)> {
        let mut next = Vec::new();
        if self.allocated < 2
            && !self.phases.contains(&Phase::Succeeded)
            && (self.active.is_none() || mutation == Mutation::OverlappingSelection)
        {
            let mut s = self;
            let i = s.allocated;
            s.phases[i] = Phase::Selected;
            s.active = Some(i);
            s.allocated += 1;
            next.push((format!("select continuation {i}"), s));
        }
        for i in 0..self.allocated {
            if self.phases[i] == Phase::Selected {
                let mut s = self;
                s.phases[i] = Phase::Ready;
                next.push((format!("retain exact verified approval for {i}"), s));
            }
            if matches!(self.phases[i], Phase::Selected | Phase::Ready) {
                let mut s = self;
                s.phases[i] = Phase::ClosedNoEffect;
                s.active = None;
                next.push((format!("authoritatively close {i} before capture"), s));
                if self.epochs[i] < 2 {
                    for worker in 0..2 {
                        let mut s = self;
                        s.epochs[i] += 1;
                        s.claims[worker] = Some(Claim {
                            operation: i,
                            epoch: s.epochs[i],
                        });
                        next.push((
                            format!(
                                "coordinator {worker} acquires epoch {} for {i}",
                                s.epochs[i]
                            ),
                            s,
                        ));
                    }
                }
            }
            if self.phases[i] == Phase::Ready && !self.consumed[i] && self.active == Some(i) {
                for worker in 0..2 {
                    let Some(claim) = self.claims[worker] else {
                        continue;
                    };
                    if claim.operation != i {
                        continue;
                    }
                    let stale = claim.epoch != self.epochs[i];
                    if stale && mutation != Mutation::IgnoreOwnerEpoch {
                        continue;
                    }
                    let mut s = self;
                    s.phases[i] = Phase::Captured;
                    s.consumed[i] = true;
                    s.stale_capture = stale;
                    next.push((
                        format!("coordinator {worker} captures {i} at epoch {}", claim.epoch),
                        s,
                    ));
                }
            }
            if self.phases[i] == Phase::Captured {
                let mut s = self;
                s.phases[i] = Phase::Unknown;
                s.claims = [None; 2];
                next.push((
                    format!("crash after capture {i}, before external effect"),
                    s,
                ));
                let mut effected = s;
                effected.effects[i] += 1;
                next.push((
                    format!("external effect {i}, then lost response/process death"),
                    effected,
                ));
            }
            if self.phases[i] == Phase::Unknown {
                if self.effects[i] > 0 {
                    let mut s = self;
                    s.phases[i] = Phase::Succeeded;
                    s.active = None;
                    next.push((format!("verify original completed effect {i}"), s));
                }
                if self.effects[i] == 0 || mutation == Mutation::UnknownMeansNoEffect {
                    let mut s = self;
                    s.phases[i] = Phase::ClosedNoEffect;
                    s.active = None;
                    next.push((
                        format!(
                            "close {i} using {}",
                            if self.effects[i] == 0 {
                                "authoritative final no-effect proof"
                            } else {
                                "MUTATED unknown-as-no-effect inference"
                            }
                        ),
                        s,
                    ));
                }
                if mutation == Mutation::ReplayUnknown {
                    let mut s = self;
                    s.phases[i] = Phase::Captured;
                    next.push((format!("MUTATED fresh dispatch owner for unknown {i}"), s));
                }
            }
        }
        if self.claims.iter().any(Option::is_some) {
            let mut s = self;
            s.claims = [None; 2];
            next.push(("crash coordinators; retain all durable state".into(), s));
        }
        next
    }
}
