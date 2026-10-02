use std::path::Path;

use chio_composed_baseline::outcome_ledger as ledger;
use chio_runtime_core::outcome_continuation::{
    OutcomeDispatchPermit, OutcomeEffectArguments, OutcomeEffectRequest, OutcomeEffectRule,
    OutcomeEffectState,
};
use chio_runtime_core::SqliteRuntimeOrchestrationStore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn convert<T: serde::de::DeserializeOwned>(value: &impl Serialize) -> Result<T> {
    Ok(serde_json::from_value(serde_json::to_value(value)?)?)
}

pub enum Gate {
    Chio(SqliteRuntimeOrchestrationStore),
    Ledger(ledger::ReceiverLedger),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "backend", deny_unknown_fields)]
pub enum Prepared {
    Chio {
        request: Box<OutcomeEffectRequest>,
    },
    Ledger {
        handle: String,
        arguments: OutcomeEffectArguments,
    },
}

impl Prepared {
    pub fn arguments(&self) -> &OutcomeEffectArguments {
        match self {
            Self::Chio { request } => &request.arguments,
            Self::Ledger { arguments, .. } => arguments,
        }
    }

    pub fn arguments_mut(&mut self) -> &mut OutcomeEffectArguments {
        match self {
            Self::Chio { request } => &mut request.arguments,
            Self::Ledger { arguments, .. } => arguments,
        }
    }
}

pub enum Permit {
    Chio(OutcomeDispatchPermit),
    Ledger(ledger::Permit),
}

impl Gate {
    pub fn open(kind: &str, directory: &Path, rule: &OutcomeEffectRule) -> Result<Self> {
        std::fs::create_dir_all(directory)?;
        let path = directory.join("receiver.sqlite");
        match kind {
            "chio" => {
                let store = SqliteRuntimeOrchestrationStore::open(path)?;
                store.activate_outcome_effect(rule)?;
                Ok(Self::Chio(store))
            }
            "ledger" => {
                let store = ledger::ReceiverLedger::open(&path)?;
                store.provision(&convert(rule)?)?;
                Ok(Self::Ledger(store))
            }
            _ => Err("unknown comparison backend".into()),
        }
    }

    pub fn prepare(
        &self,
        request: &OutcomeEffectRequest,
        server: &str,
        tool: &str,
        now: u64,
    ) -> Result<Prepared> {
        match self {
            Self::Chio(store) => {
                store.preview_outcome_effect(request, server, tool, now)?;
                Ok(Prepared::Chio {
                    request: Box::new(request.clone()),
                })
            }
            Self::Ledger(store) => Ok(Prepared::Ledger {
                handle: store.exchange(
                    &convert(&request.evidence)?,
                    &convert(&request.arguments)?,
                    server,
                    tool,
                    now,
                )?,
                arguments: request.arguments.clone(),
            }),
        }
    }

    pub fn claim(&self, prepared: &Prepared, server: &str, tool: &str, now: u64) -> Result<Permit> {
        match (self, prepared) {
            (Self::Chio(store), Prepared::Chio { request }) => Ok(Permit::Chio(
                store.claim_outcome_effect(request, server, tool, "comparison-attempt", now)?,
            )),
            (Self::Ledger(store), Prepared::Ledger { handle, arguments }) => Ok(Permit::Ledger(
                store.claim(handle, &convert(arguments)?, server, tool, now)?,
            )),
            _ => Err("prepared authorization belongs to another backend".into()),
        }
    }

    pub fn complete(&self, permit: Permit, result: &Value) -> Result<()> {
        match (self, permit) {
            (Self::Chio(store), Permit::Chio(permit)) => {
                Ok(store.complete_outcome_effect(permit, result)?)
            }
            (Self::Ledger(store), Permit::Ledger(permit)) => Ok(store.complete(permit, result)?),
            _ => Err("dispatch permit belongs to another backend".into()),
        }
    }

    pub fn revoke(&self, rule: &OutcomeEffectRule) -> Result<()> {
        match self {
            Self::Chio(store) => Ok(store.revoke_outcome_effect(&rule.slot)?),
            Self::Ledger(store) => Ok(store.revoke(&convert(&rule.slot)?)?),
        }
    }

    pub fn status(&self, rule: &OutcomeEffectRule) -> Result<(String, Option<Value>)> {
        match self {
            Self::Chio(store) => Ok(match store.outcome_effect_status(&rule.slot)?.state {
                OutcomeEffectState::Waiting => ("waiting".into(), None),
                OutcomeEffectState::DispatchClaimed { .. } => ("claimed".into(), None),
                OutcomeEffectState::Completed { result, .. } => ("completed".into(), Some(result)),
            }),
            Self::Ledger(store) => Ok(store.status(&convert(&rule.slot)?)?),
        }
    }

    /// Compare persisted claim identity for a domain-specific effect observer.
    /// A true result is not a new dispatch permit or generic retry permission.
    pub fn claimed_matches(&self, request: &OutcomeEffectRequest) -> Result<bool> {
        match self {
            Self::Chio(store) => Ok(
                match store
                    .outcome_effect_status(&request.evidence.body.slot)?
                    .state
                {
                    OutcomeEffectState::Waiting => false,
                    OutcomeEffectState::DispatchClaimed { claim }
                    | OutcomeEffectState::Completed { claim, .. } => {
                        claim.arguments == request.arguments
                            && claim.evidence_sha256
                                == chio_core_types::crypto::sha256_hex(
                                    &chio_core_types::crypto::canonical_json_bytes(
                                        &request.evidence,
                                    )?,
                                )
                    }
                },
            ),
            Self::Ledger(store) => Ok(
                match store.claimed_authorization(&convert(&request.evidence.body.slot)?)? {
                    Some((evidence, effect)) => {
                        evidence == convert(&request.evidence)?
                            && effect == convert(&request.arguments)?
                    }
                    None => false,
                },
            ),
        }
    }
}
