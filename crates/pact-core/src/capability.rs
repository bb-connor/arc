//! Capability tokens: Ed25519-signed, scoped, time-bounded authorizations.
//!
//! A PACT capability token is the sole authority to invoke a tool. There is no
//! ambient authority. The Kernel validates the token on every request and denies
//! access if any check fails.

use serde::{Deserialize, Serialize};

use crate::crypto::{Keypair, PublicKey, Signature};
use crate::error::{Error, Result};

/// A PACT capability token. Ed25519-signed, scoped, time-bounded.
///
/// The `signature` field covers the canonical JSON of all other fields.
/// Verification re-serializes the token (excluding the signature), computes
/// the canonical form, and checks the Ed25519 signature against `issuer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Unique token ID (UUIDv7 recommended, used for revocation).
    pub id: String,
    /// Capability Authority (or delegating agent) that issued this token.
    pub issuer: PublicKey,
    /// Agent this capability is bound to (DPoP sender constraint).
    pub subject: PublicKey,
    /// What this token authorizes.
    pub scope: PactScope,
    /// Unix timestamp (seconds) when the token was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when the token expires.
    pub expires_at: u64,
    /// Ordered list of delegation links from the root CA to this token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_chain: Vec<DelegationLink>,
    /// Ed25519 signature over canonical JSON of all fields above.
    pub signature: Signature,
}

/// The body of a capability token, containing every field except the signature.
/// Used as the signing input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityTokenBody {
    pub id: String,
    pub issuer: PublicKey,
    pub subject: PublicKey,
    pub scope: PactScope,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_chain: Vec<DelegationLink>,
}

impl CapabilityToken {
    /// Extract the body (everything except the signature) for re-verification.
    #[must_use]
    pub fn body(&self) -> CapabilityTokenBody {
        CapabilityTokenBody {
            id: self.id.clone(),
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            scope: self.scope.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            delegation_chain: self.delegation_chain.clone(),
        }
    }

    /// Sign a capability token body with the given keypair.
    pub fn sign(body: CapabilityTokenBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            id: body.id,
            issuer: body.issuer,
            subject: body.subject,
            scope: body.scope,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            delegation_chain: body.delegation_chain,
            signature,
        })
    }

    /// Verify the token's signature against its issuer key.
    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.issuer.verify_canonical(&body, &self.signature)
    }

    /// Check whether this token is expired at the given unix timestamp.
    #[must_use]
    pub fn is_expired_at(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Check whether this token is valid at the given unix timestamp
    /// (issued_at <= now < expires_at).
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    /// Validate time bounds, returning an error on failure.
    pub fn validate_time(&self, now: u64) -> Result<()> {
        if now < self.issued_at {
            return Err(Error::CapabilityNotYetValid {
                not_before: self.issued_at,
            });
        }
        if now >= self.expires_at {
            return Err(Error::CapabilityExpired {
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }
}

/// What a capability token authorizes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PactScope {
    /// Individual tool grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<ToolGrant>,

    /// Individual resource grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_grants: Vec<ResourceGrant>,

    /// Individual prompt grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompt_grants: Vec<PromptGrant>,
}

impl PactScope {
    /// Returns true if `self` is a subset of `other` -- that is, every grant
    /// in `self` is covered by some grant in `other`.
    #[must_use]
    pub fn is_subset_of(&self, other: &PactScope) -> bool {
        self.grants.iter().all(|child_grant| {
            other
                .grants
                .iter()
                .any(|parent| child_grant.is_subset_of(parent))
        }) && self.resource_grants.iter().all(|child_grant| {
            other
                .resource_grants
                .iter()
                .any(|parent| child_grant.is_subset_of(parent))
        }) && self.prompt_grants.iter().all(|child_grant| {
            other
                .prompt_grants
                .iter()
                .any(|parent| child_grant.is_subset_of(parent))
        })
    }
}

/// Authorization for a single tool on a single server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolGrant {
    /// Which tool server (by server_id from the manifest).
    pub server_id: String,
    /// Which tool on that server.
    pub tool_name: String,
    /// Allowed operations.
    pub operations: Vec<Operation>,
    /// Parameter constraints that narrow the tool's input space.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<Constraint>,
    /// Maximum number of invocations allowed under this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invocations: Option<u32>,
}

impl ToolGrant {
    /// Returns true if `self` is a subset of `parent`.
    ///
    /// A child grant is a subset when:
    /// - It targets the same server and tool, unless the parent uses `*`.
    /// - Its operations are a subset of the parent's.
    /// - Its max_invocations is no greater than the parent's (if set).
    /// - Its constraints are at least as restrictive (superset of constraints).
    #[must_use]
    pub fn is_subset_of(&self, parent: &ToolGrant) -> bool {
        // Must target the same server + tool (or parent grants all via "*")
        if parent.server_id != "*" && self.server_id != parent.server_id {
            return false;
        }
        if parent.tool_name != "*" && self.tool_name != parent.tool_name {
            return false;
        }

        // Child operations must be a subset of parent operations
        let ops_ok = self
            .operations
            .iter()
            .all(|op| parent.operations.contains(op));
        if !ops_ok {
            return false;
        }

        // If parent has an invocation cap, child must too and it must be <= parent
        if let Some(parent_max) = parent.max_invocations {
            match self.max_invocations {
                Some(child_max) if child_max <= parent_max => {}
                None => return false, // child is uncapped but parent is capped
                Some(_) => return false, // child exceeds parent
            }
        }

        // Child must have at least as many constraints (more restrictive).
        // Each parent constraint must appear in the child's constraint list.
        let constraints_ok = parent
            .constraints
            .iter()
            .all(|pc| self.constraints.contains(pc));
        if !constraints_ok {
            return false;
        }

        true
    }
}

/// Authorization for reading or subscribing to a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGrant {
    /// URI pattern identifying which resources are in scope.
    pub uri_pattern: String,
    /// Allowed operations.
    pub operations: Vec<Operation>,
}

impl ResourceGrant {
    #[must_use]
    pub fn is_subset_of(&self, parent: &ResourceGrant) -> bool {
        pattern_covers(&parent.uri_pattern, &self.uri_pattern)
            && self
                .operations
                .iter()
                .all(|operation| parent.operations.contains(operation))
    }
}

/// Authorization for retrieving a prompt by name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptGrant {
    /// Prompt name pattern.
    pub prompt_name: String,
    /// Allowed operations.
    pub operations: Vec<Operation>,
}

impl PromptGrant {
    #[must_use]
    pub fn is_subset_of(&self, parent: &PromptGrant) -> bool {
        pattern_covers(&parent.prompt_name, &self.prompt_name)
            && self
                .operations
                .iter()
                .all(|operation| parent.operations.contains(operation))
    }
}

fn pattern_covers(parent: &str, child: &str) -> bool {
    if parent == "*" {
        return true;
    }

    if let Some(prefix) = parent.strip_suffix('*') {
        return child.starts_with(prefix);
    }

    parent == child
}

/// An operation that can be performed under a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Invoke the tool (execute it).
    Invoke,
    /// Read the result of a previous invocation.
    ReadResult,
    /// Read a resource.
    Read,
    /// Subscribe to resource updates.
    Subscribe,
    /// Retrieve a prompt.
    Get,
    /// Delegate this grant to another agent.
    Delegate,
}

/// A constraint on tool parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Constraint {
    /// File path parameter must start with this prefix.
    PathPrefix(String),
    /// Network domain must match exactly.
    DomainExact(String),
    /// Network domain must match a glob pattern.
    DomainGlob(String),
    /// Parameter must match a regular expression.
    RegexMatch(String),
    /// String parameter must not exceed this length.
    MaxLength(usize),
    /// Extensibility: arbitrary key-value constraint.
    Custom(String, String),
}

/// A link in the delegation chain, recording that `delegator` granted a
/// narrowed capability to `delegatee`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLink {
    /// Capability ID of the ancestor token delegated at this step.
    pub capability_id: String,
    /// Public key of the agent that delegated.
    pub delegator: PublicKey,
    /// Public key of the agent that received the delegation.
    pub delegatee: PublicKey,
    /// How the scope was narrowed in this delegation step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attenuations: Vec<Attenuation>,
    /// Unix timestamp of the delegation.
    pub timestamp: u64,
    /// Ed25519 signature by the delegator over the canonical form of the
    /// other fields in this link.
    pub signature: Signature,
}

/// The body of a delegation link, used as the signing input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLinkBody {
    pub capability_id: String,
    pub delegator: PublicKey,
    pub delegatee: PublicKey,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attenuations: Vec<Attenuation>,
    pub timestamp: u64,
}

impl DelegationLink {
    /// Sign a delegation link body.
    pub fn sign(body: DelegationLinkBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            capability_id: body.capability_id,
            delegator: body.delegator,
            delegatee: body.delegatee,
            attenuations: body.attenuations,
            timestamp: body.timestamp,
            signature,
        })
    }

    /// Extract the signable body.
    #[must_use]
    pub fn body(&self) -> DelegationLinkBody {
        DelegationLinkBody {
            capability_id: self.capability_id.clone(),
            delegator: self.delegator.clone(),
            delegatee: self.delegatee.clone(),
            attenuations: self.attenuations.clone(),
            timestamp: self.timestamp,
        }
    }

    /// Verify this link's signature against the delegator's key.
    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.delegator.verify_canonical(&body, &self.signature)
    }
}

/// Describes how a scope was narrowed during delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Attenuation {
    /// A tool was removed from the scope.
    RemoveTool {
        server_id: String,
        tool_name: String,
    },
    /// An operation was removed from a tool grant.
    RemoveOperation {
        server_id: String,
        tool_name: String,
        operation: Operation,
    },
    /// A constraint was added to a tool grant.
    AddConstraint {
        server_id: String,
        tool_name: String,
        constraint: Constraint,
    },
    /// The invocation budget was reduced.
    ReduceBudget {
        server_id: String,
        tool_name: String,
        max_invocations: u32,
    },
    /// The expiration was shortened.
    ShortenExpiry { new_expires_at: u64 },
}

/// Validate an entire delegation chain.
///
/// Checks that:
/// 1. Each link's signature is valid.
/// 2. Adjacent links are connected (link[i].delegatee == link[i+1].delegator).
/// 3. Timestamps are non-decreasing.
/// 4. The chain length does not exceed `max_depth` (if provided).
pub fn validate_delegation_chain(chain: &[DelegationLink], max_depth: Option<u32>) -> Result<()> {
    if let Some(max) = max_depth {
        let len = u32::try_from(chain.len()).unwrap_or(u32::MAX);
        if len > max {
            return Err(Error::DelegationDepthExceeded { depth: len, max });
        }
    }

    for (i, link) in chain.iter().enumerate() {
        let sig_valid = link.verify_signature()?;
        if !sig_valid {
            return Err(Error::DelegationChainBroken {
                reason: format!("signature invalid at link index {i}"),
            });
        }

        if i > 0 {
            let prev = &chain[i - 1];
            if prev.delegatee != link.delegator {
                return Err(Error::DelegationChainBroken {
                    reason: format!("link {i} delegator does not match link {} delegatee", i - 1),
                });
            }
            if link.timestamp < prev.timestamp {
                return Err(Error::DelegationChainBroken {
                    reason: format!(
                        "link {i} timestamp ({}) precedes link {} timestamp ({})",
                        link.timestamp,
                        i - 1,
                        prev.timestamp
                    ),
                });
            }
        }
    }

    Ok(())
}

/// Validate that a child scope is a valid attenuation of a parent scope.
///
/// Returns Ok(()) if child is a subset of parent. Returns an error otherwise.
pub fn validate_attenuation(parent: &PactScope, child: &PactScope) -> Result<()> {
    if child.is_subset_of(parent) {
        Ok(())
    } else {
        Err(Error::AttenuationViolation {
            reason: "child scope is not a subset of parent scope".to_string(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_grant(server: &str, tool: &str, ops: Vec<Operation>) -> ToolGrant {
        ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: ops,
            constraints: vec![],
            max_invocations: None,
        }
    }

    fn make_scope(grants: Vec<ToolGrant>) -> PactScope {
        PactScope {
            grants,
            ..PactScope::default()
        }
    }

    #[test]
    fn capability_token_serde_roundtrip() {
        let kp = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-001".to_string(),
            issuer: kp.public_key(),
            subject: Keypair::generate().public_key(),
            scope: make_scope(vec![make_grant(
                "srv-a",
                "file_read",
                vec![Operation::Invoke],
            )]),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &kp).unwrap();

        let json = serde_json::to_string_pretty(&token).unwrap();
        let restored: CapabilityToken = serde_json::from_str(&json).unwrap();

        assert_eq!(token.id, restored.id);
        assert_eq!(token.issuer, restored.issuer);
        assert_eq!(token.subject, restored.subject);
        assert_eq!(token.issued_at, restored.issued_at);
        assert_eq!(token.expires_at, restored.expires_at);
        assert_eq!(token.signature.to_hex(), restored.signature.to_hex());
    }

    #[test]
    fn capability_token_signature_verification() {
        let kp = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-002".to_string(),
            issuer: kp.public_key(),
            subject: Keypair::generate().public_key(),
            scope: make_scope(vec![make_grant(
                "srv-a",
                "shell_exec",
                vec![Operation::Invoke, Operation::ReadResult],
            )]),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &kp).unwrap();
        assert!(token.verify_signature().unwrap());
    }

    #[test]
    fn wrong_key_signature_fails() {
        let kp = Keypair::generate();
        let other_kp = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-003".to_string(),
            issuer: other_kp.public_key(), // issuer != signer
            subject: Keypair::generate().public_key(),
            scope: make_scope(vec![]),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &kp).unwrap();
        // Signature was made by kp but issuer is other_kp, so it should fail.
        assert!(!token.verify_signature().unwrap());
    }

    #[test]
    fn time_validation() {
        let kp = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-time".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: make_scope(vec![]),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &kp).unwrap();

        assert!(token.is_valid_at(1000));
        assert!(token.is_valid_at(1500));
        assert!(token.is_valid_at(1999));
        assert!(!token.is_valid_at(999)); // before issued_at
        assert!(!token.is_valid_at(2000)); // at expires_at (exclusive)
        assert!(!token.is_valid_at(3000)); // after expires_at

        assert!(token.is_expired_at(2000));
        assert!(token.is_expired_at(3000));
        assert!(!token.is_expired_at(1999));

        assert!(token.validate_time(1500).is_ok());
        assert!(token.validate_time(999).is_err());
        assert!(token.validate_time(2000).is_err());
    }

    #[test]
    fn scope_subset_same() {
        let scope = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        assert!(scope.is_subset_of(&scope));
    }

    #[test]
    fn scope_subset_fewer_grants() {
        let parent = make_scope(vec![
            make_grant("a", "t1", vec![Operation::Invoke]),
            make_grant("a", "t2", vec![Operation::Invoke]),
        ]);
        let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn scope_subset_fewer_operations() {
        let parent = make_scope(vec![make_grant(
            "a",
            "t1",
            vec![Operation::Invoke, Operation::ReadResult],
        )]);
        let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn scope_not_subset_different_server() {
        let parent = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        let child = make_scope(vec![make_grant("b", "t1", vec![Operation::Invoke])]);
        assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn scope_not_subset_different_tool() {
        let parent = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        let child = make_scope(vec![make_grant("a", "t2", vec![Operation::Invoke])]);
        assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn scope_subset_wildcard_tool() {
        let parent = make_scope(vec![make_grant("a", "*", vec![Operation::Invoke])]);
        let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn grant_subset_with_invocation_budget() {
        let parent = ToolGrant {
            server_id: "a".to_string(),
            tool_name: "t1".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(10),
        };
        let child_ok = ToolGrant {
            max_invocations: Some(5),
            ..parent.clone()
        };
        let child_exceed = ToolGrant {
            max_invocations: Some(20),
            ..parent.clone()
        };
        let child_none = ToolGrant {
            max_invocations: None,
            ..parent.clone()
        };

        assert!(child_ok.is_subset_of(&parent));
        assert!(!child_exceed.is_subset_of(&parent));
        assert!(!child_none.is_subset_of(&parent)); // uncapped child of capped parent
    }

    #[test]
    fn grant_subset_with_constraints() {
        let parent = ToolGrant {
            server_id: "a".to_string(),
            tool_name: "t1".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::PathPrefix("/app".to_string())],
            max_invocations: None,
        };
        // Child has parent's constraint + an extra one (more restrictive)
        let child = ToolGrant {
            constraints: vec![
                Constraint::PathPrefix("/app".to_string()),
                Constraint::MaxLength(1024),
            ],
            ..parent.clone()
        };
        // Child missing parent's constraint (less restrictive)
        let bad_child = ToolGrant {
            constraints: vec![Constraint::MaxLength(1024)],
            ..parent.clone()
        };

        assert!(child.is_subset_of(&parent));
        assert!(!bad_child.is_subset_of(&parent));
    }

    #[test]
    fn grant_subset_with_wildcard_server() {
        let parent = ToolGrant {
            server_id: "*".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
        };
        let child = ToolGrant {
            server_id: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
        };

        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn validate_attenuation_ok() {
        let parent = make_scope(vec![
            make_grant("a", "t1", vec![Operation::Invoke, Operation::ReadResult]),
            make_grant("a", "t2", vec![Operation::Invoke]),
        ]);
        let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        assert!(validate_attenuation(&parent, &child).is_ok());
    }

    #[test]
    fn validate_attenuation_escalation_fails() {
        let parent = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        let child = make_scope(vec![make_grant(
            "a",
            "t1",
            vec![Operation::Invoke, Operation::Delegate],
        )]);
        assert!(validate_attenuation(&parent, &child).is_err());
    }

    fn make_signed_link(
        capability_id: &str,
        delegator_kp: &Keypair,
        delegatee: &PublicKey,
        timestamp: u64,
    ) -> DelegationLink {
        let body = DelegationLinkBody {
            capability_id: capability_id.to_string(),
            delegator: delegator_kp.public_key(),
            delegatee: delegatee.clone(),
            attenuations: vec![],
            timestamp,
        };
        DelegationLink::sign(body, delegator_kp).unwrap()
    }

    #[test]
    fn delegation_chain_valid() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
        let link2 = make_signed_link("cap-b", &kp_b, &kp_c.public_key(), 200);

        assert!(validate_delegation_chain(&[link1, link2], None).is_ok());
    }

    #[test]
    fn delegation_chain_broken_connectivity() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();
        let kp_d = Keypair::generate();

        // link1: A -> B, link2: C -> D (not connected)
        let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
        let link2 = make_signed_link("cap-c", &kp_c, &kp_d.public_key(), 200);

        let err = validate_delegation_chain(&[link1, link2], None).unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn delegation_chain_non_monotonic_timestamps() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 200);
        let link2 = make_signed_link("cap-b", &kp_b, &kp_c.public_key(), 100); // earlier!

        let err = validate_delegation_chain(&[link1, link2], None).unwrap_err();
        assert!(err.to_string().contains("precedes"));
    }

    #[test]
    fn delegation_chain_exceeds_depth() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
        let link2 = make_signed_link("cap-b", &kp_b, &kp_c.public_key(), 200);

        let err = validate_delegation_chain(&[link1, link2], Some(1)).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn delegation_chain_invalid_signature() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        let mut link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
        // Tamper: change the delegatee after signing
        link1.delegatee = kp_c.public_key();

        let err = validate_delegation_chain(&[link1], None).unwrap_err();
        assert!(err.to_string().contains("signature invalid"));
    }

    #[test]
    fn delegation_link_serde_roundtrip() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let link = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 12345);

        let json = serde_json::to_string_pretty(&link).unwrap();
        let restored: DelegationLink = serde_json::from_str(&json).unwrap();

        assert_eq!(link.capability_id, restored.capability_id);
        assert_eq!(link.delegator, restored.delegator);
        assert_eq!(link.delegatee, restored.delegatee);
        assert_eq!(link.timestamp, restored.timestamp);
        assert_eq!(link.signature.to_hex(), restored.signature.to_hex());
    }

    #[test]
    fn constraint_serde_roundtrip() {
        let constraints = vec![
            Constraint::PathPrefix("/app/src".to_string()),
            Constraint::DomainExact("api.example.com".to_string()),
            Constraint::DomainGlob("*.example.com".to_string()),
            Constraint::RegexMatch(r"^[a-z]+$".to_string()),
            Constraint::MaxLength(1024),
            Constraint::Custom("category".to_string(), "read-only".to_string()),
        ];

        let json = serde_json::to_string_pretty(&constraints).unwrap();
        let restored: Vec<Constraint> = serde_json::from_str(&json).unwrap();
        assert_eq!(constraints, restored);
    }

    #[test]
    fn operation_serde_roundtrip() {
        let ops = vec![
            Operation::Invoke,
            Operation::ReadResult,
            Operation::Delegate,
        ];
        let json = serde_json::to_string(&ops).unwrap();
        let restored: Vec<Operation> = serde_json::from_str(&json).unwrap();
        assert_eq!(ops, restored);
    }

    #[test]
    fn attenuation_serde_roundtrip() {
        let attenuations = vec![
            Attenuation::RemoveTool {
                server_id: "srv".to_string(),
                tool_name: "danger".to_string(),
            },
            Attenuation::RemoveOperation {
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                operation: Operation::Delegate,
            },
            Attenuation::AddConstraint {
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                constraint: Constraint::PathPrefix("/safe".to_string()),
            },
            Attenuation::ReduceBudget {
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                max_invocations: 5,
            },
            Attenuation::ShortenExpiry {
                new_expires_at: 9999,
            },
        ];

        let json = serde_json::to_string_pretty(&attenuations).unwrap();
        let restored: Vec<Attenuation> = serde_json::from_str(&json).unwrap();
        assert_eq!(attenuations, restored);
    }
}
