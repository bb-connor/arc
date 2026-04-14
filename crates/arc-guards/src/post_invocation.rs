//! Post-invocation hook pipeline -- inspects responses before delivery.
//!
//! This module provides a pipeline of post-invocation hooks that run after
//! a tool has produced a response but before that response is delivered to
//! the agent. Each hook can:
//!
//! - **Allow** the response to pass through unmodified
//! - **Block** the response entirely (replacing it with an error)
//! - **Redact** parts of the response before delivery
//! - **Escalate** the response to operator review
//!
//! The pipeline runs hooks in order. A Block from any hook stops the pipeline.

use serde_json::Value;

// ---------------------------------------------------------------------------
// PostInvocationVerdict
// ---------------------------------------------------------------------------

/// Verdict from a post-invocation hook.
#[derive(Debug, Clone)]
pub enum PostInvocationVerdict {
    /// Allow the response to pass through unmodified.
    Allow,
    /// Block the response entirely, replacing it with the given error message.
    Block(String),
    /// Allow the response but with redacted content.
    Redact(Value),
    /// Escalate the response for operator review. The response is still
    /// delivered, but an escalation signal is emitted.
    Escalate(String),
}

// ---------------------------------------------------------------------------
// PostInvocationHook trait
// ---------------------------------------------------------------------------

/// A hook that inspects tool responses after invocation.
pub trait PostInvocationHook: Send + Sync {
    /// Human-readable hook name.
    fn name(&self) -> &str;

    /// Inspect the response and return a verdict.
    ///
    /// `tool_name`: the tool that produced the response.
    /// `response`: the response payload from the tool.
    fn inspect(&self, tool_name: &str, response: &Value) -> PostInvocationVerdict;
}

// ---------------------------------------------------------------------------
// PostInvocationPipeline
// ---------------------------------------------------------------------------

/// Pipeline of post-invocation hooks evaluated in registration order.
///
/// If any hook returns Block, the pipeline short-circuits and returns Block.
/// If any hook returns Redact, subsequent hooks see the redacted version.
/// Escalate signals are collected but do not stop the pipeline.
pub struct PostInvocationPipeline {
    hooks: Vec<Box<dyn PostInvocationHook>>,
}

impl PostInvocationPipeline {
    /// Create an empty pipeline.
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    /// Add a hook to the end of the pipeline.
    pub fn add(&mut self, hook: Box<dyn PostInvocationHook>) {
        self.hooks.push(hook);
    }

    /// Return the number of hooks in the pipeline.
    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    /// Return whether the pipeline has no hooks.
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    /// Run all hooks against a response.
    ///
    /// Returns the final verdict and any escalation messages collected.
    pub fn evaluate(
        &self,
        tool_name: &str,
        response: &Value,
    ) -> (PostInvocationVerdict, Vec<String>) {
        let mut current_response = response.clone();
        let mut escalations = Vec::new();

        for hook in &self.hooks {
            match hook.inspect(tool_name, &current_response) {
                PostInvocationVerdict::Allow => continue,
                PostInvocationVerdict::Block(reason) => {
                    return (PostInvocationVerdict::Block(reason), escalations);
                }
                PostInvocationVerdict::Redact(redacted) => {
                    current_response = redacted;
                }
                PostInvocationVerdict::Escalate(msg) => {
                    escalations.push(msg);
                }
            }
        }

        if current_response != *response {
            (PostInvocationVerdict::Redact(current_response), escalations)
        } else if !escalations.is_empty() {
            (
                PostInvocationVerdict::Escalate(escalations.join("; ")),
                escalations,
            )
        } else {
            (PostInvocationVerdict::Allow, escalations)
        }
    }
}

impl Default for PostInvocationPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct AllowHook;
    impl PostInvocationHook for AllowHook {
        fn name(&self) -> &str {
            "allow-all"
        }
        fn inspect(&self, _tool: &str, _resp: &Value) -> PostInvocationVerdict {
            PostInvocationVerdict::Allow
        }
    }

    struct BlockHook(String);
    impl PostInvocationHook for BlockHook {
        fn name(&self) -> &str {
            "block-all"
        }
        fn inspect(&self, _tool: &str, _resp: &Value) -> PostInvocationVerdict {
            PostInvocationVerdict::Block(self.0.clone())
        }
    }

    struct RedactHook;
    impl PostInvocationHook for RedactHook {
        fn name(&self) -> &str {
            "redact-all"
        }
        fn inspect(&self, _tool: &str, _resp: &Value) -> PostInvocationVerdict {
            PostInvocationVerdict::Redact(serde_json::json!({"redacted": true}))
        }
    }

    struct EscalateHook(String);
    impl PostInvocationHook for EscalateHook {
        fn name(&self) -> &str {
            "escalate"
        }
        fn inspect(&self, _tool: &str, _resp: &Value) -> PostInvocationVerdict {
            PostInvocationVerdict::Escalate(self.0.clone())
        }
    }

    #[test]
    fn empty_pipeline_allows() {
        let pipeline = PostInvocationPipeline::new();
        let response = serde_json::json!({"data": "hello"});
        let (verdict, escalations) = pipeline.evaluate("tool", &response);
        assert!(matches!(verdict, PostInvocationVerdict::Allow));
        assert!(escalations.is_empty());
    }

    #[test]
    fn all_allow_passes() {
        let mut pipeline = PostInvocationPipeline::new();
        pipeline.add(Box::new(AllowHook));
        pipeline.add(Box::new(AllowHook));

        let response = serde_json::json!({"data": "hello"});
        let (verdict, _) = pipeline.evaluate("tool", &response);
        assert!(matches!(verdict, PostInvocationVerdict::Allow));
    }

    #[test]
    fn block_stops_pipeline() {
        let mut pipeline = PostInvocationPipeline::new();
        pipeline.add(Box::new(AllowHook));
        pipeline.add(Box::new(BlockHook("blocked".to_string())));
        pipeline.add(Box::new(AllowHook)); // Should not run.

        let response = serde_json::json!({"data": "hello"});
        let (verdict, _) = pipeline.evaluate("tool", &response);
        assert!(matches!(verdict, PostInvocationVerdict::Block(_)));
    }

    #[test]
    fn redact_modifies_response() {
        let mut pipeline = PostInvocationPipeline::new();
        pipeline.add(Box::new(RedactHook));

        let response = serde_json::json!({"data": "sensitive"});
        let (verdict, _) = pipeline.evaluate("tool", &response);
        match verdict {
            PostInvocationVerdict::Redact(v) => {
                assert_eq!(v, serde_json::json!({"redacted": true}));
            }
            other => panic!("expected Redact, got {other:?}"),
        }
    }

    #[test]
    fn escalations_collected() {
        let mut pipeline = PostInvocationPipeline::new();
        pipeline.add(Box::new(EscalateHook("warning 1".to_string())));
        pipeline.add(Box::new(EscalateHook("warning 2".to_string())));

        let response = serde_json::json!({"data": "hello"});
        let (verdict, escalations) = pipeline.evaluate("tool", &response);
        assert!(matches!(verdict, PostInvocationVerdict::Escalate(_)));
        assert_eq!(escalations.len(), 2);
        assert_eq!(escalations[0], "warning 1");
        assert_eq!(escalations[1], "warning 2");
    }

    #[test]
    fn block_after_escalation_returns_block_with_escalations() {
        let mut pipeline = PostInvocationPipeline::new();
        pipeline.add(Box::new(EscalateHook("noticed something".to_string())));
        pipeline.add(Box::new(BlockHook("critical".to_string())));

        let response = serde_json::json!({"data": "hello"});
        let (verdict, escalations) = pipeline.evaluate("tool", &response);
        assert!(matches!(verdict, PostInvocationVerdict::Block(_)));
        assert_eq!(escalations.len(), 1);
    }

    #[test]
    fn len_and_is_empty() {
        let mut pipeline = PostInvocationPipeline::new();
        assert!(pipeline.is_empty());
        assert_eq!(pipeline.len(), 0);
        pipeline.add(Box::new(AllowHook));
        assert!(!pipeline.is_empty());
        assert_eq!(pipeline.len(), 1);
    }
}
