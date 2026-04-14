//! Tower middleware for ARC capability validation and receipt signing.
//!
//! Provides a `tower::Layer` that wraps any HTTP service with ARC evaluation:
//! extracting caller identity, evaluating requests against the ARC kernel,
//! and attaching signed receipts to responses.
//!
//! Works with any Tower-compatible framework including Axum (HTTP) and
//! Tonic (gRPC).
//!
//! # Example with Tower service
//!
//! ```rust
//! use arc_tower::ArcLayer;
//! use arc_core_types::crypto::Keypair;
//! use tower::Layer;
//!
//! let keypair = Keypair::generate();
//! let layer = ArcLayer::new(keypair, "policy-hash-abc".to_string());
//!
//! // Wrap any tower Service with ARC evaluation.
//! let inner = tower::service_fn(|_req: http::Request<()>| async {
//!     Ok::<_, Box<dyn std::error::Error + Send + Sync>>(http::Response::new(()))
//! });
//! let _service = layer.layer(inner);
//! ```

mod error;
mod evaluator;
mod identity;
mod layer;
mod service;

pub use error::ArcTowerError;
pub use evaluator::{ArcEvaluator, EvaluationResult};
pub use identity::{extract_identity, IdentityExtractor};
pub use layer::ArcLayer;
pub use service::ArcService;
