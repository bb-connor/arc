//! ARC tower Layer implementation.

use arc_core_types::crypto::Keypair;
use tower_layer::Layer;

use crate::evaluator::ArcEvaluator;
use crate::service::ArcService;

/// Tower `Layer` that wraps inner services with ARC evaluation.
///
/// # Example
///
/// ```rust,no_run
/// use arc_tower::ArcLayer;
/// use arc_core_types::crypto::Keypair;
///
/// let keypair = Keypair::generate();
/// let layer = ArcLayer::new(keypair, "policy-hash".to_string());
/// ```
#[derive(Clone)]
pub struct ArcLayer {
    evaluator: ArcEvaluator,
}

impl ArcLayer {
    /// Create a new ARC layer with the given kernel keypair and policy hash.
    pub fn new(keypair: Keypair, policy_hash: String) -> Self {
        Self {
            evaluator: ArcEvaluator::new(keypair, policy_hash),
        }
    }

    /// Create a layer from an existing evaluator.
    pub fn from_evaluator(evaluator: ArcEvaluator) -> Self {
        Self { evaluator }
    }
}

impl<S> Layer<S> for ArcLayer {
    type Service = ArcService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ArcService::new(inner, self.evaluator.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;

    #[test]
    fn layer_creates_service() {
        let keypair = Keypair::generate();
        let layer = ArcLayer::new(keypair, "test-policy".to_string());

        // Verify that layer can wrap a simple closure.
        let _service = layer.layer(tower::service_fn(
            |_req: http::Request<Full<Bytes>>| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(()))
            },
        ));
    }
}
