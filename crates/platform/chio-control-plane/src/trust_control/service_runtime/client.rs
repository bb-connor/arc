#[path = "client/auth.rs"]
mod auth;
#[path = "client/budget.rs"]
mod budget;
#[path = "client/cluster.rs"]
mod cluster;
#[path = "client/factory.rs"]
mod factory;
#[path = "client/operations.rs"]
mod operations;
#[path = "client/stop.rs"]
mod stop;
#[path = "client/transport.rs"]
mod transport;
#[path = "client/validation.rs"]
mod validation;

pub use factory::{build_client, build_public_client};

pub(crate) use factory::build_cluster_peer_client;
#[cfg(test)]
pub(crate) use validation::encode_path_segment;
pub(crate) use validation::{
    certification_marketplace_search_path, certification_marketplace_transparency_path,
    path_with_encoded_param, should_retry_status,
};

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "client/egress_tests.rs"]
mod egress_tests;
