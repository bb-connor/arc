use std::error::Error;

use chio_egress_contract::HttpEgressError;

use super::factory::build_client;
use crate::CliError;

const TOKEN: &str = "egress-regression-token";

fn egress_refusal(error: &CliError) -> Option<HttpEgressError> {
    let mut current: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(cause) = current {
        if let Some(refusal) = cause.downcast_ref::<HttpEgressError>() {
            return Some(refusal.clone());
        }
        current = cause.source();
    }
    None
}

fn refused(control_url: &str) -> HttpEgressError {
    let Err(error) = build_client(control_url, TOKEN) else {
        panic!("control endpoint {control_url} must be refused");
    };
    egress_refusal(&error).unwrap_or_else(|| panic!("untyped refusal for {control_url}: {error}"))
}

#[test]
fn link_local_control_endpoint_is_refused_at_construction() {
    assert_eq!(
        refused("https://169.254.169.254"),
        HttpEgressError::LinkLocalDenied {
            host: "169.254.169.254".to_string()
        }
    );
    assert_eq!(
        refused("https://[fe80::1]:8443"),
        HttpEgressError::LinkLocalDenied {
            host: "fe80::1".to_string()
        }
    );
    assert_eq!(
        refused("https://control.example,https://169.254.169.254:9443"),
        HttpEgressError::LinkLocalDenied {
            host: "169.254.169.254".to_string()
        }
    );
}

#[test]
fn unlisted_private_control_endpoint_is_refused() {
    assert_eq!(
        refused("https://10.20.0.5:8443"),
        HttpEgressError::PrivateNetworkDenied {
            host: "10.20.0.5".to_string()
        }
    );
}
