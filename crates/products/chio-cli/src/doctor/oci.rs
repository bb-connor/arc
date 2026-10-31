//! OCI registry reachability probe.
//!
//! Resolves the configured guard registry endpoint and surfaces a
//! reachability report. The probe consumes `chio-guard-registry`
//! read-only: it reads the configured registry reference but never
//! duplicates the pull path.
//!
//! Test mode and `CHIO_DOCTOR_SKIP_NETWORK=1` short-circuit any actual
//! network reach, returning an info-level report instead. The probe is
//! warning-severity on reachability failures (not fatal) so a green
//! workspace can still pass the gate when a developer is offline.

use std::path::PathBuf;

use super::egress::{is_policy_refusal, probe_get, refusal_finding, REFUSAL_HELP};
use super::probe::{Probe, ProbeConfig, ProbeReport, ProbeSeverity};

const REGISTRY_ENV: &str = "CHIO_GUARD_REGISTRY";
const ALT_REGISTRY_ENV: &str = "CHIO_GUARD_REGISTRY_REFERENCE";

#[derive(Debug, Default, Clone)]
pub struct OciProbe {
    registry_override: Option<String>,
}

impl OciProbe {
    #[cfg(test)]
    #[must_use]
    pub fn with_registry(mut self, registry: impl Into<String>) -> Self {
        self.registry_override = Some(registry.into());
        self
    }

    fn resolve_registry(&self, config: &ProbeConfig) -> Option<String> {
        if let Some(reg) = &self.registry_override {
            return Some(reg.clone());
        }
        if let Ok(value) = std::env::var(REGISTRY_ENV) {
            if !value.is_empty() {
                return Some(value);
            }
        }
        if let Ok(value) = std::env::var(ALT_REGISTRY_ENV) {
            if !value.is_empty() {
                return Some(value);
            }
        }
        // Fall back to a chio.yaml `registry:` line in the workspace.
        let root = config
            .workdir
            .clone()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        let body = std::fs::read_to_string(root.join("chio.yaml")).ok()?;
        for line in body.lines() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("registry:") {
                let value = rest.trim().trim_matches('"').trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
        None
    }
}

impl Probe for OciProbe {
    fn name(&self) -> &'static str {
        "oci"
    }

    fn run(&self, config: &ProbeConfig) -> ProbeReport {
        let registry = match self.resolve_registry(config) {
            Some(r) => r,
            None => {
                return ProbeReport {
                    probe: self.name(),
                    severity: ProbeSeverity::Info,
                    code: "urn:chio:error:cli:other",
                    message: "No guard OCI registry configured. Skipping reachability probe."
                        .to_string(),
                    help: Some(
                        "Set CHIO_GUARD_REGISTRY or add a `registry:` line to chio.yaml \
                         to enable the OCI reachability probe."
                            .to_string(),
                    ),
                    context: Vec::new(),
                    repaired: false,
                };
            }
        };

        if config.skip_network || std::env::var("CHIO_DOCTOR_SKIP_NETWORK").is_ok() {
            return ProbeReport::ok(
                self.name(),
                format!("Registry endpoint {registry} resolved. Network probe skipped."),
            )
            .with_context("registry", registry);
        }

        // Best-effort reachability. Treat any failure as a warning, never a
        // hard error: the probe is read-only and a transient network blip
        // should not block CI.
        let url = if registry.starts_with("http") {
            registry.clone()
        } else {
            format!("https://{registry}/v2/")
        };
        match probe_get(&url) {
            Ok(response) => {
                let status = response.status();
                if (200..300).contains(&status) || status == 401 || status == 404 {
                    ProbeReport::ok(
                        self.name(),
                        format!("Registry {registry} reachable ({status})."),
                    )
                    .with_context("registry", registry)
                } else {
                    ProbeReport::fail(
                        self.name(),
                        ProbeSeverity::Warning,
                        "urn:chio:error:cli:doctor-oci-unreachable",
                        format!("Registry {registry} returned status {status}."),
                    )
                    .with_context("registry", registry)
                }
            }
            Err(err) if is_policy_refusal(&err) => ProbeReport::fail(
                self.name(),
                ProbeSeverity::Warning,
                "urn:chio:error:cli:doctor-oci-unreachable",
                format!("Registry {registry} {}", refusal_finding(&err)),
            )
            .with_help(REFUSAL_HELP)
            .with_context("registry", registry),
            Err(err) => ProbeReport::fail(
                self.name(),
                ProbeSeverity::Warning,
                "urn:chio:error:cli:doctor-oci-unreachable",
                format!("Registry {registry} unreachable: {err}"),
            )
            .with_context("registry", registry),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn no_registry_returns_info() {
        let probe = OciProbe::default();
        let config = ProbeConfig {
            skip_network: true,
            workdir: Some(tempfile::tempdir().unwrap().path().to_path_buf()),
            ..Default::default()
        };
        let report = probe.run(&config);
        assert_eq!(report.severity, ProbeSeverity::Info);
    }

    #[test]
    fn skip_network_returns_ok_when_registry_configured() {
        let probe = OciProbe::default().with_registry("ghcr.io/example/chio");
        let config = ProbeConfig {
            skip_network: true,
            ..Default::default()
        };
        let report = probe.run(&config);
        assert_eq!(report.severity, ProbeSeverity::Ok);
        assert_eq!(report.code, "urn:chio:error:cli:other");
        assert!(report
            .context
            .iter()
            .any(|ctx| ctx.key == "registry" && ctx.value == "ghcr.io/example/chio"));
    }

    #[test]
    fn redirect_to_another_authority_is_not_followed() {
        use super::super::egress::test_support::{redirect_to, serve};
        use std::sync::atomic::Ordering;
        let target =
            serve("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string());
        let origin = serve(redirect_to(&format!("http://127.0.0.1:{}/", target.port)));
        let probe = OciProbe::default().with_registry(format!("http://127.0.0.1:{}/", origin.port));
        let _ = probe.run(&ProbeConfig::default());
        assert_eq!(origin.hits.load(Ordering::SeqCst), 1);
        assert_eq!(target.hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn link_local_authority_is_refused_without_dialing() {
        let probe = OciProbe::default().with_registry("https://169.254.169.254/latest/meta-data");
        let report = probe.run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Warning);
        assert!(report.message.contains("link-local"), "{}", report.message);
    }
}
