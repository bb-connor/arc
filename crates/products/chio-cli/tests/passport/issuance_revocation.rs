use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use chio_control_plane::passport_revocation::passport_revocation_oracle_path;
use chio_control_plane::CliError;
use chio_core::crypto::Keypair;
use chio_revocation_oracle::{passport_revocation_key, SqliteRevocationOracle};

use super::{
    current_unix_secs, publish_passport_status, unique_path, workspace_root,
    write_passport_artifact,
};

const ISSUER_URL: &str = "https://trust.example.com";

/// A locally published active passport with an issued offer whose
/// pre-authorized code has been redeemed for an access token.
struct LocalIssuance {
    passport: PathBuf,
    statuses: PathBuf,
    offers: PathBuf,
    offer: PathBuf,
    token: PathBuf,
    passport_id: String,
    now: u64,
}

fn chio(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args(args)
        .output()
        .expect("run chio")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_refused(output: &Output, message: &str) {
    assert!(
        !output.status.success(),
        "stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report = CliError::policy_error(message).report();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.lines().next(),
        Some(format!("error [{}]: {}", report.code, report.message).as_str()),
        "{stderr}"
    );
}

fn path(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

impl LocalIssuance {
    fn prepare(label: &str) -> Self {
        let now = current_unix_secs();
        let passport = unique_path(&format!("{label}-passport"), ".json");
        let issuance = Self {
            statuses: unique_path(&format!("{label}-statuses"), ".json"),
            offers: unique_path(&format!("{label}-offers"), ".json"),
            offer: unique_path(&format!("{label}-offer"), ".json"),
            token: unique_path(&format!("{label}-token"), ".json"),
            passport_id: String::new(),
            passport,
            now,
        };
        write_passport_artifact(
            &issuance.passport,
            &Keypair::generate(),
            &Keypair::generate(),
            now.saturating_sub(60),
            now.saturating_add(3_600),
            label,
        );
        let published = publish_passport_status(&issuance.passport, &issuance.statuses);
        let passport_id = published["passportId"]
            .as_str()
            .expect("passport id")
            .to_string();
        let issuance = Self {
            passport_id,
            ..issuance
        };
        assert_success(&issuance.issue_offer(&issuance.offer));
        assert_success(&chio(&[
            "passport",
            "issuance",
            "token",
            "--offer",
            path(&issuance.offer),
            "--output",
            path(&issuance.token),
            "--passport-issuance-offers-file",
            path(&issuance.offers),
        ]));
        issuance
    }

    fn issue_offer(&self, output: &Path) -> Output {
        chio(&[
            "passport",
            "issuance",
            "offer",
            "--input",
            path(&self.passport),
            "--output",
            path(output),
            "--issuer-url",
            ISSUER_URL,
            "--passport-issuance-offers-file",
            path(&self.offers),
            "--passport-statuses-file",
            path(&self.statuses),
            "--ttl-secs",
            "300",
        ])
    }

    fn redeem_credential(&self) -> Output {
        chio(&[
            "passport",
            "issuance",
            "credential",
            "--offer",
            path(&self.offer),
            "--token",
            path(&self.token),
            "--passport-issuance-offers-file",
            path(&self.offers),
            "--passport-statuses-file",
            path(&self.statuses),
        ])
    }

    fn oracle(&self) -> PathBuf {
        passport_revocation_oracle_path(&self.statuses).expect("passport revocation oracle path")
    }

    fn assert_registry_active(&self) {
        let resolved = chio(&[
            "--json",
            "passport",
            "status",
            "get",
            "--passport-id",
            &self.passport_id,
            "--passport-statuses-file",
            path(&self.statuses),
        ]);
        assert_success(&resolved);
        let record: serde_json::Value =
            serde_json::from_slice(&resolved.stdout).expect("parse passport status");
        assert_eq!(record["status"], "active");
    }
}

#[test]
fn local_issuance_refuses_a_passport_revoked_only_in_the_oracle() {
    let issuance = LocalIssuance::prepare("issuance-oracle-revoked");
    SqliteRevocationOracle::open(&issuance.oracle())
        .expect("open passport revocation oracle")
        .revoke(
            passport_revocation_key(&issuance.passport_id),
            issuance.now * 1_000,
        )
        .expect("revoke passport in the oracle");
    issuance.assert_registry_active();
    let refusal = format!(
        "passport `{}` is revoked in the passport revocation oracle",
        issuance.passport_id
    );

    let before = std::fs::read(&issuance.offers).expect("read offers registry");
    assert_refused(&issuance.redeem_credential(), &refusal);
    let second_offer = unique_path("issuance-oracle-revoked-second-offer", ".json");
    assert_refused(&issuance.issue_offer(&second_offer), &refusal);
    assert_eq!(
        std::fs::read(&issuance.offers).expect("read offers registry"),
        before
    );
    assert!(!second_offer.exists());
}

#[test]
fn local_issuance_refuses_when_the_passport_revocation_oracle_is_unreadable() {
    let issuance = LocalIssuance::prepare("issuance-oracle-unreadable");
    std::fs::remove_file(issuance.oracle()).expect("remove the passport revocation oracle");
    std::fs::create_dir(issuance.oracle()).expect("block the oracle path");
    let unavailable = SqliteRevocationOracle::open(&issuance.oracle())
        .err()
        .expect("a directory opened as the passport revocation oracle");
    let refusal = format!("passport revocation oracle unavailable: {unavailable}");

    let before = std::fs::read(&issuance.offers).expect("read offers registry");
    assert_refused(&issuance.redeem_credential(), &refusal);
    let second_offer = unique_path("issuance-oracle-unreadable-second-offer", ".json");
    assert_refused(&issuance.issue_offer(&second_offer), &refusal);
    assert_eq!(
        std::fs::read(&issuance.offers).expect("read offers registry"),
        before
    );
    issuance.assert_registry_active();
}
