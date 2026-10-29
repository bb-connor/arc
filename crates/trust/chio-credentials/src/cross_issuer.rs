#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum CrossIssuerPortfolioEntryKind {
    Native,
    Imported,
    Migrated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CrossIssuerPortfolioEntry {
    pub entry_id: String,
    pub profile_family: String,
    pub source_kind: CrossIssuerPortfolioEntryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub passport: AgentPassport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<PassportLifecycleResolution>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certification_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CrossIssuerPortfolio {
    pub schema: String,
    pub portfolio_id: String,
    pub subject: String,
    pub entries: Vec<CrossIssuerPortfolioEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub migrations: Vec<SignedCrossIssuerMigration>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedCrossIssuerMigrationBody {
    pub schema: String,
    pub migration_id: String,
    pub attester: String,
    pub signer_public_key: PublicKey,
    pub from_issuer: String,
    pub to_issuer: String,
    pub from_subject: String,
    pub to_subject: String,
    pub prior_passport_ids: Vec<String>,
    pub reason: String,
    pub continuity_ref: String,
    pub issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedCrossIssuerMigration {
    pub body: SignedCrossIssuerMigrationBody,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSignedCrossIssuerMigrationArgs {
    pub migration_id: String,
    pub attester: String,
    pub from_issuer: String,
    pub to_issuer: String,
    pub from_subject: String,
    pub to_subject: String,
    pub prior_passport_ids: Vec<String>,
    pub reason: String,
    pub continuity_ref: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CrossIssuerPortfolioEntryVerification {
    pub entry_id: String,
    pub passport_id: String,
    pub subject: String,
    pub issuers: Vec<String>,
    pub issuer_count: usize,
    pub profile_family: String,
    pub source_kind: CrossIssuerPortfolioEntryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<PassportLifecycleState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CrossIssuerPortfolioVerification {
    pub schema: String,
    pub portfolio_id: String,
    pub subject: String,
    pub entry_count: usize,
    pub issuer_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<String>,
    pub migration_count: usize,
    pub verified_at: u64,
    pub entry_results: Vec<CrossIssuerPortfolioEntryVerification>,
}


pub fn create_signed_cross_issuer_migration(
    signer: &Keypair,
    args: CreateSignedCrossIssuerMigrationArgs,
) -> Result<SignedCrossIssuerMigration, CredentialError> {
    let CreateSignedCrossIssuerMigrationArgs {
        migration_id,
        attester,
        from_issuer,
        to_issuer,
        from_subject,
        to_subject,
        prior_passport_ids,
        reason,
        continuity_ref,
        issued_at,
        expires_at,
    } = args;
    let body = SignedCrossIssuerMigrationBody {
        schema: CROSS_ISSUER_MIGRATION_SCHEMA.to_string(),
        migration_id,
        attester,
        signer_public_key: signer.public_key(),
        from_issuer,
        to_issuer,
        from_subject,
        to_subject,
        prior_passport_ids,
        reason,
        continuity_ref,
        issued_at,
        expires_at,
    };
    verify_signed_cross_issuer_migration_body(&body)?;
    let signature =
        signer.sign_wrapped(CROSS_ISSUER_MIGRATION_SCHEMA, &chio_core::canonical::CanonicalBytes::from_serializable(&body)?)?;
    Ok(SignedCrossIssuerMigration { body, signature })
}

pub fn verify_signed_cross_issuer_migration(
    migration: &SignedCrossIssuerMigration,
    now: u64,
) -> Result<(), CredentialError> {
    verify_signed_cross_issuer_migration_body(&migration.body)?;
    if now < migration.body.issued_at {
        return Err(CredentialError::InvalidCrossIssuerMigration(format!(
            "cross-issuer migration `{}` is not yet valid",
            migration.body.migration_id
        )));
    }
    if let Some(expires_at) = migration.body.expires_at {
        if now > expires_at {
            return Err(CredentialError::InvalidCrossIssuerMigration(format!(
                "cross-issuer migration `{}` has expired",
                migration.body.migration_id
            )));
        }
    }
    let signed = chio_core::crypto::verify_wrapped(
        &migration.body.signer_public_key,
        CROSS_ISSUER_MIGRATION_SCHEMA,
        &migration.body,
        &migration.signature,
    )
    .is_ok();
    if !signed {
        return Err(CredentialError::InvalidCrossIssuerMigration(format!(
            "cross-issuer migration `{}` signature verification failed",
            migration.body.migration_id
        )));
    }
    Ok(())
}


pub fn verify_cross_issuer_portfolio(
    portfolio: &CrossIssuerPortfolio,
    trusted_issuers: &BTreeSet<String>,
    now: u64,
) -> Result<CrossIssuerPortfolioVerification, CredentialError> {
    if portfolio.schema != CROSS_ISSUER_PORTFOLIO_SCHEMA {
        return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
            "cross-issuer portfolio schema must be {CROSS_ISSUER_PORTFOLIO_SCHEMA}"
        )));
    }
    if portfolio.portfolio_id.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerPortfolio(
            "cross-issuer portfolios must include a non-empty portfolio_id".to_string(),
        ));
    }
    DidChio::from_str(&portfolio.subject)?;
    if portfolio.entries.is_empty() {
        return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
            "cross-issuer portfolio `{}` must include at least one entry",
            portfolio.portfolio_id
        )));
    }

    let migration_map = portfolio
        .migrations
        .iter()
        .map(|migration| {
            verify_signed_cross_issuer_migration(migration, now)?;
            Ok((migration.body.migration_id.clone(), migration.body.clone()))
        })
        .collect::<Result<BTreeMap<_, _>, CredentialError>>()?;
    if migration_map.len() != portfolio.migrations.len() {
        return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
            "cross-issuer portfolio `{}` contains duplicate migration ids",
            portfolio.portfolio_id
        )));
    }

    let mut seen_entry_ids = BTreeSet::new();
    let mut seen_passport_ids = BTreeSet::new();
    let mut issuers = BTreeSet::new();
    let mut entry_results = Vec::with_capacity(portfolio.entries.len());
    for entry in &portfolio.entries {
        validate_cross_issuer_portfolio_entry(entry)?;
        if !seen_entry_ids.insert(entry.entry_id.clone()) {
            return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                "cross-issuer portfolio `{}` contains duplicate entry_id `{}`",
                portfolio.portfolio_id, entry.entry_id
            )));
        }
        let verification = verify_agent_passport(&entry.passport, trusted_issuers, now)?;
        let passport_id = verification.passport_id.clone();
        if !seen_passport_ids.insert(passport_id.clone()) {
            return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                "cross-issuer portfolio `{}` contains duplicate passport `{}`",
                portfolio.portfolio_id, passport_id
            )));
        }
        if let Some(lifecycle) = &entry.lifecycle {
            lifecycle.validate()?;
            if lifecycle.passport_id != passport_id {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` lifecycle passport_id does not match embedded passport",
                    entry.entry_id
                )));
            }
            if lifecycle.subject != verification.subject {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` lifecycle subject does not match embedded passport",
                    entry.entry_id
                )));
            }
            if lifecycle.issuers != verification.issuers {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` lifecycle issuers do not match embedded passport",
                    entry.entry_id
                )));
            }
        }

        if let Some(migration_id) = &entry.migration_id {
            let migration = migration_map.get(migration_id).ok_or_else(|| {
                CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` references unknown migration `{migration_id}`",
                    entry.entry_id
                ))
            })?;
            if migration.from_subject != verification.subject {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` migration `{migration_id}` does not match entry subject",
                    entry.entry_id
                )));
            }
            if migration.to_subject != portfolio.subject {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` migration `{migration_id}` does not target the portfolio subject",
                    entry.entry_id
                )));
            }
            if !verification.issuers.contains(&migration.from_issuer) {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` migration `{migration_id}` does not match an embedded issuer",
                    entry.entry_id
                )));
            }
            if !migration.prior_passport_ids.contains(&passport_id) {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` migration `{migration_id}` does not reference the embedded passport",
                    entry.entry_id
                )));
            }
        }

        issuers.extend(verification.issuers.iter().cloned());
        entry_results.push(CrossIssuerPortfolioEntryVerification {
            entry_id: entry.entry_id.clone(),
            passport_id,
            subject: verification.subject,
            issuers: verification.issuers,
            issuer_count: verification.issuer_count,
            profile_family: entry.profile_family.clone(),
            source_kind: entry.source_kind,
            source: entry.source.clone(),
            migration_id: entry.migration_id.clone(),
            lifecycle_state: entry.lifecycle.as_ref().map(|lifecycle| lifecycle.state),
        });
    }

    Ok(CrossIssuerPortfolioVerification {
        schema: CROSS_ISSUER_PORTFOLIO_SCHEMA.to_string(),
        portfolio_id: portfolio.portfolio_id.clone(),
        subject: portfolio.subject.clone(),
        entry_count: entry_results.len(),
        issuer_count: issuers.len(),
        issuers: issuers.into_iter().collect(),
        migration_count: portfolio.migrations.len(),
        verified_at: now,
        entry_results,
    })
}

fn validate_cross_issuer_portfolio_entry(
    entry: &CrossIssuerPortfolioEntry,
) -> Result<(), CredentialError> {
    if entry.entry_id.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerPortfolio(
            "cross-issuer portfolio entries must include a non-empty entry_id".to_string(),
        ));
    }
    if entry.profile_family.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
            "portfolio entry `{}` must include a non-empty profile_family",
            entry.entry_id
        )));
    }
    if let Some(source) = &entry.source {
        if source.trim().is_empty() {
            return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                "portfolio entry `{}` cannot include an empty source",
                entry.entry_id
            )));
        }
    }
    if let Some(migration_id) = &entry.migration_id {
        if migration_id.trim().is_empty() {
            return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                "portfolio entry `{}` cannot include an empty migration_id",
                entry.entry_id
            )));
        }
    }
    match entry.source_kind {
        CrossIssuerPortfolioEntryKind::Native => {
            if entry.migration_id.is_some() {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "native portfolio entry `{}` cannot include a migration_id",
                    entry.entry_id
                )));
            }
        }
        CrossIssuerPortfolioEntryKind::Imported => {
            if entry.source.is_none() {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "imported portfolio entry `{}` must include a source",
                    entry.entry_id
                )));
            }
            if entry.migration_id.is_some() {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "imported portfolio entry `{}` cannot include a migration_id unless it is marked migrated",
                    entry.entry_id
                )));
            }
        }
        CrossIssuerPortfolioEntryKind::Migrated => {
            if entry.source.is_none() {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "migrated portfolio entry `{}` must include a source",
                    entry.entry_id
                )));
            }
            if entry.migration_id.is_none() {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "migrated portfolio entry `{}` must include a migration_id",
                    entry.entry_id
                )));
            }
        }
    }
    if let Some(lifecycle) = &entry.lifecycle {
        lifecycle.validate()?;
    }
    validate_sorted_unique_strings(
        &entry.certification_refs,
        "certification_refs",
        &entry.entry_id,
        CredentialError::InvalidCrossIssuerPortfolio,
    )
}

fn verify_signed_cross_issuer_migration_body(
    body: &SignedCrossIssuerMigrationBody,
) -> Result<(), CredentialError> {
    if body.schema != CROSS_ISSUER_MIGRATION_SCHEMA {
        return Err(CredentialError::InvalidCrossIssuerMigration(format!(
            "cross-issuer migration schema must be {CROSS_ISSUER_MIGRATION_SCHEMA}"
        )));
    }
    if body.migration_id.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerMigration(
            "cross-issuer migrations must include a non-empty migration_id".to_string(),
        ));
    }
    if body.attester.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerMigration(format!(
            "cross-issuer migration `{}` must include a non-empty attester",
            body.migration_id
        )));
    }
    DidChio::from_str(&body.from_issuer)?;
    DidChio::from_str(&body.to_issuer)?;
    DidChio::from_str(&body.from_subject)?;
    DidChio::from_str(&body.to_subject)?;
    if body.reason.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerMigration(format!(
            "cross-issuer migration `{}` must include a non-empty reason",
            body.migration_id
        )));
    }
    if body.continuity_ref.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerMigration(format!(
            "cross-issuer migration `{}` must include a non-empty continuity_ref",
            body.migration_id
        )));
    }
    if body.prior_passport_ids.is_empty() {
        return Err(CredentialError::InvalidCrossIssuerMigration(format!(
            "cross-issuer migration `{}` must reference at least one prior passport",
            body.migration_id
        )));
    }
    validate_sorted_unique_strings(
        &body.prior_passport_ids,
        "prior_passport_ids",
        &body.migration_id,
        CredentialError::InvalidCrossIssuerMigration,
    )?;
    if let Some(expires_at) = body.expires_at {
        if body.issued_at > expires_at {
            return Err(CredentialError::InvalidCrossIssuerMigration(format!(
                "cross-issuer migration `{}` must not expire before it is issued",
                body.migration_id
            )));
        }
    }
    Ok(())
}


fn validate_sorted_unique_strings(
    values: &[String],
    field: &str,
    id: &str,
    error: fn(String) -> CredentialError,
) -> Result<(), CredentialError> {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted != values {
        return Err(error(format!(
            "`{field}` for `{id}` must be stored in sorted unique order"
        )));
    }
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(error(format!(
            "`{field}` for `{id}` cannot contain empty values"
        )));
    }
    Ok(())
}
