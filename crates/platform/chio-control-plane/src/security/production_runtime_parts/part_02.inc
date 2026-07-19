impl ProductionWatermarkSourceContextResolver {
    fn new(
        configured: &[ProductionWatermarkSourceContextConfig],
    ) -> Result<Self, BrokerIntegrationError> {
        if configured.is_empty() {
            return Err(invalid(
                "production watermark verification requires authoritative source-receipt contexts",
            ));
        }
        let mut contexts = BTreeMap::new();
        for entry in configured {
            if entry.issued_at_unix_ms == 0
                || entry.issued_at_unix_ms > MAX_IJSON_INTEGER
                || entry.not_after_unix_ms > MAX_IJSON_INTEGER
                || entry.not_after_unix_ms <= entry.issued_at_unix_ms
            {
                return Err(invalid(
                    "production watermark source-receipt context has an invalid time window",
                ));
            }
            let source_receipt_id =
                RecordId::new(entry.source_receipt_id.clone()).map_err(|error| {
                    invalid(format!("watermark source receipt id is invalid: {error}"))
                })?;
            let context = WatermarkSourceContext {
                tenant_id: TenantId::new(entry.tenant_id.clone()).map_err(|error| {
                    invalid(format!("watermark source tenant id is invalid: {error}"))
                })?,
                application_id: RecordId::new(entry.application_id.clone()).map_err(|error| {
                    invalid(format!("watermark application id is invalid: {error}"))
                })?,
                session_id: RecordId::new(entry.session_id.clone()).map_err(|error| {
                    invalid(format!("watermark session id is invalid: {error}"))
                })?,
                source_receipt_id: source_receipt_id.clone(),
                tool_id: RecordId::new(entry.tool_id.clone())
                    .map_err(|error| invalid(format!("watermark tool id is invalid: {error}")))?,
                issued_at_unix_ms: entry.issued_at_unix_ms,
                not_after_unix_ms: entry.not_after_unix_ms,
            };
            if contexts.insert(source_receipt_id, context).is_some() {
                return Err(invalid(
                    "production watermark source-receipt context set contains a duplicate receipt id",
                ));
            }
        }
        Ok(Self {
            contexts: Arc::new(contexts),
        })
    }
}

impl WatermarkSourceContextResolver for ProductionWatermarkSourceContextResolver {
    fn resolve(&self, source_receipt_id: &RecordId) -> PortResult<Option<WatermarkSourceContext>> {
        Ok(self.contexts.get(source_receipt_id).cloned())
    }
}

struct DurableFileAlertBackend {
    file: Arc<Mutex<File>>,
}

impl DurableFileAlertBackend {
    fn open(path: &Path) -> Result<Self, BrokerIntegrationError> {
        let mut options = OpenOptions::new();
        options.create(true).append(true).read(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(path)
            .map_err(|error| invalid(format!("security alert archive open failed: {error}")))?;
        let metadata = file
            .metadata()
            .map_err(|error| invalid(format!("security alert archive metadata failed: {error}")))?;
        if !metadata.is_file() {
            return Err(invalid("security alert archive is not a regular file"));
        }
        #[cfg(unix)]
        {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                |error| {
                    invalid(format!(
                        "security alert archive permission hardening failed: {error}"
                    ))
                },
            )?;
            let path_metadata = std::fs::symlink_metadata(path).map_err(|error| {
                invalid(format!(
                    "security alert archive path metadata failed: {error}"
                ))
            })?;
            if path_metadata.file_type().is_symlink()
                || path_metadata.dev() != metadata.dev()
                || path_metadata.ino() != metadata.ino()
            {
                return Err(invalid("security alert archive path identity is invalid"));
            }
        }
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    fn append(&self, alert: &Alert) -> Result<(), ExportError> {
        let mut bytes = canonical_json_bytes(&serde_json::json!({
            "dedupKey": &alert.dedup_key,
            "guard": &alert.guard,
            "receiptId": &alert.receipt_id,
            "receipt": &alert.receipt_json,
            "severity": alert.severity.as_tag(),
            "summary": &alert.summary,
            "toolName": &alert.tool_name,
            "toolServer": &alert.tool_server,
        }))
        .map_err(|error| ExportError::SerializationError(error.to_string()))?;
        bytes.push(b'\n');
        let mut file = self
            .file
            .lock()
            .map_err(|_| ExportError::HttpError("alert archive lock is unavailable".to_string()))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_data())
            .map_err(|error| ExportError::HttpError(error.to_string()))
    }
}

impl AlertBackend for DurableFileAlertBackend {
    fn name(&self) -> &str {
        "chio-durable-alert-archive"
    }

    fn dispatch<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ExportError>> + Send + 'a>>
    {
        Box::pin(async move { self.append(alert) })
    }
}

struct GovernedProductionResponsePolicy {
    runtime_policy_hash: String,
    policy_version: RecordId,
    approval_policy_id: RecordId,
    allowed_effects: BTreeSet<ResponseEffectKind>,
    automatic_ttl_ceiling_ms: u64,
    max_finding_age_ms: u64,
}

impl GovernedProductionResponsePolicy {
    fn validate_effects(
        &self,
        effects: impl IntoIterator<Item = ResponseEffectKind>,
    ) -> Result<(), ActiveResponsePolicyResolutionError> {
        if effects
            .into_iter()
            .all(|effect| self.allowed_effects.contains(&effect))
        {
            Ok(())
        } else {
            Err(ActiveResponsePolicyResolutionError::Invalid(
                "active response contains an effect outside the production allowlist".to_string(),
            ))
        }
    }

    fn classify_declared_requirement(
        &self,
        declared: &ResponseApprovalRequirement,
        ttl_ms: u64,
        effects: &[ResponseEffectKind],
    ) -> Result<ActiveResponseRequirement, ActiveResponsePolicyResolutionError> {
        if ttl_ms == 0 || effects.is_empty() {
            return Err(ActiveResponsePolicyResolutionError::Invalid(
                "active response TTL or effect set is outside the production bound".to_string(),
            ));
        }
        self.validate_effects(effects.iter().copied())?;
        match declared {
            ResponseApprovalRequirement::Automatic
                if ttl_ms <= self.automatic_ttl_ceiling_ms
                    && effects.iter().all(|effect| {
                        matches!(
                            effect,
                            ResponseEffectKind::ThrottleSession
                                | ResponseEffectKind::RestrictEgress
                        )
                    }) => Ok(ActiveResponseRequirement::automatic(
                self.runtime_policy_hash.clone(),
                self.policy_version.clone(),
                self.automatic_ttl_ceiling_ms,
                self.max_finding_age_ms,
            )),
            ResponseApprovalRequirement::Automatic
                if effects.iter().all(|effect| {
                    matches!(
                        effect,
                        ResponseEffectKind::ThrottleSession | ResponseEffectKind::RestrictEgress
                    )
                }) => Err(ActiveResponsePolicyResolutionError::Invalid(
                "automatic production response TTL exceeds the configured automatic ceiling"
                    .to_string(),
            )),
            ResponseApprovalRequirement::Automatic => {
                Err(ActiveResponsePolicyResolutionError::Invalid(
                    "automatic production response is limited to bounded session throttle and egress restriction"
                        .to_string(),
                ))
            }
            ResponseApprovalRequirement::Governed { policy_id }
                if policy_id == &self.approval_policy_id => {
                Ok(ActiveResponseRequirement::governed(
                    self.runtime_policy_hash.clone(),
                    self.policy_version.clone(),
                    self.approval_policy_id.clone(),
                    self.max_finding_age_ms,
                ))
            }
            ResponseApprovalRequirement::Governed { .. } => {
                Err(ActiveResponsePolicyResolutionError::Invalid(
                    "active response approval policy does not match production policy".to_string(),
                ))
            }
        }
    }
}

impl chio_kernel::ActiveResponseRequirementResolver for GovernedProductionResponsePolicy {
    fn resolve_active_response_requirement(
        &self,
        request: &ActiveResponsePolicyRequest,
        policy_hash: &str,
    ) -> Result<ActiveResponseRequirement, ActiveResponsePolicyResolutionError> {
        if policy_hash != self.runtime_policy_hash {
            return Err(ActiveResponsePolicyResolutionError::StalePolicy {
                expected: self.runtime_policy_hash.clone(),
                received: policy_hash.to_string(),
            });
        }
        if request.policy_version() != &self.policy_version {
            return Err(ActiveResponsePolicyResolutionError::Invalid(
                "active response does not match the production policy version".to_string(),
            ));
        }
        let effects = request
            .exact_effects()
            .iter()
            .map(|effect| effect.kind)
            .collect::<Vec<_>>();
        self.classify_declared_requirement(
            request.declared_approval_requirement(),
            request.ttl_ms(),
            &effects,
        )
    }
}

#[cfg(test)]
mod tests {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/security/production_runtime_parts/nested_01.inc"));
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/security/production_runtime_parts/nested_02.inc"));
}
