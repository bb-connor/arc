//! Build fixture admission evidence after durable collateral acceptance.
use super::*;

impl MarketWeb {
    pub(super) async fn refresh_admission_evidence(
        &mut self,
        state: &TrustServiceState,
    ) -> TestResult {
        let authority = state
            .joint_authority_store
            .as_ref()
            .ok_or_else(|| missing("joint authority store before report"))?;
        let allocation = authority
            .finding_market_store()
            .get_allocation(&self.allocation_id)?
            .ok_or_else(|| missing("accepted allocation before report"))?;
        // Admission requires observation strictly after acceptance at second
        // granularity. Wait for that retained boundary, not a setup-time guess.
        let first_observation = allocation
            .accepted_at
            .checked_add(1)
            .ok_or_else(|| missing("allocation observation time overflow"))?;
        wait_until_unix(first_observation).await;
        let evaluated_at = state.finding_challenge_clock.unix_millis()?.as_secs();
        // Collateral has now been durably accepted. Evaluate the real evidence
        // at this observation and bind the resulting report into a fresh admission.
        self.report = make_signed_report(
            &ReportInputs {
                governance: &keypair(1),
                kernel: &keypair(21),
                profile: &self.profile,
                finding: &self.finding,
                raw_finding: &self.raw_finding,
                receipts: &self.receipts,
                checkpoint: &self.checkpoint,
                recipe_bytes: &self.recipe_bytes,
                backing: &self.backing,
                terms: &self.terms,
                fee_schedule: &self.schedule,
                collateral: &keypair(4),
            },
            evaluated_at,
        )?;
        let mut admission = self.admission.body.clone();
        admission.verifier_report_id = self.report.body.report_id.clone();
        admission.verifier_report_envelope_sha256 = digest_of(&self.report)?;
        admission.admission_id = compute_admission_id(&admission)?;
        self.admission = SignedExportEnvelope::sign(admission, &self.venue)?;
        self.admission_json = canonical_string(&self.admission)?;
        self.admission_sha256 = sha256_hex(self.admission_json.as_bytes());
        Ok(())
    }
}
