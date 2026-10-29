//! Replay case shapes and the signed replay evidence they build.

use super::*;

/// Knobs for the reproduction set as a whole.
pub struct ReplayShape {
    pub phases: Vec<PhaseShape>,
    /// Replace the carried recipe preimage with different canonical bytes.
    pub recipe_preimage: Option<String>,
    /// Sign the reproduction receipts with a key outside the replay role.
    pub signer: Option<u8>,
    /// Break the receipt-to-observation digest commitment.
    pub break_content_commitment: bool,
    /// Sign a receipt whose action hash contradicts its own parameters.
    pub break_action_commitment: bool,
    /// Substitute the signed receipt's mediated server.
    pub receipt_tool_server: Option<String>,
    /// Substitute the signed receipt's mediated tool.
    pub receipt_tool_name: Option<String>,
    /// Substitute a self-consistent but uncommitted invocation body.
    pub action_parameters: Option<serde_json::Value>,
    /// Report an environment other than the one the recipe committed.
    pub environment_digest: Option<String>,
    /// Decision carried by each replay receipt.
    pub decision: Decision,
}

impl Default for ReplayShape {
    fn default() -> Self {
        Self {
            phases: vec![PhaseShape::baseline_fails(), PhaseShape::candidate_passes()],
            recipe_preimage: None,
            signer: None,
            break_content_commitment: false,
            break_action_commitment: false,
            receipt_tool_server: None,
            receipt_tool_name: None,
            action_parameters: None,
            environment_digest: None,
            decision: Decision::Allow,
        }
    }
}

pub struct ReplayCase {
    pub challenge: SignedFindingChallenge,
    pub purchase_record: SignedFindingPurchaseRecord,
    pub purchase_standing: PurchaseStandingProof,
    pub replay_authority_status: SignedFindingAuthorityStatus,
    pub receipts: Vec<ResolvedReceiptEvidence>,
    pub checkpoint: KernelCheckpoint,
    pub checkpoint_transparency: CheckpointTransparencySummary,
}

impl ReplayCase {
    pub fn reproductions(&self) -> Vec<FindingResolvedReproduction<'_>> {
        self.receipts
            .iter()
            .map(|receipt| FindingResolvedReproduction {
                receipt,
                checkpoint: &self.checkpoint,
                checkpoint_transparency: &self.checkpoint_transparency,
            })
            .collect()
    }

    pub fn evidence<'a>(
        &'a self,
        reproductions: &'a [FindingResolvedReproduction<'a>],
    ) -> FindingChallengeClassEvidence<'a> {
        FindingChallengeClassEvidence::ReplayContradiction(FindingReplayContradictionEvidence {
            purchase_standing: FindingPurchaseStandingEvidence {
                purchase_record: &self.purchase_record,
                bid_request: &self.purchase_standing.bid_request,
                accepted_bid: &self.purchase_standing.accepted_bid,
                reservation_receipt: &self.purchase_standing.reservation_receipt,
                delivery_receipt: &self.purchase_standing.delivery_receipt,
                delivery_checkpoint: &self.purchase_standing.delivery_checkpoint,
                delivery_checkpoint_transparency: &self
                    .purchase_standing
                    .delivery_checkpoint_transparency,
                delivery_authority_status: &self.purchase_standing.delivery_authority_status,
            },
            replay_authority_status: &self.replay_authority_status,
            reproductions,
        })
    }
}

pub fn replay_case(world: &World, shape: &ReplayShape) -> Built<ReplayCase> {
    let (purchase_record, purchase_standing) =
        world.purchase_standing_shaped(StandingShape::Sound)?;
    let purchase_record_envelope_sha256 = signed_envelope_sha256(&purchase_record)?;
    let recipe_preimage = shape
        .recipe_preimage
        .clone()
        .unwrap_or_else(|| world.recipe_preimage.clone());
    let recipe_digest = sha256_hex(recipe_preimage.as_bytes());

    let kernel = match shape.signer {
        Some(seed) => keypair(seed),
        None => world.replay_kernel.clone(),
    };
    // The digest a run reports for its environment is the digest of the
    // environment the recipe committed, derived the same way the consumer
    // derives it.
    let environment_digest = match &shape.environment_digest {
        Some(digest) => digest.clone(),
        None => committed_environment_digest(&world.recipe)?,
    };

    let mut observation_texts = Vec::with_capacity(shape.phases.len());
    let mut receipts = Vec::with_capacity(shape.phases.len());
    let mut leaves = Vec::with_capacity(shape.phases.len());
    for (index, phase) in shape.phases.iter().enumerate() {
        let observation = FindingReplayObservation {
            schema: FINDING_REPLAY_OBSERVATION_SCHEMA_V1.to_string(),
            recipe_digest: recipe_digest.clone(),
            verifier_profile_digest: world.profile_envelope_sha256.clone(),
            phase_id: phase.phase,
            runner_manifest_digest: HEX64.to_string(),
            resolved_input_bundle_digest: match phase.phase {
                FindingRecipePhaseKind::Baseline => HEX64.to_string(),
                FindingRecipePhaseKind::Candidate => HEX64_ALT.to_string(),
            },
            environment_digest: environment_digest.clone(),
            terminal_result: phase.terminal,
            exit_code: phase.exit_code,
            report_digest: match phase.phase {
                FindingRecipePhaseKind::Baseline => HEX64.to_string(),
                FindingRecipePhaseKind::Candidate => HEX64_ALT.to_string(),
            },
            replay_run_id: REPLAY_RUN_ID.to_string(),
        };
        let text = canonical_json_string(&observation)?;
        let content_hash = if shape.break_content_commitment {
            HEX64_THIRD.to_string()
        } else {
            sha256_hex(text.as_bytes())
        };
        let phase_recipe = world
            .recipe
            .phases
            .iter()
            .find(|recipe_phase| recipe_phase.phase == phase.phase)
            .ok_or("replay shape contains an uncommitted phase")?;
        let action_parameters = shape.action_parameters.clone().unwrap_or_else(|| {
            serde_json::json!({
                "input_bundle_sha256": phase_recipe.input_bundle_sha256,
                "parameters_sha256": world.recipe.parameters_sha256,
                "phase": phase_recipe.phase,
                "pre_run_template_sha256": world.recipe.pre_run_template_sha256,
                "recipe_sha256": recipe_digest,
                "replay_run_id": REPLAY_RUN_ID,
                "runner_manifest_sha256": world.recipe.runner_manifest_sha256,
                "verifier_profile_envelope_sha256": world.recipe.verifier_profile_envelope_sha256,
            })
        });
        let mut action = ToolCallAction::from_parameters(action_parameters)?;
        if shape.break_action_commitment {
            action.parameter_hash = HEX64_THIRD.to_string();
        }
        let receipt = signed_receipt_for_server(
            &kernel,
            1_746_000_000 + index as u64,
            shape
                .receipt_tool_server
                .as_deref()
                .unwrap_or(&world.recipe.runner_server),
            shape
                .receipt_tool_name
                .as_deref()
                .unwrap_or(&world.recipe.runner_tool),
            action,
            shape.decision.clone(),
            &content_hash,
            None,
        )?;
        leaves.push(canonical_json_bytes(&receipt)?);
        receipts.push(receipt);
        observation_texts.push(text);
    }
    let checkpoint = build_checkpoint(
        1,
        1,
        receipts.len() as u64,
        &leaves,
        &world.replay_checkpoint,
    )?;
    let checkpoint_ref = checkpoint_reference(&checkpoint)?;
    let mut resolved = Vec::with_capacity(receipts.len());
    for (index, receipt) in receipts.into_iter().enumerate() {
        resolved.push(resolve(receipt, &leaves, index, 1, 1 + index as u64)?);
    }

    let reproduction: Vec<FindingReplayReproduction> = resolved
        .iter()
        .zip(&observation_texts)
        .map(|(receipt, text)| FindingReplayReproduction {
            receipt_ref: receipt_reference(receipt),
            checkpoint_ref: checkpoint_ref.clone(),
            observation_bytes: text.clone(),
        })
        .collect();

    let evidence = FindingChallengeEvidence::ReplayContradiction {
        reproduction,
        recipe_preimage,
        purchase_record_envelope_sha256: purchase_record_envelope_sha256.clone(),
    };
    let authorization = world.buyer_authorization(FindingChallengeStanding::FinalizedPurchase {
        purchase_key: purchase_record.body.purchase_key.clone(),
        purchase_record_envelope_sha256,
    });
    let affected = vec![world.affected_delivery(&receipt_reference(&world.evidence_receipts[0]))];
    let challenge = world.sign_challenge(authorization, evidence, affected)?;

    let replay_policy = world
        .profile
        .body
        .receipt_signers
        .iter()
        .find(|signer| signer.role == FindingReceiptRole::Replay)
        .ok_or("missing replay role policy")?;
    let replay_authority_status =
        signed_authority_status(&replay_policy.policy, &world.authority_status, None)?;

    let checkpoint_transparency = build_checkpoint_transparency(
        core::slice::from_ref(&checkpoint),
        std::slice::from_ref(&checkpoint.body.kernel_key),
    )?;
    Ok(ReplayCase {
        challenge,
        purchase_record,
        purchase_standing,
        replay_authority_status,
        receipts: resolved,
        checkpoint,
        checkpoint_transparency,
    })
}
