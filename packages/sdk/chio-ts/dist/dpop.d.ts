/**
 * The schema identifier for DPoP proofs. Must match chio-kernel's DPOP_SCHEMA constant.
 */
export declare const DPOP_SCHEMA = "chio.dpop_proof.v1";
/**
 * The body of a DPoP proof. Field names use snake_case to match Rust/serde serialization.
 * Field order in canonical JSON is alphabetical (RFC 8785), which also matches serde's default.
 *
 * Fields (alphabetical order as they appear in canonical JSON):
 *   action_hash, agent_key, capability_id, issued_at, nonce, schema, tool_name, tool_server
 */
export interface DpopProofBody {
    action_hash: string;
    agent_key: string;
    capability_id: string;
    issued_at: number;
    nonce: string;
    schema: string;
    tool_name: string;
    tool_server: string;
}
/**
 * A signed DPoP proof. The signature is Ed25519 over the canonical JSON of the body.
 */
export interface DpopProof {
    body: DpopProofBody;
    signature: string;
}
/**
 * Parameters for signDpopProof.
 */
export interface SignDpopProofParams {
    capabilityId: string;
    toolServer: string;
    toolName: string;
    actionArgs: unknown;
    agentSeedHex: string;
    nonce?: string;
    issuedAt?: number;
}
/**
 * Sign a DPoP proof for an Chio tool invocation.
 *
 * The proof body is serialized as RFC 8785 canonical JSON before signing,
 * ensuring compatibility with chio-kernel's verify_dpop_proof.
 *
 * @throws DpopSignError if the agentSeedHex is invalid or signing fails.
 */
export declare function signDpopProof(params: SignDpopProofParams): DpopProof;
//# sourceMappingURL=dpop.d.ts.map