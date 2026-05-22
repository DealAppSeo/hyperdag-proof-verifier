export interface VerifyResult {
  verified: boolean;
  error: string | null;
  proof_size_bytes: number;
  verifier_version: string;
}

/**
 * Verify a HyperDAG STARK proof locally.
 * 
 * @param proofBytes - Base64 encoded proof bytes
 * @param statement - The public statement (agent_id, repid_score, threshold, tier)
 */
export function verify(proofBytes: string, statement: Record<string, any>): Promise<VerifyResult>;
