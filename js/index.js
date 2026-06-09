let verifier;

async function getVerifier() {
  if (verifier) return verifier;

  const isNode = typeof process !== 'undefined' && process.versions && process.versions.node;

  if (isNode) {
    // Node.js target
    verifier = await import('../pkg-node/hyperdag_proof_verifier.js');
  } else {
    // Browser/Bundler target - assumes WASM is bundled or served
    verifier = await import('../pkg/hyperdag_proof_verifier.js');
    await verifier.default(); // Initialize WASM
  }
  
  verifier.init_panic_hook();
  return verifier;
}

/**
 * Verify a HyperDAG STARK proof locally.
 * 
 * @param {string} proofBytes - Base64 encoded proof bytes
 * @param {object} statement - The public statement (agent_id, repid_score, threshold, tier)
 * @returns {Promise<object>} - { verified: boolean, error: string | null, proof_size_bytes: number, verifier_version: string }
 */
export async function verify(proofBytes, statement) {
  const v = await getVerifier();
  
  const input = {
    proof_bytes: proofBytes,
    statement: statement
  };
  
  const resultJson = v.verify_proof(JSON.stringify(input));
  return JSON.parse(resultJson);
}

/**
 * Freshness check (0.3.0): is a proof's bound epoch recent enough? Pure, deterministic — the caller
 * supplies the current AUTHORITATIVE epoch (block-height-derived), never the proof.
 * @param {number|bigint} proofEpoch  - statement.epoch from the proof
 * @param {number|bigint} currentEpoch - the current authoritative epoch
 * @param {number|bigint} window - max epochs old before STALE
 * @returns {Promise<boolean>}
 */
export async function epochFresh(proofEpoch, currentEpoch, window) {
  const v = await getVerifier();
  return v.epoch_fresh(BigInt(proofEpoch), BigInt(currentEpoch), BigInt(window));
}
