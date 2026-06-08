use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::BabyBear;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::FriParameters as FriConfig;
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_monty_31::dft::RecursiveDft;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{verify, StarkConfig, Proof};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_air::WindowAccess;
use base64::Engine;
use sha2::{Digest, Sha256};

// --- AIR Definition (MUST mirror zkp-postcard/src/circuit.rs byte-for-byte) ---
//
// Agent-bound statement (A1): the proof's public values are the canonical tuple
//   [0..16] agent_id (16 bytes) | [16] threshold | [17] repid_score  (18 BabyBear elems)
// The verifier rebuilds these public values from the supplied Statement and passes them to
// p3_uni_stark::verify, which observes them into the Fiat-Shamir transcript. A proof made
// for agent A therefore FAILS under agent B (replay defense), and the boundary constraint
// reconstructed == repid_score - threshold - 1 ties the range check to the claimed score.

/// Canonical public-input layout — keep in lockstep with the prover (CANON P-026).
pub const NUM_PUBLIC_VALUES: usize = 18;
const PUB_THRESHOLD: usize = 16;
const PUB_REPID: usize = 17;

pub struct RepIdRangeCheckAir {
    pub value: u32,
}

impl<F: Field> BaseAir<F> for RepIdRangeCheckAir {
    fn width(&self) -> usize {
        32
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for RepIdRangeCheckAir where AB::F: Field {
    fn eval(&self, builder: &mut AB) {
        let pis = builder.public_values();
        let threshold = pis[PUB_THRESHOLD];
        let repid = pis[PUB_REPID];

        let main = builder.main();
        let row = main.current_slice();

        // MSB must be zero (value < 2^31)
        builder.assert_eq(row[0], AB::Expr::ZERO);

        // BabyBear modulus guard
        let upper_product = row[1..5]
            .iter()
            .map(|&bit: &AB::Var| bit.into())
            .product::<AB::Expr>();
        let remaining_sum = row[5..32]
            .iter()
            .map(|&bit: &AB::Var| bit.into())
            .sum::<AB::Expr>();
        builder.when(upper_product).assert_zero(remaining_sum);

        // Reconstruct the gap from its 32 bits; assert each bit is boolean.
        let mut reconstructed = AB::Expr::ZERO;
        for i in 0..32 {
            let bit = row[i];
            builder.assert_bool(bit);
            reconstructed += AB::Expr::from_u32(1 << (31 - i)) * bit;
        }

        // value-binding: the range-checked gap == repid_score - threshold - 1 (public).
        builder
            .when_first_row()
            .assert_eq(reconstructed, repid.into() - threshold.into() - AB::Expr::ONE);
    }
}

/// Map an agent identifier to 16 bytes (MUST match the prover's agent_id_to_16_bytes).
fn agent_id_to_16_bytes(agent_id: &str) -> [u8; 16] {
    let cleaned: String = agent_id.chars().filter(|c| *c != '-').collect();
    if cleaned.len() == 32 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(&cleaned) {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            return arr;
        }
    }
    let digest = Sha256::digest(agent_id.as_bytes());
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&digest[..16]);
    arr
}

/// Build the canonical 18-element public-values vector (MUST match the prover).
fn build_public_values(
    agent_id: &str,
    threshold: u64,
    repid_score: u64,
) -> Result<Vec<BabyBear>, String> {
    if threshold >= (1u64 << 31) || repid_score >= (1u64 << 31) {
        return Err("threshold/repid_score must be < 2^31".to_string());
    }
    let mut pv = Vec::with_capacity(NUM_PUBLIC_VALUES);
    for b in agent_id_to_16_bytes(agent_id) {
        pv.push(BabyBear::new(b as u32));
    }
    pv.push(BabyBear::new(threshold as u32));
    pv.push(BabyBear::new(repid_score as u32));
    Ok(pv)
}

// --- WASM Interface ---

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Statement {
    pub agent_id: String,
    pub repid_score: u64,
    pub threshold: u64,
    pub tier: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyInput {
    pub proof_bytes: String,
    pub statement: Statement,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResult {
    pub verified: bool,
    pub error: Option<String>,
    pub proof_size_bytes: usize,
    pub verifier_version: String,
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn verify_proof(input_json: &str) -> String {
    let input: VerifyInput = match serde_json::from_str(input_json) {
        Ok(v) => v,
        Err(e) => return result_to_json(false, Some(format!("input parse error: {e}")), 0),
    };

    let proof_bytes = match decode_proof_bytes(&input.proof_bytes) {
        Ok(b) => b,
        Err(e) => return result_to_json(false, Some(format!("proof decode error: {e}")), 0),
    };
    let size = proof_bytes.len();

    match inner_verify(&proof_bytes, &input.statement) {
        Ok(()) => result_to_json(true, None, size),
        Err(e) => result_to_json(false, Some(format!("verify failed: {e}")), size),
    }
}

fn decode_proof_bytes(s: &str) -> Result<Vec<u8>, String> {
    // zkp-postcard uses base64 for ProofResponse.proof_bytes
    base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| e.to_string())
}

fn inner_verify(proof_bytes: &[u8], statement: &Statement) -> Result<(), String> {
    type Val = BabyBear;
    type Challenge = BinomialExtensionField<Val, 4>;
    type ByteHash = Keccak256Hash;
    type FieldHash = SerializingHasher<ByteHash>;
    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 2, 32>;
    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    type Dft = RecursiveDft<Val>;
    type Pcs = p3_fri::TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    type MyChallenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
    type SC = StarkConfig<Pcs, Challenge, MyChallenger>;

    // 1. Claim sanity + reconstruct the gap the prover used.
    if statement.repid_score <= statement.threshold {
        return Err("Statement claim (score <= threshold) is invalid for proof".to_string());
    }
    let diff = (statement.repid_score - statement.threshold - 1) as u32;
    let air = RepIdRangeCheckAir { value: diff };

    // 2. Build the public values from the claimed statement {agent_id, threshold, repid_score}.
    let public_values = build_public_values(
        &statement.agent_id,
        statement.threshold,
        statement.repid_score,
    )?;

    // 3. Build the StarkConfig components (MUST match the prover exactly).
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(ByteHash {});
    let compress = MyCompress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_config = FriConfig {
        log_blowup: 2,
        num_queries: 28,
        log_final_poly_len: 0,
        max_log_arity: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };

    let dft = Dft::new(1 << fri_config.log_blowup);
    let pcs = Pcs::new(dft, val_mmcs, fri_config);
    let challenger = MyChallenger::new(HashChallenger::<u8, ByteHash, 32>::new(vec![], byte_hash.clone()));
    let config = SC::new(pcs, challenger);

    // 4. Deserialize the proof.
    let proof: Proof<SC> = bincode::deserialize(proof_bytes)
        .map_err(|e| format!("deser: {e}"))?;

    // 5. Verify against the agent-bound public values.
    verify(&config, &air, &proof, &public_values)
        .map_err(|e| format!("plonky3: {e:?}"))
}

fn result_to_json(verified: bool, error: Option<String>, size: usize) -> String {
    let result = VerifyResult {
        verified,
        error,
        proof_size_bytes: size,
        verifier_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    serde_json::to_string(&result).unwrap_or_else(|_| {
        r#"{"verified":false,"error":"serialize result failed","proof_size_bytes":0,"verifier_version":"unknown"}"#.to_string()
    })
}

#[cfg(test)]
mod tests {
    //! Native harness: generate a real agent-bound proof with the same Plonky3 config the
    //! prover uses, then exercise the WASM verify entrypoint (verify_proof JSON interface).
    //! This proves PASS on a valid proof and tampered-FAIL on a wrong agent_id / wrong score,
    //! without needing a wasm runtime.
    use super::*;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;
    use p3_uni_stark::prove;

    type Val = BabyBear;
    type Challenge = BinomialExtensionField<Val, 4>;
    type ByteHash = Keccak256Hash;
    type FieldHash = SerializingHasher<ByteHash>;
    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 2, 32>;
    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    type Dft = RecursiveDft<Val>;
    type Pcs = p3_fri::TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    type MyChallenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
    type SC = StarkConfig<Pcs, Challenge, MyChallenger>;

    const AGENT_A: &str = "394b6ee4-62e7-4c66-8445-29107b097b4c";
    const AGENT_B: &str = "942860a6-e26f-4334-ae94-b7c1abed1e8c";

    fn make_config() -> SC {
        let byte_hash = ByteHash {};
        let field_hash = FieldHash::new(ByteHash {});
        let compress = MyCompress::new(byte_hash);
        let val_mmcs = ValMmcs::new(field_hash, compress, 0);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri_config = FriConfig {
            log_blowup: 2,
            num_queries: 28,
            log_final_poly_len: 0,
            max_log_arity: 1,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 8,
            mmcs: challenge_mmcs,
        };
        let trace_h = 1usize;
        let dft = Dft::new(trace_h << fri_config.log_blowup);
        let pcs = Pcs::new(dft, val_mmcs, fri_config);
        let challenger = MyChallenger::new(HashChallenger::<u8, ByteHash, 32>::new(vec![], byte_hash.clone()));
        SC::new(pcs, challenger)
    }

    fn gen_trace(value: u32) -> RowMajorMatrix<Val> {
        let mut bits = Vec::with_capacity(32);
        for i in (0..32).rev() {
            bits.push(if (value & (1 << i)) != 0 { Val::ONE } else { Val::ZERO });
        }
        RowMajorMatrix::new(bits, 32)
    }

    /// Produce a base64 proof for {agent_id, threshold, repid_score}.
    fn make_proof_b64(agent_id: &str, threshold: u64, repid: u64) -> String {
        let gap = (repid - threshold - 1) as u32;
        let config = make_config();
        let air = RepIdRangeCheckAir { value: gap };
        let trace = gen_trace(gap);
        let _ = trace.height();
        let pv = build_public_values(agent_id, threshold, repid).unwrap();
        let proof = prove(&config, &air, trace, &pv);
        let bytes = bincode::serialize(&proof).unwrap();
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    }

    fn run_verify(proof_b64: &str, agent_id: &str, threshold: u64, repid: u64) -> VerifyResult {
        let input = VerifyInput {
            proof_bytes: proof_b64.to_string(),
            statement: Statement {
                agent_id: agent_id.to_string(),
                repid_score: repid,
                threshold,
                tier: "ESTABLISHED".to_string(),
            },
        };
        let json = serde_json::to_string(&input).unwrap();
        serde_json::from_str(&verify_proof(&json)).unwrap()
    }

    #[test]
    fn wasm_verify_pass_on_valid_agent_bound_proof() {
        let p = make_proof_b64(AGENT_A, 999, 2280);
        let r = run_verify(&p, AGENT_A, 999, 2280);
        assert!(r.verified, "valid agent-bound proof must verify: {:?}", r.error);
        assert!(r.proof_size_bytes > 1000);
    }

    #[test]
    fn wasm_verify_fail_on_wrong_agent_id() {
        let p = make_proof_b64(AGENT_A, 999, 2280);
        let r = run_verify(&p, AGENT_B, 999, 2280); // same score, different agent
        assert!(!r.verified, "proof must NOT verify under a different agent_id");
    }

    #[test]
    fn wasm_verify_fail_on_inflated_score() {
        let p = make_proof_b64(AGENT_A, 999, 2280);
        let r = run_verify(&p, AGENT_A, 999, 9999); // claim a higher score than proven
        assert!(!r.verified, "proof must NOT verify against an inflated repid_score");
    }
}
