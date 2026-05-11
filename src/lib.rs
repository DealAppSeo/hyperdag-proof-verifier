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

// --- AIR Definition (Mirrored from zkp-postcard/src/circuit.rs) ---

pub struct RepIdRangeCheckAir {
    pub value: u32,
}

impl<F: Field> BaseAir<F> for RepIdRangeCheckAir {
    fn width(&self) -> usize {
        32
    }
}

impl<AB: AirBuilder> Air<AB> for RepIdRangeCheckAir where AB::F: Field {
    fn eval(&self, builder: &mut AB) {
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

        // Reconstruct value from bits and verify
        let mut reconstructed = AB::Expr::ZERO;
        for i in 0..32 {
            let bit = row[i];
            builder.assert_bool(bit);
            reconstructed += AB::Expr::from_u32(1 << (31 - i)) * bit;
        }
        builder
            .when_first_row()
            .assert_eq(AB::Expr::from_u32(self.value), reconstructed);
    }
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

    // 1. Reconstruct the diff that the prover used
    if statement.repid_score <= statement.threshold {
        return Err("Statement claim (score <= threshold) is invalid for proof".to_string());
    }
    let diff = (statement.repid_score - statement.threshold - 1) as u32;
    let air = RepIdRangeCheckAir { value: diff };

    // 2. Build the StarkConfig components
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

    // 3. Deserialize the proof
    let proof: Proof<SC> = bincode::deserialize(proof_bytes)
        .map_err(|e| format!("deser: {e}"))?;

    // 4. Verify
    verify(&config, &air, &proof, &vec![])
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
