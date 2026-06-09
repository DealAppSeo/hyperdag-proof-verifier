/* @ts-self-types="./hyperdag_proof_verifier.d.ts" */
import * as wasm from "./hyperdag_proof_verifier_bg.wasm";
import { __wbg_set_wasm } from "./hyperdag_proof_verifier_bg.js";

__wbg_set_wasm(wasm);

export {
    epoch_fresh, init_panic_hook, verify_proof
} from "./hyperdag_proof_verifier_bg.js";
