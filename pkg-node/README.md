# @hyperdag/proof-verifier

Verify HyperDAG Plonky3 STARK RepID proofs in your browser or Node app. **Trust math, not a server.**

## Why this exists
HyperDAG's `zkp-postcard` service generates a Plonky3 STARK proof that an agent's RepID exceeds a threshold. If you trust the server when it says `verified: true`, you're trusting a server. With this package your code verifies the cryptographic proof itself — locally, deterministically, no network call.

## Install
```bash
npm install @hyperdag/proof-verifier
```

## Usage (3 lines)
```js
import { verify } from '@hyperdag/proof-verifier';
const result = await verify(proofBytes, statement); // statement = { agent_id, repid_score, threshold, tier }
console.log(result.verified); // true | false
```

## End-to-end with the SDK
```js
import { TrustShell } from '@hyperdag/trustshell';
const ts = new TrustShell();
const proof = await ts.presentProof(agentId, { verify: true }); // fetches the proof + verifies it client-side
if (!proof.verification?.verified) throw new Error('proof failed verification — DO NOT TRUST');
```

## What it PROVES
The public statement is exactly `{ agent_id, threshold, repid_score }` — **no timestamp, no hidden data beyond the proof witness.** A `verified: true` means, cryptographically:

- **Agent-bound.** The proof is bound to `agent_id` (its 16 bytes are public inputs observed into the Fiat-Shamir transcript). A proof minted for agent A **fails** verification under any other agent_id — it cannot be replayed.
- **Range-sound (16-bit range check).** The circuit proves `repid_score > threshold` by range-checking the gap `repid_score − threshold − 1` into **16 bits** (the high 16 bits are constrained to zero). A claim where `repid_score ≤ threshold` has no satisfying witness — including the field-wrap case (`gap = −1 = p−1`), which an earlier 31-bit check would have admitted. (Soundness assumption: `repid_score − threshold < 65536`, always true for RepID where `repid_score ≤ 10000`.)
- **Value-bound.** An AIR boundary constraint ties the range-checked gap to the public `{threshold, repid_score}` — the proof attests *this* agent's score exceeds *this* threshold, not merely "some 32-bit value exists."

## What it does NOT prove
- It does **not** hide `repid_score` — the score is part of the public statement. This is a verifiable attestation that the proof is consistent with the stated values, not a zero-knowledge concealment of the score.
- It carries **no timestamp** — there is no "had RepID X at time T" claim. The statement is timeless `{agent_id, threshold, repid_score}`.
- It does not re-verify the server's upstream RepID computation — it verifies the proof matches the stated `{agent_id, threshold, repid_score}`.

## Plonky3 version pinning
Pinned to the EXACT Plonky3 revision used by `zkp-postcard` (`27d59f7350daf6b02d11b01c3a55af453554b515`). A mismatched pin cannot verify. See `Cargo.toml`.

## Bundle size
| Target  | .wasm size |
|---------|-----------|
| bundler | ~245 KB   |
| nodejs  | ~245 KB   |
| web     | ~245 KB   |

## Performance
Verify time (avg, Node 22): ~30 ms per proof (native build; in-browser WASM is comparable).

## License
Apache-2.0
