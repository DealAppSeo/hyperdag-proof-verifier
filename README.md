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
The public statement is exactly `{ agent_id, threshold, repid_score, epoch }`. A `verified: true` means, cryptographically:

- **Agent-bound.** The proof is bound to `agent_id` (its 16 bytes are public inputs observed into the Fiat-Shamir transcript). A proof minted for agent A **fails** verification under any other agent_id — it cannot be replayed across agents.
- **Range-sound (16-bit range check).** The circuit proves `repid_score > threshold` by range-checking the gap `repid_score − threshold − 1` into **16 bits** (the high 16 bits are constrained to zero). A claim where `repid_score ≤ threshold` has no satisfying witness — including the field-wrap case (`gap = −1 = p−1`), which an earlier 31-bit check would have admitted. (Soundness assumption: `repid_score − threshold < 65536`, always true for RepID where `repid_score ≤ 10000`.)
- **Value-bound.** An AIR boundary constraint ties the range-checked gap to the public `{threshold, repid_score}`.
- **Freshness-bound (0.3.0).** The proof is bound to an `epoch` — an **authoritative** value the prover derives from chain (Base Sepolia block height), **never** from agent input. A proof minted at one epoch fails verification under any other epoch.

## Freshness — defeating replay-across-time
The crypto `verify` confirms the proof is bound to its `epoch`; a separate `epochFresh` check decides whether that epoch is recent enough, given the **current authoritative epoch** (which the caller fetches — never the proof):
```js
import { verify, epochFresh } from '@hyperdag/proof-verifier';
const v = await verify(proofBytes, statement);          // crypto: bound to statement incl. epoch
const fresh = await epochFresh(statement.epoch, currentEpoch, /*window*/ 6); // is it stale?
if (!v.verified || !fresh) throw new Error('invalid or stale proof — DO NOT TRUST');
```
An old proof (minted when RepID was high) still verifies cryptographically, but **fails freshness** once the chain has moved past its window — so it can't be replayed later.

## What it does NOT prove
- It does **not** hide `repid_score` — the score is in the public statement. This is a verifiable attestation that the proof is consistent with the stated values, not zero-knowledge concealment.
- `epoch` is a **freshness** value, not a precise timestamp — it's a coarse `block_height / N` window, so the claim is "minted within this epoch," not "at time T."
- It does not re-verify the server's upstream RepID computation — it verifies the proof matches the stated `{agent_id, threshold, repid_score, epoch}`.

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
