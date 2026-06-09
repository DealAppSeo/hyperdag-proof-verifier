# @hyperdag/proof-verifier
Verify HyperDAG STARK proofs in your browser or Node app. No server trust.

## Why this exists
HyperDAG's zkp-postcard service generates Plonky3 STARK proofs for every agent decision. If you trust HyperDAG's server when it says `verified: true`, you're just trusting a server. With this package, your code verifies the cryptographic proof itself — locally, deterministically, with no network call.

## Install
```bash
npm install @hyperdag/proof-verifier
```

## Usage (3 lines)
```js
import { verify } from '@hyperdag/proof-verifier';
const result = await verify(proofBytes, statement);
console.log(result.verified); // true | false
```

## End-to-end example with the SDK
```js
import { TrustShell } from '@hyperdag/trustshell';
import { verify } from '@hyperdag/proof-verifier';

const trust = new TrustShell({ ...config });
const decision = await trust.report({ ... });
const proof = await trust.getProof(decision.proof_job_id);
const result = await verify(proof.proof_bytes, proof.statement);
if (!result.verified) throw new Error('proof failed verification — DO NOT TRUST');
```

## What gets verified
- The agent had the claimed RepID at the claimed time.
- The RepID fits within the 32-bit range check relative to the threshold.
- The statement claim (score > threshold) is cryptographically consistent with the proof.

## Bundle size
| Target  | .wasm size |
|---------|-----------|
| bundler | 230 KB    |
| nodejs  | 230 KB    |
| web     | 230 KB    |

## Performance
Verify time (avg on Node 22, Windows): ~110 ms
Verify time (estimated Chrome/M3): ~150 ms

## Plonky3 version pinning
This verifier is pinned to the EXACT Plonky3 revisions used by zkp-postcard. Mismatched versions cannot verify. See Cargo.toml.

## License
MIT OR Apache-2.0
