import { verify } from '../js/index.js';

const ZKP_URL = 'https://zkp-postcard-production.up.railway.app';
const SOPHIA = 'f3ef0bf8-5cdc-4fad-bce8-5144f01dc271';

describe('e2e: real production proof', () => {
  let realProof;

  beforeAll(async () => {
    console.log('Fetching real proof from production...');
    const resp = await fetch(`${ZKP_URL}/prove/trade_auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_id: SOPHIA }),
    });
    
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`zkp-postcard returned ${resp.status}: ${text}`);
    }
    
    const data = await resp.json();
    // zkp-postcard returns { proof_bytes, public_statement, agent_id, tier, threshold, ... }
    // Our verify function expects { agent_id, repid_score, threshold, tier }
    // Wait, let's check the zkp-postcard Response shape again.
    // main.rs:253: repid_score_actual: repid
    
    realProof = {
      proof_bytes: data.proof_bytes,
      statement: {
        agent_id: data.agent_id,
        repid_score: data.repid_score_actual,
        threshold: data.threshold || 7999, // VETERAN threshold
        tier: data.tier
      }
    };
    console.log(`Proof fetched. Score: ${data.repid_score_actual}, Tier: ${data.tier}`);
  }, 60_000);

  test('PASS: real proof verifies', async () => {
    const result = await verify(realProof.proof_bytes, realProof.statement);
    if (result.error) console.error('Verification error:', result.error);
    expect(result.verified).toBe(true);
    expect(result.error).toBeNull();
  });

  test('FAIL: corrupted proof rejected', async () => {
    const corrupted = corruptByte(realProof.proof_bytes, 100);
    const result = await verify(corrupted, realProof.statement);
    expect(result.verified).toBe(false);
    expect(result.error).not.toBeNull();
  });

  test('FAIL: wrong statement rejected', async () => {
    const wrongStatement = { ...realProof.statement, repid_score: 99999 };
    const result = await verify(realProof.proof_bytes, wrongStatement);
    expect(result.verified).toBe(false);
  });
});

function corruptByte(base64Str, idx) {
  const bytes = Buffer.from(base64Str, 'base64');
  bytes[idx] = bytes[idx] ^ 0xff;
  return bytes.toString('base64');
}
