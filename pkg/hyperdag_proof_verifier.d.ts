/* tslint:disable */
/* eslint-disable */

/**
 * 0.3.0 FRESHNESS CHECK — separate from cryptographic verification. `verify_proof` proves the proof
 * is cryptographically bound to {agent_id, threshold, repid_score, epoch}; THIS decides whether that
 * bound epoch is recent enough, given the current AUTHORITATIVE epoch (block-height-derived, supplied
 * by the caller — NEVER by the proof). A proof minted `window` or more epochs in the past is STALE;
 * a future-dated epoch (proof_epoch > current_epoch) is also rejected. This is the replay-across-time
 * defense: an old proof still verifies cryptographically, but fails freshness once the chain moves on.
 */
export function epoch_fresh(proof_epoch: bigint, current_epoch: bigint, window: bigint): boolean;

export function init_panic_hook(): void;

export function verify_proof(input_json: string): string;
