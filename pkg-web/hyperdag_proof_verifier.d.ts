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

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly epoch_fresh: (a: bigint, b: bigint, c: bigint) => number;
    readonly verify_proof: (a: number, b: number, c: number) => void;
    readonly init_panic_hook: () => void;
    readonly __wbindgen_export: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export2: (a: number, b: number) => number;
    readonly __wbindgen_export3: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
