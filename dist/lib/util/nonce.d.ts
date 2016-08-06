import arrays = require('../util/arrays');
/**
 * This array contains 64 bits in two unsigned ints, with high 32 bits in the
 * 1st element and low 32 bits in the 0th one.
 */
export interface U64 extends Uint32Array {
}
/**
 * @param u is a U64 object
 */
export declare function u64To52(u: U64): number;
/**
 * This takes a given 24-byte nonce as three 8-byte numbers, and adds
 * a given delta to each number.
 * @param n is Uint8Array, 24 bytes long nonce that will be changed in-place.
 * @param delta is a number from 1 to 255 inclusive.
 */
export declare function advance(n: Uint8Array, delta: number): void;
/**
 * This takes a given 24-byte nonce as three 8-byte numbers, and adds
 * 1 to each number.
 * @param n is Uint8Array, 24 bytes long nonce that will be changed in-place.
 */
export declare function advanceOddly(n: Uint8Array): void;
/**
 * This takes a given 24-byte nonce as three 8-byte numbers, and adds
 * 2 to each number.
 * @param n is Uint8Array, 24 bytes long nonce that will be changed in-place.
 */
export declare function advanceEvenly(n: Uint8Array): void;
/**
 * @param initNonce
 * @param delta
 * @param arrFactory is an optional factory, which provides array for a
 * calculated nonce.
 * @return new nonce, calculated from an initial one by adding a delta to it.
 */
export declare function calculateNonce(initNonce: Uint8Array, delta: number | U64, arrFactory?: arrays.Factory): Uint8Array;
/**
 * @param n1
 * @param n2
 * @return delta (unsigned 64-bit integer), which, when added to the first
 * nonce (n1), produces the second nonce (n2).
 * Undefined is returned, if given nonces are not related to each other.
 */
export declare function calculateDelta(n1: Uint8Array, n2: Uint8Array): U64;
