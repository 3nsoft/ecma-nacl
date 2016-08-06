import arrays = require('../util/arrays');
/**
 * Analog of crypto_scalarmult in crypto_scalarmult/curve25519/ref/smult.c
 * @param q is Uint8Array, 32 items long.
 * @param n is Uint8Array, 32 items long.
 * @param p is Uint8Array, 32 items long.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use.
 */
export declare function curve25519(q: Uint8Array, n: Uint8Array, p: Uint8Array, arrFactory: arrays.Factory): void;
/**
 * Analog of crypto_scalarmult_base in crypto_scalarmult/curve25519/ref/base.c
 * @param q is Uint8Array, 32 items long.
 * @param n is Uint8Array, 32 items long.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use.
 */
export declare function curve25519_base(q: Uint8Array, n: Uint8Array, arrFactory: arrays.Factory): void;
