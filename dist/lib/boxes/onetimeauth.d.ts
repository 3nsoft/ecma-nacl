import arrays = require('../util/arrays');
/**
 * Analog of crypto_onetimeauth in crypto_onetimeauth/poly1305/ref/auth.c
 * @param outArr is Uint8Array, 16 bytes long, into which poly hash is placed.
 * @param inArr is Uint8Array, with incoming bytes, whatever the length there is.
 * @param k is Uint8Array, 32 bytes long.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use.
 */
export declare function poly1305(outArr: Uint8Array, inArr: Uint8Array, k: Uint8Array, arrFactory: arrays.Factory): void;
/**
 * Analog of crypto_onetimeauth in crypto_onetimeauth/poly1305/ref/verify.c
 * @param h is Uint8Array, 16 bytes long poly hash.
 * @param inArr is Uint8Array, with incoming bytes, whatever the length there is.
 * @param k is Uint8Array, 32 bytes long.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use.
 * @return true, if calculated poly hash is identical to the given hash, otherwise,
 * false.
 */
export declare function poly1305_verify(h: Uint8Array, inArr: Uint8Array, k: Uint8Array, arrFactory: arrays.Factory): boolean;
