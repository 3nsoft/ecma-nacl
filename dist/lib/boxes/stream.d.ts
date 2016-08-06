import arrays = require('../util/arrays');
/**
 * sigma array in crypto_stream/salsa20/ref/stream.c
 */
export declare var SIGMA: Uint8Array;
/**
 * Analog of crypto_stream in crypto_stream/xsalsa20/ref/stream.c
 * @param c is Uint8Array of some length, for outgoing bytes (cipher).
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long key.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use.
 */
export declare function xsalsa20(c: Uint8Array, n: Uint8Array, k: Uint8Array, arrFactory: arrays.Factory): void;
/**
 * Analog of crypto_stream_xor in crypto_stream/xsalsa20/ref/xor.c
 * @param c is Uint8Array of outgoing bytes with resulting cipher, of the same
 * length as incoming array m.
 * @param m is Uint8Array of incoming bytes, of some plain text message.
 * @param mPadLen is number of zeros that should be in front of message array,
 * always between 0 and 63.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long key.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use. It may be undefined, in which case an internally created one is used.
 */
export declare function xsalsa20_xor(c: Uint8Array, m: Uint8Array, mPadLen: number, n: Uint8Array, k: Uint8Array, arrFactory?: arrays.Factory): void;
