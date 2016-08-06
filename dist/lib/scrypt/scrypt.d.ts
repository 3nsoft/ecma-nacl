/**
 * This is a TypeScrypt rewrite of scrypt-1.1.6.
 * In particular this file contains scrypt algorithm's main part.
 */
import arrays = require('../util/arrays');
/**
 * Analog of crypto_scrypt in lib/crypto/crypto_scrypt-ref.c
 * crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen) and write the result into buf.  The parameters r, p, and buflen
 * must satisfy r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N
 * must be a power of 2.
 *
 * Return Uint8Array with result; or throw an error.
 */
export declare function scrypt(passwd: Uint8Array, salt: Uint8Array, logN: number, r: number, p: number, dkLen: number, progressCB: (p: number) => void, arrFactory?: arrays.Factory): Uint8Array;
