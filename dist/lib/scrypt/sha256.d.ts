/**
 * This is a TypeScrypt rewrite of scrypt-1.1.6.
 * In particular this file contains PKDF2-SHA256 algorithm
 * that are  used in scrypt algorithm.
 */
import arrays = require('../util/arrays');
/**
 * Functions exported below are supposed to be used in PBKDF2-SHA256,
 * which is itself is used inside scrypt.
 */
export interface SHA256_CTX {
    buf: Uint8Array;
    bufBytes: number;
    state: Uint8Array;
    count: number;
    arrFactory: arrays.Factory;
}
export declare function makeSha256Ctx(arrFactory: arrays.Factory): SHA256_CTX;
export declare function recycleSha256Ctxs(...ctxs: SHA256_CTX[]): void;
export declare function SHA256_Init(ctx: SHA256_CTX): void;
export declare function SHA256_Update(ctx: SHA256_CTX, m: Uint8Array, mi: number, mlen: number): void;
export declare function SHA256_Final(h: Uint8Array, ctx: SHA256_CTX): void;
/**
 * Analog of be32enc in lib/util/sysendian.h
 */
export declare function be32enc(p: Uint8Array, pi: number, x: number): void;
/**
 * Analog of PBKDF2_SHA256 in lib/crypto/sha256.c
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf, length dkLen, which must be at most 32 * (2^32 - 1).
 */
export declare function PBKDF2_SHA256(passwd: Uint8Array, salt: Uint8Array, c: number, buf: Uint8Array, arrFactory: arrays.Factory): void;
