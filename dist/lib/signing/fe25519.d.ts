import arrays = require('../util/arrays');
/**
 * Analog of struct fe25519 in crypto_sign/ed25519/ref/fe25519.h
 */
export interface fe25519 extends Uint32Array {
    /**
     * Do not use this field. It is present only in interface to stop
     * type-script from error-less casting of arrays to this interface.
     */
    fe25519: boolean;
}
export declare function make_fe25519(arrFactory: arrays.Factory): fe25519;
/**
 * Analog of fe25519_unpack in crypto_sign/ed25519/ref/fe25519.c
 */
export declare function unpack(r: fe25519, x: Uint8Array): void;
/**
 * Analog of fe25519_unpack in crypto_sign/ed25519/ref/fe25519.c
 * Assumes input x being reduced below 2^255
 */
export declare function pack(r: Uint8Array, x: fe25519, arrFactory: arrays.Factory): void;
/**
 * Analog of fe25519_iseq_vartime in crypto_sign/ed25519/ref/fe25519.c
 */
export declare function iseq_vartime(x: fe25519, y: fe25519, arrFactory: arrays.Factory): boolean;
/**
 * Analog of fe25519_cmov in crypto_sign/ed25519/ref/fe25519.c
 */
export declare function cmov(r: fe25519, x: fe25519, b: number): void;
/**
 * Analog of fe25519_getparity in crypto_sign/ed25519/ref/fe25519.c
 */
export declare function getparity(x: fe25519, arrFactory: arrays.Factory): number;
/**
 * Analog of fe25519_setone in crypto_sign/ed25519/ref/fe25519.c
 */
export declare function setone(r: fe25519): void;
/**
 * Analog of fe25519_setzero in crypto_sign/ed25519/ref/fe25519.c
 */
export declare function setzero(r: fe25519): void;
/**
 * Analog of fe25519_neg in crypto_sign/ed25519/ref/fe25519.c
 */
export declare function neg(r: fe25519, x: fe25519, arrFactory: arrays.Factory): void;
/**
 * Analog of fe25519_add in crypto_sign/ed25519/ref/fe25519.c
 */
export declare function add(r: fe25519, x: fe25519, y: fe25519): void;
/**
 * Analog of fe25519_sub in crypto_sign/ed25519/ref/fe25519.c
 */
export declare function sub(r: fe25519, x: fe25519, y: fe25519, arrFactory: arrays.Factory): void;
/**
 * Analog of fe25519_mul in crypto_sign/ed25519/ref/fe25519.c
 */
export declare function mul(r: fe25519, x: fe25519, y: fe25519, arrFactory: arrays.Factory): void;
/**
 * Analog of fe25519_square in crypto_sign/ed25519/ref/fe25519.c
 */
export declare function square(r: fe25519, x: fe25519, arrFactory: arrays.Factory): void;
/**
 * Analog of fe25519_invert in crypto_sign/ed25519/ref/fe25519.c
 */
export declare function invert(r: fe25519, x: fe25519, arrFactory: arrays.Factory): void;
/**
 * Analog of fe25519_pow2523 in crypto_sign/ed25519/ref/fe25519.c
 */
export declare function pow2523(r: fe25519, x: fe25519, arrFactory: arrays.Factory): void;
