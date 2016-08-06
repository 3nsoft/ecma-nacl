import fe = require('./fe25519');
import sc = require('./sc25519');
import arrays = require('../util/arrays');
/**
 * Analog of struct ge25519 in crypto_sign/ed25519/ref/ge25519.h
 */
export interface ge25519 {
    x: fe.fe25519;
    z: fe.fe25519;
    y: fe.fe25519;
    t: fe.fe25519;
}
export declare function make_ge25519(arrFactory: arrays.Factory): ge25519;
/**
 * Analog of struct ge25519_p2 in crypto_sign/ed25519/ref/ge25519.c
 */
export interface ge25519_p2 {
    x: fe.fe25519;
    y: fe.fe25519;
    z: fe.fe25519;
}
export declare function recycle_ge25519(arrFactory: arrays.Factory, ...ges: ge25519_p2[]): void;
/**
 * Analog of constant ge25519_base in crypto_sign/ed25519/ref/ge25519.c
 * Packed coordinates of the base point
 */
export declare var base: ge25519;
/**
 * Analog of ge25519_unpackneg_vartime in crypto_sign/ed25519/ref/ge25519.c
 * return true on success, false otherwise
 */
export declare function unpackneg_vartime(r: ge25519, p: Uint8Array, arrFactory: arrays.Factory): boolean;
/**
 * Analog of ge25519_pack in crypto_sign/ed25519/ref/ge25519.c
 */
export declare function pack(r: Uint8Array, p: ge25519, arrFactory: arrays.Factory): void;
/**
 * Analog of ge25519_double_scalarmult_vartime in
 * crypto_sign/ed25519/ref/ge25519.c
 * computes [s1]p1 + [s2]p2
 */
export declare function double_scalarmult_vartime(r: ge25519, p1: ge25519, s1: sc.sc25519, p2: ge25519, s2: sc.sc25519, arF: arrays.Factory): void;
/**
 * Analog of ge25519_scalarmult_base in crypto_sign/ed25519/ref/ge25519.c
 */
export declare function scalarmult_base(r: ge25519, s: sc.sc25519, arrFactory: arrays.Factory): void;
