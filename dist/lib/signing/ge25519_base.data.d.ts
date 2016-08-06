/**
 * This whole file is an analogy of crypto_sign/ed25519/ref/ge25519_base.data
 * producing one big array with points.
 */
import fe = require('./fe25519');
import arrays = require('../util/arrays');
/**
 * Analog of struct ge25519_aff in crypto_sign/ed25519/ref/ge25519.c
 */
export interface ge25519_aff {
    x: fe.fe25519;
    y: fe.fe25519;
    /**
     * Do not use this field. It is present only in interface to stop
     * type-script from error-less casting of p3 to this interface.
     */
    ge25519_aff: boolean;
}
export declare function make_ge25519_aff(arrFactory: arrays.Factory): ge25519_aff;
export declare var base_multiples_affine: ge25519_aff[];
