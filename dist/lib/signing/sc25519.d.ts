import arrays = require('../util/arrays');
/**
 * Arithmetic modulo the group order
 * n = 2^252 +  27742317777372353535851937790883648493 =
 * 7237005577332262213973186563042994240857116359379907606001950938285454250989
 */
/**
 * Analog of struct sc25519 in crypto_sign/ed25519/ref/sc25519.h
 */
export interface sc25519 extends Uint32Array {
    /**
     * Do not use this field. It is present only in interface to stop
     * type-script from error-less casting of arrays to this interface.
     */
    sc25519: boolean;
}
export declare function make_sc25519(arrFactory: arrays.Factory): sc25519;
/**
 * Analog of struct shortsc25519 in crypto_sign/ed25519/ref/sc25519.h
 */
export interface shortsc25519 extends Uint32Array {
    /**
     * Do not use this field. It is present only in interface to stop
     * type-script from error-less casting of arrays to this interface.
     */
    shortsc25519: boolean;
}
export declare function make_shortsc25519(arrFactory: arrays.Factory): shortsc25519;
/**
 * Analog of sc25519_from32bytes in crypto_sign/ed25519/ref/sc25519.c
 */
export declare function from32bytes(r: sc25519, x: Uint8Array, arrFactory: arrays.Factory): void;
/**
 * Analog of sc25519_from64bytes in crypto_sign/ed25519/ref/sc25519.c
 */
export declare function from64bytes(r: sc25519, x: Uint8Array, arrFactory: arrays.Factory): void;
/**
 * Analog of sc25519_to32bytes in crypto_sign/ed25519/ref/sc25519.c
 */
export declare function to32bytes(r: Uint8Array, x: sc25519): void;
/**
 * Analog of sc25519_add in crypto_sign/ed25519/ref/sc25519.c
 */
export declare function add(r: sc25519, x: sc25519, y: sc25519, arrFactory: arrays.Factory): void;
/**
 * Analog of sc25519_mul in crypto_sign/ed25519/ref/sc25519.c
 */
export declare function mul(r: sc25519, x: sc25519, y: sc25519, arrFactory: arrays.Factory): void;
/**
 * Analog of sc25519_window3 in crypto_sign/ed25519/ref/sc25519.c
 */
export declare function window3(r: Int8Array, s: sc25519): void;
/**
 * Analog of sc25519_2interleave2 in crypto_sign/ed25519/ref/sc25519.c
 */
export declare function interleave2(r: Uint8Array, s1: sc25519, s2: sc25519): void;
