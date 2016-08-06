import arrays = require('../util/arrays');
export interface Keypair {
    /**
     * Secret key of this pair.
     */
    skey: Uint8Array;
    /**
     * Public key of this pair.
     */
    pkey: Uint8Array;
}
/**
 * Analog of crypto_sign_keypair in crypto_sign/ed25519/ref/keypair.c
 */
export declare function generate_keypair(seed: Uint8Array, arrFactory?: arrays.Factory): Keypair;
export declare function extract_pkey(sk: Uint8Array): Uint8Array;
/**
 * Analog of crypto_sign in crypto_sign/ed25519/ref/sign.c
 */
export declare function sign(m: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
export declare function signature(m: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
/**
 * Analog of crypto_sign_open in crypto_sign/ed25519/ref/open.c
 */
export declare function open(sm: Uint8Array, pk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
export declare function verify(sig: Uint8Array, m: Uint8Array, pk: Uint8Array, arrFactory?: arrays.Factory): boolean;
export declare var JWK_ALG_NAME: string;
export declare var PUBLIC_KEY_LENGTH: number;
export declare var SECRET_KEY_LENGTH: number;
