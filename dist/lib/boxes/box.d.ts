import arrays = require('../util/arrays');
import sbox = require('./secret_box');
/**
 * Replacement of crypto_box_keypair in
 * crypto_box/curve25519xsalsa20poly1305/ref/keypair.c
 * Public key can be generated for any given secret key, which itself should be
 * randomly generated.
 * @param sk is Uint8Array of 32 bytes of a secret key.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use. It may be undefined, in which case an internally created one is used.
 * @returns Uint8Array with 32 bytes of a public key, that corresponds given
 * secret key.
 */
export declare function generate_pubkey(sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
/**
 * Analog of crypto_box_beforenm in
 * crypto_box/curve25519xsalsa20poly1305/ref/before.c
 * @param pk is Uint8Array, 32 items long.
 * @param sk is Uint8Array, 32 items long.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use. It may be undefined, in which case an internally created one is used.
 * @return Uint8Array with 32 bytes of stream key for the box, under given
 * public and secret keys.
 */
export declare function calc_dhshared_key(pk: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
/**
 * Analog of crypto_box in crypto_box/curve25519xsalsa20poly1305/ref/box.c
 * @param m is Uint8Array of message bytes that need to be encrypted to given
 * secret and public keys.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
 * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use. It may be undefined, in which case an internally created one is used.
 * @return Uint8Array with resulting cipher of incoming message, packaged according
 * to NaCl's xsalsa20+poly1305 secret-box bytes layout, trimmed of initial zeros.
 */
export declare function pack(m: Uint8Array, n: Uint8Array, pk: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
/**
 * Analog of crypto_box_open in crypto_box/curve25519xsalsa20poly1305/ref/box.c
 * @param c is Uint8Array of cipher bytes that need to be opened.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
 * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use. It may be undefined, in which case an internally created one is used.
 * @return Uint8Array with decrypted message bytes.
 * Array is a view of buffer, which has 32 zeros preceding message bytes.
 * @throws Error when cipher bytes fail verification.
 */
export declare function open(c: Uint8Array, n: Uint8Array, pk: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
export declare module stream {
    var pack: typeof sbox.pack;
    var open: typeof sbox.open;
}
export declare module formatWN {
    /**
     * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
     * @param n is Uint8Array, 24 bytes long nonce.
     * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
     * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
     * @param arrFactory is typed arrays factory, used to allocated/find an array
     * for use. It may be undefined, in which case an internally created one is used.
     * @returns Uint8Array, where nonce is packed together with cipher.
     * Length of the returned array is 40 bytes greater than that of a message.
     */
    function pack(m: Uint8Array, n: Uint8Array, pk: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
    /**
     * @param c is Uint8Array with nonce and cipher bytes that need to be opened by
     * secret key.
     * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
     * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
     * @param arrFactory is typed arrays factory, used to allocated/find an array
     * for use. It may be undefined, in which case an internally created one is used.
     * @return Uint8Array with decrypted message bytes.
     * Array is a view of buffer, which has 32 zeros preceding message bytes.
     */
    function open(c: Uint8Array, pk: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
    var copyNonceFrom: typeof sbox.formatWN.copyNonceFrom;
    /**
     * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
     * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
     * @param nextNonce is nonce, which should be used for the very first packing.
     * All further packing will be done with new nonce, as it is automatically evenly
     * advanced.
     * Note that nextNonce will be copied.
     * @param delta is a number between 1 and 255 inclusive, used to advance nonce.
     * When missing, it defaults to two.
     * @param arrFactory is typed arrays factory, used to allocated/find an array
     * for use. It may be undefined, in which case an internally created one is used.
     * @return a frozen object with pack & open functions, and destroy
     * It is NaCl's secret box for a calculated DH-shared key, with automatically
     * evenly advancing nonce.
     */
    function makeEncryptor(pk: Uint8Array, sk: Uint8Array, nextNonce: Uint8Array, delta?: number, arrFactory?: arrays.Factory): sbox.Encryptor;
    /**
     * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
     * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
     * @param arrFactory is typed arrays factory, used to allocated/find an array
     * for use. It may be undefined, in which case an internally created one is used.
     * @return a frozen object with open and destroy functions.
     * It is NaCl's secret box for a calculated DH-shared key.
     */
    function makeDecryptor(pk: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): sbox.Decryptor;
}
export declare var NONCE_LENGTH: number;
export declare var KEY_LENGTH: number;
export declare var JWK_ALG_NAME: string;
