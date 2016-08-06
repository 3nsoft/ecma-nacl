import arrays = require('../util/arrays');
/**
 * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long secret key.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use. It may be undefined, in which case an internally created one is used.
 * @return Uint8Array with resulting cipher of incoming message, packaged according
 * to NaCl's xsalsa20+poly1305 secret-box bytes layout, trimmed of initial zeros,
 * by having a view on array, starting with non-zero part.
 */
export declare function pack(m: Uint8Array, n: Uint8Array, k: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
/**
 * Analog of crypto_secretbox_open in crypto_secretbox/xsalsa20poly1305/ref/box.c
 * with an addition that given cipher should not be padded with zeros, and all
 * padding happen automagically without copying cipher array.
 * @param c is Uint8Array of cipher bytes that need to be opened by secret key.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long secret key.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use. It may be undefined, in which case an internally created one is used.
 * @return Uint8Array with opened message.
 * Array is a view of buffer, which has 32 zeros preceding message bytes.
 */
export declare function open(c: Uint8Array, n: Uint8Array, k: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
/**
 * This is an encryptor that packs bytes according to "with-nonce" format.
 */
export interface Encryptor {
    /**
     * This encrypts given bytes using internally held nonce, which is
     * advanced for every packing operation, ensuring that every call will
     * have a different nonce.
     * @param m is a byte array that should be encrypted
     * @return byte array with cipher formatted with nonce
     */
    pack(m: Uint8Array): Uint8Array;
    /**
     * This method securely wipes internal key, and drops resources, so that
     * memory can be GC-ed.
     */
    destroy(): void;
    /**
     * @return an integer, by which nonce is advanced.
     */
    getDelta(): number;
}
/**
 * This is an dencryptor that unpacks bytes from "with-nonce" format.
 */
export interface Decryptor {
    /**
     * @param c is a byte array with cipher, formatted with nonce.
     * @return decrypted bytes.
     */
    open(c: Uint8Array): Uint8Array;
    /**
     * This method securely wipes internal key, and drops resources, so that
     * memory can be GC-ed.
     */
    destroy(): void;
}
export declare module formatWN {
    /**
     * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
     * @param n is Uint8Array, 24 bytes long nonce.
     * @param k is Uint8Array, 32 bytes long secret key.
     * @param arrFactory is typed arrays factory, used to allocated/find an array
     * for use. It may be undefined, in which case an internally created one is used.
     * @returns Uint8Array, where nonce is packed together with cipher.
     * Length of the returned array is 40 bytes greater than that of a message.
     */
    function pack(m: Uint8Array, n: Uint8Array, k: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
    /**
     * @param c is Uint8Array with nonce and cipher bytes that need to be opened by secret key.
     * @param k is Uint8Array, 32 bytes long secret key.
     * @param arrFactory is typed arrays factory, used to allocated/find an array for use.
     * It may be undefined, in which case an internally created one is used.
     * @return Uint8Array with opened message.
     * Array is a view of buffer, which has 32 zeros preceding message bytes.
     */
    function open(c: Uint8Array, k: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
    /**
     * @param c is Uint8Array with nonce and cipher bytes
     * @returns Uint8Array, which is a copy of 24-byte nonce from a given array c
     */
    function copyNonceFrom(c: Uint8Array): Uint8Array;
    /**
     *
     * @param key for new encryptor.
     * Note that key will be copied, thus, if given array shall never be used anywhere, it should
     * be wiped after this call.
     * @param nextNonce is nonce, which should be used for the very first packing.
     * All further packing will be done with new nonce, as it is automatically advanced.
     * Note that nextNonce will be copied.
     * @param delta is a number between 1 and 255 inclusive, used to advance nonce.
     * When missing, it defaults to one.
     * @param arrFactory is typed arrays factory, used to allocated/find an array for use.
     * It may be undefined, in which case an internally created one is used.
     * @return a frozen object with pack & open functions, and destroy
     * It is NaCl's secret box for a given key, with automatically advancing nonce.
     */
    function makeEncryptor(key: Uint8Array, nextNonce: Uint8Array, delta?: number, arrFactory?: arrays.Factory): Encryptor;
    /**
     *
     * @param key for new decryptor.
     * @param arrFactory is typed arrays factory, used to allocated/find an array for use.
     * It may be undefined, in which case an internally created one is used.
     * Note that key will be copied, thus, if given array shall never be used anywhere,
     * it should be wiped after this call.
     * @return a frozen object with pack & open and destroy functions.
     */
    function makeDecryptor(key: Uint8Array, arrFactory?: arrays.Factory): Decryptor;
}
export declare var NONCE_LENGTH: number;
export declare var KEY_LENGTH: number;
export declare var POLY_LENGTH: number;
export declare var JWK_ALG_NAME: string;
