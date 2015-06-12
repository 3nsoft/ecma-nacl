/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
var stream = require('./stream');
var auth = require('./onetimeauth');
var arrays = require('../util/arrays');
var nonceUtils = require('../util/nonce');
function checkPackArgs(m, n, k) {
    if (m.BYTES_PER_ELEMENT !== 1) {
        throw new TypeError("Message array m must be Uint8Array.");
    }
    if (m.length === 0) {
        throw new Error("Message array should have at least one byte.");
    }
    if (n.BYTES_PER_ELEMENT !== 1) {
        throw new TypeError("Nonce array n must be Uint8Array.");
    }
    if (n.length !== 24) {
        throw new Error("Nonce array n should have 24 elements (bytes) in it, but it is " + n.length + " elements long.");
    }
    if (k.BYTES_PER_ELEMENT !== 1) {
        throw new TypeError("Key array k must be Uint8Array.");
    }
    if (k.length !== 32) {
        throw new Error("Key array k should have 32 elements (bytes) in it, but it is " + k.length + " elements long.");
    }
}
/**
 * Analog of crypto_secretbox in crypto_secretbox/xsalsa20poly1305/ref/box.c
 * with an addition that given message should not be padded with zeros, and all
 * padding happen automagically without copying message array.
 * @param c is Uint8Array for resulting cipher, with length being 32 bytes longer
 * than message.
 * Resulting cipher of incoming message, packaged according to NaCl's
 * xsalsa20+poly1305 secret-box bytes layout, with 16 leading zeros.
 * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long secret key.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use.
 */
function xsalsa20poly1305_pad_and_pack(c, m, n, k, arrFactory) {
    if (c.length < 32 + m.length) {
        throw new Error("Given array c is too short for output.");
    }
    stream.xsalsa20_xor(c, m, 32, n, k, arrFactory);
    var dataPartOfC = c.subarray(32), polyOut = c.subarray(16, 32), polyKey = c.subarray(0, 32);
    auth.poly1305(polyOut, dataPartOfC, polyKey, arrFactory);
    for (var i = 0; i < 16; i += 1) {
        c[i] = 0;
    }
}
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
function pack(m, n, k, arrFactory) {
    checkPackArgs(m, n, k);
    if (!arrFactory) {
        arrFactory = arrays.makeFactory();
    }
    var c = new Uint8Array(m.length + 32);
    xsalsa20poly1305_pad_and_pack(c, m, n, k, arrFactory);
    c = c.subarray(16);
    arrFactory.wipeRecycled();
    return c;
}
exports.pack = pack;
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
function open(c, n, k, arrFactory) {
    if (c.BYTES_PER_ELEMENT !== 1) {
        throw new TypeError("Cipher array c must be Uint8Array.");
    }
    if (c.length < 17) {
        throw new Error("Cipher array c should have at least 17 elements (bytes) in it, but is only " + c.length + " elements long.");
    }
    if (n.BYTES_PER_ELEMENT !== 1) {
        throw new TypeError("Nonce array n must be Uint8Array.");
    }
    if (n.length !== 24) {
        throw new Error("Nonce array n should have 24 elements (bytes) in it, but it is " + n.length + " elements long.");
    }
    if (k.BYTES_PER_ELEMENT !== 1) {
        throw new TypeError("Key array k must be Uint8Array.");
    }
    if (k.length !== 32) {
        throw new Error("Key array k should have 32 elements (bytes) in it, but it is " + k.length + " elements long.");
    }
    if (!arrFactory) {
        arrFactory = arrays.makeFactory();
    }
    var m = new Uint8Array(c.length + 16);
    var subkey = arrFactory.getUint8Array(32);
    stream.xsalsa20(subkey, n, k, arrFactory);
    var polyPartOfC = c.subarray(0, 16);
    var msgPartOfC = c.subarray(16);
    if (!auth.poly1305_verify(polyPartOfC, msgPartOfC, subkey, arrFactory)) {
        var err = new Error("Cipher bytes fail verification.");
        err.failedCipherVerification = true;
        throw err;
    }
    stream.xsalsa20_xor(m, c, 16, n, k, arrFactory);
    for (var i = 0; i < 32; i++) {
        m[i] = 0;
    }
    arrFactory.recycle(subkey);
    arrFactory.wipeRecycled();
    m = m.subarray(32);
    return m;
}
exports.open = open;
/**
 * @param c is Uint8Array for packing nonce together with cipher.
 * Its length should be 40 bytes longer than that of a message.
 * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long secret key.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use. It may be undefined, in which case an internally created one is used.
 */
function packWithNonceInto(c, m, n, k, arrFactory) {
    checkPackArgs(m, n, k);
    if (c.length < 40 + m.length) {
        throw new Error("Array c, for packing nonce and cipher, is too short.");
    }
    if (!arrFactory) {
        arrFactory = arrays.makeFactory();
    }
    xsalsa20poly1305_pad_and_pack(c.subarray(8), m, n, k, arrFactory);
    c.set(n); // sets first 24 bytes (length of n) to nonce value
    arrFactory.wipeRecycled();
}
var regularOpen = open;
var formatWN;
(function (formatWN) {
    /**
     * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
     * @param n is Uint8Array, 24 bytes long nonce.
     * @param k is Uint8Array, 32 bytes long secret key.
     * @param arrFactory is typed arrays factory, used to allocated/find an array
     * for use. It may be undefined, in which case an internally created one is used.
     * @returns Uint8Array, where nonce is packed together with cipher.
     * Length of the returned array is 40 bytes greater than that of a message.
     */
    function pack(m, n, k, arrFactory) {
        if (!arrFactory) {
            arrFactory = arrays.makeFactory();
        }
        var c = new Uint8Array(40 + m.length);
        packWithNonceInto(c, m, n, k, arrFactory);
        arrFactory.wipeRecycled();
        return c;
    }
    formatWN.pack = pack;
    /**
     * @param c is Uint8Array with nonce and cipher bytes that need to be opened by secret key.
     * @param k is Uint8Array, 32 bytes long secret key.
     * @param arrFactory is typed arrays factory, used to allocated/find an array for use.
     * It may be undefined, in which case an internally created one is used.
     * @return Uint8Array with opened message.
     * Array is a view of buffer, which has 32 zeros preceding message bytes.
     */
    function open(c, k, arrFactory) {
        if (c.length < 41) {
            throw new Error("Array c with nonce and cipher should " + "have at least 41 elements (bytes) in it, but is only " + c.length + " elements long.");
        }
        if (!arrFactory) {
            arrFactory = arrays.makeFactory();
        }
        var n = c.subarray(0, 24);
        c = c.subarray(24);
        var m = regularOpen(c, n, k, arrFactory);
        arrFactory.wipeRecycled();
        return m;
    }
    formatWN.open = open;
    /**
     * @param c is Uint8Array with nonce and cipher bytes
     * @returns Uint8Array, which is a copy of 24-byte nonce from a given array c
     */
    function copyNonceFrom(c) {
        if (c.length < 41) {
            throw new Error("Array c with nonce and cipher should have at " + "least 41 elements (bytes) in it, but is only " + c.length + " elements long.");
        }
        return new Uint8Array(c.subarray(0, 24));
    }
    formatWN.copyNonceFrom = copyNonceFrom;
    /**
     *
     * @param key for new encryptor.
     * Note that key will be copied, thus, if given array shall never be used anywhere, it should
     * be wiped after this call.
     * @param nextNonce is nonce, which should be used for the very first packing.
     * All further packing will be done with new nonce, as it is automatically evenly advanced.
     * Note that nextNonce will be copied.
     * @param delta is a number between 1 and 255 inclusive, used to advance nonce.
     * When missing, it defaults to one.
     * @param arrFactory is typed arrays factory, used to allocated/find an array for use.
     * It may be undefined, in which case an internally created one is used.
     * @return a frozen object with pack & open functions, and destroy
     * It is NaCl's secret box for a given key, with automatically evenly advancing nonce.
     */
    function makeEncryptor(key, nextNonce, delta, arrFactory) {
        if (nextNonce.BYTES_PER_ELEMENT !== 1) {
            throw new TypeError("Nonce array nextNonce must be Uint8Array.");
        }
        if (nextNonce.length !== 24) {
            throw new Error("Nonce array nextNonce should have 24 elements (bytes) in it, but it is " + nextNonce.length + " elements long.");
        }
        if (key.BYTES_PER_ELEMENT !== 1) {
            throw new TypeError("Key array key must be Uint8Array.");
        }
        if (key.length !== 32) {
            throw new Error("Key array key should have 32 elements (bytes) in it, but it is " + key.length + " elements long.");
        }
        if ('number' !== typeof delta) {
            delta = 1;
        }
        else if ((delta < 1) || (delta > 255)) {
            throw new Error("Given delta is out of bounds.");
        }
        // set variable in the closure
        if (!arrFactory) {
            arrFactory = arrays.makeFactory();
        }
        key = new Uint8Array(key);
        nextNonce = new Uint8Array(nextNonce);
        var counter = 0;
        // arrange and freeze resulting object
        var encryptor = {
            pack: function (m) {
                if (!key) {
                    throw new Error("This encryptor cannot be used, " + "as it had already been destroyed.");
                }
                if (counter > 0xfffffffffffff) {
                    throw new Error("This encryptor " + "has been used 2^52 (too many) times. Further use may " + "lead to duplication of nonces.");
                }
                var c = pack(m, nextNonce, key, arrFactory);
                nonceUtils.advance(nextNonce, delta);
                counter += 1;
                return c;
            },
            destroy: function () {
                if (!key) {
                    return;
                }
                arrFactory.wipe(key, nextNonce);
                key = null;
                nextNonce = null;
                arrFactory = null;
            },
            getDelta: function () {
                return delta;
            }
        };
        Object.freeze(encryptor);
        return encryptor;
    }
    formatWN.makeEncryptor = makeEncryptor;
    /**
     *
     * @param key for new decryptor.
     * @param arrFactory is typed arrays factory, used to allocated/find an array for use.
     * It may be undefined, in which case an internally created one is used.
     * Note that key will be copied, thus, if given array shall never be used anywhere,
     * it should be wiped after this call.
     * @return a frozen object with pack & open and destroy functions.
     */
    function makeDecryptor(key, arrFactory) {
        if (key.BYTES_PER_ELEMENT !== 1) {
            throw new TypeError("Key array key must be Uint8Array.");
        }
        if (key.length !== 32) {
            throw new Error("Key array key should have 32 elements (bytes) in it, but it is " + key.length + " elements long.");
        }
        // set variable in the closure
        if (!arrFactory) {
            arrFactory = arrays.makeFactory();
        }
        key = new Uint8Array(key);
        // arrange and freeze resulting object
        var decryptor = {
            open: function (c) {
                if (!key) {
                    throw new Error("This encryptor cannot be used, " + "as it had already been destroyed.");
                }
                return open(c, key, arrFactory);
            },
            destroy: function () {
                if (!key) {
                    return;
                }
                arrFactory.wipe(key);
                key = null;
                arrFactory = null;
            }
        };
        Object.freeze(decryptor);
        return decryptor;
    }
    formatWN.makeDecryptor = makeDecryptor;
})(formatWN = exports.formatWN || (exports.formatWN = {}));
Object.freeze(formatWN);
exports.NONCE_LENGTH = 24;
exports.KEY_LENGTH = 32;
exports.POLY_LENGTH = 16;
exports.JWK_ALG_NAME = 'NaCl-sbox-XSP';
Object.freeze(exports);
