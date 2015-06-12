/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

import arrays = require('../util/arrays');
import sm = require('./scalarmult');
import core = require('./core');
import sbox = require('./secret_box');
import streamMod = require('./stream');
var SIGMA = streamMod.SIGMA;

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
export function generate_pubkey(sk: Uint8Array,
		arrFactory?: arrays.Factory): Uint8Array {
	if (sk.BYTES_PER_ELEMENT !== 1) { throw new TypeError(
			"Key array k must be Uint8Array."); }
	if (sk.length !== 32) { throw new Error("Key array sk should have 32 "+
			"elements (bytes) in it, but it is "+sk.length+" elements long."); }
	if (!arrFactory) { arrFactory = arrays.makeFactory(); }
	var pk = arrFactory.getUint8Array(32);
	sm.curve25519_base(pk,sk,arrFactory);
	arrFactory.wipeRecycled();
	return pk;
}

/**
 * n array in crypto_box/curve25519xsalsa20poly1305/ref/before.c
 */
var n_to_calc_dhshared_key = new Uint8Array(16);

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
export function calc_dhshared_key(pk: Uint8Array, sk: Uint8Array,
		arrFactory?: arrays.Factory): Uint8Array {
	if (pk.BYTES_PER_ELEMENT !== 1) { throw new TypeError("Public key array pk must be Uint8Array."); }
	if (pk.length !== 32) { throw new Error(
			"Public key array pk should have 32 elements (bytes) in it, but it is "+
			pk.length+" elements long."); }
	if (sk.BYTES_PER_ELEMENT !== 1) { throw new TypeError("Secret key array sk must be Uint8Array."); }
	if (sk.length !== 32) { throw new Error(
			"Secret key array sk should have 32 elements (bytes) in it, but it is "+
			sk.length+" elements long."); }
	if (!arrFactory) { arrFactory = arrays.makeFactory(); }
	var s = new Uint8Array(32);
	sm.curve25519(s, sk, pk, arrFactory);
	core.hsalsa20(s, n_to_calc_dhshared_key, s, SIGMA);
	arrFactory.wipeRecycled();
	return s;
}

/**
 * Analog of crypto_box in crypto_box/curve25519xsalsa20poly1305/ref/box.c
 * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
 * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use. It may be undefined, in which case an internally created one is used.
 * @return Uint8Array with resulting cipher of incoming message, packaged according
 * to NaCl's xsalsa20+poly1305 secret-box bytes layout, trimmed of initial zeros.
 */
export function pack(m: Uint8Array, n: Uint8Array, pk: Uint8Array,
		sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array {
	if (!arrFactory) { arrFactory = arrays.makeFactory(); }
	var k = calc_dhshared_key(pk, sk, arrFactory);
	var c = sbox.pack(m, n, k, arrFactory);
	arrFactory.wipeRecycled();
	return c;
}

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
export function open(c: Uint8Array, n: Uint8Array,
		pk: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array {
	if (!arrFactory) { arrFactory = arrays.makeFactory(); }
	var k = calc_dhshared_key(pk, sk, arrFactory);
	var m = sbox.open(c, n, k, arrFactory);
	arrFactory.wipeRecycled();
	return m;
}

export module stream {
	export var pack = sbox.pack;
	export var open = sbox.open;
}
Object.freeze(stream);

export module formatWN {

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
	export function pack(m: Uint8Array, n: Uint8Array, pk: Uint8Array,
			sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array {
		if (!arrFactory) { arrFactory = arrays.makeFactory(); }
		var k = calc_dhshared_key(pk, sk, arrFactory);
		var c = sbox.formatWN.pack(m, n, k, arrFactory);
		arrFactory.wipeRecycled();
		return c;
	}

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
	export function open(c: Uint8Array, pk: Uint8Array, sk: Uint8Array,
			arrFactory?: arrays.Factory): Uint8Array {
		if (!arrFactory) { arrFactory = arrays.makeFactory(); }
		var k = calc_dhshared_key(pk, sk, arrFactory);
		var m = sbox.formatWN.open(c, k, arrFactory);
		arrFactory.wipeRecycled();
		return m;
	}
	
	export var copyNonceFrom = sbox.formatWN.copyNonceFrom;

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
	export function makeEncryptor(pk: Uint8Array, sk: Uint8Array,
			nextNonce: Uint8Array, delta?: number,
			arrFactory?: arrays.Factory): sbox.Encryptor {
		if ('number' !== typeof delta) {
			delta = 2;
		}
		if (!arrFactory) { arrFactory = arrays.makeFactory(); }
		var k = calc_dhshared_key(pk, sk, arrFactory);
		var enc = sbox.formatWN.makeEncryptor(k, nextNonce, delta, arrFactory);
		arrFactory.wipe(k);
		return enc;
	}

	/**
	 * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
	 * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
	 * @param arrFactory is typed arrays factory, used to allocated/find an array
	 * for use. It may be undefined, in which case an internally created one is used.
	 * @return a frozen object with open and destroy functions.
	 * It is NaCl's secret box for a calculated DH-shared key.
	 */
	export function makeDecryptor(pk: Uint8Array, sk: Uint8Array,
			arrFactory?: arrays.Factory): sbox.Decryptor {
		if (!arrFactory) { arrFactory = arrays.makeFactory(); }
		var k = calc_dhshared_key(pk, sk, arrFactory);
		var enc = sbox.formatWN.makeDecryptor(k, arrFactory);
		arrFactory.wipe(k);
		return enc;
	}
	
}
Object.freeze(formatWN);

export var NONCE_LENGTH = 24;
export var KEY_LENGTH = 32;
export var JWK_ALG_NAME = 'NaCl-box-CXSP';

Object.freeze(exports);