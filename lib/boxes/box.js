/* Copyright(c) 2013 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

var ArraysFactory = require('../util/arrays');
var sm = require('./scalarmult');
var core = require('./core');
var sbox = require('./secret_box');
var SIGMA = require('./stream').SIGMA;

/**
 * Replacement of crypto_box_keypair in crypto_box/curve25519xsalsa20poly1305/ref/keypair.c
 * Public key can be generated for any given secret key, which itself should be randomly generated.
 * @param sk is Uint8Array of 32 bytes of a secret key.
 * @returns Uint8Array with 32 bytes of a public key, that corresponds given secret key. 
 */
function generate_pubkey(sk) {
	if (sk.BYTES_PER_ELEMENT !== 1) { throw new TypeError("Key array k must be Uint8Array."); }
	if (sk.length !== 32) { throw new Error(
			"Key array sk should have 32 elements (bytes) in it, but it is "+
			sk.length+" elements long."); }
	var pk = new Uint8Array(32);
	sm.curve25519_base(pk,sk);
	return pk;
}

/**
 * n array in crypto_box/curve25519xsalsa20poly1305/ref/before.c
 */
var n_to_calc_dhshared_key = new Uint8Array(16);

/**
 * Analog of crypto_box_beforenm in crypto_box/curve25519xsalsa20poly1305/ref/before.c
 * @param pk is Uint8Array, 32 items long.
 * @param sk is Uint8Array, 32 items long.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 * @returns Uint8Array with 32 bytes of stream key for the box, under given public and secret keys.
 */
function calc_dhshared_key(pk, sk, arrFactory) {
	if (pk.BYTES_PER_ELEMENT !== 1) { throw new TypeError("Public key array pk must be Uint8Array."); }
	if (pk.length !== 32) { throw new Error(
			"Public key array pk should have 32 elements (bytes) in it, but it is "+
			pk.length+" elements long."); }
	if (sk.BYTES_PER_ELEMENT !== 1) { throw new TypeError("Secret key array sk must be Uint8Array."); }
	if (sk.length !== 32) { throw new Error(
			"Secret key array sk should have 32 elements (bytes) in it, but it is "+
			sk.length+" elements long."); }
	if (!arrFactory) {
		arrFactory = new ArraysFactory();
	}
	var s = new Uint8Array(32);
	sm.curve25519(s, sk, pk, arrFactory);
	core.hsalsa20(s, n_to_calc_dhshared_key, s, SIGMA, arrFactory);
	return s;
}

/**
 * Analog of crypto_box in crypto_box/curve25519xsalsa20poly1305/ref/box.c
 * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
 * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 * @return Uint8Array with resulting cipher of incoming message, packaged according to
 * NaCl's xsalsa20+poly1305 secret-box bytes layout, trimmed of initial zeros.
 */
function pack_box(m, n, pk, sk, arrFactory) {
	var k = calc_dhshared_key(pk, sk, arrFactory);
	return sbox.pack(m,n,k,arrFactory);
}

/**
 * Analog of crypto_box_open in crypto_box/curve25519xsalsa20poly1305/ref/box.c
 * @param c is Uint8Array of cipher bytes that need to be opened.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
 * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 * @return Uint8Array with decrypted message bytes.
 * @throws Error when cipher bytes fail verification.
 */
function open_box( c, n, pk, sk, arrFactory) {
	var k = calc_dhshared_key(pk, sk, arrFactory);
	return sbox.open(c,n,k,arrFactory);
}

module.exports = {
		generate_pubkey: generate_pubkey,
		calc_dhshared_key: calc_dhshared_key,
		pack_stream: sbox.pack,
		open_stream: sbox.open,
		pack: pack_box,
		open: open_box,
		NONCE_LENGTH: 24,
		KEY_LENGTH: 32
};
Object.freeze(module.exports);
