/* Copyright(c) 2013 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

var stream = require('./stream');
var stream_xsalsa20_xor = stream.xsalsa20_xor;
var stream_xsalsa20 = stream.xsalsa20;
var onetimeauth = require('./onetimeauth');
var onetimeauth_poly1305 = onetimeauth.poly1305;
var onetimeauth_poly1305_verify = onetimeauth.poly1305_verify;
var ArraysFactory = require('../util/arrays');

function checkPackArgs(m, n, k) {
	if (m.BYTES_PER_ELEMENT !== 1) { throw new TypeError("Message array m must be Uint8Array."); }
	if (m.length === 0) { throw new Error("Message array should have at least one byte."); }
	if (n.BYTES_PER_ELEMENT !== 1) { throw new TypeError("Nonce array n must be Uint8Array."); }
	if (n.length !== 24) { throw new Error(
			"Nonce array n should have 24 elements (bytes) in it, but it is "+
			n.length+" elements long."); }
	if (k.BYTES_PER_ELEMENT !== 1) { throw new TypeError("Key array k must be Uint8Array."); }
	if (k.length !== 32) { throw new Error(
			"Key array k should have 32 elements (bytes) in it, but it is "+
			k.length+" elements long."); }
}

/**
 * Analog of crypto_secretbox in crypto_secretbox/xsalsa20poly1305/ref/box.c
 * with an addition that given message should not be padded with zeros, and all
 * padding happen automagically without copying message array.
 * @param c is Uint8Array for resulting cipher, with length being 32 bytes longer than message.
 * Resulting cipher of incoming message, packaged according to NaCl's xsalsa20+poly1305 secret-box
 * bytes layout, with 16 leading zeros.
 * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long secret key.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 */
function xsalsa20poly1305_pad_and_pack(c, m, n, k, arrFactory) {
	if (c.length < 32+m.length) { throw new Error("Given array c is too short for output."); }
	if (!arrFactory) { arrFactory = new ArraysFactory(); }
	
	stream_xsalsa20_xor(c,m,32,n,k,arrFactory);

	var dataPartOfC = c.subarray(32)
	, polyOut = c.subarray(16,32)
	, polyKey = c.subarray(0,32);
	
	onetimeauth_poly1305(polyOut, dataPartOfC, polyKey, arrFactory);
	
	// clear poly key part, which is not overwritten by poly output
	for (var i=0; i<16; i+=1) {
		c[i] = 0;
	}
	
}

/**
 * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long secret key.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 * @return Uint8Array with resulting cipher of incoming message, packaged according to
 * NaCl's xsalsa20+poly1305 secret-box bytes layout, trimmed of initial zeros, by having
 * a view on array, starting with non-zero part.
 */
function pack(m, n, k, arrFactory) {
	checkPackArgs(m, n, k);
	var c = new Uint8Array(m.length+32);
	xsalsa20poly1305_pad_and_pack(c, m, n, k, arrFactory);
	c = c.subarray(16);
	return c;
}

/**
 * @param c is Uint8Array for packing nonce together with cipher.
 * Its length should be 40 bytes longer than that of a message.
 * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long secret key.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 */
function packIntoArrWithNonce(c, m, n, k, arrFactory) {
	checkPackArgs(m, n, k);
	if (c.length < 40+m.length) { throw new Error(
			"Array c, for packing nonce and cipher, is too short."); }
	xsalsa20poly1305_pad_and_pack(
			c.subarray(8),
			m, n, k, arrFactory);
	c.set(n);	// sets first 24 bytes (length of n) to nonce value
}

/**
 * Analog of crypto_secretbox_open in crypto_secretbox/xsalsa20poly1305/ref/box.c
 * with an addition that given cipher should not be padded with zeros, and all
 * padding happen automagically without copying cipher array.
 * @param c is Uint8Array of cipher bytes that need to be opened by secret key.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long secret key.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 * @return Uint8Array with opened message.
 * Array is a view of buffer, which has 32 zeros preceding message bytes.
 */
function xsalsa20poly1305_pad_open_trim(c, n, k, arrFactory) {
	if (c.BYTES_PER_ELEMENT !== 1) { throw new TypeError("Cipher array c must be Uint8Array."); }
	if (c.length < 17) { throw new Error(
			"Cipher array c should have at least 17 elements (bytes) in it, but is only "+
			c.length+" elements long."); }
	if (n.BYTES_PER_ELEMENT !== 1) { throw new TypeError("Nonce array n must be Uint8Array."); }
	if (n.length !== 24) { throw new Error(
			"Nonce array n should have 24 elements (bytes) in it, but it is "+
			n.length+" elements long."); }
	if (k.BYTES_PER_ELEMENT !== 1) { throw new TypeError("Key array k must be Uint8Array."); }
	if (k.length !== 32) { throw new Error(
			"Key array k should have 32 elements (bytes) in it, but it is "+
			k.length+" elements long."); }
	if (!arrFactory) { arrFactory = new ArraysFactory(); }
	
	var m = new Uint8Array(c.length+16);
	
	var subkey = arrFactory.getUint8Array(32);
	stream_xsalsa20(subkey,n,k,arrFactory);
	
	var polyPartOfC = c.subarray(0,16);
	var msgPartOfC = c.subarray(16);
	
	if (!onetimeauth_poly1305_verify(polyPartOfC,msgPartOfC,subkey,arrFactory)) {
		throw new Error("Cipher bytes fail verification.");
	}

	stream_xsalsa20_xor(m,c,16,n,k,arrFactory);

	// first 32 bytes of the opened thing should be cleared
	for (var i=0; i<32; i++) { m[i] = 0; }

	// clear and recycle subkey array
	arrFactory.wipe(subkey);
	arrFactory.recycle(subkey);

	m = m.subarray(32);
	
	return m;
}

/**
 * @param c is Uint8Array with nonce and cipher bytes that need to be opened by secret key.
 * @param k is Uint8Array, 32 bytes long secret key.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 * @return Uint8Array with opened message.
 * Array is a view of buffer, which has 32 zeros preceding message bytes.
 */
function openArrWithNonce(c, k, arrFactory) {
	if (c.length < 41) { throw new Error("Array c with nonce and cipher should have at "+
			"least 41 elements (bytes) in it, but is only "+c.length+" elements long."); }
	var n = c.subarray(0, 24);
	c = c.subarray(24);
	return xsalsa20poly1305_pad_open_trim(c, n, k, arrFactory);
}

module.exports = {
		pack: pack,
		open: xsalsa20poly1305_pad_open_trim,
		packIntoArrWithNonce: packIntoArrWithNonce,
		openArrWithNonce: openArrWithNonce,
		NONCE_LENGTH: 24,
		KEY_LENGTH: 32
};
Object.freeze(module.exports);
