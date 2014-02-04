/* Copyright(c) 2013-2014 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

var stream = require('./stream')
, stream_xsalsa20_xor = stream.xsalsa20_xor
, stream_xsalsa20 = stream.xsalsa20
, onetimeauth = require('./onetimeauth')
, onetimeauth_poly1305 = onetimeauth.poly1305
, onetimeauth_poly1305_verify = onetimeauth.poly1305_verify
, TypedArraysFactory = require('../util/arrays')
, nonceMod = require('../util/nonce');

function checkPackArgs(m, n, k) {
	"use strict";
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
	"use strict";
	
	if (c.length < 32+m.length) { throw new Error("Given array c is too short for output."); }
	if (!arrFactory) { arrFactory = new TypedArraysFactory(); }
	
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
	"use strict";
	checkPackArgs(m, n, k);
	var c = new Uint8Array(m.length+32);
	xsalsa20poly1305_pad_and_pack(c, m, n, k, arrFactory);
	c = c.subarray(16);
	return c;
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
	"use strict";
	
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
	if (!arrFactory) { arrFactory = new TypedArraysFactory(); }
	
	var m = new Uint8Array(c.length+16);
	
	var subkey = arrFactory.getUint8Array(32);
	stream_xsalsa20(subkey,n,k,arrFactory);
	
	var polyPartOfC = c.subarray(0,16);
	var msgPartOfC = c.subarray(16);
	
	if (!onetimeauth_poly1305_verify(polyPartOfC,msgPartOfC,subkey,arrFactory)) {
		var err = new Error("Cipher bytes fail verification.");
		err.failedCipherVerification = true;
		throw err;
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
 * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long secret key.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 * @returns Uint8Array, where nonce is packed together with cipher.
 * Length of the returned array is 40 bytes greater than that of a message.
 */
function packWithNonce(m, n, k, arrFactory) {
	"use strict";
	var c = new Uint8Array(40+m.length);
	packWithNonceInto(c, m, n, k, arrFactory);
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
function packWithNonceInto(c, m, n, k, arrFactory) {
	"use strict";
	checkPackArgs(m, n, k);
	if (c.length < 40+m.length) { throw new Error(
			"Array c, for packing nonce and cipher, is too short."); }
	xsalsa20poly1305_pad_and_pack(
			c.subarray(8),
			m, n, k, arrFactory);
	c.set(n);	// sets first 24 bytes (length of n) to nonce value
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
	"use strict";
	if (c.length < 41) { throw new Error("Array c with nonce and cipher should have at "+
			"least 41 elements (bytes) in it, but is only "+c.length+" elements long."); }
	var n = c.subarray(0, 24);
	c = c.subarray(24);
	return xsalsa20poly1305_pad_open_trim(c, n, k, arrFactory);
}

/**
 * @param c is Uint8Array with nonce and cipher bytes
 * @returns Uint8Array, which is a copy of 24-byte nonce from a given array c
 */
function copyNonceFrom(c) {
	"use strict";
	if (c.length < 41) { throw new Error("Array c with nonce and cipher should have at "+
			"least 41 elements (bytes) in it, but is only "+c.length+" elements long."); }
	return new Uint8Array(c.subarray(0, 24));
}

/**
 * 
 * @param key for new encryptor.
 * Note that key will be copied, thus, if given array shall never be used anywhere, it should
 * be wiped after this call.
 * @param nextNonce is nonce, which should be used for the very first packing.
 * All further packing will be done with new nonce, as it is automatically evenly advanced.
 * Note that nextNonce will be copied.
 * @return a frozen object with pack & open functions, and destroy
 * It is NaCl's secret box for a given key, with automatically evenly advancing nonce.
 */
function makeEncryptor(key, nextNonce) {
	"use strict";
	if (nextNonce.BYTES_PER_ELEMENT !== 1) { throw new TypeError("Nonce array nextNonce must be Uint8Array."); }
	if (nextNonce.length !== 24) { throw new Error(
			"Nonce array nextNonce should have 24 elements (bytes) in it, but it is "+
			nextNonce.length+" elements long."); }
	if (key.BYTES_PER_ELEMENT !== 1) { throw new TypeError("Key array key must be Uint8Array."); }
	if (key.length !== 32) { throw new Error(
			"Key array key should have 32 elements (bytes) in it, but it is "+
			key.length+" elements long."); }
	
	// set variable in the closure
	var arrFactory = new TypedArraysFactory()
	, pack, open, destroy;
	key = new Uint8Array(key);
	nextNonce = new Uint8Array(nextNonce);

	pack = function(m) {
		try {
			if (!key) { throw new Error("This encryptor cannot be used, " +
			"as it had already been destroyed."); }
			var c = formatWN.pack(m, nextNonce, key, arrFactory);
			nonceMod.advanceEvenly(nextNonce);
			return c;
		} finally {
			arrFactory.wipeRecycled();
		}
	};
	open = function(c) {
		try {
			if (!key) { throw new Error("This encryptor cannot be used, " +
					"as it had already been destroyed."); }
			return formatWN.open(c, key, arrFactory);
		} finally {
			arrFactory.wipeRecycled();
		}
	};
	destroy = function() {
		if (!key) { return; }
		TypedArraysFactory.prototype.wipe(key, nextNonce);
		key = null;
		nextNonce = null;
		arrFactory = null;
	};
	
	// arrange and freeze resulting object
	var encryptor = {
		pack: pack,
		open: open,
		destroy: destroy
	};
	Object.freeze(encryptor);
	
	return encryptor;
}

var formatWN = {
	pack: packWithNonce,
	packInto: packWithNonceInto,
	open: openArrWithNonce,
	copyNonceFrom: copyNonceFrom,
	makeEncryptor: makeEncryptor
};
Object.freeze(formatWN);

module.exports = {
		pack: pack,
		open: xsalsa20poly1305_pad_open_trim,
		formatWN: formatWN,
		NONCE_LENGTH: 24,
		KEY_LENGTH: 32,
		POLY_LENGTH: 16,
		JWK_ALG_NAME: 'NaCl-sbox-XSP'
};
Object.freeze(module.exports);
