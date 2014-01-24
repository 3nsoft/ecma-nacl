/* Copyright(c) 2013 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * This file is an external interface of Ecma-NaCl library.
 */

var secret_box = require('./boxes/secret_box')
, box = require('./boxes/box')
, TypedArraysFactory = require('./util/arrays')
, verify = require('./util/verify').verify
, nonceMod = require('./util/nonce')
, fileXSP = require('./file/xsp');

/**
 * @param x typed array
 * @param y typed array
 * @returns true, if arrays have the same length and their elements are equal;
 * and false, otherwise.
 */
function compareVectors(x, y) {
	"use strict";
	if (x.length !== y.length) { return false; }
	return verify(x, y, x.length);
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
function packFormatWN(m, n, k, arrFactory) {
	"use strict";
	var c = new Uint8Array(40+m.length);
	secret_box.packIntoArrWithNonce(c, m, n, k, arrFactory);
	return c;
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

var formatWN = {
	pack: packFormatWN,
	open: secret_box.openArrWithNonce,
	copyNonceFrom: copyNonceFrom
};
Object.freeze(formatWN);

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
function makeSecretBoxEncryptor(key, nextNonce) {
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

var sbox = {
		pack: secret_box.pack,
		open: secret_box.open,
		formatWN: formatWN,
		makeEncryptor: makeSecretBoxEncryptor,
		NONCE_LENGTH: secret_box.NONCE_LENGTH,
		KEY_LENGTH: secret_box.KEY_LENGTH,
		JWK_ALG_NAME: 'NaCl-sbox-XSP'
};
Object.freeze(sbox);

module.exports = {
		secret_box: sbox,
		box: box,
		fileXSP: fileXSP,
		TypedArraysFactory: TypedArraysFactory,
		compareVectors: compareVectors,
		wipeArrays: TypedArraysFactory.prototype.wipe,
		advanceNonceOddly: nonceMod.advanceOddly,
		advanceNonceEvenly: nonceMod.advanceEvenly,
		makeSecretBoxEncryptor: makeSecretBoxEncryptor
};
Object.freeze(module.exports);
