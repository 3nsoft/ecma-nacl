/* Copyright(c) 2013 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * 
 * @param n is Uint8Array, 24 bytes long nonce that will be changed in-place.
 * @param delta is a number, by which 8-byte numbers, constituting given
 * 24-bytes nonce, are advanced.
 */
function advanceNonce(n, delta) {
	"use strict";
	if (n.BYTES_PER_ELEMENT !== 1) { throw new TypeError(
			"Nonce array n must be Uint8Array."); }
	if (n.length !== 24) { throw new Error(
			"Nonce array n should have 24 elements (bytes) in it, but it is "+
			n.length+" elements long."); }
	var t;
	for (var i=0; i<3; i+=1) {
		t = delta;
		for (var j=0; j<8; j+=1) {
			t += n[j+i*8];
			n[j+i*8] = t & 0xff;
			t >>>= 8;
			if (t === 0) { break; }
		}
	}
}

function advanceNonceOddly(n) {
	"use strict";
	advanceNonce(n, 1);
}

function advanceNonceEvenly(n) {
	"use strict";
	advanceNonce(n, 2);
}

var nonceModule = {
		advanceOddly: advanceNonceOddly,
		advanceEvenly: advanceNonceEvenly
};

Object.freeze(nonceModule);

module.exports = nonceModule;
