/* Copyright(c) 2013 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

var mult32 = require('../util/int32').mult;
var verify = require('../util/verify');

/**
 * Analog of add in crypto_onetimeauth/poly1305/ref/auth.c
 * @param h is array of 17 uint32's.
 * @param c is array of 17 uint32's.
 */
function add(h, c) {
	var u = 0;
	for (var j= 0; j<17; j+=1) {
		u += h[j] + c[j];
		u &= 0xffffffff;
		h[j] = u & 255;
		u >>>= 8;
	}
}

/**
 * Analog of squeeze in crypto_onetimeauth/poly1305/ref/auth.c
 * @param h is array of 17 uint32's.
 */
function squeeze(h) {
	var u = 0;
	for (var j=0; j<16; j+=1) {
		u += h[j];
		u &= 0xffffffff;
		h[j] = u & 255;
		u >>>= 8;
	}
	u += h[16];
	u &= 0xffffffff;
	h[16] = u & 3;
	u = 5 * (u >>> 2);	// multiplication by 5 is safe here
	u &= 0xffffffff;
	for (j=0; j<16; j+=1) {
		u += h[j];
		u &= 0xffffffff;
		h[j] = u & 255;
		u >>>= 8;
	}
	u += h[16];
	u &= 0xffffffff;
	h[16] = u;
}

/**
 * minusp array in crypto_onetimeauth/poly1305/ref/auth.c
 */
var minusp = new Uint32Array(17);
minusp.set([ 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252 ]);

/**
 * Analog of freeze in crypto_onetimeauth/poly1305/ref/auth.c
 * @param h is array of 17 uint32's.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 */
function freeze(h, arrFactory) {
	var horig = arrFactory.getUint32Array(17);
	horig.set(h);
	add(h, minusp);
	var negative = -(h[16] >> 7);
	negative &= 0xffffffff;
	for (var j=0; j<17; j+=1) {
		h[j] ^= negative & (horig[j] ^ h[j]);
	}
	arrFactory.recycle(horig);
}

/**
 * Analog of mulmod in crypto_onetimeauth/poly1305/ref/auth.c
 * @param h is array of 17 uint32's.
 * @param r is array of 17 uint32's.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 */
function mulmod(h, r, arrFactory) {
	var hr = arrFactory.getUint32Array(17)
	, u = 0;
	for (var i=0; i<17; i+=1) {
		u = 0;
		for (var j=0; j<=i; j+=1) {
			u += mult32(h[j], r[i - j]);
			u &= 0xffffffff;
		}
		for (var j=i+1; j<17; j+=1) {
			u += 320 * mult32(h[j], r[i + 17 - j]);	// regular multiplication by 320 is safe here
			u &= 0xffffffff;
		}
		hr[i] = u;
	}
	h.set(hr);
	squeeze(h);
	arrFactory.recycle(hr);
}

/**
 * Analog of crypto_onetimeauth in crypto_onetimeauth/poly1305/ref/auth.c
 * @param outArr is Uint8Array, 16 bytes long, into which result is placed.
 * @param inArr is Uint8Array, with incoming bytes, whatever the length there is.
 * @param k is Uint8Array, 32 bytes long.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 */
function crypto_onetimeauth(outArr, inArr, k, arrFactory) {
	var r = arrFactory.getUint32Array(17)
	, h = arrFactory.getUint32Array(17)
	, c = arrFactory.getUint32Array(17)
	, inlen = inArr.length
	, inArrInd = 0;

	r[0] = k[0];
	r[1] = k[1];
	r[2] = k[2];
	r[3] = k[3] & 15;
	r[4] = k[4] & 252;
	r[5] = k[5];
	r[6] = k[6];
	r[7] = k[7] & 15;
	r[8] = k[8] & 252;
	r[9] = k[9];
	r[10] = k[10];
	r[11] = k[11] & 15;
	r[12] = k[12] & 252;
	r[13] = k[13];
	r[14] = k[14];
	r[15] = k[15] & 15;
	r[16] = 0;
	
	for (var j=0; j<17; j+=1) { h[j] = 0; }

	var j = 0;
	while (inlen > 0) {
		for (j=0; j<17; j+=1) {
			c[j] = 0;
		}
		for (j=0; (j < 16) && (j < inlen); j+=1) {
			c[j] = inArr[inArrInd+j];
		}
		c[j] = 1;
		inArrInd += j; inlen -= j;
		add(h, c);
		mulmod(h, r, arrFactory);
	}

	freeze(h, arrFactory);

	for (var j=0; j<16; j+=1) {
		c[j] = k[j + 16];
	}
	c[16] = 0;
	add(h, c);
	for (var j=0; j<16; j+=1) {
		outArr[j] = h[j];
	}
}


/**
 * Analog of crypto_onetimeauth in crypto_onetimeauth/poly1305/ref/verify.c
 * @param h is Uint8Array, 16 bytes long.
 * @param inArr is Uint8Array, with incoming bytes, whatever the length there is.
 * @param k is Uint8Array, 32 bytes long.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 */
function crypto_onetimeauth_verify(h, inArr, k, arrFactory) {
	var correct = arrFactory.getUint8Array(16);
	crypto_onetimeauth(correct, inArr, k, arrFactory);
	var areSame = verify.v16(h, correct);
	arrFactory.recycle(correct);
	return areSame;
}

module.exports = {
		poly1305: crypto_onetimeauth,
		poly1305_verify: crypto_onetimeauth_verify
};