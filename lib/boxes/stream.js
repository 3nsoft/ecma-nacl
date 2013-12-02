/* Copyright(c) 2013 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

var ArraysFactory = require('../util/arrays');
var core = require('./core');

/**
 * sigma array in crypto_stream/salsa20/ref/stream.c
 */
var sigma = new Uint8Array(16);
(function () {
	"use strict";
	var str = "expand 32-byte k";
	for (var i=0; i<16; i+=1) {
		sigma[i] = str.charCodeAt(i);
	}
})();

/**
 * Analog of crypto_stream in crypto_stream/salsa20/ref/stream.c
 * @param c is Uint8Array of some length, for outgoing bytes (cipher).
 * @param n is Uint8Array, 8 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long key.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 */
function stream_salsa20(c, n, k, arrFactory) {
	"use strict";
	
	if (!arrFactory) { arrFactory = new ArraysFactory(); }
	var inArr = arrFactory.getUint8Array(16)
	, u = 0;

	if (c.length === 0) { return; }

	inArr.set(n);
	for (var i=8; i<16; i+=1) { inArr[i] = 0; }

	var cstart = 0
	, clen = c.length
	, outArr;
	while (clen >= 64) {
		outArr = new Uint8Array(c, cstart, 64);
		
		core.salsa20(outArr,inArr,k,sigma,arrFactory);
		
		u = 1;
		for (var i=8; i<16; i+=1) {
			u += inArr[i];
			u &= 0xffffffff;
			inArr[i] = u;
			u >>>= 8;
		}

		clen -= 64;
		cstart += 64;
	}

	if (clen > 0) {
		var block = arrFactory.getUint8Array(64);
		core.salsa20(block,inArr,k,sigma,arrFactory);
		for (i = 0;i < clen;++i) {
			c[i] = block[i];
		}
		arrFactory.recycle(block);
	}
	
	arrFactory.recycle(inArr);
}

/**
 * Analog of crypto_stream_xor in crypto_stream/salsa20/ref/xor.c
 * with an addition of pad parameter for incoming array, which creates the pad on the fly,
 * without wasteful copying of potentially big xor-ed incoming array.
 * @param c is Uint8Array of outgoing bytes with resulting cipher, of the same length as
 * incoming array m, plus the pad.
 * @param m is Uint8Array of incoming bytes, that are xor-ed into cryptographic stream.
 * @param mPadLen is number of zeros that should be in front of message array, always between 0 and 63.
 * @param n is Uint8Array, 8 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long key.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 */
function stream_salsa20_xor(c, m, mPadLen, n, k, arrFactory) {
	"use strict";
	
	if (!arrFactory) { arrFactory = new ArraysFactory(); }
	var inArr = arrFactory.getUint8Array(16)
	, block = arrFactory.getUint8Array(64)
	, u = 0;

	if (m.length === 0) { return; }

	inArr.set(n);
	for (var i=8; i<16; i+=1) { inArr[i] = 0; }

	var mWithPadLen = m.length+mPadLen;
	
	if (mWithPadLen < 64) {
		core.salsa20(block,inArr,k,sigma,arrFactory);
		for (var i=0; i<mPadLen; i+=1) {
			c[i] = block[i];
		}
		for (var i=mPadLen; i<mWithPadLen; i+=1) {
			c[i] = m[i-mPadLen] ^ block[i];
		}
		return;
	}
	
	var cp = 0
	, mp = 0;
	{ // first loop with pad
		core.salsa20(block,inArr,k,sigma,arrFactory);
		for (var i=0; i<mPadLen; i+=1) {
			c[i] = block[i];
		}
		for (var i=mPadLen; i<64; i+=1) {
			c[i] = m[i-mPadLen] ^ block[i];
		}
		
		u = 1;
		for (var i=8; i<16; i+=1) {
			u += inArr[i];
			u &= 0xffffffff;
			inArr[i] = u;
			u >>>= 8;
		}

		mWithPadLen -= 64;
		mp = 64 - mPadLen;
		cp = 64;
	}

	while (mWithPadLen >= 64) {
		core.salsa20(block,inArr,k,sigma,arrFactory);
		for (var i=0; i<64; i+=1) {
			c[cp+i] = m[mp+i] ^ block[i];
		}
		
		u = 1;
		for (var i=8; i<16; i+=1) {
			u += inArr[i];
			u &= 0xffffffff;
			inArr[i] = u;
			u >>>= 8;
		}

		mWithPadLen -= 64;
		mp += 64;
		cp += 64;
	}

	if (mWithPadLen > 0) {
		core.salsa20(block,inArr,k,sigma,arrFactory);
		for (var i=0; i<mWithPadLen; i+=1) {
			c[cp+i] = m[mp+i] ^ block[i];
		}
	}
	
	arrFactory.recycle(inArr, block);
}

/**
 * Analog of crypto_stream in crypto_stream/xsalsa20/ref/stream.c
 * @param c is Uint8Array of some length, for outgoing bytes (cipher).
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long key.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 */
function stream_xsalsa20(c, n, k, arrFactory) {
	"use strict";
	
	if (!arrFactory) {
		arrFactory = new ArraysFactory();
	}

	var subkey = arrFactory.getUint8Array(32)
	, n_16 = n.subarray(16, 24);
	
	core.hsalsa20(subkey,n,k,sigma,arrFactory);
	stream_salsa20(c,n_16,subkey,arrFactory);
	
	arrFactory.recycle(subkey);
}

/**
 * Analog of crypto_stream_xor in crypto_stream/xsalsa20/ref/xor.c
 * @param c is Uint8Array of outgoing bytes with resulting cipher, of the same length as
 * incoming array m.
 * @param m is Uint8Array of incoming bytes, of some plain text message.
 * @param mPadLen is number of zeros that should be in front of message array, always between 0 and 63.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long key.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 */
function stream_xsalsa20_xor(c, m, mPadLen, n, k, arrFactory) {
	"use strict";
	
	if (!arrFactory) { arrFactory = new ArraysFactory(); }
	var subkey = arrFactory.getUint8Array(32)
	, n_16 = n.subarray(16, 24);
	
	core.hsalsa20(subkey,n,k,sigma,arrFactory);
	stream_salsa20_xor(c,m,mPadLen,n_16,subkey,arrFactory);
	
	arrFactory.recycle(subkey);
}

module.exports = {
		xsalsa20: stream_xsalsa20,
		xsalsa20_xor: stream_xsalsa20_xor,
		SIGMA: sigma
};