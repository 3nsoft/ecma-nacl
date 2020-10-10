/*
 Copyright(c) 2013 - 2015, 2020 3NSoft Inc.
 This Source Code Form is subject to the terms of the Mozilla Public
 License, v. 2.0. If a copy of the MPL was not distributed with this
 file, you can obtain one at http://mozilla.org/MPL/2.0/.
*/

import { Factory, makeFactory } from '../util/arrays';
import * as core from './core';

/**
 * sigma array in crypto_stream/salsa20/ref/stream.c
 */
export const SIGMA = new Uint8Array(16);
(() => {
	const str = "expand 32-byte k";
	for (let i=0; i<16; i+=1) {
		SIGMA[i] = str.charCodeAt(i);
	}
})();

/**
 * Analog of crypto_stream in crypto_stream/salsa20/ref/stream.c
 * @param c is Uint8Array of some length, for outgoing bytes (cipher).
 * @param n is Uint8Array, 8 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long key.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use. It may be undefined, in which case an internally created one is used.
 */
function stream_salsa20(
	c: Uint8Array, n: Uint8Array, k: Uint8Array, arrFactory?: Factory
): void {
	
	if (!arrFactory) { arrFactory = makeFactory(); }
	const inArr = arrFactory.getUint8Array(16);
	let u = 0;

	if (c.length === 0) { return; }

	inArr.set(n);
	for (let i=8; i<16; i+=1) { inArr[i] = 0; }

	let cstart = 0
	, clen = c.length
	, outArr;
	while (clen >= 64) {
		outArr = new Uint8Array(c.buffer, cstart, 64);
		
		core.salsa20(outArr,inArr,k,SIGMA);
		
		u = 1;
		for (let i=8; i < 16; i+=1) {
			u += inArr[i];
			u &= 0xffffffff;
			inArr[i] = u;
			u >>>= 8;
		}

		clen -= 64;
		cstart += 64;
	}

	if (clen > 0) {
		const block = arrFactory.getUint8Array(64);
		core.salsa20(block,inArr,k,SIGMA);
		for (let i=0; i < clen; i+=1) {
			c[cstart+i] = block[i];
		}
		arrFactory.recycle(block);
	}
	
	arrFactory.recycle(inArr);
}

/**
 * Analog of crypto_stream_xor in crypto_stream/salsa20/ref/xor.c
 * with an addition of pad parameter for incoming array, which creates the pad on
 * the fly, without wasteful copying of potentially big xor-ed incoming array.
 * @param c is Uint8Array of outgoing bytes with resulting cipher, of the same
 * length as incoming array m, plus the pad.
 * @param m is Uint8Array of incoming bytes, that are xor-ed into cryptographic
 * stream.
 * @param mPadLen is number of zeros that should be in front of message array,
 * always between 0 and 63.
 * @param n is Uint8Array, 8 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long key.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use. It may be undefined, in which case an internally created one is used.
 */
function stream_salsa20_xor(
	c: Uint8Array, m: Uint8Array, mPadLen: number, n: Uint8Array, k: Uint8Array,
	arrFactory?: Factory
): void {
	
	if (!arrFactory) { arrFactory = makeFactory(); }
	const inArr = arrFactory.getUint8Array(16);
	const block = arrFactory.getUint8Array(64);
	let u = 0;

	if (m.length === 0) { return; }

	inArr.set(n);
	for (let i=8; i<16; i+=1) { inArr[i] = 0; }

	let mWithPadLen = m.length+mPadLen;
	
	if (mWithPadLen < 64) {
		core.salsa20(block,inArr,k,SIGMA);
		for (let i=0; i<mPadLen; i+=1) {
			c[i] = block[i];
		}
		for (let i=mPadLen; i<mWithPadLen; i+=1) {
			c[i] = m[i-mPadLen] ^ block[i];
		}
		return;
	}
	
	let cp = 0
	, mp = 0;
	{ // first loop with pad
		core.salsa20(block,inArr,k,SIGMA);
		for (let i=0; i<mPadLen; i+=1) {
			c[i] = block[i];
		}
		for (let i=mPadLen; i<64; i+=1) {
			c[i] = m[i-mPadLen] ^ block[i];
		}
		
		u = 1;
		for (let i=8; i<16; i+=1) {
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
		core.salsa20(block,inArr,k,SIGMA);
		for (let i=0; i<64; i+=1) {
			c[cp+i] = m[mp+i] ^ block[i];
		}
		
		u = 1;
		for (let i=8; i<16; i+=1) {
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
		core.salsa20(block,inArr,k,SIGMA);
		for (let i=0; i<mWithPadLen; i+=1) {
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
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use.
 */
export function xsalsa20(
	c: Uint8Array, n: Uint8Array, k: Uint8Array, arrFactory: Factory
): void {

	const subkey = arrFactory.getUint8Array(32);
	const n_16 = n.subarray(16, 24);
	
	core.hsalsa20(subkey,n,k,SIGMA);
	stream_salsa20(c,n_16,subkey,arrFactory);
	
	arrFactory.recycle(subkey);
}

/**
 * Analog of crypto_stream_xor in crypto_stream/xsalsa20/ref/xor.c
 * @param c is Uint8Array of outgoing bytes with resulting cipher, of the same
 * length as incoming array m.
 * @param m is Uint8Array of incoming bytes, of some plain text message.
 * @param mPadLen is number of zeros that should be in front of message array,
 * always between 0 and 63.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long key.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use. It may be undefined, in which case an internally created one is
 * used.
 */
export function xsalsa20_xor(
	c: Uint8Array, m: Uint8Array, mPadLen: number, n: Uint8Array, k: Uint8Array,
	arrFactory?: Factory
): void {
	
	if (!arrFactory) { arrFactory = makeFactory(); }
	const subkey = arrFactory.getUint8Array(32);
	const n_16 = n.subarray(16, 24);
	
	core.hsalsa20(subkey,n,k,SIGMA);
	stream_salsa20_xor(c,m,mPadLen,n_16,subkey,arrFactory);
	
	arrFactory.recycle(subkey);
}

Object.freeze(exports);