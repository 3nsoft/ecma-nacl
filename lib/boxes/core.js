/* Copyright(c) 2013 Cubic Base Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Analog of load_littleendian in crypto_core/salsa20/ref/core.c
 * @param x is Uint8Array, from which 4-byte number is loaded.
 * @param i is a position, at which 4-byte loading starts.
 * @returns number within uint32 limits, loaded in a littleendian manner from a given array.
 */
function load_littleendian(x, i) {
	return x[i] | (x[i+1] << 8) | (x[i+2] << 16) | (x[i+3] << 24);
}

/**
 * Analog of store_littleendian in crypto_core/salsa20/ref/core.c
 * @param x is Uint8Array, into which 4-byte number is inserted.
 * @param i is a position, at which 4-byte insertion starts.
 * @param u is a number within uint32 limits, to be stored/inserted in a manner, compatible
 * with above loading function.
 */
function store_littleendian(x, i, u) {
	  x[i] = u; u >>>= 8;
	x[i+1] = u; u >>>= 8;
	x[i+2] = u; u >>>= 8;
	x[i+3] = u;
}

/**
 * Analog of crypto_core in crypto_core/salsa20/ref/core.c
 * It makes nicer, shorter code to have variables of this function sitting in one array,
 * but expanded version runs faster.
 * We also inserted rotate() function from the original source.
 * @param outArr is Uint8Array, 64 bytes long, into which result is placed.
 * @param inArr is Uint8Array, 16 bytes long, of incoming bytes.
 * @param k is Uint8Array, 32 bytes long.
 * @param c is Uint8Array, 16 bytes long.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 */
function salsa20(outArr, inArr, k, c, arrFactory) {

	var j0 = x0 = load_littleendian(c, 0)
	,   j1 = x1 = load_littleendian(k, 0)
	,   j2 = x2 = load_littleendian(k, 4)
	,   j3 = x3 = load_littleendian(k, 8)
	,   j4 = x4 = load_littleendian(k, 12)
	,   j5 = x5 = load_littleendian(c, 4)
	,   j6 = x6 = load_littleendian(inArr, 0)
	,   j7 = x7 = load_littleendian(inArr, 4)
	,   j8 = x8 = load_littleendian(inArr, 8)
	,   j9 = x9 = load_littleendian(inArr, 12)
	,  j10 = x10 = load_littleendian(c, 8)
	,  j11 = x11 = load_littleendian(k, 16)
	,  j12 = x12 = load_littleendian(k, 20)
	,  j13 = x13 = load_littleendian(k, 24)
	,  j14 = x14 = load_littleendian(k, 28)
	,  j15 = x15 = load_littleendian(c, 12)
	, t = 0;
	
	for (var i=20; i>0; i-=2) {
		t = ( x0+x12) & 0xffffffff;
		 x4 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = ( x4+ x0) & 0xffffffff;
		 x8 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = ( x8+ x4) & 0xffffffff;
		x12 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = (x12+ x8) & 0xffffffff;
		 x0 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
		t = ( x5+ x1) & 0xffffffff;
		 x9 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = ( x9+ x5) & 0xffffffff;
		x13 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = (x13+ x9) & 0xffffffff;
		 x1 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = ( x1+x13) & 0xffffffff;
		 x5 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
		t = (x10+ x6) & 0xffffffff;
		x14 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = (x14+x10) & 0xffffffff;
		 x2 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = ( x2+x14) & 0xffffffff;
		 x6 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = ( x6+ x2) & 0xffffffff;
		x10 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
		t = (x15+x11) & 0xffffffff;
		 x3 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = ( x3+x15) & 0xffffffff;
		 x7 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = ( x7+ x3) & 0xffffffff;
		x11 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = (x11+ x7) & 0xffffffff;
		x15 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
		t = ( x0+ x3) & 0xffffffff;
		 x1 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = ( x1+ x0) & 0xffffffff;
		 x2 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = ( x2+ x1) & 0xffffffff;
		 x3 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = ( x3+ x2) & 0xffffffff;
		 x0 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
		t = ( x5+ x4) & 0xffffffff;
		 x6 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = ( x6+ x5) & 0xffffffff;
		 x7 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = ( x7+ x6) & 0xffffffff;
		 x4 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = ( x4+ x7) & 0xffffffff;
		 x5 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
		t = (x10+ x9) & 0xffffffff;
		x11 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = (x11+x10) & 0xffffffff;
		 x8 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = ( x8+x11) & 0xffffffff;
		 x9 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = ( x9+ x8) & 0xffffffff;
		x10 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
		t = (x15+x14) & 0xffffffff;
		x12 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = (x12+x15) & 0xffffffff;
		x13 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = (x13+x12) & 0xffffffff;
		x14 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = (x14+x13) & 0xffffffff;
		x15 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
	}

	x0 = (x0 + j0) & 0xffffffff;
	x1 = (x1 + j1) & 0xffffffff;
	x2 = (x2 + j2) & 0xffffffff;
	x3 = (x3 + j3) & 0xffffffff;
	x4 = (x4 + j4) & 0xffffffff;
	x5 = (x5 + j5) & 0xffffffff;
	x6 = (x6 + j6) & 0xffffffff;
	x7 = (x7 + j7) & 0xffffffff;
	x8 = (x8 + j8) & 0xffffffff;
	x9 = (x9 + j9) & 0xffffffff;
	x10 = (x10+j10) & 0xffffffff;
	x11 = (x11+j11) & 0xffffffff;
	x12 = (x12+j12) & 0xffffffff;
	x13 = (x13+j13) & 0xffffffff;
	x14 = (x14+j14) & 0xffffffff;
	x15 = (x15+j15) & 0xffffffff;

	store_littleendian(outArr, 0,x0);
	store_littleendian(outArr, 4,x1);
	store_littleendian(outArr, 8,x2);
	store_littleendian(outArr, 12,x3);
	store_littleendian(outArr, 16,x4);
	store_littleendian(outArr, 20,x5);
	store_littleendian(outArr, 24,x6);
	store_littleendian(outArr, 28,x7);
	store_littleendian(outArr, 32,x8);
	store_littleendian(outArr, 36,x9);
	store_littleendian(outArr, 40,x10);
	store_littleendian(outArr, 44,x11);
	store_littleendian(outArr, 48,x12);
	store_littleendian(outArr, 52,x13);
	store_littleendian(outArr, 56,x14);
	store_littleendian(outArr, 60,x15);
}


/**
 * Analog of crypto_core in crypto_core/hsalsa20/ref2/core.c
 * It makes nicer, shorter code to have variables of this function sitting in one array,
 * but expanded version runs faster.
 * We also inserted rotate() function from the original source.
 * @param outArr is Uint8Array, 32 bytes long, into which result is placed.
 * @param inArr is Uint8Array, 16 bytes long, of incoming bytes.
 * @param k is Uint8Array, 32 bytes long.
 * @param c is Uint8Array, 16 bytes long.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 */
function hsalsa20(outArr, inArr, k, c, arrFactory) {

	var x0 = load_littleendian(c, 0)
	,   x1 = load_littleendian(k, 0)
	,   x2 = load_littleendian(k, 4)
	,   x3 = load_littleendian(k, 8)
	,   x4 = load_littleendian(k, 12)
	,   x5 = load_littleendian(c, 4)
	,   x6 = load_littleendian(inArr, 0)
	,   x7 = load_littleendian(inArr, 4)
	,   x8 = load_littleendian(inArr, 8)
	,   x9 = load_littleendian(inArr, 12)
	,  x10 = load_littleendian(c, 8)
	,  x11 = load_littleendian(k, 16)
	,  x12 = load_littleendian(k, 20)
	,  x13 = load_littleendian(k, 24)
	,  x14 = load_littleendian(k, 28)
	,  x15 = load_littleendian(c, 12);

	for (var i=20; i>0; i-=2) {
		t = ( x0+x12) & 0xffffffff;
		 x4 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = ( x4+ x0) & 0xffffffff;
		 x8 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = ( x8+ x4) & 0xffffffff;
		x12 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = (x12+ x8) & 0xffffffff;
		 x0 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
		t = ( x5+ x1) & 0xffffffff;
		 x9 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = ( x9+ x5) & 0xffffffff;
		x13 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = (x13+ x9) & 0xffffffff;
		 x1 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = ( x1+x13) & 0xffffffff;
		 x5 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
		t = (x10+ x6) & 0xffffffff;
		x14 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = (x14+x10) & 0xffffffff;
		 x2 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = ( x2+x14) & 0xffffffff;
		 x6 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = ( x6+ x2) & 0xffffffff;
		x10 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
		t = (x15+x11) & 0xffffffff;
		 x3 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = ( x3+x15) & 0xffffffff;
		 x7 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = ( x7+ x3) & 0xffffffff;
		x11 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = (x11+ x7) & 0xffffffff;
		x15 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
		t = ( x0+ x3) & 0xffffffff;
		 x1 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = ( x1+ x0) & 0xffffffff;
		 x2 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = ( x2+ x1) & 0xffffffff;
		 x3 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = ( x3+ x2) & 0xffffffff;
		 x0 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
		t = ( x5+ x4) & 0xffffffff;
		 x6 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = ( x6+ x5) & 0xffffffff;
		 x7 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = ( x7+ x6) & 0xffffffff;
		 x4 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = ( x4+ x7) & 0xffffffff;
		 x5 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
		t = (x10+ x9) & 0xffffffff;
		x11 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = (x11+x10) & 0xffffffff;
		 x8 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = ( x8+x11) & 0xffffffff;
		 x9 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = ( x9+ x8) & 0xffffffff;
		x10 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
		t = (x15+x14) & 0xffffffff;
		x12 ^= ((t << 7) & 0xffffffff) | (t >>> 25);
		t = (x12+x15) & 0xffffffff;
		x13 ^= ((t << 9) & 0xffffffff) | (t >>> 23);
		t = (x13+x12) & 0xffffffff;
		x14 ^= ((t << 13) & 0xffffffff) | (t >>> 19);
		t = (x14+x13) & 0xffffffff;
		x15 ^= ((t << 18) & 0xffffffff) | (t >>> 14);
	}

	store_littleendian(outArr, 0, x0);
	store_littleendian(outArr, 4, x5);
	store_littleendian(outArr, 8, x10);
	store_littleendian(outArr, 12, x15);
	store_littleendian(outArr, 16, x6);
	store_littleendian(outArr, 20, x7);
	store_littleendian(outArr, 24, x8);
	store_littleendian(outArr, 28, x9);
}

module.exports = {
		salsa20: salsa20,
		hsalsa20: hsalsa20
};