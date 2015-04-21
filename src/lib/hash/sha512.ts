/* Copyright(c) 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * This contains implementation of SHA512.
 * Implementation note 1:
 * All C macros shuffle variables with digits in their names.
 * This gives a possibilty to have functions that except indecies,
 * which are shuffled/set at call point.
 * In everything else we try to keep as close to original code as
 * possible.
 * Implementation note 2:
 * Since there are no unsigned 64-bit integers in JavaScript, we
 * use 32-bit integers.
 * Notice that in array we keep high int first, with lower int following.
 */

import arrays = require('../util/arrays');

/**
 * This adds 64 bit integer from x into s.
 */
function addInto(s: Uint32Array, si: number, x: Uint32Array, xi: number): void {
	var h = s[si]  + x[xi];
	var l = s[si+1]+ x[xi+1];
	s[si] = h + ((l / 0x100000000) | 0);
	s[si+1] = l;
}

function shr(t: Uint32Array, x: Uint32Array, xi: number, c: number): void {
	var h = x[xi];
	var l = x[xi+1];
	t[0] = h >>> c;
	t[1] = (h << (32 - c)) | (l >>> c);
}

/**
 * Analog of load_bigendian in crypto_hashblocks/sha512/inplace/blocks.c
 */
function load_bigendian(s: Uint32Array, si: number,
		x: Uint8Array, i: number): void {
	s[si] = (x[i+3] | x[i+2] << 8) | (x[i+1] << 16) | (x[i] << 24);
	s[si+1] = (x[i+7] | x[i+6] << 8) | (x[i+5] << 16) | (x[i+4] << 24);
}

/**
 * Analog of store_bigendian in crypto_hashblocks/sha512/inplace/blocks.c
 */
function store_bigendian(x: Uint8Array, i: number,
		u: Uint32Array, ui: number): void {
	var h = u[ui];
	var l = u[ui+1];
	x[i+7] = l;
	x[i+6] = l >>> 8;
	x[i+5] = l >>> 16;
	x[i+4] = l >>> 24;
	x[i+3] = h;
	x[i+2] = h >>> 8;
	x[i+1] = h >>> 16;
	x[i] = h >>> 24;
}

/**
 * Analog of macro ROTR in crypto_hashblocks/sha512/inplace/blocks.c
 */
function ROTRandXorInto(t: Uint32Array,
		x: Uint32Array, xi: number, c: number): void {
	var h = x[xi];
	var l = x[xi+1];
	if (c <= 32) {
		t[0] ^= (l << (32 - c)) | (h >>> c);
		t[1] ^= (h << (32 - c)) | (l >>> c);
	} else {
		t[0] ^= (h << (64 - c)) | (l >>> (c - 32));
		t[1] ^= (l << (64 - c)) | (h >>> (c - 32));
	}
}

/**
 * Analog of macro Ch in crypto_hashblocks/sha512/inplace/blocks.c
 */
function Ch(t: Uint32Array, r: Uint32Array,
		xi: number, yi: number, zi: number): void {
	var xh = r[xi];
	var xl = r[xi+1];
	t[0] = (xh & r[yi]) ^ (~xh & r[zi]);
	t[1] = (xl & r[yi+1]) ^ (~xl & r[zi+1]);
}

/**
 * Analog of macro Maj in crypto_hashblocks/sha512/inplace/blocks.c
 */
function Maj(t: Uint32Array, r: Uint32Array,
		xi: number, yi: number, zi: number): void {
	var xh = r[xi];
	var xl = r[xi+1];
	var yh = r[yi];
	var yl = r[yi+1];
	var zh = r[zi];
	var zl = r[zi+1];
	t[0] = (xh & yh) ^ (xh & zh) ^ (yh & zh);
	t[1] = (xl & yl) ^ (xl & zl) ^ (yl & zl);
}

/**
 * Analog of macro Sigma0 in crypto_hashblocks/sha512/inplace/blocks.c
 */
function Sigma0(t: Uint32Array, x: Uint32Array, xi: number): void {
	t[0] = 0;
	t[1] = 0;
	ROTRandXorInto(t, x, xi, 28);
	ROTRandXorInto(t, x, xi, 34);
	ROTRandXorInto(t, x, xi, 39);
}

/**
 * Analog of macro Sigma1 in crypto_hashblocks/sha512/inplace/blocks.c
 */
function Sigma1(t: Uint32Array, x: Uint32Array, xi: number): void {
	t[0] = 0;
	t[1] = 0;
	ROTRandXorInto(t, x, xi, 14);
	ROTRandXorInto(t, x, xi, 18);
	ROTRandXorInto(t, x, xi, 41);
}

/**
 * Analog of macro sigma0 in crypto_hashblocks/sha512/inplace/blocks.c
 */
function sigma0(t: Uint32Array, x: Uint32Array, xi: number): void {
	shr(t, x, xi, 7);
	ROTRandXorInto(t, x, xi, 1);
	ROTRandXorInto(t, x, xi, 8);
}

/**
 * Analog of macro sigma1 in crypto_hashblocks/sha512/inplace/blocks.c
 */
function sigma1(t: Uint32Array, x: Uint32Array, xi: number): void {
	shr(t, x, xi,  6);
	ROTRandXorInto(t, x, xi, 19);
	ROTRandXorInto(t, x, xi, 61);
}

/**
 * Analog of macro M in crypto_hashblocks/sha512/inplace/blocks.c
 */
function M(w: Uint32Array, i0: number, i14: number, i9: number, i1: number,
		t: Uint32Array): void {
	sigma1(t, w, i14);
	addInto(w, i0, t, 0);
	addInto(w, i0, w, i9);
	sigma0(t, w, i1);
	addInto(w, i0, t, 0);
}

/**
 * Analog of macro EXPAND in crypto_hashblocks/sha512/inplace/blocks.c
 */
function EXPAND(w: Uint32Array, t: Uint32Array): void {
	M(w,  0, 28, 18,  2,  t);
	M(w,  2, 30, 20,  4,  t);
	M(w,  4,  0, 22,  6,  t);
	M(w,  6,  2, 24,  8,  t);
	M(w,  8,  4, 26, 10,  t);
	M(w, 10,  6, 28, 12,  t);
	M(w, 12,  8, 30, 14,  t);
	M(w, 14, 10,  0, 16,  t);
	M(w, 16, 12,  2, 18,  t);
	M(w, 18, 14,  4, 20,  t);
	M(w, 20, 16,  6, 22,  t);
	M(w, 22, 18,  8, 24,  t);
	M(w, 24, 20, 10, 26,  t);
	M(w, 26, 22, 12, 28,  t);
	M(w, 28, 24, 14, 30,  t);
	M(w, 30, 26, 16,  0,  t);
}

/**
 * Analog of macro F in crypto_hashblocks/sha512/inplace/blocks.c
 */
function F(r: Uint32Array, i0: number, i1: number, i2: number, i3: number,
		i4: number, i5: number, i6: number, i7: number,
		w: Uint32Array, wi: number, k: Uint32Array, ki: number,
		t: Uint32Array): void {
	Sigma1(t, r, i4);
	addInto(r, i7, t, 0);
	Ch(t, r, i4, i5, i6);
	addInto(r, i7, t, 0);
	addInto(r, i7, k, ki);
	addInto(r, i7, w, wi);

	addInto(r, i3, r, i7);
	
	Sigma0(t, r, i0);
	addInto(r, i7, t, 0);
	Maj(t, r, i0, i1, i2);
	addInto(r, i7, t, 0);
}

/**
 * Analog of round in crypto_hashblocks/sha512/inplace/blocks.c
 */
var round = new Uint32Array([
	0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f,
	0xe9b5dba5, 0x8189dbbc, 0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
	0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118, 0xd807aa98, 0xa3030242,
	0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
	0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235,
	0xc19bf174, 0xcf692694, 0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
	0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65, 0x2de92c6f, 0x592b0275,
	0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
	0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f,
	0xbf597fc7, 0xbeef0ee4, 0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
	0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70, 0x27b70a85, 0x46d22ffc,
	0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
	0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6,
	0x92722c85, 0x1482353b, 0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
	0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30, 0xd192e819, 0xd6ef5218,
	0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
	0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99,
	0x34b0bcb5, 0xe19b48a8, 0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
	0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3, 0x748f82ee, 0x5defb2fc,
	0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
	0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915,
	0xc67178f2, 0xe372532b, 0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
	0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178, 0x06f067aa, 0x72176fba,
	0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
	0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc,
	0x431d67c4, 0x9c100d4c, 0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
	0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817 ]);

/**
 * Analog of macro G in crypto_hashblocks/sha512/inplace/blocks.c
 */
function G(r: Uint32Array, w: Uint32Array, i: number, t: Uint32Array): void {
	F(r, 0, 2, 4, 6, 8,10,12,14, w, 0, round,     (i)*2, t);
	F(r,14, 0, 2, 4, 6, 8,10,12, w, 2, round, (i+ 1)*2, t);
	F(r,12,14, 0, 2, 4, 6, 8,10, w, 4, round, (i+ 2)*2, t);
	F(r,10,12,14, 0, 2, 4, 6, 8, w, 6, round, (i+ 3)*2, t);
	F(r, 8,10,12,14, 0, 2, 4, 6, w, 8, round, (i+ 4)*2, t);
	F(r, 6, 8,10,12,14, 0, 2, 4, w,10, round, (i+ 5)*2, t);
	F(r, 4, 6, 8,10,12,14, 0, 2, w,12, round, (i+ 6)*2, t);
	F(r, 2, 4, 6, 8,10,12,14, 0, w,14, round, (i+ 7)*2, t);
	F(r, 0, 2, 4, 6, 8,10,12,14, w,16, round, (i+ 8)*2, t);
	F(r,14, 0, 2, 4, 6, 8,10,12, w,18, round, (i+ 9)*2, t);
	F(r,12,14, 0, 2, 4, 6, 8,10, w,20, round, (i+10)*2, t);
	F(r,10,12,14, 0, 2, 4, 6, 8, w,22, round, (i+11)*2, t);
	F(r, 8,10,12,14, 0, 2, 4, 6, w,24, round, (i+12)*2, t);
	F(r, 6, 8,10,12,14, 0, 2, 4, w,26, round, (i+13)*2, t);
	F(r, 4, 6, 8,10,12,14, 0, 2, w,28, round, (i+14)*2, t);
	F(r, 2, 4, 6, 8,10,12,14, 0, w,30, round, (i+15)*2, t);
}

/**
 * Analog of crypto_hashblocks in crypto_hashblocks/sha512/inplace/blocks.c
 */
function crypto_hashblocks(statebytes: Uint8Array, inArr: Uint8Array,
		arrFactory: arrays.Factory): number {
	var state = arrFactory.getUint32Array(16);
	var r = arrFactory.getUint32Array(16);
	var w = arrFactory.getUint32Array(32);
	var t = arrFactory.getUint32Array(2);
	var inlen = inArr.length;
	var inInd = 0;

	for (var i=0; i<8; i+=1) {
		load_bigendian(r, i*2, statebytes, i*8);
	}
	state.set(r);

	while (inlen >= 128) {
		
		for (var i=0; i<16; i+=1) {
			load_bigendian(w, i*2, inArr, inInd + i*8);
		}

		G(r, w, 0, t);
		EXPAND(w, t);
		G(r, w, 16, t);
		EXPAND(w, t);
		G(r, w, 32, t);
		EXPAND(w, t);
		G(r, w, 48, t);
		EXPAND(w, t);
		G(r, w, 64, t);

		for (var i=0; i<8; i+=1) {
			addInto(r, i*2, state, i*2);
		}
		state.set(r);

		inInd += 128;
		inlen -= 128;
	}

	for (var i=0; i<8; i+=1) {
		store_bigendian(statebytes, i*8, state, i*2);
	}
	
	arrFactory.recycle(r, w, t);
	
	return inlen;
}

/**
 * Analog of iv in crypto_hash/sha512/ref/hash.c
 */
var iv = new Uint8Array(64);
iv.set([ 0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
		 0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
		 0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
		 0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
		 0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
		 0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
		 0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
		 0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79 ]);

function hash_padded_block(h: Uint8Array, oddBytes: Uint8Array,
		totalLen: number, arrFactory: arrays.Factory): void {
	var padded = arrFactory.getUint8Array(256);
	var oddLen = oddBytes.length;
	var bytes = arrFactory.getUint32Array(2);
	bytes[0] = (totalLen / 0x20000000) | 0;
	bytes[1] = totalLen << 3;

	for (var i=0; i<oddLen; i+=1) {
		padded[i] = oddBytes[i];
	}
	padded[oddLen] = 0x80;

	if (oddLen < 112) {
		for (var i=oddLen+1; i<120; i+=1) {
			padded[i] = 0;
		}
		store_bigendian(padded, 120, bytes, 0);
		crypto_hashblocks(h, padded.subarray(0,128), arrFactory);
	} else {
		for (var i=oddLen+1; i<248; i+=1) {
			padded[i] = 0;
		}
		store_bigendian(padded, 248, bytes, 0);
		crypto_hashblocks(h, padded, arrFactory);
	}
	
	arrFactory.recycle(padded, bytes);
}

/**
 * Analog of crypto_hash in crypto_hash/sha512/ref/hash.c
 * with ending part of make hash of padded arranged into its
 * own function.
 */
export function hash(inArr: Uint8Array,
		arrFactory?: arrays.Factory): Uint8Array {

	if (inArr.length > 0xffffffffffff) { new Error("This implementation "+
			"cannot handle byte arrays longer than 2^48 (256 TB)."); }
	if (!arrFactory) {
		arrFactory = arrays.makeFactory();
	}
	
	var h = arrFactory.getUint8Array(64);
	var totalLen = inArr.length;

	h.set(iv);

	var oddLen = crypto_hashblocks(h, inArr, arrFactory);
	inArr = inArr.subarray(totalLen - oddLen);
	
	hash_padded_block(h, inArr, totalLen, arrFactory);

	arrFactory.wipeRecycled();

	return h;
}


export interface Hasher {
	
	/**
	 * This absorbs bytes as they stream in, hashing even blocks.
	 */
	update(m: Uint8Array): void;
	
	/**
	 * This method tells a hasher that there are no more bytes to hash,
	 * and that a final hash should be produced.
	 * This also forgets all of hasher's state.
	 * And if this hasher is not single-use, update can be called
	 * again to produce hash for a new stream of bytes.
	 */
	digest(): Uint8Array;
	
	/**
	 * This method securely wipes internal state, and drops resources, so that
	 * memory can be GC-ed.
	 */
	destroy(): void;
}

export function makeHasher(isSingleUse: boolean = true,
		arrFactory?: arrays.Factory): Hasher {
	if (!arrFactory) { arrFactory = arrays.makeFactory(); }
	
	var cache = arrFactory.getUint8Array(128);
	var cachedBytes = 0;
	var totalLen = 0;
	var h: Uint8Array = null;
	
	return {
		update: function(m: Uint8Array): void {
			if (!cache) { throw new Error("Cannot use destroyed hasher."); }
			if (m.length === 0) { return; }
			totalLen += m.length;
			if (!h) {
				h = arrFactory.getUint8Array(64);
				h.set(iv);
			}
			if (cachedBytes > 0) {
				var delta = Math.min(m.length, 128-cachedBytes);
				for (var i=0; i<delta; i+=1) {
					cache[cachedBytes + i] = m[i];
				}
				if ((cachedBytes + delta) < 128) {
					cachedBytes += delta;
					return;
				} else {
					crypto_hashblocks(h, cache, arrFactory);
					cachedBytes = 0;
					m = m.subarray(delta);
					if (m.length === 0) {
						arrFactory.wipe(cache);
						return;
					}
				}
			}
			cachedBytes = crypto_hashblocks(h, m, arrFactory);
			m = m.subarray(m.length - cachedBytes);
			for (var i=0; i<cachedBytes; i+=1) {
				cache[i] = m[i];
			}
			for (var i=cachedBytes; i<cache.length; i+=1) {
				cache[i] = 0;
			}
		},
		digest: function(): Uint8Array {
			if (!cache) { throw new Error("Cannot use destroyed hasher."); }
			if (!h) { throw new Error("No bytes were hashed so far."); }
			hash_padded_block(h,
					cache.subarray(0, cachedBytes),
					totalLen, arrFactory);
			var hashResult = h;
			h = null;
			arrFactory.wipe(cache);
			totalLen = 0;
			cachedBytes = 0;
			arrFactory.wipeRecycled();
			if (isSingleUse) { this.destroy(); }
			return hashResult;
		},
		destroy: function(): void {
			if (!cache) { return; }
			arrFactory.recycle(cache);
			if (!h) {
				arrFactory.recycle(h);
				h = null;
			}
			arrFactory.wipeRecycled();
			cache = null;
			arrFactory = null;
		}
	};
}

Object.freeze(exports);