/* Copyright(c) 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * This is a TypeScrypt rewrite of scrypt-1.1.6.
 * In particular this file contains scrypt algorithm's main part.
 */

import arrays = require('../util/arrays');
import sha256 = require('./sha256');

/**
 * Analog of blkcpy in lib/crypto/crypto_scrypt-ref.c
 */
function blkcpy(dest: Uint8Array, di: number,
		src: Uint8Array, si: number, len: number): void {
	for (var i=0; i<len; i+=1) {
		dest[di+i] = src[si+i];
	}
}

/**
 * Analog of blkxor in lib/crypto/crypto_scrypt-ref.c
 */
function blkxor(dest: Uint8Array, di: number,
		src: Uint8Array, si: number, len: number): void {
	for (var i=0; i<len; i+=1) {
		dest[di+i] ^= src[si+i];
	}
}

/**
 * Analog of salsa20_8 in lib/crypto/crypto_scrypt-ref.c
 * salsa20_8(B):
 * Apply the salsa20/8 core to the provided block.
 */
function salsa20_8(B: Uint8Array): void {

	// inlined load_littleendian()'s
	var x0 = B[0] | (B[1] << 8) | (B[2] << 16) | (B[3] << 24);
	var j0 = x0;
	var x1 = B[4] | (B[5] << 8) | (B[6] << 16) | (B[7] << 24);
	var j1 = x1;
	var x2 = B[8] | (B[9] << 8) | (B[10] << 16) | (B[11] << 24);
	var j2 = x2;
	var x3 = B[12] | (B[13] << 8) | (B[14] << 16) | (B[15] << 24);
	var j3 = x3;
	var x4 = B[16] | (B[17] << 8) | (B[18] << 16) | (B[19] << 24);
	var j4 = x4;
	var x5 = B[20] | (B[21] << 8) | (B[22] << 16) | (B[23] << 24);
	var j5 = x5;
	var x6 = B[24] | (B[25] << 8) | (B[26] << 16) | (B[27] << 24);
	var j6 = x6;
	var x7 = B[28] | (B[29] << 8) | (B[30] << 16) | (B[31] << 24);
	var j7 = x7;
	var x8 = B[32] | (B[33] << 8) | (B[34] << 16) | (B[35] << 24);
	var j8 = x8;
	var x9 = B[36] | (B[37] << 8) | (B[38] << 16) | (B[39] << 24);
	var j9 = x9;
	var x10 = B[40] | (B[41] << 8) | (B[42] << 16) | (B[43] << 24);
	var j10 = x10;
	var x11 = B[44] | (B[45] << 8) | (B[46] << 16) | (B[47] << 24);
	var j11 = x11;
	var x12 = B[48] | (B[49] << 8) | (B[50] << 16) | (B[51] << 24);
	var j12 = x12;
	var x13 = B[52] | (B[53] << 8) | (B[54] << 16) | (B[55] << 24);
	var j13 = x13;
	var x14 = B[56] | (B[57] << 8) | (B[58] << 16) | (B[59] << 24);
	var j14 = x14;
	var x15 = B[60] | (B[61] << 8) | (B[62] << 16) | (B[63] << 24);
	var j15 = x15;
	var t = 0;
	
	for (var i=0; i<8; i+=2) {
		// inlined rotate()'s
		t = ( x0+x12);
		 x4 ^= (t << 7) | (t >>> 25);
		t = ( x4+ x0);
		 x8 ^= (t << 9) | (t >>> 23);
		t = ( x8+ x4);
		x12 ^= (t << 13) | (t >>> 19);
		t = (x12+ x8);
		 x0 ^= (t << 18) | (t >>> 14);
		t = ( x5+ x1);
		 x9 ^= (t << 7) | (t >>> 25);
		t = ( x9+ x5);
		x13 ^= (t << 9) | (t >>> 23);
		t = (x13+ x9);
		 x1 ^= (t << 13) | (t >>> 19);
		t = ( x1+x13);
		 x5 ^= (t << 18) | (t >>> 14);
		t = (x10+ x6);
		x14 ^= (t << 7) | (t >>> 25);
		t = (x14+x10);
		 x2 ^= (t << 9) | (t >>> 23);
		t = ( x2+x14);
		 x6 ^= (t << 13) | (t >>> 19);
		t = ( x6+ x2);
		x10 ^= (t << 18) | (t >>> 14);
		t = (x15+x11);
		 x3 ^= (t << 7) | (t >>> 25);
		t = ( x3+x15);
		 x7 ^= (t << 9) | (t >>> 23);
		t = ( x7+ x3);
		x11 ^= (t << 13) | (t >>> 19);
		t = (x11+ x7);
		x15 ^= (t << 18) | (t >>> 14);
		t = ( x0+ x3);
		 x1 ^= (t << 7) | (t >>> 25);
		t = ( x1+ x0);
		 x2 ^= (t << 9) | (t >>> 23);
		t = ( x2+ x1);
		 x3 ^= (t << 13) | (t >>> 19);
		t = ( x3+ x2);
		 x0 ^= (t << 18) | (t >>> 14);
		t = ( x5+ x4);
		 x6 ^= (t << 7) | (t >>> 25);
		t = ( x6+ x5);
		 x7 ^= (t << 9) | (t >>> 23);
		t = ( x7+ x6);
		 x4 ^= (t << 13) | (t >>> 19);
		t = ( x4+ x7);
		 x5 ^= (t << 18) | (t >>> 14);
		t = (x10+ x9);
		x11 ^= (t << 7) | (t >>> 25);
		t = (x11+x10);
		 x8 ^= (t << 9) | (t >>> 23);
		t = ( x8+x11);
		 x9 ^= (t << 13) | (t >>> 19);
		t = ( x9+ x8);
		x10 ^= (t << 18) | (t >>> 14);
		t = (x15+x14);
		x12 ^= (t << 7) | (t >>> 25);
		t = (x12+x15);
		x13 ^= (t << 9) | (t >>> 23);
		t = (x13+x12);
		x14 ^= (t << 13) | (t >>> 19);
		t = (x14+x13);
		x15 ^= (t << 18) | (t >>> 14);
	}

	x0 = (x0 + j0);
	x1 = (x1 + j1);
	x2 = (x2 + j2);
	x3 = (x3 + j3);
	x4 = (x4 + j4);
	x5 = (x5 + j5);
	x6 = (x6 + j6);
	x7 = (x7 + j7);
	x8 = (x8 + j8);
	x9 = (x9 + j9);
	x10 = (x10+j10);
	x11 = (x11+j11);
	x12 = (x12+j12);
	x13 = (x13+j13);
	x14 = (x14+j14);
	x15 = (x15+j15);

	// inlined store_littleendian()'s
	B[0] = x0;	B[1] = x0>>>8;	B[2] = x0>>>16;	B[3] = x0>>>24;
	B[4] = x1;	B[5] = x1>>>8;	B[6] = x1>>>16;	B[7] = x1>>>24;
	B[8] = x2;	B[9] = x2>>>8;	B[10] = x2>>>16;	B[11] = x2>>>24;
	B[12] = x3;	B[13] = x3>>>8;	B[14] = x3>>>16;	B[15] = x3>>>24;
	B[16] = x4;	B[17] = x4>>>8;	B[18] = x4>>>16;	B[19] = x4>>>24;
	B[20] = x5;	B[21] = x5>>>8;	B[22] = x5>>>16;	B[23] = x5>>>24;
	B[24] = x6;	B[25] = x6>>>8;	B[26] = x6>>>16;	B[27] = x6>>>24;
	B[28] = x7;	B[29] = x7>>>8;	B[30] = x7>>>16;	B[31] = x7>>>24;
	B[32] = x8;	B[33] = x8>>>8;	B[34] = x8>>>16;	B[35] = x8>>>24;
	B[36] = x9;	B[37] = x9>>>8;	B[38] = x9>>>16;	B[39] = x9>>>24;
	B[40] = x10;	B[41] = x10>>>8;	B[42] = x10>>>16;	B[43] = x10>>>24;
	B[44] = x11;	B[45] = x11>>>8;	B[46] = x11>>>16;	B[47] = x11>>>24;
	B[48] = x12;	B[49] = x12>>>8;	B[50] = x12>>>16;	B[51] = x12>>>24;
	B[52] = x13;	B[53] = x13>>>8;	B[54] = x13>>>16;	B[55] = x13>>>24;
	B[56] = x14;	B[57] = x14>>>8;	B[58] = x14>>>16;	B[59] = x14>>>24;
	B[60] = x15;	B[61] = x15>>>8;	B[62] = x15>>>16;	B[63] = x15>>>24;
}

/**
 * Analog of blockmix_salsa8 in lib/crypto/crypto_scrypt-ref.c
 * blockmix_salsa8(B, Y, r):
 * Compute B = BlockMix_{salsa20/8, r}(B).  The input B must be 128r bytes in
 * length; the temporary space Y must also be the same size.
 */
function blockmix_salsa8(B: Uint8Array, Y: Uint8Array, r: number,
		arrFactory: arrays.Factory): void {
	var X = arrFactory.getUint8Array(64);

	/* 1: X <-- B_{2r - 1} */
	blkcpy(X, 0, B, (2*r - 1)*64, 64);

	/* 2: for i = 0 to 2r - 1 do */
	for (var i=0; i<2*r; i+=1) {
		/* 3: X <-- H(X \xor B_i) */
		blkxor(X, 0, B, i*64, 64);
		salsa20_8(X);

		/* 4: Y_i <-- X */
		blkcpy(Y, i*64, X, 0, 64);
	}

	/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
	for (var i=0; i<r; i+=1) {
		blkcpy(B, i*64, Y, (i*2)*64, 64);
	}
	for (var i=0; i<r; i+=1) {
		blkcpy(B, (i + r)*64, Y, (i*2 + 1)*64, 64);
	}
	
	arrFactory.recycle(X);
}

/**
 * Analog of integerify in lib/crypto/crypto_scrypt-ref.c
 * plus another operation.
 * Return the result of parsing B_{2r-1} as a little-endian integer,
 * mod (N-1), where it is assumed that logN < 32.
 * As a result of a limit on N, only 32-bit integer should be read,
 * instead of an original 64-bit.
 */
function integerifyAndMod(B: Uint8Array, r: number, N: number): number {
	var i = (2*r - 1)*64;
	return (B[i] + (B[i+1] << 8) +(B[i+2] << 16) + (B[i+3] << 24)) & (N - 1);
}

interface ProgressIndicator {
	completed: number;
	deltaWork: number;
	deltaN: number;
	addDelta(): void;
}

/**
 * Analog of smix in lib/crypto/crypto_scrypt-ref.c
 * smix(B, r, N, V, XY):
 * Compute B = SMix_r(B, N).  The input B must be 128r bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage
 * XY must be 256r bytes in length.  The value N must be a power of 2, and
 * logN < 32.
 */
function smix(B: Uint8Array, r: number, N: number, V: Uint8Array,
		XY: Uint8Array, progress: ProgressIndicator,
		arrFactory: arrays.Factory): void {
	var X = XY.subarray(0, 128*r);
	var Y = XY.subarray(128*r);
	var nextProgInd = progress.deltaN;

	/* 1: X <-- B */
	blkcpy(X, 0, B, 0, 128 * r);

	/* 2: for i = 0 to N - 1 do */
	for (var i=0; i<N; i+=1) {
		/* 3: V_i <-- X */
		blkcpy(V, i*(128*r), X, 0, 128*r);

		/* 4: X <-- H(X) */
		blockmix_salsa8(X, Y, r, arrFactory);
		
		if (i === nextProgInd) {
			progress.addDelta();
			nextProgInd += progress.deltaN;
		}
	}

	nextProgInd = progress.deltaN;
	
	/* 6: for i = 0 to N - 1 do */
	var j: number;
	for (i=0; i<N; i+=1) {
		/* 7: j <-- Integerify(X) mod N */
		j = integerifyAndMod(X, r, N);

		/* 8: X <-- H(X \xor V_j) */
		blkxor(X, 0, V, j*(128*r), 128*r);
		blockmix_salsa8(X, Y, r, arrFactory);
		
		if (i === nextProgInd) {
			progress.addDelta();
			nextProgInd += progress.deltaN;
		}
	}

	/* 10: B' <-- X */
	blkcpy(B, 0, X, 0, 128*r);
}

/**
 * Analog of crypto_scrypt in lib/crypto/crypto_scrypt-ref.c
 * crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen) and write the result into buf.  The parameters r, p, and buflen
 * must satisfy r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N
 * must be a power of 2.
 *
 * Return Uint8Array with result; or throw an error.
 */
export function scrypt(passwd: Uint8Array, salt: Uint8Array,
		logN: number, r: number, p: number, dkLen: number,
		progressCB: (p: number) => void,
		arrFactory?: arrays.Factory): Uint8Array {
	if (!arrFactory) { arrFactory = arrays.makeFactory(); }
	
	if ((logN >= 32) || (logN < 1)) { throw new Error(
			'Parameter logN is out of bounds.'); }
	if ((r < 1) || (p < 1) || (r*p >= (1 << 30))) { throw new Error(
			'Parameters p and r are out of bounds.'); }
	
	var N = (1 << logN);
	var V: Uint8Array;
	var B: Uint8Array;
	var XY: Uint8Array;

	/* Allocate memory. */
	try {
		V = arrFactory.getUint8Array(128 * r * N);
		B = arrFactory.getUint8Array(128 * r * p);
		XY = arrFactory.getUint8Array(256 * r);
	} catch (e) {
		e.message = "Cannot allocate memory for given parameters: "+e.message;
		throw e;
	}
	
	/* 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen) */
	sha256.PBKDF2_SHA256(passwd, salt, 1, B, arrFactory);
	progressCB(3);	// set 3% progress after the first PBKDF run
	
	var progShow: ProgressIndicator = {
		completed: 3,
		deltaWork: 1,
		deltaN: Math.floor(2*N*p / 93),
		addDelta: function() {
			this.completed += this.deltaWork;
			progressCB(this.completed);
		}
	};

	/* 2: for i = 0 to p - 1 do */
	for (var i=0; i<p; i+=1) {
		/* 3: B_i <-- MF(B_i, N) */
		smix(B.subarray(i*128*r), r, N, V, XY, progShow, arrFactory);
	}

	/* 5: DK <-- PBKDF2(P, B, 1, dkLen) */
	var buf = arrFactory.getUint8Array(dkLen);
	sha256.PBKDF2_SHA256(passwd, B, 1, buf, arrFactory);
	progressCB(99);	// set 99% progress after the last PBKDF run

	arrFactory.wipe(V, B, XY);
	arrFactory.wipeRecycled();
	progressCB(100);	// set 100% progress after the cleanup
	
	return buf;
}
