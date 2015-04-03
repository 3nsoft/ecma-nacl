/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

import arrays = require('../util/arrays');

function loadLEU32(x: Uint8Array, i: number): number {
	return (x[i+3] << 24) | (x[i+2] << 16) | (x[i+1] << 8) | x[i];
}

function storeLEU32(x: Uint8Array, i: number, u: number): void {
	x[i+3] = u >>> 24;
	x[i+2] = u >>> 16;
	x[i+1] = u >>> 8;
	x[i] = u;
}

/**
 * This takes a given 24-byte nonce as three 8-byte numbers, and adds
 * a given delta to each number.
 * @param n is Uint8Array, 24 bytes long nonce that will be changed in-place.
 * @param delta is a number from 1 to 255 inclusive.
 */
export function advance(n: Uint8Array, delta: number): void {
	if (n.length !== 24) { throw new Error(
			"Nonce array n should have 24 elements (bytes) in it, but it is "+
			n.length+" elements long."); }
	if ((delta < 1) || (delta > 255)) { throw new Error(
			"Given delta is out of limits."); }
	for (var i=0; i<3; i+=1) {
		storeLEU32(n, i*4, (loadLEU32(n, i*4) + delta));
	}
}

/**
 * This takes a given 24-byte nonce as three 8-byte numbers, and adds
 * 1 to each number.
 * @param n is Uint8Array, 24 bytes long nonce that will be changed in-place.
 */
export function advanceOddly(n: Uint8Array): void {
	advance(n, 1);
}

/**
 * This takes a given 24-byte nonce as three 8-byte numbers, and adds
 * 2 to each number.
 * @param n is Uint8Array, 24 bytes long nonce that will be changed in-place.
 */
export function advanceEvenly(n: Uint8Array): void {
	advance(n, 2);
}

/**
 * @param initNonce
 * @param delta
 * @return new nonce, calculated from an initial one by adding a delta to it.
 */
export function calculateNonce(initNonce: Uint8Array, delta: number,
		arrFactory: arrays.Factory): Uint8Array {
	if ((delta > 0xffffffff) || (delta < 0)) { throw new Error(
			"Given delta is out of limits."); }
	var n = arrFactory.getUint8Array(24);
	for (var i=0; i<3; i+=1) {
		storeLEU32(n, i*4, (loadLEU32(initNonce, i*4) + delta));
	}
	return n;
}

/**
 * @param n1
 * @param n2
 * @return delta (unsigned 32-bit integer), which, when added to the first
 * nonce (n1), produces the second nonce (n2).
 * Null is returned, if given nonces are not related to each other.
 */
export function calculateDelta(n1: Uint8Array, n2: Uint8Array): number {
	var delta = loadLEU32(n2, 0) - loadLEU32(n1, 0);
	for (var i=1; i<3; i+=1) {
		if (delta !== (loadLEU32(n2, i*4) - loadLEU32(n1, i*4))) {
			return null;
		}
	}
	if (delta < 0) {
		delta += 0x100000000;
	}
	return delta;
}

Object.freeze(exports);