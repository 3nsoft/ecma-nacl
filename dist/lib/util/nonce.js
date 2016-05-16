/* Copyright(c) 2013 - 2016 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
"use strict";
/**
 * @param u is a U64 object
 */
function u64To52(u) {
    if (u[1] > 0xfffff) {
        return;
    }
    return u[1] * 0x100000000 + u[0];
}
exports.u64To52 = u64To52;
function addU64(a, b) {
    var l = a[0] + b[0];
    var h = a[1] + b[1] + ((l / 0x100000000) | 0);
    return new Uint32Array([l, h]);
}
function subU64(a, b) {
    var h = a[1] - b[1];
    var l = a[0] - b[0];
    if (l < 0) {
        h -= 1;
        l += 0x100000000;
    }
    return new Uint32Array([l, h]);
}
// XXX read 64 bytes, into obj that represents 64 number and has addition
//		read/write and call of storing ops should be adjusted
function loadLEU64(x, i) {
    var l = (x[i + 3] << 24) | (x[i + 2] << 16) | (x[i + 1] << 8) | x[i];
    var h = (x[i + 7] << 24) | (x[i + 6] << 16) | (x[i + 5] << 8) | x[i + 4];
    return new Uint32Array([l, h]);
}
function storeLEU64(x, i, u) {
    x[i + 7] = u[1] >>> 24;
    x[i + 6] = u[1] >>> 16;
    x[i + 5] = u[1] >>> 8;
    x[i + 4] = u[1];
    x[i + 3] = u[0] >>> 24;
    x[i + 2] = u[0] >>> 16;
    x[i + 1] = u[0] >>> 8;
    x[i] = u[0];
}
/**
 * This takes a given 24-byte nonce as three 8-byte numbers, and adds
 * a given delta to each number.
 * @param n is Uint8Array, 24 bytes long nonce that will be changed in-place.
 * @param delta is a number from 1 to 255 inclusive.
 */
function advance(n, delta) {
    if (n.length !== 24) {
        throw new Error("Nonce array n should have 24 elements (bytes) in it, but it is " +
            n.length + " elements long.");
    }
    if ((delta < 1) || (delta > 255)) {
        throw new Error("Given delta is out of limits.");
    }
    var deltaU64 = new Uint32Array([delta, 0]);
    for (var i = 0; i < 3; i += 1) {
        storeLEU64(n, i * 8, addU64(loadLEU64(n, i * 8), deltaU64));
    }
}
exports.advance = advance;
/**
 * This takes a given 24-byte nonce as three 8-byte numbers, and adds
 * 1 to each number.
 * @param n is Uint8Array, 24 bytes long nonce that will be changed in-place.
 */
function advanceOddly(n) {
    advance(n, 1);
}
exports.advanceOddly = advanceOddly;
/**
 * This takes a given 24-byte nonce as three 8-byte numbers, and adds
 * 2 to each number.
 * @param n is Uint8Array, 24 bytes long nonce that will be changed in-place.
 */
function advanceEvenly(n) {
    advance(n, 2);
}
exports.advanceEvenly = advanceEvenly;
/**
 * @param initNonce
 * @param delta
 * @param arrFactory is an optional factory, which provides array for a
 * calculated nonce.
 * @return new nonce, calculated from an initial one by adding a delta to it.
 */
function calculateNonce(initNonce, delta, arrFactory) {
    var deltaU64;
    if (typeof delta === 'number') {
        if ((delta > 0xfffffffffffff) || (delta < 0)) {
            throw new Error("Given delta is out of limits.");
        }
        deltaU64 = new Uint32Array([delta, delta / 0x100000000]);
    }
    else {
        deltaU64 = delta;
    }
    var n = (arrFactory ? arrFactory.getUint8Array(24) : new Uint8Array(24));
    for (var i = 0; i < 3; i += 1) {
        storeLEU64(n, i * 8, addU64(loadLEU64(initNonce, i * 8), deltaU64));
    }
    return n;
}
exports.calculateNonce = calculateNonce;
/**
 * @param n1
 * @param n2
 * @return delta (unsigned 64-bit integer), which, when added to the first
 * nonce (n1), produces the second nonce (n2).
 * Undefined is returned, if given nonces are not related to each other.
 */
function calculateDelta(n1, n2) {
    var delta = subU64(loadLEU64(n2, 0), loadLEU64(n1, 0));
    var dx;
    for (var i = 1; i < 3; i += 1) {
        dx = subU64(loadLEU64(n2, i * 8), loadLEU64(n1, i * 8));
        if ((delta[0] !== dx[0]) || (delta[1] !== dx[1])) {
            return;
        }
    }
    return delta;
}
exports.calculateDelta = calculateDelta;
Object.freeze(exports);
