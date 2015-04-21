/* Copyright(c) 2013-2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
/**
 * Analog of crypto_core in crypto_core/salsa20/ref/core.c
 * It makes nicer, shorter code to have variables of this function sitting in
 * one array, but expanded version runs faster.
 * We inlined load_littleendian(() & store_littleendian(), and rotate()
 * functions from the original source.
 * @param out is Uint8Array, 64 bytes long, into which result is placed.
 * @param inArr is Uint8Array, 16 bytes long, of incoming bytes.
 * @param k is Uint8Array, 32 bytes long.
 * @param c is Uint8Array, 16 bytes long.
 */
function salsa20(out, inArr, k, c) {
    // inlined load_littleendian()'s
    var x0 = c[0] | (c[1] << 8) | (c[2] << 16) | (c[3] << 24);
    var j0 = x0;
    var x1 = k[0] | (k[1] << 8) | (k[2] << 16) | (k[3] << 24);
    var j1 = x1;
    var x2 = k[4] | (k[5] << 8) | (k[6] << 16) | (k[7] << 24);
    var j2 = x2;
    var x3 = k[8] | (k[9] << 8) | (k[10] << 16) | (k[11] << 24);
    var j3 = x3;
    var x4 = k[12] | (k[13] << 8) | (k[14] << 16) | (k[15] << 24);
    var j4 = x4;
    var x5 = c[4] | (c[5] << 8) | (c[6] << 16) | (c[7] << 24);
    var j5 = x5;
    var x6 = inArr[0] | (inArr[1] << 8) | (inArr[2] << 16) | (inArr[3] << 24);
    var j6 = x6;
    var x7 = inArr[4] | (inArr[5] << 8) | (inArr[6] << 16) | (inArr[7] << 24);
    var j7 = x7;
    var x8 = inArr[8] | (inArr[9] << 8) | (inArr[10] << 16) | (inArr[11] << 24);
    var j8 = x8;
    var x9 = inArr[12] | (inArr[13] << 8) | (inArr[14] << 16) | (inArr[15] << 24);
    var j9 = x9;
    var x10 = c[8] | (c[9] << 8) | (c[10] << 16) | (c[11] << 24);
    var j10 = x10;
    var x11 = k[16] | (k[17] << 8) | (k[18] << 16) | (k[19] << 24);
    var j11 = x11;
    var x12 = k[20] | (k[21] << 8) | (k[22] << 16) | (k[23] << 24);
    var j12 = x12;
    var x13 = k[24] | (k[25] << 8) | (k[26] << 16) | (k[27] << 24);
    var j13 = x13;
    var x14 = k[28] | (k[29] << 8) | (k[30] << 16) | (k[31] << 24);
    var j14 = x14;
    var x15 = c[12] | (c[13] << 8) | (c[14] << 16) | (c[15] << 24);
    var j15 = x15;
    var t = 0;
    for (var i = 20; i > 0; i -= 2) {
        // inlined rotate()'s
        t = (x0 + x12);
        x4 ^= (t << 7) | (t >>> 25);
        t = (x4 + x0);
        x8 ^= (t << 9) | (t >>> 23);
        t = (x8 + x4);
        x12 ^= (t << 13) | (t >>> 19);
        t = (x12 + x8);
        x0 ^= (t << 18) | (t >>> 14);
        t = (x5 + x1);
        x9 ^= (t << 7) | (t >>> 25);
        t = (x9 + x5);
        x13 ^= (t << 9) | (t >>> 23);
        t = (x13 + x9);
        x1 ^= (t << 13) | (t >>> 19);
        t = (x1 + x13);
        x5 ^= (t << 18) | (t >>> 14);
        t = (x10 + x6);
        x14 ^= (t << 7) | (t >>> 25);
        t = (x14 + x10);
        x2 ^= (t << 9) | (t >>> 23);
        t = (x2 + x14);
        x6 ^= (t << 13) | (t >>> 19);
        t = (x6 + x2);
        x10 ^= (t << 18) | (t >>> 14);
        t = (x15 + x11);
        x3 ^= (t << 7) | (t >>> 25);
        t = (x3 + x15);
        x7 ^= (t << 9) | (t >>> 23);
        t = (x7 + x3);
        x11 ^= (t << 13) | (t >>> 19);
        t = (x11 + x7);
        x15 ^= (t << 18) | (t >>> 14);
        t = (x0 + x3);
        x1 ^= (t << 7) | (t >>> 25);
        t = (x1 + x0);
        x2 ^= (t << 9) | (t >>> 23);
        t = (x2 + x1);
        x3 ^= (t << 13) | (t >>> 19);
        t = (x3 + x2);
        x0 ^= (t << 18) | (t >>> 14);
        t = (x5 + x4);
        x6 ^= (t << 7) | (t >>> 25);
        t = (x6 + x5);
        x7 ^= (t << 9) | (t >>> 23);
        t = (x7 + x6);
        x4 ^= (t << 13) | (t >>> 19);
        t = (x4 + x7);
        x5 ^= (t << 18) | (t >>> 14);
        t = (x10 + x9);
        x11 ^= (t << 7) | (t >>> 25);
        t = (x11 + x10);
        x8 ^= (t << 9) | (t >>> 23);
        t = (x8 + x11);
        x9 ^= (t << 13) | (t >>> 19);
        t = (x9 + x8);
        x10 ^= (t << 18) | (t >>> 14);
        t = (x15 + x14);
        x12 ^= (t << 7) | (t >>> 25);
        t = (x12 + x15);
        x13 ^= (t << 9) | (t >>> 23);
        t = (x13 + x12);
        x14 ^= (t << 13) | (t >>> 19);
        t = (x14 + x13);
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
    x10 = (x10 + j10);
    x11 = (x11 + j11);
    x12 = (x12 + j12);
    x13 = (x13 + j13);
    x14 = (x14 + j14);
    x15 = (x15 + j15);
    // inlined store_littleendian()'s
    out[0] = x0;
    out[1] = x0 >>> 8;
    out[2] = x0 >>> 16;
    out[3] = x0 >>> 24;
    out[4] = x1;
    out[5] = x1 >>> 8;
    out[6] = x1 >>> 16;
    out[7] = x1 >>> 24;
    out[8] = x2;
    out[9] = x2 >>> 8;
    out[10] = x2 >>> 16;
    out[11] = x2 >>> 24;
    out[12] = x3;
    out[13] = x3 >>> 8;
    out[14] = x3 >>> 16;
    out[15] = x3 >>> 24;
    out[16] = x4;
    out[17] = x4 >>> 8;
    out[18] = x4 >>> 16;
    out[19] = x4 >>> 24;
    out[20] = x5;
    out[21] = x5 >>> 8;
    out[22] = x5 >>> 16;
    out[23] = x5 >>> 24;
    out[24] = x6;
    out[25] = x6 >>> 8;
    out[26] = x6 >>> 16;
    out[27] = x6 >>> 24;
    out[28] = x7;
    out[29] = x7 >>> 8;
    out[30] = x7 >>> 16;
    out[31] = x7 >>> 24;
    out[32] = x8;
    out[33] = x8 >>> 8;
    out[34] = x8 >>> 16;
    out[35] = x8 >>> 24;
    out[36] = x9;
    out[37] = x9 >>> 8;
    out[38] = x9 >>> 16;
    out[39] = x9 >>> 24;
    out[40] = x10;
    out[41] = x10 >>> 8;
    out[42] = x10 >>> 16;
    out[43] = x10 >>> 24;
    out[44] = x11;
    out[45] = x11 >>> 8;
    out[46] = x11 >>> 16;
    out[47] = x11 >>> 24;
    out[48] = x12;
    out[49] = x12 >>> 8;
    out[50] = x12 >>> 16;
    out[51] = x12 >>> 24;
    out[52] = x13;
    out[53] = x13 >>> 8;
    out[54] = x13 >>> 16;
    out[55] = x13 >>> 24;
    out[56] = x14;
    out[57] = x14 >>> 8;
    out[58] = x14 >>> 16;
    out[59] = x14 >>> 24;
    out[60] = x15;
    out[61] = x15 >>> 8;
    out[62] = x15 >>> 16;
    out[63] = x15 >>> 24;
}
exports.salsa20 = salsa20;
/**
 * Analog of crypto_core in crypto_core/hsalsa20/ref2/core.c
 * It makes nicer, shorter code to have variables of this function sitting in
 * one array, but expanded version runs faster.
 * We inlined load_littleendian(() & store_littleendian(), and rotate()
 * functions from the original source.
 * @param out is Uint8Array, 32 bytes long, into which result is placed.
 * @param inArr is Uint8Array, 16 bytes long, of incoming bytes.
 * @param k is Uint8Array, 32 bytes long.
 * @param c is Uint8Array, 16 bytes long.
 */
function hsalsa20(out, inArr, k, c) {
    // inlined load_littleendian()'s
    var x0 = c[0] | (c[1] << 8) | (c[2] << 16) | (c[3] << 24);
    var x1 = k[0] | (k[1] << 8) | (k[2] << 16) | (k[3] << 24);
    var x2 = k[4] | (k[5] << 8) | (k[6] << 16) | (k[7] << 24);
    var x3 = k[8] | (k[9] << 8) | (k[10] << 16) | (k[11] << 24);
    var x4 = k[12] | (k[13] << 8) | (k[14] << 16) | (k[15] << 24);
    var x5 = c[4] | (c[5] << 8) | (c[6] << 16) | (c[7] << 24);
    var x6 = inArr[0] | (inArr[1] << 8) | (inArr[2] << 16) | (inArr[3] << 24);
    var x7 = inArr[4] | (inArr[5] << 8) | (inArr[6] << 16) | (inArr[7] << 24);
    var x8 = inArr[8] | (inArr[9] << 8) | (inArr[10] << 16) | (inArr[11] << 24);
    var x9 = inArr[12] | (inArr[13] << 8) | (inArr[14] << 16) | (inArr[15] << 24);
    var x10 = c[8] | (c[9] << 8) | (c[10] << 16) | (c[11] << 24);
    var x11 = k[16] | (k[17] << 8) | (k[18] << 16) | (k[19] << 24);
    var x12 = k[20] | (k[21] << 8) | (k[22] << 16) | (k[23] << 24);
    var x13 = k[24] | (k[25] << 8) | (k[26] << 16) | (k[27] << 24);
    var x14 = k[28] | (k[29] << 8) | (k[30] << 16) | (k[31] << 24);
    var x15 = c[12] | (c[13] << 8) | (c[14] << 16) | (c[15] << 24);
    var t = 0;
    for (var i = 20; i > 0; i -= 2) {
        // inlined rotate()'s
        t = (x0 + x12);
        x4 ^= (t << 7) | (t >>> 25);
        t = (x4 + x0);
        x8 ^= (t << 9) | (t >>> 23);
        t = (x8 + x4);
        x12 ^= (t << 13) | (t >>> 19);
        t = (x12 + x8);
        x0 ^= (t << 18) | (t >>> 14);
        t = (x5 + x1);
        x9 ^= (t << 7) | (t >>> 25);
        t = (x9 + x5);
        x13 ^= (t << 9) | (t >>> 23);
        t = (x13 + x9);
        x1 ^= (t << 13) | (t >>> 19);
        t = (x1 + x13);
        x5 ^= (t << 18) | (t >>> 14);
        t = (x10 + x6);
        x14 ^= (t << 7) | (t >>> 25);
        t = (x14 + x10);
        x2 ^= (t << 9) | (t >>> 23);
        t = (x2 + x14);
        x6 ^= (t << 13) | (t >>> 19);
        t = (x6 + x2);
        x10 ^= (t << 18) | (t >>> 14);
        t = (x15 + x11);
        x3 ^= (t << 7) | (t >>> 25);
        t = (x3 + x15);
        x7 ^= (t << 9) | (t >>> 23);
        t = (x7 + x3);
        x11 ^= (t << 13) | (t >>> 19);
        t = (x11 + x7);
        x15 ^= (t << 18) | (t >>> 14);
        t = (x0 + x3);
        x1 ^= (t << 7) | (t >>> 25);
        t = (x1 + x0);
        x2 ^= (t << 9) | (t >>> 23);
        t = (x2 + x1);
        x3 ^= (t << 13) | (t >>> 19);
        t = (x3 + x2);
        x0 ^= (t << 18) | (t >>> 14);
        t = (x5 + x4);
        x6 ^= (t << 7) | (t >>> 25);
        t = (x6 + x5);
        x7 ^= (t << 9) | (t >>> 23);
        t = (x7 + x6);
        x4 ^= (t << 13) | (t >>> 19);
        t = (x4 + x7);
        x5 ^= (t << 18) | (t >>> 14);
        t = (x10 + x9);
        x11 ^= (t << 7) | (t >>> 25);
        t = (x11 + x10);
        x8 ^= (t << 9) | (t >>> 23);
        t = (x8 + x11);
        x9 ^= (t << 13) | (t >>> 19);
        t = (x9 + x8);
        x10 ^= (t << 18) | (t >>> 14);
        t = (x15 + x14);
        x12 ^= (t << 7) | (t >>> 25);
        t = (x12 + x15);
        x13 ^= (t << 9) | (t >>> 23);
        t = (x13 + x12);
        x14 ^= (t << 13) | (t >>> 19);
        t = (x14 + x13);
        x15 ^= (t << 18) | (t >>> 14);
    }
    // inlined store_littleendian()'s
    out[0] = x0;
    out[1] = x0 >>> 8;
    out[2] = x0 >>> 16;
    out[3] = x0 >>> 24;
    out[4] = x5;
    out[5] = x5 >>> 8;
    out[6] = x5 >>> 16;
    out[7] = x5 >>> 24;
    out[8] = x10;
    out[9] = x10 >>> 8;
    out[10] = x10 >>> 16;
    out[11] = x10 >>> 24;
    out[12] = x15;
    out[13] = x15 >>> 8;
    out[14] = x15 >>> 16;
    out[15] = x15 >>> 24;
    out[16] = x6;
    out[17] = x6 >>> 8;
    out[18] = x6 >>> 16;
    out[19] = x6 >>> 24;
    out[20] = x7;
    out[21] = x7 >>> 8;
    out[22] = x7 >>> 16;
    out[23] = x7 >>> 24;
    out[24] = x8;
    out[25] = x8 >>> 8;
    out[26] = x8 >>> 16;
    out[27] = x8 >>> 24;
    out[28] = x9;
    out[29] = x9 >>> 8;
    out[30] = x9 >>> 16;
    out[31] = x9 >>> 24;
}
exports.hsalsa20 = hsalsa20;
Object.freeze(exports);
