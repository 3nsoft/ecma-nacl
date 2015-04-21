/* Copyright(c) 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
function make_sc25519(arrFactory) {
    return arrFactory.getUint32Array(32);
}
exports.make_sc25519 = make_sc25519;
function make_shortsc25519(arrFactory) {
    return arrFactory.getUint32Array(16);
}
exports.make_shortsc25519 = make_shortsc25519;
/**
 * Analog of constant m in crypto_sign/ed25519/ref/sc25519.c
 */
var m = new Uint8Array(32);
m.set([0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10]);
/**
 * Analog of constant mu in crypto_sign/ed25519/ref/sc25519.c
 */
var mu = new Uint8Array(33);
mu.set([0x1B, 0x13, 0x2C, 0x0A, 0xA3, 0xE5, 0x9C, 0xED, 0xA7, 0x29, 0x63, 0x08, 0x5D, 0x21, 0x06, 0x21, 0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
/**
 * Analog of lt in crypto_sign/ed25519/ref/sc25519.c
 * All inputs are 16-bit.
 */
function lt(a, b) {
    return (a < b) ? 1 : 0;
    //	return ((a - b) >>> 31); /* (a less than b) ? 1: yes; 0: no */
}
/**
 * Analog of reduce_add_sub in crypto_sign/ed25519/ref/sc25519.c
 * Reduce coefficients of r before calling reduce_add_sub
 */
function reduce_add_sub(r, arrFactory) {
    var pb = 0;
    var b;
    var mask;
    var t = arrFactory.getUint8Array(32);
    for (var i = 0; i < 32; i += 1) {
        pb += m[i];
        b = lt(r[i], pb);
        t[i] = r[i] - pb + (b << 8);
        pb = b;
    }
    mask = (b - 1) | 0;
    for (var i = 0; i < 32; i += 1) {
        r[i] ^= mask & (r[i] ^ t[i]);
    }
    arrFactory.recycle(t);
}
/**
 * Analog of barrett_reduce in crypto_sign/ed25519/ref/sc25519.c
 * Reduce coefficients of x before calling barrett_reduce
 */
function barrett_reduce(r, x, arrFactory) {
    /* See HAC, Alg. 14.42 */
    var q2 = arrFactory.getUint32Array(66);
    var q3 = q2.subarray(33);
    var r1 = arrFactory.getUint32Array(33);
    var r2 = arrFactory.getUint32Array(33);
    var carry;
    var pb = 0;
    var b;
    for (var i = 0; i < 66; i += 1) {
        q2[i] = 0;
    }
    for (var i = 0; i < 33; i += 1) {
        r2[i] = 0;
    }
    for (var i = 0; i < 33; i += 1) {
        for (var j = 0; j < 33; j += 1) {
            if (i + j >= 31) {
                q2[i + j] += mu[i] * x[j + 31];
            }
        }
    }
    carry = q2[31] >>> 8;
    q2[32] += carry;
    carry = q2[32] >>> 8;
    q2[33] += carry;
    for (var i = 0; i < 33; i += 1) {
        r1[i] = x[i];
    }
    for (var i = 0; i < 32; i += 1) {
        for (var j = 0; j < 33; j += 1) {
            if (i + j < 33) {
                r2[i + j] += m[i] * q3[j];
            }
        }
    }
    for (var i = 0; i < 32; i += 1) {
        carry = r2[i] >>> 8;
        r2[i + 1] += carry;
        r2[i] &= 0xff;
    }
    for (var i = 0; i < 32; i += 1) {
        pb += r2[i];
        b = lt(r1[i], pb);
        r[i] = r1[i] - pb + (b << 8);
        pb = b;
    }
    /* XXX: Can it really happen that r<0?, See HAC, Alg 14.42, Step 3
     * If so: Handle	it here!
     */
    reduce_add_sub(r, arrFactory);
    reduce_add_sub(r, arrFactory);
    arrFactory.recycle(q2, r1, r2);
}
/**
 * Analog of sc25519_from32bytes in crypto_sign/ed25519/ref/sc25519.c
 */
function from32bytes(r, x, arrFactory) {
    var t = arrFactory.getUint32Array(64);
    for (var i = 0; i < 32; i += 1) {
        t[i] = x[i];
    }
    for (var i = 32; i < 64; i += 1) {
        t[i] = 0;
    }
    barrett_reduce(r, t, arrFactory);
    arrFactory.recycle(t);
}
exports.from32bytes = from32bytes;
/**
 * Analog of sc25519_from64bytes in crypto_sign/ed25519/ref/sc25519.c
 */
function from64bytes(r, x, arrFactory) {
    var t = arrFactory.getUint32Array(64);
    for (var i = 0; i < 64; i += 1) {
        t[i] = x[i];
    }
    barrett_reduce(r, t, arrFactory);
    arrFactory.recycle(t);
}
exports.from64bytes = from64bytes;
/**
 * Analog of sc25519_to32bytes in crypto_sign/ed25519/ref/sc25519.c
 */
function to32bytes(r, x) {
    for (var i = 0; i < 32; i += 1) {
        r[i] = x[i];
    }
}
exports.to32bytes = to32bytes;
/**
 * Analog of sc25519_add in crypto_sign/ed25519/ref/sc25519.c
 */
function add(r, x, y, arrFactory) {
    var carry;
    for (var i = 0; i < 32; i += 1) {
        r[i] = x[i] + y[i];
    }
    for (var i = 0; i < 31; i += 1) {
        carry = r[i] >>> 8;
        r[i + 1] += carry;
        r[i] &= 0xff;
    }
    reduce_add_sub(r, arrFactory);
}
exports.add = add;
/**
 * Analog of sc25519_mul in crypto_sign/ed25519/ref/sc25519.c
 */
function mul(r, x, y, arrFactory) {
    var carry;
    var t = arrFactory.getUint32Array(64);
    for (var i = 0; i < 64; i += 1) {
        t[i] = 0;
    }
    for (var i = 0; i < 32; i += 1) {
        for (var j = 0; j < 32; j += 1) {
            t[i + j] += x[i] * y[j];
        }
    }
    for (var i = 0; i < 63; i += 1) {
        carry = t[i] >>> 8;
        t[i + 1] += carry;
        t[i] &= 0xff;
    }
    barrett_reduce(r, t, arrFactory);
    arrFactory.recycle(t);
}
exports.mul = mul;
/**
 * Analog of sc25519_window3 in crypto_sign/ed25519/ref/sc25519.c
 */
function window3(r, s) {
    for (var i = 0; i < 10; i += 1) {
        r[8 * i + 0] = s[3 * i + 0] & 7;
        r[8 * i + 1] = (s[3 * i + 0] >>> 3) & 7;
        r[8 * i + 2] = (s[3 * i + 0] >>> 6) & 7;
        r[8 * i + 2] ^= (s[3 * i + 1] << 2) & 7;
        r[8 * i + 3] = (s[3 * i + 1] >>> 1) & 7;
        r[8 * i + 4] = (s[3 * i + 1] >>> 4) & 7;
        r[8 * i + 5] = (s[3 * i + 1] >>> 7) & 7;
        r[8 * i + 5] ^= (s[3 * i + 2] << 1) & 7;
        r[8 * i + 6] = (s[3 * i + 2] >>> 2) & 7;
        r[8 * i + 7] = (s[3 * i + 2] >>> 5) & 7;
    }
    r[8 * i + 0] = s[3 * i + 0] & 7;
    r[8 * i + 1] = (s[3 * i + 0] >>> 3) & 7;
    r[8 * i + 2] = (s[3 * i + 0] >>> 6) & 7;
    r[8 * i + 2] ^= (s[3 * i + 1] << 2) & 7;
    r[8 * i + 3] = (s[3 * i + 1] >>> 1) & 7;
    r[8 * i + 4] = (s[3 * i + 1] >>> 4) & 7;
    /* Making it signed */
    var carry = 0;
    for (var i = 0; i < 84; i += 1) {
        r[i] += carry;
        r[i + 1] += r[i] >>> 3;
        r[i] &= 7;
        carry = r[i] >>> 2;
        r[i] -= carry << 3;
    }
    r[84] += carry;
}
exports.window3 = window3;
/**
 * Analog of sc25519_2interleave2 in crypto_sign/ed25519/ref/sc25519.c
 */
function interleave2(r, s1, s2) {
    for (var i = 0; i < 31; i += 1) {
        r[4 * i] = (s1[i] & 3) ^ ((s2[i] & 3) << 2);
        r[4 * i + 1] = ((s1[i] >>> 2) & 3) ^ (((s2[i] >>> 2) & 3) << 2);
        r[4 * i + 2] = ((s1[i] >>> 4) & 3) ^ (((s2[i] >>> 4) & 3) << 2);
        r[4 * i + 3] = ((s1[i] >>> 6) & 3) ^ (((s2[i] >>> 6) & 3) << 2);
    }
    r[124] = (s1[31] & 3) ^ ((s2[31] & 3) << 2);
    r[125] = ((s1[31] >>> 2) & 3) ^ (((s2[31] >>> 2) & 3) << 2);
    r[126] = ((s1[31] >>> 4) & 3) ^ (((s2[31] >>> 4) & 3) << 2);
}
exports.interleave2 = interleave2;
Object.freeze(exports);
