/* Copyright(c) 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
function make_fe25519(arrFactory) {
    return arrFactory.getUint32Array(32);
}
exports.make_fe25519 = make_fe25519;
function make_copy_fe25519(x, arrFactory) {
    var c = arrFactory.getUint32Array(32);
    c.set(x);
    return c;
}
// The following defs are not used in crypto_sign/ed25519/ref/fe25519.c
//#define WINDOWSIZE 1 /* Should be 1,2, or 4 */
//#define WINDOWMASK ((1<<WINDOWSIZE)-1)
/**
 * Analog of equal in crypto_sign/ed25519/ref/fe25519.c
 * All inputs are 16-bit.
 */
function equal(a, b) {
    return (a === b) ? 1 : 0;
    //	return (((a ^ b) - 1) >>> 31); /* (a equals b) ? 1: yes; 0: no */
}
/**
 * Analog of ge in crypto_sign/ed25519/ref/fe25519.c
 * All inputs are 16-bit.
 */
function ge(a, b) {
    return (a >= b) ? 1 : 0;
    //	return (((a - b) >>> 31) ^ 1); /* (a greater or equals b) ? 1: yes; 0: no */
}
/**
 * Analog of times19 in crypto_sign/ed25519/ref/fe25519.c
 */
function times19(a) {
    return (a << 4) + (a << 1) + a;
}
/**
 * Analog of times38 in crypto_sign/ed25519/ref/fe25519.c
 */
function times38(a) {
    return (a << 5) + (a << 2) + (a << 1);
}
/**
 * Analog of reduce_add_sub in crypto_sign/ed25519/ref/fe25519.c
 */
function reduce_add_sub(r) {
    var t;
    for (var rep = 0; rep < 4; rep += 1) {
        t = r[31] >>> 7;
        r[31] &= 127;
        t = times19(t);
        r[0] += t;
        for (var i = 0; i < 31; i += 1) {
            t = r[i] >>> 8;
            r[i + 1] += t;
            r[i] &= 255;
        }
    }
}
/**
 * Analog of reduce_mul in crypto_sign/ed25519/ref/fe25519.c
 */
function reduce_mul(r) {
    var t;
    for (var rep = 0; rep < 2; rep += 1) {
        t = r[31] >>> 7;
        r[31] &= 127;
        t = times19(t);
        r[0] += t;
        for (var i = 0; i < 31; i += 1) {
            t = r[i] >>> 8;
            r[i + 1] += t;
            r[i] &= 255;
        }
    }
}
/**
 * Analog of fe25519_freeze in crypto_sign/ed25519/ref/fe25519.c
 * reduction modulo 2^255-19
 */
function fe25519_freeze(r) {
    var m = equal(r[31], 127);
    for (var i = 30; i > 0; i -= 1) {
        m &= equal(r[i], 255);
    }
    m &= ge(r[0], 237);
    m = -m;
    r[31] -= m & 127;
    for (var i = 30; i > 0; i -= 1) {
        r[i] -= m & 255;
    }
    r[0] -= m & 237;
}
/**
 * Analog of fe25519_unpack in crypto_sign/ed25519/ref/fe25519.c
 */
function unpack(r, x) {
    for (var i = 0; i < 32; i += 1) {
        r[i] = x[i];
    }
    r[31] &= 127;
}
exports.unpack = unpack;
/**
 * Analog of fe25519_unpack in crypto_sign/ed25519/ref/fe25519.c
 * Assumes input x being reduced below 2^255
 */
function pack(r, x, arrFactory) {
    var y = make_copy_fe25519(x, arrFactory);
    fe25519_freeze(y);
    for (var i = 0; i < 32; i += 1) {
        r[i] = y[i];
    }
    arrFactory.recycle(y);
}
exports.pack = pack;
/**
 * Analog of fe25519_iseq_vartime in crypto_sign/ed25519/ref/fe25519.c
 */
function iseq_vartime(x, y, arrFactory) {
    var t1 = make_copy_fe25519(x, arrFactory);
    var t2 = make_copy_fe25519(y, arrFactory);
    fe25519_freeze(t1);
    fe25519_freeze(t2);
    for (var i = 0; i < 32; i += 1) {
        if (t1[i] !== t2[i]) {
            return false;
        }
    }
    arrFactory.recycle(t1, t2);
    return true;
}
exports.iseq_vartime = iseq_vartime;
/**
 * Analog of fe25519_cmov in crypto_sign/ed25519/ref/fe25519.c
 */
function cmov(r, x, b) {
    for (var i = 0; i < 32; i += 1) {
        r[i] ^= (-b) & (x[i] ^ r[i]);
    }
}
exports.cmov = cmov;
/**
 * Analog of fe25519_getparity in crypto_sign/ed25519/ref/fe25519.c
 */
function getparity(x, arrFactory) {
    var t = make_copy_fe25519(x, arrFactory);
    fe25519_freeze(t);
    var res = t[0] & 1;
    arrFactory.recycle(t);
    return res;
}
exports.getparity = getparity;
/**
 * Analog of fe25519_setone in crypto_sign/ed25519/ref/fe25519.c
 */
function setone(r) {
    r[0] = 1;
    for (var i = 1; i < 32; i += 1) {
        r[i] = 0;
    }
}
exports.setone = setone;
/**
 * Analog of fe25519_setzero in crypto_sign/ed25519/ref/fe25519.c
 */
function setzero(r) {
    for (var i = 0; i < 32; i += 1) {
        r[i] = 0;
    }
}
exports.setzero = setzero;
/**
 * Analog of fe25519_neg in crypto_sign/ed25519/ref/fe25519.c
 */
function neg(r, x, arrFactory) {
    var t = make_copy_fe25519(x, arrFactory);
    setzero(r);
    sub(r, r, t, arrFactory);
    arrFactory.recycle(t);
}
exports.neg = neg;
/**
 * Analog of fe25519_add in crypto_sign/ed25519/ref/fe25519.c
 */
function add(r, x, y) {
    for (var i = 0; i < 32; i += 1) {
        r[i] = x[i] + y[i];
    }
    reduce_add_sub(r);
}
exports.add = add;
/**
 * Analog of fe25519_sub in crypto_sign/ed25519/ref/fe25519.c
 */
function sub(r, x, y, arrFactory) {
    var t = make_fe25519(arrFactory);
    t[0] = x[0] + 0x1da;
    for (var i = 1; i < 31; i += 1) {
        t[i] = x[i] + 0x1fe;
    }
    t[31] = x[31] + 0xfe;
    for (var i = 0; i < 32; i += 1) {
        r[i] = t[i] - y[i];
    }
    reduce_add_sub(r);
    arrFactory.recycle(t);
}
exports.sub = sub;
/**
 * Analog of fe25519_mul in crypto_sign/ed25519/ref/fe25519.c
 */
function mul(r, x, y, arrFactory) {
    var t = arrFactory.getUint32Array(63);
    for (var i = 0; i < 63; i += 1) {
        t[i] = 0;
    }
    for (var i = 0; i < 32; i += 1) {
        for (var j = 0; j < 32; j += 1) {
            t[i + j] += x[i] * y[j];
        }
    }
    for (var i = 32; i < 63; i += 1) {
        r[i - 32] = t[i - 32] + times38(t[i]);
    }
    r[31] = t[31]; /* result now in r[0]...r[31] */
    reduce_mul(r);
    arrFactory.recycle(t);
}
exports.mul = mul;
/**
 * Analog of fe25519_square in crypto_sign/ed25519/ref/fe25519.c
 */
function square(r, x, arrFactory) {
    mul(r, x, x, arrFactory);
}
exports.square = square;
/**
 * Analog of fe25519_invert in crypto_sign/ed25519/ref/fe25519.c
 */
function invert(r, x, arrFactory) {
    var z2 = make_fe25519(arrFactory);
    var z9 = make_fe25519(arrFactory);
    var z11 = make_fe25519(arrFactory);
    var z2_5_0 = make_fe25519(arrFactory);
    var z2_10_0 = make_fe25519(arrFactory);
    var z2_20_0 = make_fe25519(arrFactory);
    var z2_50_0 = make_fe25519(arrFactory);
    var z2_100_0 = make_fe25519(arrFactory);
    var t0 = make_fe25519(arrFactory);
    var t1 = make_fe25519(arrFactory);
    /* 2 */ square(z2, x, arrFactory);
    /* 4 */ square(t1, z2, arrFactory);
    /* 8 */ square(t0, t1, arrFactory);
    /* 9 */ mul(z9, t0, x, arrFactory);
    /* 11 */ mul(z11, z9, z2, arrFactory);
    /* 22 */ square(t0, z11, arrFactory);
    /* 2^5 - 2^0 = 31 */ mul(z2_5_0, t0, z9, arrFactory);
    /* 2^6 - 2^1 */ square(t0, z2_5_0, arrFactory);
    /* 2^7 - 2^2 */ square(t1, t0, arrFactory);
    /* 2^8 - 2^3 */ square(t0, t1, arrFactory);
    /* 2^9 - 2^4 */ square(t1, t0, arrFactory);
    /* 2^10 - 2^5 */ square(t0, t1, arrFactory);
    /* 2^10 - 2^0 */ mul(z2_10_0, t0, z2_5_0, arrFactory);
    /* 2^11 - 2^1 */ square(t0, z2_10_0, arrFactory);
    /* 2^12 - 2^2 */ square(t1, t0, arrFactory);
    for (var i = 2; i < 10; i += 2) {
        square(t0, t1, arrFactory);
        square(t1, t0, arrFactory);
    }
    /* 2^20 - 2^0 */ mul(z2_20_0, t1, z2_10_0, arrFactory);
    /* 2^21 - 2^1 */ square(t0, z2_20_0, arrFactory);
    /* 2^22 - 2^2 */ square(t1, t0, arrFactory);
    for (var i = 2; i < 20; i += 2) {
        square(t0, t1, arrFactory);
        square(t1, t0, arrFactory);
    }
    /* 2^40 - 2^0 */ mul(t0, t1, z2_20_0, arrFactory);
    /* 2^41 - 2^1 */ square(t1, t0, arrFactory);
    /* 2^42 - 2^2 */ square(t0, t1, arrFactory);
    for (var i = 2; i < 10; i += 2) {
        square(t1, t0, arrFactory);
        square(t0, t1, arrFactory);
    }
    /* 2^50 - 2^0 */ mul(z2_50_0, t0, z2_10_0, arrFactory);
    /* 2^51 - 2^1 */ square(t0, z2_50_0, arrFactory);
    /* 2^52 - 2^2 */ square(t1, t0, arrFactory);
    for (var i = 2; i < 50; i += 2) {
        square(t0, t1, arrFactory);
        square(t1, t0, arrFactory);
    }
    /* 2^100 - 2^0 */ mul(z2_100_0, t1, z2_50_0, arrFactory);
    /* 2^101 - 2^1 */ square(t1, z2_100_0, arrFactory);
    /* 2^102 - 2^2 */ square(t0, t1, arrFactory);
    for (var i = 2; i < 100; i += 2) {
        square(t1, t0, arrFactory);
        square(t0, t1, arrFactory);
    }
    /* 2^200 - 2^0 */ mul(t1, t0, z2_100_0, arrFactory);
    /* 2^201 - 2^1 */ square(t0, t1, arrFactory);
    /* 2^202 - 2^2 */ square(t1, t0, arrFactory);
    for (var i = 2; i < 50; i += 2) {
        square(t0, t1, arrFactory);
        square(t1, t0, arrFactory);
    }
    /* 2^250 - 2^0 */ mul(t0, t1, z2_50_0, arrFactory);
    /* 2^251 - 2^1 */ square(t1, t0, arrFactory);
    /* 2^252 - 2^2 */ square(t0, t1, arrFactory);
    /* 2^253 - 2^3 */ square(t1, t0, arrFactory);
    /* 2^254 - 2^4 */ square(t0, t1, arrFactory);
    /* 2^255 - 2^5 */ square(t1, t0, arrFactory);
    /* 2^255 - 21 */ mul(r, t1, z11, arrFactory);
    arrFactory.recycle(z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t0, t1);
}
exports.invert = invert;
/**
 * Analog of fe25519_pow2523 in crypto_sign/ed25519/ref/fe25519.c
 */
function pow2523(r, x, arrFactory) {
    var z2 = make_fe25519(arrFactory);
    var z9 = make_fe25519(arrFactory);
    var z11 = make_fe25519(arrFactory);
    var z2_5_0 = make_fe25519(arrFactory);
    var z2_10_0 = make_fe25519(arrFactory);
    var z2_20_0 = make_fe25519(arrFactory);
    var z2_50_0 = make_fe25519(arrFactory);
    var z2_100_0 = make_fe25519(arrFactory);
    var t = make_fe25519(arrFactory);
    /* 2 */ square(z2, x, arrFactory);
    /* 4 */ square(t, z2, arrFactory);
    /* 8 */ square(t, t, arrFactory);
    /* 9 */ mul(z9, t, x, arrFactory);
    /* 11 */ mul(z11, z9, z2, arrFactory);
    /* 22 */ square(t, z11, arrFactory);
    /* 2^5 - 2^0 = 31 */ mul(z2_5_0, t, z9, arrFactory);
    /* 2^6 - 2^1 */ square(t, z2_5_0, arrFactory);
    for (var i = 1; i < 5; i += 1) {
        square(t, t, arrFactory);
    }
    /* 2^10 - 2^0 */ mul(z2_10_0, t, z2_5_0, arrFactory);
    /* 2^11 - 2^1 */ square(t, z2_10_0, arrFactory);
    for (var i = 1; i < 10; i += 1) {
        square(t, t, arrFactory);
    }
    /* 2^20 - 2^0 */ mul(z2_20_0, t, z2_10_0, arrFactory);
    /* 2^21 - 2^1 */ square(t, z2_20_0, arrFactory);
    for (var i = 1; i < 20; i += 1) {
        square(t, t, arrFactory);
    }
    /* 2^40 - 2^0 */ mul(t, t, z2_20_0, arrFactory);
    /* 2^41 - 2^1 */ square(t, t, arrFactory);
    for (var i = 1; i < 10; i += 1) {
        square(t, t, arrFactory);
    }
    /* 2^50 - 2^0 */ mul(z2_50_0, t, z2_10_0, arrFactory);
    /* 2^51 - 2^1 */ square(t, z2_50_0, arrFactory);
    for (var i = 1; i < 50; i += 1) {
        square(t, t, arrFactory);
    }
    /* 2^100 - 2^0 */ mul(z2_100_0, t, z2_50_0, arrFactory);
    /* 2^101 - 2^1 */ square(t, z2_100_0, arrFactory);
    for (var i = 1; i < 100; i += 1) {
        square(t, t, arrFactory);
    }
    /* 2^200 - 2^0 */ mul(t, t, z2_100_0, arrFactory);
    /* 2^201 - 2^1 */ square(t, t, arrFactory);
    for (var i = 1; i < 50; i += 1) {
        square(t, t, arrFactory);
    }
    /* 2^250 - 2^0 */ mul(t, t, z2_50_0, arrFactory);
    /* 2^251 - 2^1 */ square(t, t, arrFactory);
    /* 2^252 - 2^2 */ square(t, t, arrFactory);
    /* 2^252 - 3 */ mul(r, t, x, arrFactory);
    arrFactory.recycle(z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t);
}
exports.pow2523 = pow2523;
Object.freeze(exports);
