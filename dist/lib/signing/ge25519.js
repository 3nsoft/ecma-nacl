/* Copyright(c) 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
var fe = require('./fe25519');
var sc = require('./sc25519');
var ge_base = require('./ge25519_base.data');
var arrays = require('../util/arrays');
function make_ge25519(arrFactory) {
    return {
        x: fe.make_fe25519(arrFactory),
        y: fe.make_fe25519(arrFactory),
        z: fe.make_fe25519(arrFactory),
        t: fe.make_fe25519(arrFactory),
    };
}
exports.make_ge25519 = make_ge25519;
function make_ge25519_p1p1(arrFactory) {
    return make_ge25519(arrFactory);
}
function make_ge25519_p2(arrFactory) {
    return {
        x: fe.make_fe25519(arrFactory),
        y: fe.make_fe25519(arrFactory),
        z: fe.make_fe25519(arrFactory),
    };
}
function make_ge25519_p3(arrFactory) {
    return make_ge25519(arrFactory);
}
function copy_ge25519_p3(c, x) {
    c.x.set(x.x);
    c.y.set(x.y);
    c.z.set(x.z);
    c.t.set(x.t);
}
function copy_ge25519_aff(c, x) {
    c.x.set(x.x);
    c.y.set(x.y);
}
function recycle_ge25519_aff(arrFactory) {
    var ges = [];
    for (var _i = 1; _i < arguments.length; _i++) {
        ges[_i - 1] = arguments[_i];
    }
    var x;
    for (var i = 0; i < ges.length; i += 1) {
        x = ges[i];
        arrFactory.recycle(x.x, x.y);
    }
}
function recycle_ge25519(arrFactory) {
    var ges = [];
    for (var _i = 1; _i < arguments.length; _i++) {
        ges[_i - 1] = arguments[_i];
    }
    var x;
    for (var i = 0; i < ges.length; i += 1) {
        x = ges[i];
        arrFactory.recycle(x.x, x.y, x.z);
        if (x.t) {
            arrFactory.recycle(x.t);
        }
    }
}
exports.recycle_ge25519 = recycle_ge25519;
/**
 * Analog of constant ge25519_ecd in crypto_sign/ed25519/ref/ge25519.c
 *  d
 */
var ge25519_ecd = new Uint32Array(32);
ge25519_ecd.set([0xA3, 0x78, 0x59, 0x13, 0xCA, 0x4D, 0xEB, 0x75, 0xAB, 0xD8, 0x41, 0x41, 0x4D, 0x0A, 0x70, 0x00, 0x98, 0xE8, 0x79, 0x77, 0x79, 0x40, 0xC7, 0x8C, 0x73, 0xFE, 0x6F, 0x2B, 0xEE, 0x6C, 0x03, 0x52]);
/**
 * Analog of constant ge25519_ec2d in crypto_sign/ed25519/ref/ge25519.c
 *  2*d
 */
var ge25519_ec2d = new Uint32Array(32);
ge25519_ec2d.set([0x59, 0xF1, 0xB2, 0x26, 0x94, 0x9B, 0xD6, 0xEB, 0x56, 0xB1, 0x83, 0x82, 0x9A, 0x14, 0xE0, 0x00, 0x30, 0xD1, 0xF3, 0xEE, 0xF2, 0x80, 0x8E, 0x19, 0xE7, 0xFC, 0xDF, 0x56, 0xDC, 0xD9, 0x06, 0x24]);
/**
 * Analog of constant ge25519_sqrtm1 in crypto_sign/ed25519/ref/ge25519.c
 *  sqrt(-1)
 */
var ge25519_sqrtm1 = new Uint32Array(32);
ge25519_sqrtm1.set([0xB0, 0xA0, 0x0E, 0x4A, 0x27, 0x1B, 0xEE, 0xC4, 0x78, 0xE4, 0x2F, 0xAD, 0x06, 0x18, 0x43, 0x2F, 0xA7, 0xD7, 0xFB, 0x3D, 0x99, 0x00, 0x4D, 0x2B, 0x0B, 0xDF, 0xC1, 0x4F, 0x80, 0x24, 0x83, 0x2B]);
/**
 * Analog of constant ge25519_base in crypto_sign/ed25519/ref/ge25519.c
 * Packed coordinates of the base point
 */
exports.base = make_ge25519(arrays.makeFactory());
exports.base.x.set([0x1A, 0xD5, 0x25, 0x8F, 0x60, 0x2D, 0x56, 0xC9, 0xB2, 0xA7, 0x25, 0x95, 0x60, 0xC7, 0x2C, 0x69, 0x5C, 0xDC, 0xD6, 0xFD, 0x31, 0xE2, 0xA4, 0xC0, 0xFE, 0x53, 0x6E, 0xCD, 0xD3, 0x36, 0x69, 0x21]);
exports.base.y.set([0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66]);
exports.base.z.set([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
exports.base.t.set([0xA3, 0xDD, 0xB7, 0xA5, 0xB3, 0x8A, 0xDE, 0x6D, 0xF5, 0x52, 0x51, 0x77, 0x80, 0x9F, 0xF0, 0x20, 0x7D, 0xE3, 0xAB, 0x64, 0x8E, 0x4E, 0xEA, 0x66, 0x65, 0x76, 0x8B, 0xD7, 0x0F, 0x5F, 0x87, 0x67]);
/**
 * Analog of constant ge25519_base_multiples_affine in
 * crypto_sign/ed25519/ref/ge25519.c
 * Multiples of the base point in affine representation
 */
var ge25519_base_multiples_affine = ge_base.base_multiples_affine;
/**
 * Analog of p1p1_to_p2 in crypto_sign/ed25519/ref/ge25519.c
 */
function p1p1_to_p2(r, p, arrFactory) {
    fe.mul(r.x, p.x, p.t, arrFactory);
    fe.mul(r.y, p.y, p.z, arrFactory);
    fe.mul(r.z, p.z, p.t, arrFactory);
}
/**
 * Analog of p1p1_to_p3 in crypto_sign/ed25519/ref/ge25519.c
 */
function p1p1_to_p3(r, p, arrFactory) {
    p1p1_to_p2(r, p, arrFactory);
    fe.mul(r.t, p.x, p.y, arrFactory);
}
/**
 * Analog of ge25519_mixadd2 in crypto_sign/ed25519/ref/ge25519.c
 */
function ge25519_mixadd2(r, q, arrFactory) {
    var a = fe.make_fe25519(arrFactory);
    var b = fe.make_fe25519(arrFactory);
    var t1 = fe.make_fe25519(arrFactory);
    var t2 = fe.make_fe25519(arrFactory);
    var c = fe.make_fe25519(arrFactory);
    var d = fe.make_fe25519(arrFactory);
    var e = fe.make_fe25519(arrFactory);
    var f = fe.make_fe25519(arrFactory);
    var g = fe.make_fe25519(arrFactory);
    var h = fe.make_fe25519(arrFactory);
    var qt = fe.make_fe25519(arrFactory);
    fe.mul(qt, q.x, q.y, arrFactory);
    fe.sub(a, r.y, r.x, arrFactory); /* A = (Y1-X1)*(Y2-X2) */
    fe.add(b, r.y, r.x); /* B = (Y1+X1)*(Y2+X2) */
    fe.sub(t1, q.y, q.x, arrFactory);
    fe.add(t2, q.y, q.x);
    fe.mul(a, a, t1, arrFactory);
    fe.mul(b, b, t2, arrFactory);
    fe.sub(e, b, a, arrFactory); /* E = B-A */
    fe.add(h, b, a); /* H = B+A */
    fe.mul(c, r.t, qt, arrFactory); /* C = T1*k*T2 */
    fe.mul(c, c, ge25519_ec2d, arrFactory);
    fe.add(d, r.z, r.z); /*a, b, c, d, t D = Z1*2 */
    fe.sub(f, d, c, arrFactory); /* F = D-C */
    fe.add(g, d, c); /* G = D+C */
    fe.mul(r.x, e, f, arrFactory);
    fe.mul(r.y, h, g, arrFactory);
    fe.mul(r.z, g, f, arrFactory);
    fe.mul(r.t, e, h, arrFactory);
    arrFactory.recycle(a, b, t1, t2, c, d, e, f, g, h, qt);
}
/**
 * Analog of add_p1p1 in crypto_sign/ed25519/ref/ge25519.c
 */
function add_p1p1(r, p, q, arrFactory) {
    var a = fe.make_fe25519(arrFactory);
    var b = fe.make_fe25519(arrFactory);
    var c = fe.make_fe25519(arrFactory);
    var d = fe.make_fe25519(arrFactory);
    var t = fe.make_fe25519(arrFactory);
    fe.sub(a, p.y, p.x, arrFactory); /* A = (Y1-X1)*(Y2-X2) */
    fe.sub(t, q.y, q.x, arrFactory);
    fe.mul(a, a, t, arrFactory);
    fe.add(b, p.x, p.y); /* B = (Y1+X1)*(Y2+X2) */
    fe.add(t, q.x, q.y);
    fe.mul(b, b, t, arrFactory);
    fe.mul(c, p.t, q.t, arrFactory); /* C = T1*k*T2 */
    fe.mul(c, c, ge25519_ec2d, arrFactory);
    fe.mul(d, p.z, q.z, arrFactory); /* D = Z1*2*Z2 */
    fe.add(d, d, d);
    fe.sub(r.x, b, a, arrFactory); /* E = B-A */
    fe.sub(r.t, d, c, arrFactory); /* F = D-C */
    fe.add(r.z, d, c); /* G = D+C */
    fe.add(r.y, b, a); /* H = B+A */
    arrFactory.recycle(a, b, c, d, t);
}
/**
 * Analog of dbl_p1p1 in crypto_sign/ed25519/ref/ge25519.c
 * See http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd
 */
function dbl_p1p1(r, p, arrFactory) {
    var a = fe.make_fe25519(arrFactory);
    var b = fe.make_fe25519(arrFactory);
    var c = fe.make_fe25519(arrFactory);
    var d = fe.make_fe25519(arrFactory);
    fe.square(a, p.x, arrFactory);
    fe.square(b, p.y, arrFactory);
    fe.square(c, p.z, arrFactory);
    fe.add(c, c, c);
    fe.neg(d, a, arrFactory);
    fe.add(r.x, p.x, p.y);
    fe.square(r.x, r.x, arrFactory);
    fe.sub(r.x, r.x, a, arrFactory);
    fe.sub(r.x, r.x, b, arrFactory);
    fe.add(r.z, d, b);
    fe.sub(r.t, r.z, c, arrFactory);
    fe.sub(r.y, d, b, arrFactory);
    arrFactory.recycle(a, b, c, d);
}
/**
 * Analog of add_p1p1 in crypto_sign/ed25519/ref/ge25519.c
 * Constant-time version of: if(b) r = p
 */
function cmov_aff(r, p, b) {
    fe.cmov(r.x, p.x, b);
    fe.cmov(r.y, p.y, b);
}
/**
 * Analog of equal in crypto_sign/ed25519/ref/ge25519.c
 */
function equal(b, c) {
    return (b === c) ? 1 : 0;
    //	return ((b ^ c) - 1) >>> 31; /* 1: yes; 0: no */
}
/**
 * Analog of negative in crypto_sign/ed25519/ref/ge25519.c
 */
function negative(b) {
    return (b < 0) ? 1 : 0;
    //	return (b >>> 31); /* 1: yes; 0: no */
}
/**
 * Analog of choose_t in crypto_sign/ed25519/ref/ge25519.c
 */
function choose_t(t, pos, b, arrFactory) {
    /* constant time */
    var v = fe.make_fe25519(arrFactory);
    copy_ge25519_aff(t, ge25519_base_multiples_affine[5 * pos + 0]);
    cmov_aff(t, ge25519_base_multiples_affine[5 * pos + 1], equal(b, 1) | equal(b, -1));
    cmov_aff(t, ge25519_base_multiples_affine[5 * pos + 2], equal(b, 2) | equal(b, -2));
    cmov_aff(t, ge25519_base_multiples_affine[5 * pos + 3], equal(b, 3) | equal(b, -3));
    cmov_aff(t, ge25519_base_multiples_affine[5 * pos + 4], equal(b, -4));
    fe.neg(v, t.x, arrFactory);
    fe.cmov(t.x, v, negative(b));
    arrFactory.recycle(v);
}
/**
 * Analog of setneutral in crypto_sign/ed25519/ref/ge25519.c
 */
function setneutral(r) {
    fe.setzero(r.x);
    fe.setone(r.y);
    fe.setone(r.z);
    fe.setzero(r.t);
}
function unpackneg_vartime(r, p, arrFactory) {
    var t = fe.make_fe25519(arrFactory);
    var chk = fe.make_fe25519(arrFactory);
    var num = fe.make_fe25519(arrFactory);
    var den = fe.make_fe25519(arrFactory);
    var den2 = fe.make_fe25519(arrFactory);
    var den4 = fe.make_fe25519(arrFactory);
    var den6 = fe.make_fe25519(arrFactory);
    fe.setone(r.z);
    var par = p[31] >>> 7;
    fe.unpack(r.y, p);
    fe.square(num, r.y, arrFactory); /* x = y^2 */
    fe.mul(den, num, ge25519_ecd, arrFactory); /* den = dy^2 */
    fe.sub(num, num, r.z, arrFactory); /* x = y^2-1 */
    fe.add(den, r.z, den); /* den = dy^2+1 */
    /* Computation of sqrt(num/den) */
    /* 1.: computation of num^((p-5)/8)*den^((7p-35)/8) = (num*den^7)^((p-5)/8) */
    fe.square(den2, den, arrFactory);
    fe.square(den4, den2, arrFactory);
    fe.mul(den6, den4, den2, arrFactory);
    fe.mul(t, den6, num, arrFactory);
    fe.mul(t, t, den, arrFactory);
    fe.pow2523(t, t, arrFactory);
    /* 2. computation of r->x = t * num * den^3 */
    fe.mul(t, t, num, arrFactory);
    fe.mul(t, t, den, arrFactory);
    fe.mul(t, t, den, arrFactory);
    fe.mul(r.x, t, den, arrFactory);
    /* 3. Check whether sqrt computation gave correct result, multiply by sqrt(-1) if not: */
    fe.square(chk, r.x, arrFactory);
    fe.mul(chk, chk, den, arrFactory);
    if (!fe.iseq_vartime(chk, num, arrFactory)) {
        fe.mul(r.x, r.x, ge25519_sqrtm1, arrFactory);
    }
    /* 4. Now we have one of the two square roots, except if input was not a square */
    fe.square(chk, r.x, arrFactory);
    fe.mul(chk, chk, den, arrFactory);
    if (!fe.iseq_vartime(chk, num, arrFactory)) {
        return false;
    }
    /* 5. Choose the desired square root according to parity: */
    if (fe.getparity(r.x, arrFactory) !== (1 - par)) {
        fe.neg(r.x, r.x, arrFactory);
    }
    fe.mul(r.t, r.x, r.y, arrFactory);
    arrFactory.recycle(t, chk, num, den, den2, den4, den6);
    return true;
}
exports.unpackneg_vartime = unpackneg_vartime;
function pack(r, p, arrFactory) {
    var tx = fe.make_fe25519(arrFactory);
    var ty = fe.make_fe25519(arrFactory);
    var zi = fe.make_fe25519(arrFactory);
    fe.invert(zi, p.z, arrFactory);
    fe.mul(tx, p.x, zi, arrFactory);
    fe.mul(ty, p.y, zi, arrFactory);
    fe.pack(r, ty, arrFactory);
    r[31] ^= fe.getparity(tx, arrFactory) << 7;
    arrFactory.recycle(tx, ty, zi);
}
exports.pack = pack;
function double_scalarmult_vartime(r, p1, s1, p2, s2, arF) {
    var tp1p1 = make_ge25519_p1p1(arF);
    var pre = new Array(16);
    for (var i = 0; i < 16; i += 1) {
        if ((i !== 1) || (i !== 4)) {
            pre[i] = make_ge25519_p3(arF);
        }
    }
    var b = arF.getUint8Array(127);
    /* precomputation                                                        s2 s1 */
    setneutral(pre[0]); /* 00 00 */
    pre[1] = p1; /* 00 01 */
    dbl_p1p1(tp1p1, p1, arF);
    p1p1_to_p3(pre[2], tp1p1, arF); /* 00 10 */
    add_p1p1(tp1p1, pre[1], pre[2], arF);
    p1p1_to_p3(pre[3], tp1p1, arF); /* 00 11 */
    pre[4] = p2; /* 01 00 */
    add_p1p1(tp1p1, pre[1], pre[4], arF);
    p1p1_to_p3(pre[5], tp1p1, arF); /* 01 01 */
    add_p1p1(tp1p1, pre[2], pre[4], arF);
    p1p1_to_p3(pre[6], tp1p1, arF); /* 01 10 */
    add_p1p1(tp1p1, pre[3], pre[4], arF);
    p1p1_to_p3(pre[7], tp1p1, arF); /* 01 11 */
    dbl_p1p1(tp1p1, p2, arF);
    p1p1_to_p3(pre[8], tp1p1, arF); /* 10 00 */
    add_p1p1(tp1p1, pre[1], pre[8], arF);
    p1p1_to_p3(pre[9], tp1p1, arF); /* 10 01 */
    dbl_p1p1(tp1p1, pre[5], arF);
    p1p1_to_p3(pre[10], tp1p1, arF); /* 10 10 */
    add_p1p1(tp1p1, pre[3], pre[8], arF);
    p1p1_to_p3(pre[11], tp1p1, arF); /* 10 11 */
    add_p1p1(tp1p1, pre[4], pre[8], arF);
    p1p1_to_p3(pre[12], tp1p1, arF); /* 11 00 */
    add_p1p1(tp1p1, pre[1], pre[12], arF);
    p1p1_to_p3(pre[13], tp1p1, arF); /* 11 01 */
    add_p1p1(tp1p1, pre[2], pre[12], arF);
    p1p1_to_p3(pre[14], tp1p1, arF); /* 11 10 */
    add_p1p1(tp1p1, pre[3], pre[12], arF);
    p1p1_to_p3(pre[15], tp1p1, arF); /* 11 11 */
    sc.interleave2(b, s1, s2);
    /* scalar multiplication */
    copy_ge25519_p3(r, pre[b[126]]);
    for (var i = 125; i >= 0; i -= 1) {
        dbl_p1p1(tp1p1, r, arF);
        p1p1_to_p2(r, tp1p1, arF);
        dbl_p1p1(tp1p1, r, arF);
        if (b[i] !== 0) {
            p1p1_to_p3(r, tp1p1, arF);
            add_p1p1(tp1p1, r, pre[b[i]], arF);
        }
        if (i !== 0) {
            p1p1_to_p2(r, tp1p1, arF);
        }
        else {
            p1p1_to_p3(r, tp1p1, arF);
        }
    }
    recycle_ge25519(arF, tp1p1);
    for (var i = 0; i < 16; i += 1) {
        if ((i !== 1) && (i !== 4)) {
            recycle_ge25519(arF, pre[i]);
        }
    }
    arF.recycle(b);
}
exports.double_scalarmult_vartime = double_scalarmult_vartime;
function scalarmult_base(r, s, arrFactory) {
    var b = new Int8Array(85);
    var t = ge_base.make_ge25519_aff(arrFactory);
    sc.window3(b, s);
    choose_t(r, 0, b[0], arrFactory);
    fe.setone(r.z);
    fe.mul(r.t, r.x, r.y, arrFactory);
    for (var i = 1; i < 85; i += 1) {
        choose_t(t, i, b[i], arrFactory);
        ge25519_mixadd2(r, t, arrFactory);
    }
    recycle_ge25519_aff(arrFactory, t);
}
exports.scalarmult_base = scalarmult_base;
Object.freeze(exports);
