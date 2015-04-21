/* Copyright(c) 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
/**
 * Analog of round in crypto_hashblocks/sha256/inplace/blocks.c
 */
var round = new Uint32Array(64);
round.set([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
/**
 * Analog of SHA256_Transform in lib/crypto/sha256.h
 * with all C macros expanded.
 */
function crypto_hashblocks(state, inArr, arrFactory) {
    var W = arrFactory.getUint32Array(64);
    var inlen = inArr.length;
    var inInd = 0;
    var a;
    var b;
    var c;
    var d;
    var e;
    var f;
    var g;
    var h;
    var t0;
    var t1;
    var t;
    while (inlen >= 64) {
        for (var i = 0; i < 16; i += 1) {
            t = inInd + i * 4;
            W[i] = (inArr[t] << 24) + (inArr[t + 1] << 16) + (inArr[t + 2] << 8) + inArr[t + 3];
        }
        for (var i = 16; i < 64; i += 1) {
            t = W[i - 2];
            // t0 = sigma1(t); expanded below
            t0 = ((t >>> 17) | (t << 15)) ^ ((t >>> 19) | (t << 13)) ^ (t >>> 10);
            t = W[i - 15];
            // t1 = sigma0(t); expanded below
            t1 = ((t >>> 7) | (t << 25)) ^ ((t >>> 18) | (t << 14)) ^ (t >>> 3);
            W[i] = t0 + W[i - 7] + t1 + W[i - 16];
        }
        /* Mix.
           All RNDr's are put into one loop for 0<=i<64.
           All index calculations inside RNDr are equivalent to having
           8 local variables (a...h) instead of array S, with values
           rotation on every loop, with last rotation returning values
           to initial mapping.
           All macros are inlined, instead of having them as function
           calls (less calls and a use of local variables instead of
           arrays, make faster this heavily used part of code). */
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];
        for (var i = 0; i < 64; i += 1) {
            t0 = h + W[i] + round[i];
            // t0 += Sigma1(e);
            t0 += ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
            // t0 += Ch(e, f, g);
            t0 += (e & (f ^ g)) ^ g;
            // t1 = Sigma0(a);
            t1 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
            // t1 += Maj(a, b, c);
            t1 += (a & (b | c)) | (b & c);
            d += t0;
            h = t0 + t1;
            // do values flipping
            t0 = h;
            h = g;
            g = f;
            f = e;
            e = d;
            d = c;
            c = b;
            b = a;
            a = t0;
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
        inInd += 64;
        inlen -= 64;
    }
    arrFactory.recycle(W);
    return inlen;
}
function hashFromU32toU8(statebytes, state) {
    var u;
    for (var i = 0; i < 8; i += 1) {
        u = state[i];
        statebytes[i * 4 + 3] = u;
        statebytes[i * 4 + 2] = u >>> 8;
        statebytes[i * 4 + 1] = u >>> 16;
        statebytes[i * 4] = u >>> 24;
    }
}
/**
 * Analog of iv in crypto_hash/sha256/inplace/ref.c
 */
var iv = new Uint32Array(8);
iv.set([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
function hash_padded_block(h, oddBytes, totalLen, arrFactory) {
    var padded = arrFactory.getUint8Array(128);
    var oddLen = oddBytes.length;
    var bits = arrFactory.getUint32Array(2);
    bits[0] = (totalLen / 0x20000000) | 0;
    bits[1] = totalLen << 3;
    for (var i = 0; i < oddLen; i += 1) {
        padded[i] = oddBytes[i];
    }
    padded[oddLen] = 0x80;
    if (oddLen < 56) {
        for (var i = oddLen + 1; i < 56; i += 1) {
            padded[i] = 0;
        }
        padded[56] = bits[0] >>> 56;
        padded[57] = bits[0] >>> 48;
        padded[58] = bits[0] >>> 40;
        padded[59] = bits[0] >>> 32;
        padded[60] = bits[1] >>> 24;
        padded[61] = bits[1] >>> 16;
        padded[62] = bits[1] >>> 8;
        padded[63] = bits[1];
        crypto_hashblocks(h, padded.subarray(0, 64), arrFactory);
    }
    else {
        for (var i = oddLen + 1; i < 120; i += 1) {
            padded[i] = 0;
        }
        padded[120] = bits[0] >>> 56;
        padded[121] = bits[0] >>> 48;
        padded[122] = bits[0] >>> 40;
        padded[123] = bits[0] >>> 32;
        padded[124] = bits[1] >>> 24;
        padded[125] = bits[1] >>> 16;
        padded[126] = bits[1] >>> 8;
        padded[127] = bits[1];
        crypto_hashblocks(h, padded, arrFactory);
    }
    arrFactory.recycle(padded, bits);
}
function makeSha256Ctx(arrFactory) {
    return {
        buf: arrFactory.getUint8Array(64),
        bufBytes: 0,
        state: arrFactory.getUint32Array(8),
        count: 0,
        arrFactory: arrFactory
    };
}
exports.makeSha256Ctx = makeSha256Ctx;
function recycleSha256Ctxs() {
    var ctxs = [];
    for (var _i = 0; _i < arguments.length; _i++) {
        ctxs[_i - 0] = arguments[_i];
    }
    var ctx;
    for (var i = 0; i < ctxs.length; i += 1) {
        ctx = ctxs[i];
        ctx.arrFactory.recycle(ctx.state, ctx.buf);
        ctx.state = null;
        ctx.buf = null;
        ctx.arrFactory = null;
    }
}
exports.recycleSha256Ctxs = recycleSha256Ctxs;
function SHA256_Init(ctx) {
    ctx.state.set(iv);
    ctx.bufBytes = 0;
    ctx.count = 0;
}
exports.SHA256_Init = SHA256_Init;
function SHA256_Update(ctx, m, mi, mlen) {
    if (mlen === 0) {
        return;
    }
    ctx.count += mlen;
    if (ctx.bufBytes > 0) {
        var delta = Math.min(mlen, 64 - ctx.bufBytes);
        for (var i = 0; i < delta; i += 1) {
            ctx.buf[ctx.bufBytes + i] = m[mi + i];
        }
        ctx.bufBytes += delta;
        if (ctx.bufBytes < 64) {
            return;
        }
        else {
            crypto_hashblocks(ctx.state, ctx.buf, ctx.arrFactory);
            ctx.bufBytes = 0;
            mi += delta;
            mlen -= delta;
            if (mlen === 0) {
                return;
            }
        }
    }
    ctx.bufBytes = crypto_hashblocks(ctx.state, m.subarray(mi, mi + mlen), ctx.arrFactory);
    mi += mlen - ctx.bufBytes;
    for (var i = 0; i < ctx.bufBytes; i += 1) {
        ctx.buf[i] = m[mi + i];
    }
}
exports.SHA256_Update = SHA256_Update;
function SHA256_Final(h, ctx) {
    hash_padded_block(ctx.state, ctx.buf.subarray(0, ctx.bufBytes), ctx.count, ctx.arrFactory);
    ctx.count = 0;
    ctx.bufBytes = 0;
    hashFromU32toU8(h, ctx.state);
}
exports.SHA256_Final = SHA256_Final;
function makeHmacSHA256Context(arrFactory) {
    return {
        ictx: makeSha256Ctx(arrFactory),
        octx: makeSha256Ctx(arrFactory),
        arrFactory: arrFactory
    };
}
function recycleHmacSHA256Context() {
    var ctxs = [];
    for (var _i = 0; _i < arguments.length; _i++) {
        ctxs[_i - 0] = arguments[_i];
    }
    var ctx;
    for (var i = 0; i < ctxs.length; i += 1) {
        ctx = ctxs[i];
        recycleSha256Ctxs(ctx.ictx, ctx.octx);
    }
}
function copyHmacSHA256Context(dst, src) {
    dst.ictx.state.set(src.ictx.state);
    dst.ictx.count = src.ictx.count;
    dst.ictx.buf.set(src.ictx.buf);
    dst.ictx.bufBytes = src.ictx.bufBytes;
    dst.octx.state.set(src.octx.state);
    dst.octx.count = src.octx.count;
    dst.octx.buf.set(src.octx.buf);
    dst.octx.bufBytes = src.octx.bufBytes;
}
function copyBytes(dst, di, src, si, len) {
    for (var i = 0; i < len; i += 1) {
        dst[di + i] = src[si + i];
    }
}
/**
 * Analog of HMAC_SHA256_Init in lib/crypto/sha256.c
 * Initialize an HMAC-SHA256 operation with the given key.
 */
function HMAC_SHA256_Init(ctx, K, KInd, Klen) {
    var pad = ctx.arrFactory.getUint8Array(64);
    var khash = ctx.arrFactory.getUint8Array(32);
    /* If Klen > 64, the key is really SHA256(K). */
    if (Klen > 64) {
        SHA256_Init(ctx.ictx);
        SHA256_Update(ctx.ictx, K, KInd, Klen);
        SHA256_Final(khash, ctx.ictx);
        K = khash;
        KInd = 0;
        Klen = 32;
    }
    /* Inner SHA256 operation is SHA256(K xor [block of 0x36] || data). */
    SHA256_Init(ctx.ictx);
    for (var i = 0; i < Klen; i += 1) {
        pad[i] = K[i] ^ 0x36;
    }
    for (var i = Klen; i < 64; i += 1) {
        pad[i] = 0x36;
    }
    SHA256_Update(ctx.ictx, pad, 0, 64);
    /* Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash). */
    SHA256_Init(ctx.octx);
    for (var i = 0; i < Klen; i += 1) {
        pad[i] = K[i] ^ 0x5c;
    }
    for (var i = Klen; i < 64; i += 1) {
        pad[i] = 0x5c;
    }
    SHA256_Update(ctx.octx, pad, 0, 64);
    ctx.arrFactory.recycle(khash, pad);
}
/**
 * Analog of HMAC_SHA256_Update in lib/crypto/sha256.c
 * Add bytes to the HMAC-SHA256 operation.
 */
function HMAC_SHA256_Update(ctx, inArr, inInd, len) {
    /* Feed data to the inner SHA256 operation. */
    SHA256_Update(ctx.ictx, inArr, inInd, len);
}
/**
 * Analog of HMAC_SHA256_Update in lib/crypto/sha256.c
 * Finish an HMAC-SHA256 operation.
 */
function HMAC_SHA256_Final(digest, ctx) {
    var ihash = ctx.arrFactory.getUint8Array(32);
    /* Finish the inner SHA256 operation. */
    SHA256_Final(ihash, ctx.ictx);
    /* Feed the inner hash to the outer SHA256 operation. */
    SHA256_Update(ctx.octx, ihash, 0, 32);
    /* Finish the outer SHA256 operation. */
    SHA256_Final(digest, ctx.octx);
    ctx.arrFactory.recycle(ihash);
}
/**
 * Analog of be32enc in lib/util/sysendian.h
 */
function be32enc(p, pi, x) {
    p[pi + 3] = x;
    p[pi + 2] = (x >>> 8);
    p[pi + 1] = (x >>> 16);
    p[pi] = (x >>> 24);
}
exports.be32enc = be32enc;
/**
 * Analog of PBKDF2_SHA256 in lib/crypto/sha256.c
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf, length dkLen, which must be at most 32 * (2^32 - 1).
 */
function PBKDF2_SHA256(passwd, salt, c, buf, arrFactory) {
    var dkLen = buf.length;
    var PShctx = makeHmacSHA256Context(arrFactory);
    var hctx = makeHmacSHA256Context(arrFactory);
    var ivec = arrFactory.getUint8Array(4);
    var U = arrFactory.getUint8Array(32);
    var T = arrFactory.getUint8Array(32);
    /* Compute HMAC state after processing P and S. */
    HMAC_SHA256_Init(PShctx, passwd, 0, passwd.length);
    HMAC_SHA256_Update(PShctx, salt, 0, salt.length);
    for (var i = 0; (i * 32) < dkLen; i += 1) {
        /* Generate INT(i + 1). */
        be32enc(ivec, 0, i + 1);
        /* Compute U_1 = PRF(P, S || INT(i)). */
        copyHmacSHA256Context(hctx, PShctx);
        HMAC_SHA256_Update(hctx, ivec, 0, 4);
        HMAC_SHA256_Final(U, hctx);
        /* T_i = U_1 ... */
        copyBytes(T, 0, U, 0, 32);
        for (var j = 2; j <= c; j += 1) {
            /* Compute U_j. */
            HMAC_SHA256_Init(hctx, passwd, 0, passwd.length);
            HMAC_SHA256_Update(hctx, U, 0, 32);
            HMAC_SHA256_Final(U, hctx);
            for (var k = 0; k < 32; k += 1) {
                T[k] ^= U[k];
            }
        }
        /* Copy as many bytes as necessary into buf. */
        var clen = dkLen - i * 32;
        if (clen > 32) {
            clen = 32;
        }
        copyBytes(buf, (i * 32), T, 0, clen);
    }
    recycleHmacSHA256Context(PShctx, hctx);
    arrFactory.recycle(ivec, U, T);
}
exports.PBKDF2_SHA256 = PBKDF2_SHA256;
Object.freeze(exports);
