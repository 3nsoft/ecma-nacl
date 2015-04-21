/* Copyright(c) 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
exports.segments = require('./xsp-segments');
function asciiToUint8Array(str) {
    var arr = new Uint8Array(str.length);
    for (var i = 0; i < str.length; i += 1) {
        arr[i] = str.charCodeAt(i);
    }
    return arr;
}
/**
 * This is a starting sequence of xsp file, which contains both
 * encrypted segments and a header.
 */
exports.FILE_START = asciiToUint8Array('xsp');
/**
 * This is an offset to segments in xsp file with both segments and header.
 */
exports.SEGMENTS_OFFSET = exports.FILE_START.length + 8;
/**
 * This is a starting sequence of a file with a header only.
 */
exports.HEADER_FILE_START = asciiToUint8Array('hxsp');
/**
 * This is a starting sequence of a file with encrypted segments nly.
 */
exports.SEGMENTS_FILE_START = asciiToUint8Array('sxsp');
/**
 * @param x
 * @param i
 * @param u is an unsigned integer (up to 48-bit) to be stored littleendian
 * way in x, starting at index i.
 */
function storeUintIn8Bytes(x, i, u) {
    x[i] = 0;
    x[i + 1] = 0;
    var h = (u / 0x100000000) | 0;
    x[i + 2] = h >>> 8;
    x[i + 3] = h;
    x[i + 4] = u >>> 24;
    x[i + 5] = u >>> 16;
    x[i + 6] = u >>> 8;
    x[i + 7] = u;
}
/**
 * @param x
 * @param i
 * @return unsigned integer (up to 48 bits), stored littleendian way
 * in 8 bytes of x, starting at index i.
 */
function loadUintFrom8Bytes(x, i) {
    if ((x[i] !== 0) || (x[i + 1] !== 0)) {
        throw new Error("This implementation does not allow numbers greater than 2^48.");
    }
    var h = (x[i + 2] << 8) | x[i + 3];
    var l = (x[i + 4] << 24) | (x[i + 5] << 16) | (x[i + 6] << 8) | x[i + 7];
    return (h * 0x100000000) + l;
}
/**
 * @param segsLen is a total length of encrypted segments.
 * @return XSP file starting bytes, which are
 * (1) 3 bytes "xsp", (2) 8 bytes with an offset, at which header starts.
 */
function generateXSPFileStart(segsLen) {
    if (segsLen > 0xffffffffffff) {
        new Error("This implementation " + "cannot handle byte arrays longer than 2^48 (256 TB).");
    }
    var fileStartLen = exports.FILE_START.length;
    var arr = new Uint8Array(fileStartLen + 8);
    arr.set(exports.FILE_START);
    storeUintIn8Bytes(arr, fileStartLen, segsLen + arr.length);
    return arr;
}
exports.generateXSPFileStart = generateXSPFileStart;
function getXSPHeaderOffset(xspBytes) {
    var fileStartLen = exports.FILE_START.length;
    if (xspBytes.length < (fileStartLen + 8)) {
        throw new Error("Given byte array is too short.");
    }
    for (var i = 0; i < fileStartLen; i += 1) {
        if (xspBytes[i] !== exports.FILE_START[i]) {
            throw new Error("Incorrect start of xsp file.");
        }
    }
    return loadUintFrom8Bytes(xspBytes, fileStartLen);
}
exports.getXSPHeaderOffset = getXSPHeaderOffset;
Object.freeze(exports);
