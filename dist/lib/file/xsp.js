/* Copyright(c) 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
var arrays = require('../util/arrays');
var sbox = require('../boxes/secret_box');
var segments = require('./xsp-segments');
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
var KEY_PACK_LENGTH = 72;
var KeyHolder = (function () {
    function KeyHolder(key, keyPack, arrFactory) {
        this.key = key;
        this.keyPack = keyPack;
        this.arrFactory = (arrFactory ? arrFactory : arrays.makeFactory());
    }
    KeyHolder.prototype.newSegWriter = function (segSizein256bs, randomBytes) {
        var writer = new segments.SegWriter(this.key, this.keyPack, null, segSizein256bs, randomBytes, this.arrFactory);
        return writer.wrap();
    };
    KeyHolder.prototype.segWriter = function (header, randomBytes) {
        var writer = new segments.SegWriter(this.key, new Uint8Array(header.subarray(0, KEY_PACK_LENGTH)), header.subarray(KEY_PACK_LENGTH), null, randomBytes, this.arrFactory);
        return writer.wrap();
    };
    KeyHolder.prototype.segReader = function (header) {
        var reader = new segments.SegReader(this.key, header, this.arrFactory);
        return reader.wrap();
    };
    KeyHolder.prototype.destroy = function () {
        if (this.key) {
            arrays.wipe(this.key);
            this.key = null;
        }
        this.keyPack = null;
        if (this.arrFactory) {
            this.arrFactory.wipeRecycled();
            this.arrFactory = null;
        }
    };
    KeyHolder.prototype.wrap = function () {
        var wrap = {
            destroy: this.destroy.bind(this),
            newSegWriter: this.newSegWriter.bind(this),
            segWriter: this.segWriter.bind(this),
            segReader: this.segReader.bind(this),
            clone: this.clone.bind(this)
        };
        Object.freeze(wrap);
        return wrap;
    };
    KeyHolder.prototype.clone = function (arrFactory) {
        var kh = new KeyHolder(this.key, this.keyPack, arrFactory);
        return kh.wrap();
    };
    return KeyHolder;
})();
/**
 * @param mkeyEncr master key encryptor, which is used to make file key pack.
 * @param randomBytes is a function that produces cryptographically strong
 * random numbers (bytes).
 * @param arrFactory (optional) array factory
 * @return file key holder with a newly generated key.
 */
function makeNewFileKeyHolder(mkeyEncr, randomBytes, arrFactory) {
    var fileKey = randomBytes(sbox.KEY_LENGTH);
    var fileKeyPack = mkeyEncr.pack(fileKey);
    var kh = new KeyHolder(fileKey, fileKeyPack, arrFactory);
    return kh.wrap();
}
exports.makeNewFileKeyHolder = makeNewFileKeyHolder;
/**
 * @param mkeyDecr master key decryptor, which is used to open file key.
 * @param header is an array with file's header. Array can be smaller than whole
 * header, but it must contain initial file key pack.
 * @param arrFactory (optional) array factory
 * @return file key holder with a key, extracted from a given header.
 */
function makeFileKeyHolder(mkeyDecr, header, arrFactory) {
    var fileKeyPack = new Uint8Array(header.subarray(0, KEY_PACK_LENGTH));
    var fileKey = mkeyDecr.open(fileKeyPack);
    var kh = new KeyHolder(fileKey, fileKeyPack, arrFactory);
    return kh.wrap();
}
exports.makeFileKeyHolder = makeFileKeyHolder;
Object.freeze(exports);
