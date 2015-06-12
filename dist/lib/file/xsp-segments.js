/* Copyright(c) 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
var __extends = this.__extends || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    __.prototype = b.prototype;
    d.prototype = new __();
};
/**
 * This file contains code for working with file headers and (un)packing
 * file segments.
 * Exported classes should be used inside xsp library, and must be wrapped,
 * if such functionality is needed externally.
 */
var arrays = require('../util/arrays');
var sbox = require('../boxes/secret_box');
var nonceMod = require('../util/nonce');
/**
 * @param x
 * @param i
 * @return unsigned 16-bit integer (2 bytes), stored littleendian way in x,
 * starting at index i.
 */
function loadUintFrom2Bytes(x, i) {
    return (x[i] << 8) | x[i + 1];
}
/**
 * @param x
 * @param i
 * @param u is an unsigned 16-bit integer (2 bytes) to be stored littleendian
 * way in x, starting at index i.
 */
function storeUintIn2Bytes(x, i, u) {
    x[i] = u >>> 8;
    x[i + 1] = u;
}
/**
 * @param x
 * @param i
 * @return unsigned 32-bit integer (4 bytes), stored littleendian way in x,
 * starting at index i.
 */
function loadUintFrom4Bytes(x, i) {
    return (x[i] << 24) | (x[i + 1] << 16) | (x[i + 2] << 8) | x[i + 3];
}
/**
 * @param x
 * @param i
 * @param u is an unsigned 32-bit integer (4 bytes) to be stored littleendian
 * way in x, starting at index i.
 */
function storeUintIn4Bytes(x, i, u) {
    x[i] = u >>> 24;
    x[i + 1] = u >>> 16;
    x[i + 2] = u >>> 8;
    x[i + 3] = u;
}
/**
 * @param x
 * @param i
 * @return unsigned 40-bit integer (5 bytes), stored littleendian way in x,
 * starting at index i.
 */
function loadUintFrom5Bytes(x, i) {
    var int = (x[i + 1] << 24) | (x[i + 2] << 16) | (x[i + 3] << 8) | x[i + 4];
    int += 0x100000000 * x[i];
    return int;
}
/**
 * @param x
 * @param i
 * @param u is an unsigned 40-bit integer (5 bytes) to be stored littleendian
 * way in x, starting at index i.
 */
function storeUintIn5Bytes(x, i, u) {
    x[i] = (u / 0x100000000) | 0;
    x[i + 1] = u >>> 24;
    x[i + 2] = u >>> 16;
    x[i + 3] = u >>> 8;
    x[i + 4] = u;
}
var SegInfoHolder = (function () {
    function SegInfoHolder() {
    }
    /**
     * Use this methods in inheriting classes.
     * @param header is a 65 bytes of a with-nonce pack, containing
     * 1) 1 byte, indicating segment size in 256byte chuncks, and
     * 2) 24 bytes of the first segment's nonce.
     * @param key is this file's key
     * @param arrFactory
     */
    SegInfoHolder.prototype.initForEndlessFile = function (header, key, arrFactory) {
        header = sbox.formatWN.open(header, key, arrFactory);
        this.totalSegsLen = null;
        this.totalContentLen = null;
        this.totalNumOfSegments = null;
        this.segSize = (header[0] << 8);
        this.segChains = [{
            numOfSegs: null,
            lastSegSize: null,
            nonce: new Uint8Array(header.subarray(1, 25))
        }];
        arrFactory.wipe(header);
    };
    /**
     * Use this methods in inheriting classes.
     * @param header is 46+n*30 bytes with-nonce pack, containing
     * 1) 5 bytes with total segments' length,
     * 2) 1 byte, indicating segment size in 256byte chuncks
     * 3) n 30-bytes chunks for each segments chain (n===0 for an empty file):
     * 3.1) 4 bytes with number of segments in this chain,
     * 3.2) 2 bytes with this chain's last segments size,
     * 3.3) 24 bytes with the first nonce in this chain.
     * @param key is this file's key
     * @param arrFactory
     */
    SegInfoHolder.prototype.initForFiniteFile = function (header, key, arrFactory) {
        header = sbox.formatWN.open(header, key, arrFactory);
        this.totalSegsLen = loadUintFrom5Bytes(header, 0);
        this.segSize = (header[5] << 8);
        if ((this.segSize === 0) || (this.totalSegsLen === 0)) {
            throw new Error("Given header is malformed.");
        }
        this.segChains = new Array((header.length - 6) / 30);
        var segChain;
        this.totalContentLen = 0;
        this.totalNumOfSegments = 0;
        var isHeaderOK = 1; // 1 for OK, and 0 for not-OK
        var offset = 6;
        for (var i = 0; i < this.segChains.length; i += 1) {
            offset += i * 30;
            segChain = {
                numOfSegs: loadUintFrom4Bytes(header, offset),
                lastSegSize: loadUintFrom2Bytes(header, offset + 4),
                nonce: new Uint8Array(header.subarray(offset + 6, offset + 30))
            };
            this.segChains[i] = segChain;
            // collect totals
            this.totalContentLen += segChain.lastSegSize + this.segSize * (segChain.numOfSegs - 1) - 16 * segChain.numOfSegs;
            this.totalNumOfSegments += segChain.numOfSegs;
            // check consistency of segments' length information
            isHeaderOK *= ((segChain.numOfSegs < 1) ? 0 : 1) * ((segChain.lastSegSize < 17) ? 0 : 1) * ((segChain.lastSegSize > this.segSize) ? 0 : 1);
        }
        arrFactory.wipe(header);
        // check consistency of totals
        isHeaderOK *= ((this.totalSegsLen === ((this.totalContentLen + 16 * this.totalNumOfSegments))) ? 1 : 0);
        if (isHeaderOK === 0) {
            throw new Error("Given header is malformed.");
        }
    };
    SegInfoHolder.prototype.isEndlessFile = function () {
        return (this.totalNumOfSegments === null);
    };
    SegInfoHolder.prototype.setContentLength = function (totalContentLen) {
        if (!this.isEndlessFile()) {
            throw new Error("Cannot set an end to an already finite file.");
        }
        if ((totalContentLen > 0xffffffffffff) || (totalContentLen < 0)) {
            throw new Error("File length is out of bounds for this implementation.");
        }
        if (totalContentLen === 0) {
            this.totalContentLen = 0;
            this.totalNumOfSegments = 0;
            this.totalSegsLen = 0;
            this.segChains = [];
        }
        else {
            this.totalContentLen = totalContentLen;
            var numOfEvenSegs = Math.floor(this.totalContentLen / (this.segSize - 16));
            this.totalNumOfSegments = numOfEvenSegs;
            if (numOfEvenSegs * (this.segSize - 16) !== this.totalContentLen) {
                this.totalNumOfSegments += 1;
            }
            this.totalSegsLen = this.totalContentLen + 16 * this.totalNumOfSegments;
            var segChain = this.segChains[0];
            segChain.numOfSegs = this.totalNumOfSegments;
            segChain.lastSegSize = this.totalSegsLen - (this.totalNumOfSegments - 1) * this.segSize;
        }
    };
    /**
     * @param pos is byte's position index in file content.
     * @return corresponding location in segment with segment's info.
     */
    SegInfoHolder.prototype.locationInSegments = function (pos) {
        if (pos < 0) {
            throw new Error("Given position is out of bounds.");
        }
        var contentSegSize = this.segSize - 16;
        var segInd;
        if (this.isEndlessFile()) {
            segInd = Math.floor(pos / contentSegSize);
            return {
                seg: {
                    ind: segInd,
                    start: (segInd * this.segSize),
                    len: this.segSize
                },
                pos: (pos - segInd * contentSegSize)
            };
        }
        if (pos >= this.totalContentLen) {
            throw new Error("Given position is out of bounds.");
        }
        segInd = 0;
        var segStart = 0;
        var contentOffset = 0;
        var segChain;
        var chainLen;
        for (var i = 0; i < this.segChains.length; i += 1) {
            segChain = this.segChains[i];
            chainLen = segChain.lastSegSize + (segChain.numOfSegs - 1) * this.segSize;
            contentOffset += chainLen - 16 * segChain.numOfSegs;
            if (contentOffset <= pos) {
                segInd += segChain.numOfSegs;
                segStart += chainLen;
                continue;
            }
            // @ this point contentOffset > pos
            contentOffset -= segChain.lastSegSize - 16;
            if (contentOffset <= pos) {
                return {
                    pos: (pos - contentOffset),
                    seg: {
                        ind: (segInd + segChain.numOfSegs - 1),
                        start: (chainLen - segChain.lastSegSize),
                        len: segChain.lastSegSize
                    }
                };
            }
            contentOffset -= (segChain.numOfSegs - 1) * (this.segSize - 16);
            var dSegInd = Math.floor((pos - contentOffset) / contentSegSize);
            contentOffset += dSegInd * (this.segSize - 16);
            return {
                pos: (pos - contentOffset),
                seg: {
                    ind: (segInd + dSegInd),
                    start: (segStart + dSegInd * this.segSize),
                    len: this.segSize
                }
            };
        }
        throw new Error("If we get here, there is an error in the loop above.");
    };
    SegInfoHolder.prototype.packInfoToBytes = function () {
        var head;
        if (this.isEndlessFile()) {
            head = new Uint8Array(24 + 1);
            // 1) pack segment common size in 256 chunks
            head[0] = this.segSize >>> 8;
            // 2) 24 bytes with the first segment's nonce
            head.subarray(1, 25).set(this.segChains[0].nonce);
        }
        else {
            head = new Uint8Array(6 + 30 * this.segChains.length);
            // 1) pack total segments length
            storeUintIn5Bytes(head, 0, this.totalSegsLen);
            // 2) pack segment common size in 256 chunks
            head[5] = this.segSize >>> 8;
            // 3) pack info about chained segments
            var segChain;
            var offset = 6;
            for (var i = 0; i < this.segChains.length; i += 1) {
                segChain = this.segChains[i];
                offset += i * 30;
                // 3.1) 4 bytes with number of segments in this chain
                storeUintIn4Bytes(head, offset, segChain.numOfSegs);
                // 3.2) 2 bytes with this chain's last segments size
                storeUintIn2Bytes(head, offset + 4, segChain.lastSegSize);
                // 3.3) 24 bytes with the first nonce in this chain
                head.subarray(offset + 6, offset + 30).set(segChain.nonce);
            }
        }
        return head;
    };
    /**
     * @param segInd
     * @return segment's nonce, recyclable after its use.
     */
    SegInfoHolder.prototype.getSegmentNonce = function (segInd, arrFactory) {
        if (this.isEndlessFile()) {
            if (segInd > 0xffffffff) {
                throw new Error("Given segment index is out of bounds.");
            }
            return nonceMod.calculateNonce(this.segChains[0].nonce, segInd, arrFactory);
        }
        if ((segInd >= this.totalNumOfSegments) || (segInd < 0)) {
            throw new Error("Given segment index is out of bounds.");
        }
        var segChain;
        var lastSegInd = 0;
        for (var i = 0; i < this.segChains.length; i += 1) {
            segChain = this.segChains[i];
            if ((lastSegInd + segChain.numOfSegs) <= segInd) {
                lastSegInd += segChain.numOfSegs;
                continue;
            }
            else {
                return nonceMod.calculateNonce(segChain.nonce, (segInd - lastSegInd), arrFactory);
            }
        }
        throw new Error("If we get here, there is an error in the loop above.");
    };
    SegInfoHolder.prototype.getSegmentSize = function (segInd) {
        if (this.isEndlessFile()) {
            if (segInd > 0xffffffff) {
                throw new Error("Given segment index is out of bounds.");
            }
            return this.segSize;
        }
        if ((segInd >= this.totalNumOfSegments) || (segInd < 0)) {
            throw new Error("Given segment index is out of bounds.");
        }
        var segChain;
        var lastSegInd = 0;
        for (var i = 0; i < this.segChains.length; i += 1) {
            segChain = this.segChains[i];
            if ((lastSegInd + segChain.numOfSegs) <= segInd) {
                lastSegInd += segChain.numOfSegs;
                continue;
            }
            return (((lastSegInd + segChain.numOfSegs - 1) === segInd) ? segChain.lastSegSize : this.segSize);
        }
        throw new Error("If we get here, there is an error in the loop above.");
    };
    return SegInfoHolder;
})();
/**
 * @param header is an array with header files. Array must contain only
 * header's bytes. Arrays's length is used to decide on how to process it.
 * @param mkeyDecr is a decryptor, based on a master key
 * @param arrFactory (optional)
 */
function makeReader(header, mkeyDecr, arrFactory) {
    if (!arrFactory) {
        arrFactory = arrays.makeFactory();
    }
    var reader = new SegReader(header, mkeyDecr, arrFactory);
    var wrap = {
        locationInSegments: reader.locationInSegments.bind(reader),
        openSeg: reader.openSeg.bind(reader),
        destroy: reader.destroy.bind(reader),
        isEndlessFile: reader.isEndlessFile.bind(reader)
    };
    return wrap;
}
exports.makeReader = makeReader;
var SegReader = (function (_super) {
    __extends(SegReader, _super);
    function SegReader(header, mkeyDecr, arrFactory) {
        _super.call(this);
        this.arrFactory = arrFactory;
        if (header.length < 72) {
            throw new Error("Given header array is too short.");
        }
        this.key = mkeyDecr.open(header.subarray(0, 72));
        header = header.subarray(72);
        if (header.length === 65) {
            this.initForEndlessFile(header, this.key, this.arrFactory);
        }
        else {
            if ((((header.length - 46) % 30) !== 0) || (header.length < 46)) {
                throw new Error("Given header array has incorrect size.");
            }
            this.initForFiniteFile(header, this.key, this.arrFactory);
        }
        Object.seal(this);
    }
    SegReader.prototype.openSeg = function (seg, segInd) {
        var isLastSeg = ((segInd + 1) === this.totalNumOfSegments);
        var nonce = this.getSegmentNonce(segInd, this.arrFactory);
        var segLen = this.getSegmentSize(segInd);
        if (seg.length < segLen) {
            if (!this.isEndlessFile()) {
                throw new Error("Given byte array is smaller than segment's size.");
            }
        }
        else if (seg.length > segLen) {
            seg = seg.subarray(0, segLen);
        }
        var bytes = sbox.open(seg, nonce, this.key, this.arrFactory);
        this.arrFactory.recycle(nonce);
        this.arrFactory.wipeRecycled();
        return { data: bytes, segLen: segLen, last: isLastSeg };
    };
    SegReader.prototype.destroy = function () {
        this.arrFactory.wipe(this.key);
        this.key = null;
        for (var i = 0; i < this.segChains.length; i += 1) {
            this.arrFactory.wipe(this.segChains[i].nonce);
        }
        this.segChains = null;
        this.arrFactory = null;
    };
    return SegReader;
})(SegInfoHolder);
function makeWriterWrap(writer) {
    return {
        locationInSegments: writer.locationInSegments.bind(writer),
        packSeg: writer.packSeg.bind(writer),
        packHeader: writer.packHeader.bind(writer),
        setContentLength: writer.setContentLength.bind(writer),
        splice: writer.splice.bind(writer),
        isHeaderModified: writer.isHeaderModified.bind(writer),
        destroy: writer.destroy.bind(writer),
        isEndlessFile: writer.isEndlessFile.bind(writer)
    };
}
function makeNewWriter(segSizein256bs, randomBytes, arrFactory) {
    if (!arrFactory) {
        arrFactory = arrays.makeFactory();
    }
    var writer = new SegWriter(null, null, segSizein256bs, randomBytes, arrFactory);
    return makeWriterWrap(writer);
}
exports.makeNewWriter = makeNewWriter;
/**
 * @param header is an array with header files. Array must contain only
 * header's bytes. Arrays's length is used to decide on how to process it.
 * @param mkeyDecr is a decryptor, based on a master key
 * @param randomBytes is a function that produces cryptographically strong
 * random numbers (bytes).
 * @param arrFactory (optional)
 */
function makeWriter(header, mkeyDecr, randomBytes, arrFactory) {
    if (!arrFactory) {
        arrFactory = arrays.makeFactory();
    }
    var writer = new SegWriter(header, mkeyDecr, null, randomBytes, arrFactory);
    return makeWriterWrap(writer);
}
exports.makeWriter = makeWriter;
var SegWriter = (function (_super) {
    __extends(SegWriter, _super);
    function SegWriter(header, mkeyDecr, segSizein256bs, randomBytes, arrFactory) {
        _super.call(this);
        this.arrFactory = arrFactory;
        this.randomBytes = randomBytes;
        if (header) {
            if (header.length < 72) {
                throw new Error("Given header array is too short.");
            }
            this.key = mkeyDecr.open(header.subarray(0, 72));
            header = header.subarray(72);
            if (header.length === 65) {
                this.initForEndlessFile(header, this.key, this.arrFactory);
            }
            else {
                if ((((header.length - 46) % 30) !== 0) || (header.length < 46)) {
                    throw new Error("Given header array has incorrect size.");
                }
                this.initForFiniteFile(header, this.key, this.arrFactory);
            }
            this.headerModified = false;
        }
        else if ('number' === typeof segSizein256bs) {
            if ((segSizein256bs < 1) || (segSizein256bs > 255)) {
                throw new Error("Given segment size is illegal.");
            }
            this.segSize = segSizein256bs << 8;
            this.key = randomBytes(32);
            this.totalContentLen = null;
            this.totalNumOfSegments = null;
            this.totalSegsLen = null;
            this.segChains = [{
                numOfSegs: null,
                lastSegSize: null,
                nonce: this.randomBytes(24),
                extendable: true
            }];
            this.headerModified = true;
        }
        else {
            throw new Error("Arguments are illegal, both header bytes and " + "segment size are missing");
        }
        Object.seal(this);
    }
    SegWriter.prototype.packSeg = function (content, segInd) {
        var nonce = this.getSegmentNonce(segInd, this.arrFactory);
        var expectedContentSize = this.getSegmentSize(segInd) - 16;
        if (content.length < expectedContentSize) {
            if (!this.isEndlessFile()) {
                throw new Error("Given content has length " + content.length + ", while content length of segment " + segInd + " should by " + expectedContentSize);
            }
        }
        else if (content.length > expectedContentSize) {
            content = content.subarray(0, expectedContentSize);
        }
        var seg = sbox.pack(content, nonce, this.key, this.arrFactory);
        this.arrFactory.recycle(nonce);
        this.arrFactory.wipeRecycled();
        return { seg: seg, dataLen: content.length };
    };
    SegWriter.prototype.destroy = function () {
        this.arrFactory.wipe(this.key);
        this.key = null;
        for (var i = 0; i < this.segChains.length; i += 1) {
            this.arrFactory.wipe(this.segChains[i].nonce);
        }
        this.segChains = null;
        this.arrFactory = null;
    };
    SegWriter.prototype.packHeader = function (mkeyEnc) {
        if (!this.headerModified) {
            new Error("Header has not been modified.");
        }
        // pack file key
        var packedfileKey = mkeyEnc.pack(this.key);
        // pack head
        var head = this.packInfoToBytes();
        // encrypt head with a file key
        head = sbox.formatWN.pack(head, this.randomBytes(24), this.key, this.arrFactory);
        // assemble and return complete header byte array
        var completeHeader = new Uint8Array(packedfileKey.length + head.length);
        completeHeader.subarray(0, 72).set(packedfileKey);
        completeHeader.subarray(72).set(head);
        this.headerModified = false;
        return completeHeader;
    };
    SegWriter.prototype.setContentLength = function (totalSegsLen) {
        _super.prototype.setContentLength.call(this, totalSegsLen);
        this.headerModified = true;
    };
    SegWriter.prototype.isHeaderModified = function () {
        return this.headerModified;
    };
    SegWriter.prototype.splice = function (pos, rem, ins) {
        if (this.isEndlessFile()) {
            throw new Error("Cannot splice endless file");
        }
        if (((rem < 1) && (ins < 1)) || (rem < 0) || (ins < 0)) {
            throw new Error("Invalid modification parameters.");
        }
        if ((this.totalSegsLen - rem + ins) > 0xffffffffffff) {
            throw new Error("Given modification will make file too long.");
        }
        var startLoc = this.locationInSegments(pos);
        throw new Error("Code is incomplete");
        // - calculate locations of edge bytes.
        var remEnd;
        if (rem > 0) {
        }
        // return object with info for getting bytes, and a lambda() to effect
        // the change, which should be called after reading edge bytes.
        return {};
    };
    return SegWriter;
})(SegInfoHolder);
Object.freeze(exports);
