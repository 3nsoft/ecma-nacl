/* Copyright(c) 2013 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

var sbox = require('../boxes/secret_box')
, TypedArraysFactory = require('../util/arrays')
, areBytesSame = require('../util/verify').verify;

/**
 * Minimum and maximum limits for segment size guaranty, that when
 * segment size is loaded with function provided here into 4 bytes, first
 * two zero bytes shall always be different from starting string, allowing
 * for distinguishing the first segment from all others.
 */
var MIN_SEGMENT_SIZE = 0xff
, MAX_SEGMENT_SIZE = 0xffffff
, START_STRING = "xsp"
/**
 * Segment non-message header contains:
 *  - 4 bytes with total segment length
 *  - 40 bytes of with-nonce pack (24 nonce bytes, followed by 16 poly bytes)
 */
, SEGMENT_HEADER_LEN = 44
/**
 * File header contains:
 *  - bytes with a start string (3 for 'xsp' string)
 *  - 72 bytes of file key encrypted into with-nonce form (40+32=72)
 *  - 4 bytes with a normal total segment size (the actual segment
 *    size can be smaller, but not bigger than this value) 
 */
, FILE_HEADER_LEN = START_STRING.length + 72 + 4
/**
 * First segment contains:
 *  - file header bytes
 *  - segment header bytes
 */
, FIRST_SEGMENT_HEADERS_LEN = SEGMENT_HEADER_LEN + FILE_HEADER_LEN
, FILE_START = new Uint8Array(START_STRING.length);
for (var i=0; i<START_STRING.length; i+=1) {
	FILE_START[i] = START_STRING.charCodeAt(i);
}

/**
 * @param x is Uint8Array, to which a given uint32 number should be stored.
 * @param i is position, at which storing of 4 bytes should start.
 * @param u is a number within uint32 limits, which should be stored in a given
 * byte array.
 */
function storeUint32(x, i, u) {
	"use strict";
	x[i+3] = u; u >>>= 8;
	x[i+2] = u; u >>>= 8;
	x[i+1] = u; u >>>= 8;
	x[i] = u;
}

/**
 * @param x is Uint8Array, where number is stored.
 * @param i is position, at which number's bytes start.
 * @returns number within uint32 limits, loaded from a given array.
 */
function loadUint32(x, i) {
	"use strict";
	return (x[i] << 24) | (x[i+1] << 16) | (x[i+2] << 8) | x[i+3];
}

/**
 * This throws up if given segment size is not ok.
 * @param segSize
 */
function validateSegSize(segSize) {
	"use strict";
	if (('number' !== typeof segSize) || ((segSize % 1) !== 0) ||
			(segSize < MIN_SEGMENT_SIZE) || (segSize > MAX_SEGMENT_SIZE)) {
		throw new TypeError("Given segment length parameter must be an " +
				"integer between "+MIN_SEGMENT_SIZE+" and "+MAX_SEGMENT_SIZE);
	}
}

/**
 * This function writes file header at the start of the given byte array.
 * @param seg is Uint8Array for segment bytes
 * @param fileKeyEnvelope
 * @param maxSegSize
 */
function writeFileHeader(seg, fileKeyEnvelope, maxSegSize) {
	"use strict";
	// write file starting string
	seg.set(FILE_START);
	// write key envelope
	seg.set(fileKeyEnvelope, FILE_START.length);
	// write max segment length
	storeUint32(seg, FILE_HEADER_LEN-4, maxSegSize);
}

/**
 * @param data is Uint8Array with bytes that need to be packed into xsp file.
 * @param fileKeyEnvelope is Uint8Array for the first segment, and is null,
 * for all others.
 * @param maxSegSize
 * @param fileKey
 * @param nonce
 * @param arrFactory
 * @return an object with the following fields:
 *  a) seg is an Uint8Array xsp file segment's bytes;
 *  b) dataLen is a number of data bytes that were packed into this segment.
 */
function packSegment(data, fileKeyEnvelope, maxSegSize,
		fileKey, nonce, arrFactory) {
	"use strict";
	if (!fileKey) { throw new Error(
			"This encryptor cannot be used, as file key has been wiped."); }
	if (data.length <= 0) { throw new Error("There are no bytes to encode."); }
	var headerLen = (fileKeyEnvelope ?
			FIRST_SEGMENT_HEADERS_LEN : SEGMENT_HEADER_LEN)
	, dataLen = Math.min(maxSegSize - headerLen, data.length)
	// make a segment array
	, seg = new Uint8Array(headerLen + dataLen)
	, outArr;
	// shorten data to those bytes that will be encrypted into the segment
	data = ((dataLen < data.length) ? data.subarray(0, dataLen) : data);
	if (fileKeyEnvelope) {
		writeFileHeader(seg, fileKeyEnvelope, maxSegSize);
		outArr = seg.subarray(FILE_HEADER_LEN);
	} else {
		outArr = seg;
	}
	// write this segment length
	storeUint32(outArr, 0, seg.length);
	outArr = outArr.subarray(4);
	// pack data itself
	sbox.formatWN.packInto(outArr, data, nonce, fileKey, arrFactory);
	return { seg: seg, dataLen: dataLen };
};

/**
 * @param seg is an Uint8Array with segments bytes, or with a long enough
 * part of it to contain header(s).
 * @return an object with the following fields:
 *  a) isFirstSeg is a boolean flag, telling if given segment is the first
 *  segment of a xsp file;
 *  b) segSize is an integer, telling this segmwnt's length;
 *  c) fileKeyEnvelope, present only if isFirstSeg===true, is an Uint8Array
 *     containing encrypted key of this file in a with-nonce format;
 *  d) commonSegSize, present only if isFirstSeg===true, is an integer, telling
 *     a maximum, or common segment size, used in this file. 
 */
function readHeaders(seg) {
	"use strict";
	var isFirstSegment = areBytesSame(seg, FILE_START, FILE_START.length)
	, info = {
		isFirstSeg: isFirstSegment
	};
	if (isFirstSegment) {
		if (seg.length < FIRST_SEGMENT_HEADERS_LEN) {
			throw new Error("Given seg array is "+seg.length+" bytes long, "+
					"which is too short to be the first segment header."); }
		info.fileKeyEnvelope = new Uint8Array(seg.subarray(
				FILE_START.length, FILE_HEADER_LEN-4));
		info.commonSegSize = loadUint32(seg, FILE_HEADER_LEN-4);
	} else {
		if (seg.length < SEGMENT_HEADER_LEN) {
			throw new Error("Given seg array is "+seg.length+" bytes long, "+
					"which is too short to be a segment header."); }
	}
	info.segSize = loadUint32(seg, (isFirstSegment ? FILE_HEADER_LEN : 0));
	if (!isFirstSegment && (info.segSize > MAX_SEGMENT_SIZE)) {
		throw new Error("Given seg array is misalligned with segment's bytes.");
	}
	return info;
}

/**
 * This decrypts data from a segment of xsp file.
 * @param seg is Uint8Array with xsp segment
 * @param fileKey
 * @param arrFactory
 * @return an object with the following fields:
 *  a) data is Uint8Array with bytes decrypted from a given segment
 *  b) segLen is a number of bytes read from a given segment
 */
function openSegment(seg, fileKey, arrFactory) {
	"use strict";
	if (!fileKey) { throw new Error(
			"This encryptor cannot be used, as file key has been wiped."); }
	var segInfo = readHeaders(seg);
	if (seg.length < segInfo.segSize) { throw new Error("Given seg array "+
			"is shorter than extracted size of this segment."); }
	// shorten seg to those bytes that will be opened as a with-nonce piece
	var offset = 4 + (segInfo.isFirstSeg ? FILE_HEADER_LEN : 0);
	seg = seg.subarray(offset, segInfo.segSize);
	var data = sbox.formatWN.open(seg, fileKey, arrFactory);
	return { data: data, segLen: segInfo.segSize };
};

/**
 * @param fileKeyEnvelope
 * @param segSize
 * @param fileKey
 * @param arrFactory
 * @return encryptor object with the following methods:
 *  a) packFirstSegment(data, nonce) encrypts given data, with given nonce,
 *     into the first xsp file segment.
 *     This method returns an object with segment bytes, and a field, telling
 *     how many of data bytes have been packed into the segment.
 *  b) packSegment(data, nonce) encrypts given data, with given nonce,
 *     into a xsp file segment, which is not the first segment in a file.
 *     This method returns an object with segment bytes, and a field, telling
 *     how many of data bytes have been packed into the segment.
 *  c) openSegment(seg) decrypts data bytes from a given segment.
 *     This method returns an object with data bytes, and a field, telling
 *     how many bytes have been read from a given segment array.
 *  d) destroy() wipes the file key, known to this encryptor.
 *     Encryptor becomes non-usable after this call.
 */
function makeEncryptor(fileKeyEnvelope, segSize, fileKey, arrFactory) {
	"use strict";
	var encr = {
			packFirstSegment: function(data, nonce) {
				try {
					return packSegment(data, fileKeyEnvelope,
							segSize, fileKey, nonce, arrFactory);
				} finally {
					arrFactory.wipeRecycled();
				}
			},
			packSegment: function(data, nonce) {
				try {
					return packSegment(data, null,
							segSize, fileKey, nonce, arrFactory);
				} finally {
					arrFactory.wipeRecycled();
				}
			},
			openSegment: function(seg) {
				try {
					return openSegment(seg, fileKey, arrFactory);
				} finally {
					arrFactory.wipeRecycled();
				}
			},
			commonSegSize: function() {
				return segSize;
			},
			destroy: function() {
				if (!fileKey) { return; }
				TypedArraysFactory.prototype.wipe(fileKey);
				fileKey = null;
				arrFactory = null;
			}
	};
	Object.freeze(encr);
	return encr;
}

/**
 * @param segSize is a common segment length.
 * Segments can be shorter than this, e.g. last, or changed segments, but
 * segments are never longer than this size.
 * Note that data length within the segment is always a little shorter than
 * segment's length, as crypto parameters and, in first segment, file
 * parameters are preceding encrypted data bytes.
 * @param fileKey is Uint8Array with a key, that is used to encrypt data in every
 * segment of this file.
 * This file key itself is written into the first segment of the file in encrypted
 * form.
 * @param fileKeyEncrFunc is a function that will encrypt file key.
 * Natural candidate for this is master key based encryptor's pack function.
 * @param arrFactory is an optional TypedArraysFactory, used to allocated/find
 * an array for use. If it is undefined, an internally created one is used.
 * @return encryptor object with the following methods:
 *  a) packFirstSegment(data, nonce) encrypts given data, with given nonce,
 *     into the first xsp file segment.
 *     This method returns an object with segment bytes, and a field, telling
 *     how many of data bytes have been packed into the segment.
 *  b) packSegment(data, nonce) encrypts given data, with given nonce,
 *     into a xsp file segment, which is not the first segment in a file.
 *     This method returns an object with segment bytes, and a field, telling
 *     how many of data bytes have been packed into the segment.
 *  c) openSegment(seg) decrypts data bytes from a given segment.
 *     This method returns an object with data bytes, and a field, telling
 *     how many bytes have been read from a given segment array.
 *  d) destroy() wipes the file key, known to this encryptor.
 *     Encryptor becomes non-usable after this call.
 */
function makeNewFileEncryptor(segSize, fileKey, fileKeyEncrFunc, arrFactory) {
	"use strict";
	if (fileKey.length !== sbox.KEY_LENGTH) { throw new Error(
			"Given fileKey array is "+fileKey.length+" bytes long, instead of "+
			sbox.KEY_LENGTH); }
	if ('function' !== typeof fileKeyEncrFunc) { throw new TypeError(
			"Argument 'fileKeyEncrFunc' is not a function."); }
	validateSegSize(segSize);
	var fileKeyEnvelope = fileKeyEncrFunc(fileKey);
	if ((fileKeyEnvelope.length !== 72) ||
			(fileKeyEnvelope.BYTES_PER_ELEMENT !==1)) {
		throw new Error("Key encrypting function produces wrong output."); }
	if (!arrFactory) { arrFactory = new TypedArraysFactory(); }
	return makeEncryptor(fileKeyEnvelope, segSize, fileKey, arrFactory);
}

/**
 * @param firstSegHeader is an array containing first segment's header,
 * which includes a file header.
 * @param fileKeyDecrFunc is a function for decrypting file key.
 * Natural candidate for this is master key based encryptor's open function.
 * @param arrFactory is an optional TypedArraysFactory, used to allocated/find
 * an array for use. If it is undefined, an internally created one is used.
 * @return encryptor object with the following methods:
 *  a) packFirstSegment(data, nonce) encrypts given data, with given nonce,
 *     into the first xsp file segment.
 *     This method returns an object with segment bytes, and a field, telling
 *     how many of data bytes have been packed into the segment.
 *  b) packSegment(data, nonce) encrypts given data, with given nonce,
 *     into a xsp file segment, which is not the first segment in a file.
 *     This method returns an object with segment bytes, and a field, telling
 *     how many of data bytes have been packed into the segment.
 *  c) openSegment(seg) decrypts data bytes from a given segment.
 *     This method returns an object with data bytes, and a field, telling
 *     how many bytes have been read from a given segment array.
 *  d) destroy() wipes the file key, known to this encryptor.
 *     Encryptor becomes non-usable after this call.
 */
function makeExistingFileEncryptor(firstSegHeader, fileKeyDecrFunc, arrFactory) {
	"use strict";
	var segInfo = readHeaders(firstSegHeader);
	if (!segInfo.isFirstSeg) { throw new Error("Given firstSegHeader array "+
			"does not contain file header, from the first file segment."); }
	if ('function' !== typeof fileKeyDecrFunc) { throw new TypeError(
			"Argument 'fileKeyDecrFunc' is not a function."); }
	if (!arrFactory) { arrFactory = new TypedArraysFactory(); }
	var fileKey = fileKeyDecrFunc(segInfo.fileKeyEnvelope);
	if ((fileKey.length !== sbox.KEY_LENGTH) || (fileKey.BYTES_PER_ELEMENT !==1)) {
		throw new Error("Key decrypting function produces wrong output."); }
	return makeEncryptor(segInfo.fileKeyEnvelope, segInfo.commonSegSize,
			fileKey, arrFactory);
}

var xspModule = {
		SEGMENT_HEADER_LEN: SEGMENT_HEADER_LEN,
		FILE_HEADER_LEN: FILE_HEADER_LEN,
		FIRST_SEGMENT_HEADERS_LEN: FIRST_SEGMENT_HEADERS_LEN,
		readHeaders: readHeaders,
		makeNewFileEncryptor: makeNewFileEncryptor,
		makeExistingFileEncryptor: makeExistingFileEncryptor
};

Object.freeze(xspModule);

module.exports = xspModule;
