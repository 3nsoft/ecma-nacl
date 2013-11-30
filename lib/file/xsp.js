/* Copyright(c) 2013 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

var sbox = require('../boxes/secret_box');

var MIN_SEGMENT_SIZE = 0xff
, MAX_SEGMENT_SIZE = 0xffffffff
, START_STRING = "xsp"
, SEGMENT_CRYPTO_HEADER_LEN = 40;	// non-message initial bytes when packing cipher with nonce
var FILE_HEADER_LEN = START_STRING.length + 72 + 4
, FILE_START = new Uint8Array(START_STRING.length);
for (var i=0; i<START_STRING.length; i+=1) {
	FILE_START[i] = START_STRING.charAt(i);
}

/**
 * This function wipes the key array, before dropping it.
 * This function manipulates "this", therefore, it should be called always either on
 * Reader or Writer object.
 */
function wipeFileKey() {
	if (this.fileKey) {
		for (var i=0; i<32; i+=1) { this.fileKey[i] = 0; }
		this.fileKey = null;
	}
}

/**
 * @param segLen is an actual length of a segment, for which we want to find length of data,
 * encrypted in the segment.
 * @param isFirstSegment is a boolean flag telling, if given length is for first segment (true value),
 * or not (false value).
 * @returns a length of data encrypted in the segment. 
 */
function dataLenInSegment(segLen, isFirstSegment) {
	return segLen - SEGMENT_CRYPTO_HEADER_LEN - (isFirstSegment ? FILE_HEADER_LEN : 0);
}

function posInFileOf(segLen, dataPos) {
	"use strict";
	var segInd, byteInd;
	segInd = Math.floor(dataPos / (segLen-SEGMENT_CRYPTO_HEADER_LEN));
	byteInd = dataPos - segInd*(segLen-SEGMENT_CRYPTO_HEADER_LEN) + ((segInd>0) ? FILE_HEADER_LEN : 0);
	if(byteInd >= dataLenInSegment(segLen, (segInd === 0))) {
		byteInd -= dataLenInSegment(segLen, (segInd === 0));
		segInd += 1;
	}
	return {
		s: segInd,
		b: byteInd
	};
}

function posInDataOf(segLen, segInd, byteInd) {
	var pos = 0;
	if (segInd > 0) {
		pos += segInd*(segLen - SEGMENT_CRYPTO_HEADER_LEN) - FILE_HEADER_LEN;
	}
	pos += byteInd;
	return pos;
}

/**
 * @param x is Uint8Array, to which a given uint32 number should be stored.
 * @param i is position, at which storing of 4 bytes should start.
 * @param u is a number within uint32 limits, which should be stored in a given
 * byte array.
 */
function storeUint32(x, i, u) {
	x[i] = u; u >>>= 8;
	x[i+1] = u; u >>>= 8;
	x[i+2] = u; u >>>= 8;
	x[i+3] = u;
}

/**
 * @param x is Uint8Array, where number is stored.
 * @param i is position, at which number's bytes start.
 * @returns number within uint32 limits, loaded from a given array.
 */
function loadUint32(x, i) {
	return x[i] | (x[i+1] << 8) | (x[i+2] << 16) | (x[i+3] << 24);
}

/**
 * This is a constructor function for xsp file writer.
 * Writer encrypts and packs data into segments, according to set maximum segment size.
 * Note that this object does not assume where file segments should go (file, network, or db),
 * and, therefore, it is an application that should keep track of data, order of segments, and
 * where these are destined.  
 * @param segSize is a length of a complete file segment.
 * Only the last segment of xsp file may be shorter than this length.
 * Note that data length within the segment is always a little shorter than segment's length,
 * as crypto parameters and, in first segment, file parameters are preceding encrypted data bytes.
 * @param fileKey is Uint8Array with a key, that is used to encrypt data in every segment of this
 * file.
 * This file key itself is written into the first segment of the file in encrypted form.
 * @param nonce is Uint8Array, 24 bytes long, with nonce, used for encryption of file key.
 * @param key is Uint8Array, 32 bytes long, with key, used for encryption of file key.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 */
function Writer(segSize, fileKey, nonce, key, arrFactory) {
	"use strict";
	if (('number' !== typeof segSize) ||
			(segSize < MIN_SEGMENT_SIZE) ||
			(segSize > MAX_SEGMENT_SIZE)) {
		throw new Error("Given segment length parameter must be an integer between "+
				MIN_SEGMENT_SIZE+" and "+MAX_SEGMENT_SIZE);
	}
	Math.floor(segSize);
	this.segSize = segSize;
	if (fileKey.length !== 32) { throw new Error(
			"Given fileKey array is "+fileKey.length+" bytes long, instead of 32"); }
	this.fileKey = fileKey;
	this.fileKeyEnvelope = new Uint8Array(72);
	sbox.packIntoArrWithNonce(this.fileKeyEnvelope, this.fileKey, nonce, key, arrFactory);
}

Writer.prototype.wipeFileKey = wipeFileKey;

/**
 * This function writes file header at the start of the given byte array.
 * This function should be invoked with call() method on writer object.
 * @param seg is Uint8Array for segment bytes
 */
function writeFileHeader(seg) {
	// write file starting string
	seg.set(FILE_START);
	// write key envelope
	seg.set(this.fileKeyEnvelope, FILE_START.length);
	// write max segment length
	storeUint32(seg, FILE_HEADER_LEN-4, this.segSize);
}

/**
 * @param inArr is Uint8Array with bytes that need to be encrypted and packed into xsp file.
 * @param offset is position in the given inArr, from which reading starts.
 * @param isFirstSegment is a boolean flag telling, if the first file segment should be produced
 * (true value), or not (false value).
 * @param nonce is Uint8Array, 24 bytes long, with nonce for this particular segment.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 * @returns Uint8Array with created segment of xsp file.
 * If there are enough bytes to fill segment to maximum length, the segment will have
 * maximum length.
 * If there are not enough bytes for writing into file, segment will be shorter.
 * Thus, only the last segment of xsp file may be shorter than maximum segment size.
 */
Writer.prototype.packSegment = function(inArr, offset, isFirstSegment, nonce, arrFactory) {
	"use strict";
	if (!this.fileKey) { throw new Error("This writer cannot be used, as file key has been wiped."); }
	var dataLength = inArr.length - offset;
	if (dataLength <= 0) { throw new Error("There are no bytes to encode."); }
	dataLength = Math.min(dataLength, dataLenInSegment(this.segSize, isFirstSegment));
	var seg = new Uint8Array(
			dataLength + SEGMENT_CRYPTO_HEADER_LEN + (isFirstSegment ? FILE_HEADER_LEN : 0))
	, m = inArr.subarray(offset, offset + dataLength)
	, outArr;
	if (isFirstSegment) {
		writeFileHeader.call(this, seg);
		outArr = seg.subarray(FILE_HEADER_LEN);
	} else {
		outArr = seg;
	}
	sbox.packIntoArrWithNonce(outArr, m, nonce, this.fileKey, arrFactory);
	return seg;
};

/**
 * This is a constructor function for xsp file reader.
 * Reader decrypts data from xsp file segments.
 * This constructor will initialize reader by reading around 80 bytes from the first segment of
 * xsp file, opening file key, and finding an expected length of segments (note, only the last
 * segment is shorter than maximum length).
 * If needed, use segment length to find boundaries between segments.
 * Open segments in any order, but make sure to apply a different function to the first segment,
 * as its initial layout is different from following segments.
 * @param fileHeaderBytes is Uint8Array with bytes of xps file header.
 * @param key is Uint8Array, 32 bytes long, with key to decrypt file key, located in the first segment.
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 */
function Reader(fileHeaderBytes, key, arrFactory) {
	"use strict";
	if (fileHeaderBytes.length < FILE_HEADER_LEN) { throw new Error("Given headerBytes array is " +
			fileHeaderBytes.length+" bytes long, but it should be longer than "+FILE_HEADER_LEN); }
	// read file starting sequence
	for (var i=0; i<FILE_START.length; i+=1) {
		if (fileHeaderBytes[i] !== FILE_START[i]) { throw new Error(
				"Given fileHeaderBytes array does not start, as xsp file should."); }
	}
	// read file key
	this.fileKey = sbox.openArrWithNonce(
			fileHeaderBytes.subarray(FILE_START.length, FILE_START.length+72), key, arrFactory);
	// read max segment length
	this.segSize = loadUint32(fileHeaderBytes, FILE_HEADER_LEN-4);
}

/**
 * This decrypts data from a segment of xsp file.
 * @param seg is Uint8Array with bytes of a file segment.
 * @param isFirstSegment is a boolean flag telling, if given file segment is the first in file
 * (true value), or not (false value).
 * @param arrFactory is TypedArraysFactory, used to allocated/find an array for use.
 * It may be undefined, in which case an internally created one is used.
 */
Reader.prototype.openSegment = function(seg, isFirstSegment, arrFactory) {
	"use strict";
	if (!this.fileKey) { throw new Error("This reader cannot be used, as file key has been wiped."); }
	if (seg.length > this.segSize) { throw new Error("Given seg array is "+seg.length+
			" bytes long, which is longer than set segment length maximum "+this.segSize); }
	var c;
	if (isFirstSegment) {
		if (seg.length > FILE_HEADER_LEN+SEGMENT_CRYPTO_HEADER_LEN) {
			// if segment array is shorter than segSize, subarray() will set end index to array's length
			c = seg.subarray(FILE_HEADER_LEN, this.segSize);
		} else {
			throw new Error("Given seg array is "+seg.length+" bytes long, which is " +
					"shorter than minimum "+(FILE_HEADER_LEN+SEGMENT_CRYPTO_HEADER_LEN+1));
		}
	} else {
		if (seg.length > SEGMENT_CRYPTO_HEADER_LEN) {
			// if segment array is shorter than segSize, subarray() will set end index to array's length
			c = seg.subarray(0, this.segSize);
		} else {
			throw new Error("Given seg array is "+seg.length+" bytes long, which is " +
					"shorter than minimum "+(SEGMENT_CRYPTO_HEADER_LEN+1));
		}
	}
	return sbox.openArrWithNonce(c, this.fileKey, arrFactory);
};

Reader.prototype.wipeFileKey = wipeFileKey;

module.exports = {
		Reader: Reader,
		Writer: Writer,
		SEGMENT_CRYPTO_HEADER_LEN: SEGMENT_CRYPTO_HEADER_LEN,
		FILE_HEADER_LEN: FILE_HEADER_LEN,
		dataLenInSegment: dataLenInSegment,
		posInDataOf: posInDataOf,
		posInFileOf: posInFileOf
};