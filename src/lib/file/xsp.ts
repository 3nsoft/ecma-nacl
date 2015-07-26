/* Copyright(c) 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */


import arrays = require('../util/arrays');
import sbox = require('../boxes/secret_box');
import segments = require('./xsp-segments');


export interface LocationInSegment {
	
	/**
	 * Is a position in a decrypted content of a segment.
	 */
	pos: number;
	
	/**
	 * Segment with a loaction of interest.
	 */
	seg: {
		
		/**
		 * Index that points to the segment in the file.
		 */
		ind: number;
		
		/**
		 * Segment's start in the encrypted file.
		 */
		start: number;
		
		/**
		 * Length of encrypted segment.
		 */
		len: number;
	};
}

export interface SegmentsReader {
	
	/**
	 * @param pos is byte's position index in file content.
	 * @return corresponding location in segment with segment's info.
	 */
	locationInSegments(pos: number): LocationInSegment;
	
	/**
	 * @param seg is an array with encrypted segment's bytes, starting at
	 * zeroth index. Array may be longer than a segment, but it will an error,
	 * if it is shorter.
	 * @param segInd is segment's index in file.
	 * @return decrypted content bytes of a given segment and a length of
	 * decrypted segment.
	 * Data array is a view of buffer, which has 32 zeros preceding
	 * content bytes.
	 */
	openSeg(seg: Uint8Array, segInd: number):
		{ data: Uint8Array; segLen: number; last?: boolean; };
	
	/**
	 * This wipes file key and releases used resources.
	 */
	destroy(): void;
	
	isEndlessFile(): boolean;
	
	contentLength(): number;
	
	segmentsLength(): number;
	
	segmentSize(segInd: number): number;
	
	numberOfSegments(): number;
	
}

export interface SegmentsWriter {
	
	/**
	 * @param pos is byte's position index in file content.
	 * @return corresponding location in segment with segment's info.
	 */
	locationInSegments(pos: number): LocationInSegment;
	
	packSeg(content: Uint8Array, segInd: number):
		{ dataLen: number; seg: Uint8Array };
	
	/**
	 * This wipes file key and releases used resources.
	 */
	destroy(): void;
	
	/**
	 * This resets writer's internal state, keeping a file key, and removes info
	 * about segment chains, total length, etc.
	 * This allows for 100% fresh write of segments with the same file key, and
	 * same default segment size.
	 */
	reset(): void;
	
	packHeader(): Uint8Array;
	
	setContentLength(totalContentLen: number): void;
	
	isHeaderModified(): boolean;
	
	splice(pos: number, rem: number, ins: number);
	
	isEndlessFile(): boolean;
	
	contentLength(): number;
	
	segmentsLength(): number;
	
	segmentSize(segInd: number): number;
	
	numberOfSegments(): number;
	
}


function asciiToUint8Array(str: string): Uint8Array {
	var arr = new Uint8Array(str.length);
	for (var i=0; i<str.length; i+=1) {
		arr[i] = str.charCodeAt(i);
	}
	return arr;
}

/**
 * This is a starting sequence of xsp file, which contains both
 * encrypted segments and a header.
 */
export var FILE_START = asciiToUint8Array('xsp');

/**
 * This is an offset to segments in xsp file with both segments and header.
 */
export var SEGMENTS_OFFSET = FILE_START.length + 8;

/**
 * This is a starting sequence of a file with a header only.
 */
export var HEADER_FILE_START = asciiToUint8Array('hxsp');

/**
 * This is a starting sequence of a file with encrypted segments nly.
 */
export var SEGMENTS_FILE_START = asciiToUint8Array('sxsp');

/**
 * @param x
 * @param i
 * @param u is an unsigned integer (up to 48-bit) to be stored littleendian
 * way in x, starting at index i.
 */
function storeUintIn8Bytes(x: Uint8Array, i: number, u: number): void {
	x[i] = 0;
	x[i+1] = 0;
	var h = (u / 0x100000000) | 0;
	x[i+2] = h >>> 8;
	x[i+3] = h;
	x[i+4] = u >>> 24;
	x[i+5] = u >>> 16;
	x[i+6] = u >>> 8;
	x[i+7] = u;
}

/**
 * @param x
 * @param i
 * @return unsigned integer (up to 48 bits), stored littleendian way
 * in 8 bytes of x, starting at index i.
 */
function loadUintFrom8Bytes(x: Uint8Array, i: number): number {
	if ((x[i] !== 0) || (x[i+1] !== 0)) { throw new Error(
			"This implementation does not allow numbers greater than 2^48."); }
	var h = (x[i+2] << 8) | x[i+3];
	var l = (x[i+4] << 24) | (x[i+5] << 16) | (x[i+6] << 8) | x[i+7];
	return (h * 0x100000000) + l;
}

/**
 * @param segsLen is a total length of encrypted segments.
 * @return XSP file starting bytes, which are
 * (1) 3 bytes "xsp", (2) 8 bytes with an offset, at which header starts.
 */
export function generateXSPFileStart(segsLen: number): Uint8Array {
	if (segsLen > 0xffffffffffff) { new Error("This implementation "+
			"cannot handle byte arrays longer than 2^48 (256 TB)."); }
	var fileStartLen = FILE_START.length;
	var arr = new Uint8Array(fileStartLen + 8);
	arr.set(FILE_START);
	storeUintIn8Bytes(arr, fileStartLen, segsLen + arr.length);
	return arr;
}

export function getXSPHeaderOffset(xspBytes: Uint8Array): number {
	var fileStartLen = FILE_START.length;
	if (xspBytes.length < (fileStartLen+8)) { throw new Error(
			"Given byte array is too short."); }
	for (var i=0; i<fileStartLen; i+=1) {
		if (xspBytes[i] !== FILE_START[i]) { throw new Error(
				"Incorrect start of xsp file."); }
	}
	return loadUintFrom8Bytes(xspBytes, fileStartLen);
}

export interface FileKeyHolder {
	/**
	 * @param segSizein256bs is a default segment size in 256-byte blocks
	 * @param randomBytes is a function that produces cryptographically strong
	 * random numbers (bytes).
	 * @return segments writer either for a new file, or for a complete
	 * replacement of existing file's bytes.
	 */
	newSegWriter(segSizein256bs: number,
		randomBytes: (n: number) => Uint8Array): SegmentsWriter;
	
	/**
	 * @param header is an array with file's header. Array must contain only
	 * header's bytes, as its length is used to decide how to process it.
	 * @param randomBytes is a function that produces cryptographically strong
	 * random numbers (bytes).
	 * @return segments writer for changing existing file.
	 */
	segWriter(header: Uint8Array, randomBytes: (n: number) => Uint8Array):
		SegmentsWriter;
	
	/**
	 * @param header is an array with file's header. Array must contain only
	 * header's bytes, as its length is used to decide how to process it.
	 * @return segment reader
	 */
	segReader(header: Uint8Array): SegmentsReader;
	
	/**
	 * This wipes file key and releases used resources.
	 */
	destroy(): void;
	
	/**
	 * @param (optional) array factory for use by cloned key holder.
	 * @return creates a clone of this key holder, cloning key and all internals.
	 */
	clone(arrFactory?: arrays.Factory): FileKeyHolder;
	
}

var KEY_PACK_LENGTH = 72;

class KeyHolder implements FileKeyHolder {
	
	private key: Uint8Array;
	private keyPack: Uint8Array;
	private arrFactory: arrays.Factory;
	
	constructor(key: Uint8Array, keyPack: Uint8Array,
			arrFactory?: arrays.Factory) {
		this.key = key;
		this.keyPack = keyPack;
		this.arrFactory =  (arrFactory ?
			arrFactory : arrays.makeFactory());
	}
	
	newSegWriter(segSizein256bs: number,
			randomBytes: (n: number) => Uint8Array): SegmentsWriter {
		var writer = new segments.SegWriter(this.key, this.keyPack,
			null, segSizein256bs, randomBytes, this.arrFactory);
		return writer.wrap();
	}
	
	segWriter(header: Uint8Array,
			randomBytes: (n: number) => Uint8Array): SegmentsWriter {
		var writer = new segments.SegWriter(this.key,
				new Uint8Array(header.subarray(0,KEY_PACK_LENGTH)),
				header.subarray(KEY_PACK_LENGTH), null,
				randomBytes, this.arrFactory);
		return writer.wrap();
	}
	
	segReader(header: Uint8Array): SegmentsReader {
		var reader = new segments.SegReader(this.key, header, this.arrFactory);
		return reader.wrap();
	}
	
	destroy(): void {
		if (this.key) {
			arrays.wipe(this.key);
			this.key = null;
		}
		this.keyPack = null;
		if (this.arrFactory) {
			this.arrFactory.wipeRecycled();
			this.arrFactory = null;
		}
	}
	
	wrap(): FileKeyHolder {
		var wrap: FileKeyHolder = {
			destroy: this.destroy.bind(this),
			newSegWriter: this.newSegWriter.bind(this),
			segWriter: this.segWriter.bind(this),
			segReader: this.segReader.bind(this),
			clone: this.clone.bind(this)
		};
		Object.freeze(wrap);
		return wrap;
	}
	
	clone(arrFactory?: arrays.Factory): FileKeyHolder {
		var kh = new KeyHolder(this.key, this.keyPack, arrFactory);
		return kh.wrap();
	}
	
}

/**
 * @param mkeyEncr master key encryptor, which is used to make file key pack.
 * @param randomBytes is a function that produces cryptographically strong
 * random numbers (bytes).
 * @param arrFactory (optional) array factory
 * @return file key holder with a newly generated key.
 */
export function makeNewFileKeyHolder(mkeyEncr: sbox.Encryptor,
		randomBytes: (n: number) => Uint8Array,
		arrFactory?: arrays.Factory): FileKeyHolder {
	var fileKey = randomBytes(sbox.KEY_LENGTH);
	var fileKeyPack = mkeyEncr.pack(fileKey);
	var kh = new KeyHolder(fileKey, fileKeyPack, arrFactory);
	return kh.wrap();
}

/**
 * @param mkeyDecr master key decryptor, which is used to open file key.
 * @param header is an array with file's header. Array can be smaller than whole
 * header, but it must contain initial file key pack.
 * @param arrFactory (optional) array factory
 * @return file key holder with a key, extracted from a given header.
 */
export function makeFileKeyHolder(mkeyDecr: sbox.Decryptor, header: Uint8Array,
		arrFactory?: arrays.Factory): FileKeyHolder {
	var fileKeyPack = new Uint8Array(header.subarray(0, KEY_PACK_LENGTH));
	var fileKey = mkeyDecr.open(fileKeyPack);
	var kh = new KeyHolder(fileKey, fileKeyPack, arrFactory);
	return kh.wrap();
}

Object.freeze(exports);