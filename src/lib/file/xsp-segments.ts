/* Copyright(c) 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * This file contains code for working with file headers and (un)packing
 * file segments.
 * Exported classes should be used inside xsp library, and must be wrapped,
 * if such functionality is needed externally.
 */

import arrays = require('../util/arrays');
import sbox = require('../boxes/secret_box');
import nonceMod = require('../util/nonce');
import xsp = require('./xsp');

interface ChainedSegsInfo {
	nonce: Uint8Array;
	numOfSegs: number;
	lastSegSize: number;
}

/**
 * @param x
 * @param i
 * @return unsigned 16-bit integer (2 bytes), stored littleendian way in x,
 * starting at index i.
 */
function loadUintFrom2Bytes(x: Uint8Array, i: number): number {
	return (x[i] << 8) | x[i+1];
}

/**
 * @param x
 * @param i
 * @param u is an unsigned 16-bit integer (2 bytes) to be stored littleendian
 * way in x, starting at index i.
 */
function storeUintIn2Bytes(x: Uint8Array, i: number, u: number): void {
	x[i] = u >>> 8;
	x[i+1] = u;
}

/**
 * @param x
 * @param i
 * @return unsigned 32-bit integer (4 bytes), stored littleendian way in x,
 * starting at index i.
 */
function loadUintFrom4Bytes(x: Uint8Array, i: number): number {
	return (x[i] << 24) | (x[i+1] << 16) | (x[i+2] << 8) | x[i+3];
}

/**
 * @param x
 * @param i
 * @param u is an unsigned 32-bit integer (4 bytes) to be stored littleendian
 * way in x, starting at index i.
 */
function storeUintIn4Bytes(x: Uint8Array, i: number, u: number): void {
	x[i] = u >>> 24;
	x[i+1] = u >>> 16;
	x[i+2] = u >>> 8;
	x[i+3] = u;
}

/**
 * @param x
 * @param i
 * @return unsigned 40-bit integer (5 bytes), stored littleendian way in x,
 * starting at index i.
 */
function loadUintFrom5Bytes(x: Uint8Array, i: number): number {
	var int = (x[i+1] << 24) | (x[i+2] << 16) | (x[i+3] << 8) | x[i+4];
	int += 0x100000000 * x[i];
	return int;
}

/**
 * @param x
 * @param i
 * @param u is an unsigned 40-bit integer (5 bytes) to be stored littleendian
 * way in x, starting at index i.
 */
function storeUintIn5Bytes(x: Uint8Array, i: number, u: number): void {
	x[i] = (u / 0x100000000) | 0;
	x[i+1] = u >>> 24;
	x[i+2] = u >>> 16;
	x[i+3] = u >>> 8;
	x[i+4] = u;
}

class SegInfoHolder {
	
	/**
	 * Total length of encrypted segments.
	 * Endless file has this field set to null.
	 */
	totalSegsLen: number;
	
	/**
	 * Total length of content bytes in this file.
	 * Endless file has this field set to null.
	 */
	totalContentLen: number;
	
	/**
	 * Total number of segment, for a fast boundary check.
	 * Endless file has this field set to null.
	 */
	totalNumOfSegments: number;
	
	/**
	 * Common encrypted segment size.
	 * Odd segments must be smaller than this value.
	 */
	segSize: number;
	
	/**
	 * Array with info objects about chains of segments with related nonces.
	 * This array shall have zero elements, if file is empty.
	 * If it is an endless file, then a single element shall have
	 * first segments' nonce, while all other numeric fields shall be null.
	 */
	segChains: ChainedSegsInfo[];
	
	/**
	 * Use this methods in inheriting classes.
	 * @param header is a 65 bytes of a with-nonce pack, containing
	 * 1) 1 byte, indicating segment size in 256byte chuncks, and
	 * 2) 24 bytes of the first segment's nonce.
	 * @param key is this file's key
	 * @param arrFactory
	 */
	initForEndlessFile(header: Uint8Array, key: Uint8Array,
			arrFactory: arrays.Factory): void {
		header = sbox.formatWN.open(header, key, arrFactory);
		this.totalSegsLen = null;
		this.totalContentLen = null;
		this.totalNumOfSegments = null;
		this.segSize = (header[0] << 8);
		this.segChains = [ {
			numOfSegs: null,
			lastSegSize: null,
			nonce: new Uint8Array(header.subarray(1, 25))
		} ];
		arrFactory.wipe(header);
	}
	
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
	initForFiniteFile(header: Uint8Array, key: Uint8Array,
			arrFactory: arrays.Factory): void {
		header = sbox.formatWN.open(header, key, arrFactory);
		this.totalSegsLen = loadUintFrom5Bytes(header, 0);
		this.segSize = (header[5] << 8);
		if (this.segSize === 0) { throw new Error(
			"Given header is malformed: default segment size is zero"); }
		
		// empty file
		if (this.totalSegsLen === 0) {
			this.segChains = [];
			this.totalContentLen = 0;
			this.totalNumOfSegments = 0;
			return;
		}
		
		// non-empty file
		this.segChains = new Array<ChainedSegsInfo>((header.length-6) / 30);
		var segChain: ChainedSegsInfo;
		this.totalContentLen = 0;
		this.totalNumOfSegments = 0;
		var isHeaderOK = 1;		// 1 for OK, and 0 for not-OK
		var offset = 6;
		for (var i=0; i<this.segChains.length; i+=1) {
			offset += i*30;
			segChain = {
				numOfSegs: loadUintFrom4Bytes(header, offset),
				lastSegSize: loadUintFrom2Bytes(header, offset+4),
				nonce: new Uint8Array(header.subarray(offset+6, offset+30))
			};
			this.segChains[i] = segChain;
			// collect totals
			this.totalContentLen += segChain.lastSegSize +
					this.segSize * (segChain.numOfSegs - 1) -
					16 * segChain.numOfSegs;
			this.totalNumOfSegments += segChain.numOfSegs;
			// check consistency of segments' length information
			isHeaderOK *= ((segChain.numOfSegs < 1) ? 0 : 1) *
				((segChain.lastSegSize < 17) ? 0 : 1) *
				((segChain.lastSegSize > this.segSize) ? 0 : 1);
		}
		arrFactory.wipe(header);
		// check consistency of totals
		isHeaderOK *= ((this.totalSegsLen ===
				((this.totalContentLen + 16*this.totalNumOfSegments))) ? 1 : 0);
		if (isHeaderOK === 0) { throw new Error("Given header is malformed."); }
	}
	
	isEndlessFile(): boolean {
		return (this.totalNumOfSegments === null);
	}
	
	contentLength(): number {
		return this.totalContentLen;
	}
	
	setContentLength(totalContentLen: number): void {
		if (!this.isEndlessFile()) { throw new Error(
				"Cannot set an end to an already finite file."); }
		if ((totalContentLen > 0xffffffffffff) ||
				(totalContentLen < 0)) { throw new Error(
				"File length is out of bounds for this implementation."); }
		if (totalContentLen === 0) {
			this.totalContentLen = 0;
			this.totalNumOfSegments = 0;
			this.totalSegsLen = 0;
			this.segChains = [];
		} else {
			this.totalContentLen = totalContentLen;
			var numOfEvenSegs = Math.floor(
					this.totalContentLen / (this.segSize - 16));
			this.totalNumOfSegments = numOfEvenSegs;
			if (numOfEvenSegs*(this.segSize-16) !== this.totalContentLen) {
				this.totalNumOfSegments += 1;
			}
			this.totalSegsLen =
					this.totalContentLen + 16*this.totalNumOfSegments;
			var segChain = this.segChains[0];
			segChain.numOfSegs = this.totalNumOfSegments;
			segChain.lastSegSize = this.totalSegsLen -
				(this.totalNumOfSegments - 1)*this.segSize;
		}
	}
	
	/**
	 * @param pos is byte's position index in file content.
	 * @return corresponding location in segment with segment's info.
	 */
	locationInSegments(pos: number): xsp.LocationInSegment {
		if (pos < 0) { throw new Error("Given position is out of bounds."); }
		var contentSegSize = this.segSize - 16;
		var segInd: number;
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
		if (pos >= this.totalContentLen) { throw new Error(
				"Given position is out of bounds."); }
		segInd = 0;
		var segStart = 0;
		var contentOffset = 0;
		var segChain: ChainedSegsInfo;
		var chainLen: number;
		for (var i=0; i<this.segChains.length; i+=1) {
			segChain = this.segChains[i];
			chainLen = segChain.lastSegSize +
					(segChain.numOfSegs - 1)*this.segSize;
			contentOffset += chainLen - 16*segChain.numOfSegs;
			if (contentOffset <= pos) {
				segInd += segChain.numOfSegs;
				segStart += chainLen;
				continue;
			}
			// @ this point contentOffset > pos
			contentOffset -= segChain.lastSegSize-16;
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
			contentOffset -= (segChain.numOfSegs - 1)*(this.segSize-16);
			var dSegInd = Math.floor((pos - contentOffset) / contentSegSize);
			contentOffset += dSegInd*(this.segSize-16);
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
	}
	
	packInfoToBytes(): Uint8Array {
		var head: Uint8Array;
		if (this.isEndlessFile()) {
			head = new Uint8Array(24 + 1);
			// 1) pack segment common size in 256 chunks
			head[0] = this.segSize >>> 8;
			// 2) 24 bytes with the first segment's nonce
			head.set(this.segChains[0].nonce, 1);
		} else {
			head = new Uint8Array(6 + 30*this.segChains.length);
			// 1) pack total segments length
			storeUintIn5Bytes(head, 0, this.totalSegsLen);
			// 2) pack segment common size in 256 chunks
			head[5] = this.segSize >>> 8;
			// 3) pack info about chained segments
			var segChain: ChainedSegsInfo;
			var offset = 6;
			for (var i=0; i<this.segChains.length; i+=1) {
				segChain = this.segChains[i];
				offset += i*30;
				// 3.1) 4 bytes with number of segments in this chain
				storeUintIn4Bytes(head, offset, segChain.numOfSegs);
				// 3.2) 2 bytes with this chain's last segments size
				storeUintIn2Bytes(head, offset + 4, segChain.lastSegSize);
				// 3.3) 24 bytes with the first nonce in this chain
				head.set(segChain.nonce, offset + 6);
			}
		}
		return head;
	}
	
	/**
	 * @param segInd
	 * @return segment's nonce, recyclable after its use.
	 */
	getSegmentNonce(segInd: number, arrFactory: arrays.Factory): Uint8Array {
		if (this.isEndlessFile()) {
			if (segInd > 0xffffffff) { throw new Error(
					"Given segment index is out of bounds."); }
			return nonceMod.calculateNonce(
					this.segChains[0].nonce, segInd, arrFactory);
		}
		if ((segInd >= this.totalNumOfSegments) ||
				(segInd < 0)) { throw new Error(
				"Given segment index is out of bounds."); }
		var segChain: ChainedSegsInfo;
		var lastSegInd = 0;
		for (var i=0; i<this.segChains.length; i+=1) {
			segChain = this.segChains[i];
			if ((lastSegInd + segChain.numOfSegs) <= segInd) {
				lastSegInd += segChain.numOfSegs;
				continue;
			} else {
				return nonceMod.calculateNonce(
						segChain.nonce, (segInd - lastSegInd), arrFactory);
			}
		}
		throw new Error("If we get here, there is an error in the loop above.");
	}
	
	numberOfSegments(): number {
		return this.totalNumOfSegments;
	}
	
	segmentSize(segInd: number): number {
		if (this.isEndlessFile()) {
			if (segInd > 0xffffffff) { throw new Error(
					"Given segment index is out of bounds."); }
			return this.segSize;
		}
		if ((segInd >= this.totalNumOfSegments) ||
				(segInd < 0)) { throw new Error(
				"Given segment index is out of bounds."); }
		var segChain: ChainedSegsInfo;
		var lastSegInd = 0;
		for (var i=0; i<this.segChains.length; i+=1) {
			segChain = this.segChains[i];
			if ((lastSegInd + segChain.numOfSegs) <= segInd) {
				lastSegInd += segChain.numOfSegs;
				continue;
			}
			return (((lastSegInd + segChain.numOfSegs - 1) === segInd) ?
						segChain.lastSegSize : this.segSize);
		}
		throw new Error("If we get here, there is an error in the loop above.");
	}
	
	segmentsLength(): number {
		return this.totalSegsLen;
	}
	
}

export class SegReader extends SegInfoHolder implements xsp.SegmentsReader {
	
	/**
	 * This is a file key, which should be wipped, after this object
	 * is no longer needed.
	 */
	private key: Uint8Array;
	
	private arrFactory: arrays.Factory;
	
	constructor(key: Uint8Array, header: Uint8Array,
			arrFactory: arrays.Factory) {
		super();
		this.arrFactory = arrFactory;
		if (key.length !== sbox.KEY_LENGTH) { throw new Error(
				"Given key has wrong size."); }
		this.key = new Uint8Array(key);
		header = header.subarray(72);
		if (header.length === 65) {
			this.initForEndlessFile(header, this.key, this.arrFactory);
		} else {
			if ((((header.length - 46) % 30) !== 0) ||
						(header.length < 46)) { throw new Error(
					"Given header array has incorrect size."); }
			this.initForFiniteFile(header, this.key, this.arrFactory);
		}
		Object.seal(this);
	}
	
	openSeg(seg: Uint8Array, segInd: number):
			{ data: Uint8Array; segLen: number; last?: boolean; } {
		var isLastSeg = ((segInd + 1) === this.totalNumOfSegments)
		var nonce = this.getSegmentNonce(segInd, this.arrFactory);
		var segLen = this.segmentSize(segInd);
		if (seg.length < segLen) {
			if (!this.isEndlessFile()) { throw new Error(
					"Given byte array is smaller than segment's size."); }
		} else if (seg.length > segLen) {
			seg = seg.subarray(0, segLen);
		}
		var bytes = sbox.open(seg, nonce, this.key, this.arrFactory);
		this.arrFactory.recycle(nonce);
		this.arrFactory.wipeRecycled();
		return { data: bytes, segLen: segLen, last: isLastSeg };
	}
	
	destroy(): void {
		this.arrFactory.wipe(this.key);
		this.key = null;
		for (var i=0; i<this.segChains.length; i+=1) {
			this.arrFactory.wipe(this.segChains[i].nonce);
		}
		this.segChains = null;
		this.arrFactory = null;
	}
	
	wrap(): xsp.SegmentsReader {
		var wrap: xsp.SegmentsReader = {
			locationInSegments: this.locationInSegments.bind(this),
			openSeg: this.openSeg.bind(this),
			destroy: this.destroy.bind(this),
			isEndlessFile: this.isEndlessFile.bind(this),
			contentLength: this.contentLength.bind(this),
			segmentSize: this.segmentSize.bind(this),
			segmentsLength: this.segmentsLength.bind(this),
			numberOfSegments: this.numberOfSegments.bind(this)
		};
		Object.freeze(wrap);
		return wrap;
	}
	
}

export class SegWriter extends SegInfoHolder implements xsp.SegmentsWriter {
	
	/**
	 * This is a file key, which should be wipped, after this object
	 * is no longer needed.
	 */
	private key: Uint8Array;
	
	/**
	 * This is a part of header with encrypted file key.
	 * The sole purpose of this field is to reuse these bytes on writting,
	 * eliminated a need to have a master key encryptor every time, when
	 * header is packed.
	 */
	private packedKey: Uint8Array;
	
	private arrFactory: arrays.Factory;
	
	private randomBytes: (n: number) => Uint8Array;
	
	private headerModified: boolean;
	
	/**
	 * @param key
	 * @param packedKey
	 * @param header a file's header without (!) packed key's 72 bytes.
	 * Array must contain only header's bytes, as its length is used to decide
	 * how to process it. It should be null for a new writer, and not-null,
	 * when writer is based an existing file's structure.
	 * @param segSizein256bs should be present for a new writer,
	 * otherwise, be null.
	 * @param randomBytes
	 * @param arrFactory
	 */
	constructor(key: Uint8Array, packedKey: Uint8Array,
			header: Uint8Array, segSizein256bs: number,
			randomBytes: (n: number) => Uint8Array, arrFactory: arrays.Factory) {
		super();
		this.arrFactory = arrFactory;
		this.randomBytes = randomBytes;
		if (key.length !== sbox.KEY_LENGTH) { throw new Error(
				"Given key has wrong size."); }
		this.key = new Uint8Array(key);
		if (packedKey.length !== 72) { throw new Error(
				"Given file key pack has wrong size."); }
		this.packedKey = packedKey;
		
		if (header) {
			if (header.length === 65) {
				this.initForEndlessFile(header, this.key, this.arrFactory);
			} else {
				if ((((header.length - 46) % 30) !== 0) ||
							(header.length < 46)) { throw new Error(
						"Given header array has incorrect size."); }
				this.initForFiniteFile(header, this.key, this.arrFactory);
			}
			this.headerModified = false;
		} else if ('number' === typeof segSizein256bs) {
			if ((segSizein256bs < 1) || (segSizein256bs > 255)) {
				throw new Error("Given segment size is illegal.");
			}
			this.initOfNewWriter(segSizein256bs << 8);
			this.headerModified = true;
		} else {
			throw new Error("Arguments are illegal, both header bytes and "+
					"segment size are missing");
		}
		Object.seal(this);
	}
	
	private initOfNewWriter(segSize: number): void {
		this.segSize = segSize;
		this.totalContentLen = null;
		this.totalNumOfSegments = null;
		this.totalSegsLen = null;
		this.segChains = [ {
			numOfSegs: null,
			lastSegSize: null,
			nonce: this.randomBytes(24)
		} ];
	}
	
	packSeg(content: Uint8Array, segInd: number):
			{ dataLen: number; seg: Uint8Array } {
		var nonce = this.getSegmentNonce(segInd, this.arrFactory);
		var expectedContentSize = this.segmentSize(segInd) - 16;
		if (content.length < expectedContentSize) {
			if (!this.isEndlessFile()) { throw new Error(
					"Given content has length "+content.length+
					", while content length of segment "+segInd+
					" should be "+expectedContentSize); }
		} else if (content.length > expectedContentSize) {
			content = content.subarray(0,expectedContentSize);
		}
		var seg = sbox.pack(content, nonce, this.key, this.arrFactory);
		this.arrFactory.recycle(nonce);
		this.arrFactory.wipeRecycled();
		return { seg: seg, dataLen: content.length };
	}
	
	destroy(): void {
		this.arrFactory.wipe(this.key);
		this.key = null;
		for (var i=0; i<this.segChains.length; i+=1) {
			this.arrFactory.wipe(this.segChains[i].nonce);
		}
		this.segChains = null;
		this.arrFactory = null;
	}
	
	reset(): void {
		this.initOfNewWriter(this.segSize);
		this.headerModified = true;
	}
	
	packHeader(): Uint8Array {
		// pack head
		var head = this.packInfoToBytes();
		// encrypt head with a file key
		head = sbox.formatWN.pack(head, this.randomBytes(24),
				this.key, this.arrFactory);
		// assemble and return complete header byte array
		var completeHeader = new Uint8Array(
				this.packedKey.length + head.length);
		completeHeader.set(this.packedKey, 0);
		completeHeader.set(head, 72);
		this.headerModified = false;
		return completeHeader;
	}
	
	setContentLength(totalSegsLen: number): void {
		super.setContentLength(totalSegsLen);
		this.headerModified = true;
	}
	
	isHeaderModified(): boolean {
		return this.headerModified;
	}
	
	splice(pos: number, rem: number, ins: number) {
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
		
	// TODO change segments info, and return info above required
	//      (re)encryption.
		
		throw new Error("Code is incomplete");
		
		// - calculate locations of edge bytes.
		var remEnd: xsp.LocationInSegment;
		if (rem > 0) {
			
		}
		
	
		// return object with info for getting bytes, and a lambda() to effect
		// the change, which should be called after reading edge bytes.
		
		return {};
	}
	
	wrap(): xsp.SegmentsWriter {
		var wrap: xsp.SegmentsWriter = {
			locationInSegments: this.locationInSegments.bind(this),
			packSeg: this.packSeg.bind(this),
			packHeader: this.packHeader.bind(this),
			setContentLength: this.setContentLength.bind(this),
			splice: this.splice.bind(this),
			isHeaderModified: this.isHeaderModified.bind(this),
			destroy: this.destroy.bind(this),
			reset: this.reset.bind(this),
			isEndlessFile: this.isEndlessFile.bind(this),
			contentLength: this.contentLength.bind(this),
			segmentSize: this.segmentSize.bind(this),
			segmentsLength: this.segmentsLength.bind(this),
			numberOfSegments: this.numberOfSegments.bind(this)
		};
		Object.freeze(wrap);
		return wrap;
	}
	
}


Object.freeze(exports);