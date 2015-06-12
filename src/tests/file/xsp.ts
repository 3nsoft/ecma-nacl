/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Testing xsp file format functions.
 */

import nu = require('nodeunit');
import nacl = require('../../lib/ecma-nacl');
import testUtil = require('../test-utils');

var compare = testUtil.compare;
var getRandom = testUtil.getRandom;
var xsp = nacl.fileXSP;

/**
 * Test encrypting and packing dataLen of bytes of data into xsp file
 * with segment size segSizein256bs with a simple, single chain header.
 */
function testSingleChainHeader(test: nu.Test,
		dataLen: number, segSizein256bs: number) {

	var data = getRandom(dataLen);
	var masterKey = getRandom(32);
	var mkeyEncr = nacl.secret_box.formatWN.makeEncryptor(
		masterKey, getRandom(24));
	var mkeyDecr = nacl.secret_box.formatWN.makeDecryptor(masterKey);

	// initialize writer
	var writer = xsp.segments.makeNewWriter(segSizein256bs, getRandom);
	test.ok(writer.isHeaderModified());
	test.ok(writer.isEndlessFile());
	writer.setContentLength(data.length);
	test.ok(!writer.isEndlessFile());
	
	// pack file header
	var fileHeader = writer.packHeader(mkeyEncr);

	// pack segments
	var fileSegments: Uint8Array[] = [];
	var offset = 0;
	var segInd = 0;
	var encRes: { dataLen: number; seg: Uint8Array };
	while (offset < data.length) {
		encRes = writer.packSeg(data.subarray(offset), segInd);
		offset += encRes.dataLen;
		segInd += 1;
		fileSegments.push(encRes.seg);
	}
	
	// wipe key bytes from memory
	writer.destroy();
	writer = null;

	// combine all parts into one xsp file
	offset = 0;
	for (var i=0; i<fileSegments.length; i+=1) {
		offset += fileSegments[i].length;
	}
	var fileStart = xsp.generateXSPFileStart(offset);
	offset += fileStart.length;
	var completeFile = new Uint8Array(offset + fileHeader.length);
	completeFile.set(fileStart);
	offset = fileStart.length;
	for (var i=0; i<fileSegments.length; i+=1) {
		completeFile.set(fileSegments[i], offset);
		offset += fileSegments[i].length;
	}
	completeFile.set(fileHeader, offset);
	fileStart = null;
	fileHeader = null;
	fileSegments = null;
	
	// Note: at this point completeFile contains xsp file, which
	// contains both segments and a file header. In some situations single file
	// is a good solution. In other situations segments and a header better
	// stored in separate files.

	// read xsp file
	var segsEnd = xsp.getXSPHeaderOffset(completeFile);
	var reader = xsp.segments.makeReader(
			completeFile.subarray(segsEnd), mkeyDecr);
	test.ok(!reader.isEndlessFile());
	offset = xsp.SEGMENTS_OFFSET;
	var segInd = 0;
	var dataParts: Uint8Array[] = [];
	var decRes: { data: Uint8Array; segLen: number; };
	while (offset < segsEnd) {
		decRes = reader.openSeg(completeFile.subarray(offset), segInd);
		offset += decRes.segLen;
		segInd += 1;
		dataParts.push(decRes.data);
	}
	
	// wipe key bytes from memory
	reader.destroy();

	// reconstruct and compare complete data
	offset = 0;
	for (var i=0; i<dataParts.length; i+=1) { offset += dataParts[i].length; }
	var completeReconstrData = new Uint8Array(offset);
	offset = 0;
	for (var i=0; i<dataParts.length; i+=1) {
		completeReconstrData.set(dataParts[i], offset);
		offset += dataParts[i].length;
	}
	compare(test, completeReconstrData, data,
			"Reconstructed data is not the same as original");

	test.done();
}

/**
 * Test encrypting and packing dataLen bytes of data into xsp file with
 * segment size segSizein256bs of endless nature
 */
function testEndlessFile(test: nu.Test,
		dataLen: number, segSizein256bs: number) {

	var data = getRandom(dataLen);
	var masterKey = getRandom(32);
	var mkeyEncr = nacl.secret_box.formatWN.makeEncryptor(
		masterKey, getRandom(24));
	var mkeyDecr = nacl.secret_box.formatWN.makeDecryptor(masterKey);

	// initialize writer
	var writer = xsp.segments.makeNewWriter(segSizein256bs, getRandom);
	test.ok(writer.isHeaderModified());
	test.ok(writer.isEndlessFile());
	
	// pack file header
	var fileHeader = writer.packHeader(mkeyEncr);

	// pack segments
	var fileSegments: Uint8Array[] = [];
	var offset = 0;
	var segInd = 0;
	var encRes: { dataLen: number; seg: Uint8Array };
	while (offset < data.length) {
		encRes = writer.packSeg(data.subarray(offset), segInd);
		offset += encRes.dataLen;
		segInd += 1;
		fileSegments.push(encRes.seg);
	}
	
	// wipe key bytes from memory
	writer.destroy();
	writer = null;

	// combine all parts into one xsp file
	offset = 0;
	for (var i=0; i<fileSegments.length; i+=1) {
		offset += fileSegments[i].length;
	}
	var fileStart = xsp.generateXSPFileStart(offset);
	offset += fileStart.length;
	var completeFile = new Uint8Array(offset + fileHeader.length);
	completeFile.set(fileStart);
	offset = fileStart.length;
	for (var i=0; i<fileSegments.length; i+=1) {
		completeFile.set(fileSegments[i], offset);
		offset += fileSegments[i].length;
	}
	completeFile.set(fileHeader, offset);
	fileStart = null;
	fileHeader = null;
	fileSegments = null;
	
	// Note: at this point completeFile contains xsp file, which
	// contains both segments and a file header. In some situations single file
	// is a good solution. In other situations segments and a header better
	// stored in separate files.

	// read xsp file (endless type)
	var segsEnd = xsp.getXSPHeaderOffset(completeFile);
	var reader = xsp.segments.makeReader(
			completeFile.subarray(segsEnd), mkeyDecr);
	test.ok(reader.isEndlessFile());
	offset = xsp.SEGMENTS_OFFSET;
	var segInd = 0;
	var dataParts: Uint8Array[] = [];
	var decRes: { data: Uint8Array; segLen: number; };
	while (offset < segsEnd) {
		// Note that by placing segsEnd, we make sure that last segment
		// covers array from start to end, giving implicitly info about
		// length of the last segment. In a finite file, segment length
		// comes from a header, but in an infinit case, length of the
		// last segment is an unknown for reader.
		decRes = reader.openSeg(completeFile.subarray(offset, segsEnd), segInd);
		offset += decRes.segLen;
		segInd += 1;
		dataParts.push(decRes.data);
	}
	
	// wipe key bytes from memory
	reader.destroy();

	// reconstruct and compare complete data
	offset = 0;
	for (var i=0; i<dataParts.length; i+=1) { offset += dataParts[i].length; }
	var completeReconstrData = new Uint8Array(offset);
	offset = 0;
	for (var i=0; i<dataParts.length; i+=1) {
		completeReconstrData.set(dataParts[i], offset);
		offset += dataParts[i].length;
	}
	compare(test, completeReconstrData, data,
			"Reconstructed data is not the same as original");

	test.done();
}

export function singleChainHeader_len_1_seg_64(test: nu.Test) {
	testSingleChainHeader(test, 1, 64);
}
export function singleChainHeader_len_16_seg_64(test: nu.Test) {
	testSingleChainHeader(test, 16, 64);
}
export function singleChainHeader_len_16294_seg_64(test: nu.Test) {
	testSingleChainHeader(test, 64*256-90, 64);
}
export function singleChainHeader_len_16368_seg_64(test: nu.Test) {
	testSingleChainHeader(test, 64*256-16, 64);
}
export function singleChainHeader_len_16384_seg_64(test: nu.Test) {
	testSingleChainHeader(test, 64*256, 64);
}
export function singleChainHeader_len_49152_seg_64(test: nu.Test) {
	testSingleChainHeader(test, 3*64*256, 64);
}

export function endlessFile_len_1_seg_64(test: nu.Test) {
	testEndlessFile(test, 1, 64);
}
export function endlessFile_len_16_seg_64(test: nu.Test) {
	testEndlessFile(test, 16, 64);
}
export function endlessFile_len_16294_seg_64(test: nu.Test) {
	testEndlessFile(test, 64*256-90, 64);
}
export function endlessFile_len_16368_seg_64(test: nu.Test) {
	testEndlessFile(test, 64*256-16, 64);
}
export function endlessFile_len_16384_seg_64(test: nu.Test) {
	testEndlessFile(test, 64*256, 64);
}
export function endlessFile_len_49152_seg_64(test: nu.Test) {
	testEndlessFile(test, 3*64*256, 64);
}

// TODO add tests of a file splicing, when it will be done.


