
var boxes = require('../../lib/ecma-nacl');
var xsp = boxes.fileXSP;
var compareVectors = boxes.compareVectors;
var randomBytes = require('crypto').randomBytes;
var assert = require('assert');

function getRandom(numOfBytes) {
	"use strict";
	var buf = randomBytes(numOfBytes);
	var arr = new Uint8Array(numOfBytes);
	for (var i=0; i<numOfBytes; i+=1) {
		arr[i] = buf[i];
	}
	return arr;
}

function testXSPFormatPackAndOpen(dataLen, segSize) {
	"use strict";

	console.log("Test encrypting and packing "+dataLen+" bytes of data into xsp file with segment size "+segSize);

	var data = getRandom(dataLen)
	, fileKey = getRandom(32)
	, masterKey = getRandom(32)
	, nonceToEncFileKey = getRandom(24)
	, fileSegments = [];

	// initialize writer
	var writer = new xsp.Writer(segSize, new Uint8Array(fileKey), nonceToEncFileKey, masterKey);

	// pack segments
	var offset = 0
	, seg;
	while (offset < data.length) {
		seg = writer.packSegment(data, offset, (offset === 0), getRandom(24));
		fileSegments.push(seg);
		offset += xsp.dataLenInSegment(seg.length, (offset === 0));
	}
	
	// wipe key bytes from memory
	writer.wipeFileKey();

	// mix segments into one array in order to loose implicit info about segment boundaries
	offset = 0;
	for (var i=0; i<fileSegments.length; i+=1) { offset += fileSegments[i].length; }
	var completeFile = new Uint8Array(offset);
	offset = 0;
	for (var i=0; i<fileSegments.length; i+=1) {
		if (i > 0) { offset += fileSegments[i-1].length; }
		completeFile.set(fileSegments[i], offset);
	}

	// initialize reader
	var reader = new xsp.Reader(completeFile.subarray(0, xsp.FILE_HEADER_LEN), masterKey)
	, dataParts = [];

	assert.ok(compareVectors(reader.fileKey, fileKey), "Reader recreated incorrect file key");
	assert.strictEqual(reader.segSize, segSize, "Reader recreated incorrect segment length");

	// read other segments
	var dataPiece;
	offset = 0;
	while (offset < completeFile.length) {
		dataPiece = reader.openSegment(
				completeFile.subarray(offset, offset+reader.segSize), (offset === 0));
		dataParts.push(dataPiece);
		offset += reader.segSize;
	}
	
	// wipe key bytes from memory
	reader.wipeFileKey();

	// reconstruct and compare complete data
	offset = 0;
	for (var i=0; i<dataParts.length; i+=1) { offset += dataParts[i].length; }
	var completeReconstrData = new Uint8Array(offset);
	offset = 0;
	for (var i=0; i<dataParts.length; i+=1) {
		completeReconstrData.set(dataParts[i], offset);
		offset += dataParts[i].length;
	}
	assert.ok(compareVectors(completeReconstrData, data), "Reconstructed data is not the same as original");

	console.log("PASS.\n");
}

testXSPFormatPackAndOpen(1, 16*1024);
testXSPFormatPackAndOpen(16, 16*1024);
testXSPFormatPackAndOpen(16*1024-90, 16*1024);
testXSPFormatPackAndOpen(16*1024, 16*1024);
testXSPFormatPackAndOpen(3*16*1024, 16*1024);

function testLocatingOfBytesInSegments(dataLen, segSize, checksPerSeg) {
	"use strict";

	console.log("Test locating random bytes in xsp file, containing "+dataLen+" bytes with segement size "+segSize);
	
	var data = getRandom(dataLen)
	, fileKey = getRandom(32)
	, masterKey = getRandom(32)
	, nonceToEncFileKey = getRandom(24)
	, fileSegments = [];

	// initialize writer
	var writer = new xsp.Writer(segSize, new Uint8Array(fileKey), nonceToEncFileKey, masterKey);

	// pack segments
	var offset = 0
	, seg;
	while (offset < data.length) {
		seg = writer.packSegment(data, offset, (offset === 0), getRandom(24));
		fileSegments.push(seg);
		offset += xsp.dataLenInSegment(seg.length, (offset === 0));
	}
	
	// wipe key bytes from memory
	writer.wipeFileKey();

	// initialize reader
	var reader = new xsp.Reader(fileSegments[0].subarray(0, xsp.FILE_HEADER_LEN), masterKey);
	
	// open segments
	for (var i=0; i<fileSegments.length; i+=1) {
		fileSegments[i] = reader.openSegment(fileSegments[i], (i === 0));
	}
	
	// check referencing of same bytes in data array and opened file segments
	var posInData, posInSegs, byteInds;
	for (var i=0; i<fileSegments.length; i+=1) {
		byteInds = [ 0 ];
		for (var j=0; j<checksPerSeg; j+=1) {
			byteInds.push(Math.floor(
					fileSegments[i].length * Math.random()));
		}
		for (var j=0; j<byteInds.length; j+=1) {
			posInData = xsp.posInDataOf(reader.segSize, i, byteInds[j]);
			assert.strictEqual(data[posInData], fileSegments[i][byteInds[j]],
					"Position in segment {s:"+i+",b:"+byteInds[j]+"} is calculated to be " +
					"position "+posInData+", but bytes do not match.");
			posInSegs = xsp.posInFileOf(reader.segSize, posInData);
			assert.ok((posInSegs.s === i) && (posInSegs.b === byteInds[j]),
					"Data position "+posInData+" got translated into {s:"+
					posInSegs.s+",b:"+posInSegs.b+"}, instead of {s:"+i+",b:"+byteInds[j]+"}");
		}
	}
	
	// wipe key bytes from memory
	reader.wipeFileKey();

	console.log("PASS.\n");
}

testLocatingOfBytesInSegments(1, 16*1024, 1);
testLocatingOfBytesInSegments(16, 16*1024, 5);
testLocatingOfBytesInSegments(3*16*1024, 16*1024, 10);
