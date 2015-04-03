/**
 * Testing xsp file format functions.
 */
var nacl = require('../../lib/ecma-nacl');
var assert = require('assert');
var testUtil = require('../test-utils');
var compare = testUtil.compare;
var getRandom = testUtil.getRandom;
var xsp = nacl.fileXSP;
var compareVectors = nacl.compareVectors;
function testSingleChainHeader(dataLen, segSizein256bs) {
    console.log("Test encrypting and packing " + dataLen + " bytes of data into xsp file with segment size " + segSizein256bs + "*256 with a simple, single chain header");
    var data = getRandom(dataLen);
    var masterKey = getRandom(32);
    // initialize writer
    var writer = xsp.segments.makeNewWriter(segSizein256bs, getRandom);
    assert.ok(writer.isHeaderModified());
    assert.ok(writer.isEndlessFile());
    writer.setContentLength(data.length);
    assert.ok(!writer.isEndlessFile());
    // pack file header
    var fileHeader = writer.packHeader(masterKey);
    // pack segments
    var fileSegments = [];
    var offset = 0;
    var segInd = 0;
    var encRes;
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
    for (var i = 0; i < fileSegments.length; i += 1) {
        offset += fileSegments[i].length;
    }
    var fileStart = xsp.generateXSPFileStart(offset);
    offset += fileStart.length;
    var completeFile = new Uint8Array(offset + fileHeader.length);
    completeFile.set(fileStart);
    offset = fileStart.length;
    for (var i = 0; i < fileSegments.length; i += 1) {
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
    var reader = xsp.segments.makeReader(completeFile.subarray(segsEnd), masterKey);
    assert.ok(!reader.isEndlessFile());
    offset = xsp.SEGMENTS_OFFSET;
    var segInd = 0;
    var dataParts = [];
    var decRes;
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
    for (var i = 0; i < dataParts.length; i += 1) {
        offset += dataParts[i].length;
    }
    var completeReconstrData = new Uint8Array(offset);
    offset = 0;
    for (var i = 0; i < dataParts.length; i += 1) {
        completeReconstrData.set(dataParts[i], offset);
        offset += dataParts[i].length;
    }
    assert.ok(compareVectors(completeReconstrData, data), "Reconstructed data is not the same as original");
    console.log("PASS.\n");
}
function testEndlessFile(dataLen, segSizein256bs) {
    console.log("Test encrypting and packing " + dataLen + " bytes of data into xsp file with segment size " + segSizein256bs + "*256 of endless nature");
    var data = getRandom(dataLen);
    var masterKey = getRandom(32);
    // initialize writer
    var writer = xsp.segments.makeNewWriter(segSizein256bs, getRandom);
    assert.ok(writer.isHeaderModified());
    assert.ok(writer.isEndlessFile());
    // pack file header
    var fileHeader = writer.packHeader(masterKey);
    // pack segments
    var fileSegments = [];
    var offset = 0;
    var segInd = 0;
    var encRes;
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
    for (var i = 0; i < fileSegments.length; i += 1) {
        offset += fileSegments[i].length;
    }
    var fileStart = xsp.generateXSPFileStart(offset);
    offset += fileStart.length;
    var completeFile = new Uint8Array(offset + fileHeader.length);
    completeFile.set(fileStart);
    offset = fileStart.length;
    for (var i = 0; i < fileSegments.length; i += 1) {
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
    var reader = xsp.segments.makeReader(completeFile.subarray(segsEnd), masterKey);
    assert.ok(reader.isEndlessFile());
    offset = xsp.SEGMENTS_OFFSET;
    var segInd = 0;
    var dataParts = [];
    var decRes;
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
    for (var i = 0; i < dataParts.length; i += 1) {
        offset += dataParts[i].length;
    }
    var completeReconstrData = new Uint8Array(offset);
    offset = 0;
    for (var i = 0; i < dataParts.length; i += 1) {
        completeReconstrData.set(dataParts[i], offset);
        offset += dataParts[i].length;
    }
    assert.ok(compareVectors(completeReconstrData, data), "Reconstructed data is not the same as original");
    console.log("PASS.\n");
}
testSingleChainHeader(1, 64);
testSingleChainHeader(16, 64);
testSingleChainHeader(64 * 256 - 90, 64);
testSingleChainHeader(64 * 256 - 16, 64);
testSingleChainHeader(64 * 256, 64);
testSingleChainHeader(3 * 64 * 256, 64);
testEndlessFile(1, 64);
testEndlessFile(16, 64);
testEndlessFile(64 * 256 - 90, 64);
testEndlessFile(64 * 256 - 16, 64);
testEndlessFile(64 * 256, 64);
testEndlessFile(3 * 64 * 256, 64);
// TODO add tests of a file splicing, when it will be done.
