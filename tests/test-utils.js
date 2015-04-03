var arrays = require('../lib/util/arrays');
var verify = require('../lib/util/verify');
var assert = require('assert');
var crypto = require('crypto');
var arrFactory = new arrays.Factory();
function compare(v, expectation, m) {
    assert.strictEqual(v.length, expectation.length, m);
    assert.ok(verify.verify(v, expectation, v.length), m);
}
exports.compare = compare;
function getRandom(numOfBytes) {
    var arr = new Uint8Array(numOfBytes);
    var randomBytes = crypto.randomBytes(numOfBytes);
    for (var i = 0; i < numOfBytes; i += 1) {
        arr[i] = randomBytes[i];
    }
    return arr;
}
exports.getRandom = getRandom;
function asciiStrToUint8Array(str) {
    var arr = new Uint8Array(str.length);
    for (var i = 0; i < str.length; i += 1) {
        arr[i] = str.charCodeAt(i);
    }
    return arr;
}
exports.asciiStrToUint8Array = asciiStrToUint8Array;
