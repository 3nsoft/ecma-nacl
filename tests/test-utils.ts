
import arrays = require('../lib/util/arrays');
import verify = require('../lib/util/verify');
import assert = require('assert');
import crypto = require('crypto');

var arrFactory = new arrays.Factory();

export function compare(v: Uint8Array, expectation: Array<number>, m? :string);
export function compare(v: Uint8Array, expectation: Uint8Array, m? :string);
export function compare(v: Uint8Array, expectation, m? :string) {
	assert.strictEqual(v.length, expectation.length, m);
	assert.ok(verify.verify(v, expectation, v.length), m);
}

export function getRandom(numOfBytes: number): Uint8Array {
	var arr = new Uint8Array(numOfBytes);
	var randomBytes = crypto.randomBytes(numOfBytes);
	for (var i=0; i<numOfBytes; i+=1) {
		arr[i] = randomBytes[i];
	}
	return arr;
}

export function asciiStrToUint8Array(str: string): Uint8Array {
	var arr = new Uint8Array(str.length);
	for (var i=0; i<str.length; i+=1) {
		arr[i] = str.charCodeAt(i);
	}
	return arr;
}
