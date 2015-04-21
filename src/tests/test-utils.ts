/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

import nu = require('nodeunit');
import verify = require('../lib/util/verify');
import crypto = require('crypto');

export function compare(test: nu.Test, v: Uint8Array, expectation: Array<number>, m? :string);
export function compare(test: nu.Test, v: Uint8Array, expectation: Uint8Array, m? :string);
export function compare(test: nu.Test, v: Uint8Array, expectation, m? :string) {
	test.strictEqual(v.length, expectation.length, m);
	test.ok(verify.verify(v, expectation, v.length), m);
}

export function runTimingAndLogging(numOfRuns: number, msgPref: string,
		run: () => void): void {
	var startTime = process.hrtime();
	for (var i=0; i<numOfRuns; i+=1) {
		run();
	}
	var hrtimes = process.hrtime(startTime);
	var diff = (hrtimes[0]*1e9 + hrtimes[1]) / numOfRuns / 1e6;
	console.log((msgPref? msgPref+'' : '')+diff.toFixed(3)+" milliseconds");
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
