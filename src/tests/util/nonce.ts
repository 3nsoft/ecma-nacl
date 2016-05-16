/* Copyright(c) 2016 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
/**
 * Testing module lib/util/nonce.(ts/js)
 */


import nu = require('nodeunit');
import nonce = require('../../lib/util/nonce');
import verify = require('../../lib/util/verify');
import testUtil = require('../test-utils');

var compare = testUtil.compare;

export function nonceCalc(test: nu.Test) {
	var n1 = testUtil.getRandom(24);
	var n = new Uint8Array(24);
	n.set(n1);
	
	var delta = 5;
	nonce.advance(n, delta);
	test.ok(!verify.verify(n.subarray(0, 8), n1.subarray(0, 8), 8));
	test.ok(!verify.verify(n.subarray(8, 16), n1.subarray(8, 16), 8));
	test.ok(!verify.verify(n.subarray(8), n1.subarray(8), 8));
	
	test.deepEqual(nonce.calculateDelta(n1, n), new Uint32Array([ delta, 0 ]));
	
	n[2] += 1;
	test.ok(typeof nonce.calculateDelta(n1, n) !== 'number');
	
	var longDelta = new Uint32Array([ 0xffffffff, 0x7fffffff ]);
	
	var n2 = nonce.calculateNonce(n, longDelta);
	test.deepEqual(nonce.calculateDelta(n, n2), longDelta);
	
	nonce.advanceOddly(n2);
	test.deepEqual(nonce.calculateDelta(n, n2),
		new Uint32Array([ 0, 0x80000000 ]));
	
	nonce.advanceEvenly(n2);
	test.deepEqual(nonce.calculateDelta(n, n2),
		new Uint32Array([ 2, 0x80000000 ]));
	
	test.done();
}