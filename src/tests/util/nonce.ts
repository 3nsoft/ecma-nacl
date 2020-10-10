/*
 Copyright(c) 2016, 2020 3NSoft Inc.
 This Source Code Form is subject to the terms of the Mozilla Public
 License, v. 2.0. If a copy of the MPL was not distributed with this
 file, you can obtain one at http://mozilla.org/MPL/2.0/.
*/
/**
 * Testing module lib/util/nonce.(ts/js)
 */

import nonce = require('../../lib/util/nonce');
import verify = require('../../lib/util/verify');
import { bytesEqual } from '../libs-for-tests/bytes-equal';
import { getRandom } from '../libs-for-tests/test-utils';

describe(`nonce module`, () => {

	it(`calculated related nonces`, () => {
		const n1 = getRandom(24);
		const n = new Uint8Array(24);
		n.set(n1);
		
		const delta = 5;
		nonce.advance(n, delta);
		expect(verify.verify(n.subarray(0, 8), n1.subarray(0, 8), 8)).toBe(false);
		expect(verify.verify(n.subarray(8, 16), n1.subarray(8, 16), 8)).toBe(false);
		expect(verify.verify(n.subarray(8), n1.subarray(8), 8)).toBe(false);
		
		const calculatedDelta = nonce.calculateDelta(n1, n);
		expect(calculatedDelta).not.toBeUndefined();
		expect(bytesEqual(
			calculatedDelta!, new Uint32Array([ delta, 0 ]))).toBe(true);
		
		n[2] += 1;
		expect(nonce.calculateDelta(n1, n)).toBeUndefined();
		
		const longDelta = new Uint32Array([ 0xffffffff, 0x7fffffff ]);
		
		const n2 = nonce.calculateNonce(n, longDelta);
		expect(bytesEqual(nonce.calculateDelta(n, n2)!, longDelta)).toBe(true);
		
		nonce.advanceOddly(n2);
		expect(bytesEqual(
			nonce.calculateDelta(n, n2)!, new Uint32Array([ 0, 0x80000000 ])
		)).toBe(true);
		
		nonce.advanceEvenly(n2);
		expect(bytesEqual(
			nonce.calculateDelta(n, n2)!, new Uint32Array([ 2, 0x80000000 ]
		))).toBe(true);
	});

});