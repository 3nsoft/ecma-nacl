/* Copyright(c) 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
/**
 * Testing module lib/scrypt/sha256.(ts/js) with
 * test vectors from scrypt rfc draft
 * https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-02
 */

import nu = require('nodeunit');
import sha256 = require('../../lib/scrypt/sha256');
import arrays = require('../../lib/util/arrays');
import testUtil = require('../test-utils');
import crypto = require('crypto');

var compare = testUtil.compare;
var arrFactory = arrays.makeFactory();


/**
 * Test SHA-256 for use in scrypt.
 */
export function sha256ForScrypt(test: nu.Test) {
	var x = testUtil.asciiStrToUint8Array("testing\n");
	var expected = new Uint8Array(32);
	(() => {
		var hsum = crypto.createHash('sha256');
		hsum.update(new Buffer(x));
		var digest = hsum.digest();
		for (var i=0; i<32; i+=1) {
			expected[i] = digest[i];
		}
	})();
	var hctx = sha256.makeSha256Ctx(arrFactory);
	sha256.SHA256_Init(hctx);
	sha256.SHA256_Update(hctx, x, 0, 3);
	sha256.SHA256_Update(hctx, x, 3, 2);
	sha256.SHA256_Update(hctx, x, 5, (x.length - 5));
	var result = new Uint8Array(32);
	sha256.SHA256_Final(result, hctx);
	compare(test, result, expected, "Hashes are different");
	arrFactory.wipe(result);
	arrFactory.wipeRecycled();
	test.done();
}

/**
 * Test PBKDF2 with HMAC-SHA-256, test vector #1
 */
export function pbkdf2withHmacSha256_vect1(test: nu.Test) {
	var P = testUtil.asciiStrToUint8Array("passwd");
	var S = testUtil.asciiStrToUint8Array("salt");
	var c = 1;
	var dkLen = 64;
	var expectation = new Uint8Array(dkLen);
	expectation.set(
		[ 0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16,
		  0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05, 0xf9, 0x41, 0x85, 0x21,
		  0x6d, 0xde, 0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d,
		  0xac, 0xbc, 0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45,
		  0x99, 0x16, 0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31, 0x7c, 0x71,
		  0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5, 0x09, 0x11, 0x20, 0x41,
		  0xd3, 0xa1, 0x97, 0x83 ]);
	var result = new Uint8Array(dkLen);
	sha256.PBKDF2_SHA256(P, S, c, result, arrFactory);
	compare(test, result, expectation);
	test.done();
}

/**
 * Test PBKDF2 with HMAC-SHA-256, test vector #2
 */
export function pbkdf2withHmacSha256_vect2(test: nu.Test) {
	var P = testUtil.asciiStrToUint8Array("Password");
	var S = testUtil.asciiStrToUint8Array("NaCl");
	var c = 80000;
	var dkLen = 64;
	var expectation = new Uint8Array(dkLen);
	expectation.set(
			[ 0x4d, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21, 0x83, 0x0c,
			  0xee, 0x5e, 0xf2, 0x27, 0x01, 0xf9, 0x64, 0x1a, 0x44, 0x18,
			  0xd0, 0x4c, 0x04, 0x14, 0xae, 0xff, 0x08, 0x87, 0x6b, 0x34,
			  0xab, 0x56, 0xa1, 0xd4, 0x25, 0xa1, 0x22, 0x58, 0x33, 0x54,
			  0x9a, 0xdb, 0x84, 0x1b, 0x51, 0xc9, 0xb3, 0x17, 0x6a, 0x27,
			  0x2b, 0xde, 0xbb, 0xa1, 0xd0, 0x78, 0x47, 0x8f, 0x62, 0xb3,
			  0x97, 0xf3, 0x3c, 0x8d ]);
	var result = new Uint8Array(dkLen);
	sha256.PBKDF2_SHA256(P, S, c, result, arrFactory);
	compare(test, result, expectation);
	test.done();
}

