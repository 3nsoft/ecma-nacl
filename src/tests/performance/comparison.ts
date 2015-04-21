/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
/**
 * This is a speed comparison between
 * (a) this ecma-nacl,
 * (b) js-nacl (Emscripten compiled C NaCl), and
 * (c) tweetnacl-js (JavaScript re-write of TweetNaCl).
 * Everything run in the same node instance.
 * Make sure to have js-nacl module available to satisfy this script's requirement.
 */

try {
	var js_nacl = require('js-nacl').instantiate();
} catch (err) {
	console.log("js-nacl is not accessable with require()"+
			"for this performance comparison");
}
try {
	var tweetnacl = require('tweetnacl');
} catch (err) {
	console.log("tweetnacl is not accessable with require()"+
			"for this performance comparison");
}
try {
	var js_script_factory = require('./js-scrypt');
} catch (err) {
	console.log("js-scrypt is not accessable with require()"+
			"for this performance comparison");
}

import testUtil = require('../test-utils');
import nacl = require('../../lib/ecma-nacl');
import sha256 = require('../../lib/scrypt/sha256');
import assert = require('assert');

var sbox = nacl.secret_box;
var box = nacl.box;
var sha512 = nacl.hashing.sha512;

var getRandom = testUtil.getRandom;
var run = testUtil.runTimingAndLogging;

function boxEncryption(numOfRuns: number, msgKs: number): void {
	var js_nacl_gen_keys = js_nacl.crypto_box_keypair();
	var sk1 = js_nacl_gen_keys.boxSk;
	var pk1 = js_nacl_gen_keys.boxPk;
	assert.ok(nacl.compareVectors(pk1, box.generate_pubkey(sk1)),
			"Generation of keys is incompatible with js-nacl.");
	var sk2 = getRandom(32);
	var pk2 = box.generate_pubkey(sk2);
	var nonce = getRandom(24);
	var msg = getRandom(msgKs*1024);
	var cipher1, cipher2, recoveredMsg;

	console.log("Do public key encryption of "+msgKs+"KB message.\n" +
			"Calculations are performed "+numOfRuns+
			" times, to provide an average time.");

	// ecma-nacl encryption
	run(numOfRuns, "\tecma-nacl average for packing: ", () => {
		cipher1 = box.pack(msg, nonce, pk2, sk1);
	});
	
	// js-nacl encryption
	run(numOfRuns, "\tjs-nacl average for packing: ", () => {
		cipher2 = js_nacl.crypto_box(msg, nonce, pk2, sk1);
	});
	
	assert.ok(nacl.compareVectors(cipher1, cipher2),
		"Resulting ciphers are incompatible with js-nacl.");
	
	// tweetnacl encryption
	run(numOfRuns, "\ttweetnacl average for packing: ", () => {
		cipher2 = tweetnacl.box(msg, nonce, pk2, sk1);
	});
	
	assert.ok(nacl.compareVectors(cipher1, cipher2),
		"Resulting ciphers are incompatible with tweetnacl.");
	
	// ecma-nacl decryption
	run(numOfRuns, "\tecma-nacl average for opening: ", () => {
		recoveredMsg = box.open(cipher1, nonce, pk1, sk2);
	});
	assert.ok(nacl.compareVectors(msg, recoveredMsg),
			"Message was incorrectly decrypted.");
	
	// js-nacl decryption
	run(numOfRuns, "\tjs-nacl average for opening: ", () => {
		recoveredMsg = js_nacl.crypto_box_open(cipher1, nonce, pk1, sk2);
	});
	assert.ok(nacl.compareVectors(msg, recoveredMsg),
			"Message was incorrectly decrypted.");
	
	// tweetnacl decryption
	run(numOfRuns, "\ttweetnacl average for opening: ", () => {
		recoveredMsg = tweetnacl.box.open(cipher1, nonce, pk1, sk2);
	});
	assert.ok(nacl.compareVectors(msg, recoveredMsg),
			"Message was incorrectly decrypted.");
}

function secretBoxEncryption(numOfRuns: number, msgKs: number): void {
	var k = getRandom(32);
	var nonce = getRandom(24);
	var msg = getRandom(msgKs*1024);
	var cipher1, cipher2, recoveredMsg;

	console.log("Do secret key encryption of "+msgKs+"KB message.\n" +
			"Calculations are performed "+numOfRuns+
			" times, to provide an average time.");

	// ecma-nacl encryption
	run(numOfRuns, "\tecma-nacl average for packing: ", () => {
		cipher1 = sbox.pack(msg, nonce, k);
	});
	
	// js-nacl encryption
	run(numOfRuns, "\tjs-nacl average for packing: ", () => {
		cipher2 = js_nacl.crypto_secretbox(msg, nonce, k);
	});
	
	assert.ok(nacl.compareVectors(cipher1, cipher2),
			"Resulting ciphers are incompatible with js-nacl");
	
	// tweetnacl encryption
	run(numOfRuns, "\ttweetnacl average for packing: ", () => {
		cipher2 = tweetnacl.secretbox(msg, nonce, k);
	});
	
	assert.ok(nacl.compareVectors(cipher1, cipher2),
			"Resulting ciphers are incompatible with tweetnacl");
	
	// ecma-nacl decryption
	run(numOfRuns, "\tecma-nacl average for opening: ", () => {
		recoveredMsg = sbox.open(cipher1, nonce, k);
	});
	assert.ok(nacl.compareVectors(msg, recoveredMsg),
			"Message was incorrectly decrypted.");
	
	// js-nacl decryption
	run(numOfRuns, "\tjs-nacl average for opening: ", () => {
		recoveredMsg = js_nacl.crypto_secretbox_open(cipher1, nonce, k);
	});
	assert.ok(nacl.compareVectors(msg, recoveredMsg),
			"Message was incorrectly decrypted.");
	
	// tweetnacl decryption
	run(numOfRuns, "\ttweet-nacl average for opening: ", () => {
		recoveredMsg = tweetnacl.secretbox.open(cipher1, nonce, k);
	});
	assert.ok(nacl.compareVectors(msg, recoveredMsg),
			"Message was incorrectly decrypted.");
}

function sha512Hashing(numOfRuns: number, msgKs: number): void {
	var k = getRandom(32);
	var nonce = getRandom(24);
	var msg = getRandom(msgKs*1024);
	var hash1, hash2;

	console.log("Do sha512 hashing of "+msgKs+"KB message.\n" +
			"Calculations are performed "+numOfRuns+
			" times, to provide an average time.");

	// ecma-nacl
	run(numOfRuns, "\tecma-nacl average for hashing: ", () => {
		hash1 = sha512.hash(msg);
	});
	
	// js-nacl
	run(numOfRuns, "\tjs-nacl average for hashing: ", () => {
		hash2 = js_nacl.crypto_hash(msg);
	});
	
	assert.ok(nacl.compareVectors(hash1, hash2),
			"Resulting hashes are incompatible with js-nacl");
	
	// tweetnacl
	run(numOfRuns, "\ttweetnacl average for hashing: ", () => {
		hash2 = tweetnacl.hash(msg);
	});
	
	assert.ok(nacl.compareVectors(hash1, hash2),
			"Resulting hashes are incompatible with tweetnacl");
}

function sha256Hashing(numOfRuns: number, msgKs: number): void {
	var k = getRandom(32);
	var nonce = getRandom(24);
	var msg = getRandom(msgKs*1024);
	var hash1, hash2;

	console.log("Do sha256 hashing of "+msgKs+"KB message.\n" +
			"Calculations are performed "+numOfRuns+
			" times, to provide an average time.");

	// ecma-nacl
	var hctx = sha256.makeSha256Ctx(nacl.arrays.makeFactory());
	hash1 = hctx.arrFactory.getUint8Array(32);
	run(numOfRuns, "\tecma-nacl average for hashing: ", () => {
		sha256.SHA256_Init(hctx);
		sha256.SHA256_Update(hctx, msg, 0, msg.length);
		sha256.SHA256_Final(hash1, hctx);
	});
	
	// js-nacl
	run(numOfRuns, "\tjs-nacl average for hashing: ", () => {
		hash2 = js_nacl.crypto_hash_sha256(msg);
	});
	
	assert.ok(nacl.compareVectors(hash1, hash2),
			"Resulting hashes are incompatible with js-nacl");
}

function signing(numOfRuns: number, msgKs: number): void {
	var pair = js_nacl.crypto_sign_keypair();
	var sk: Uint8Array = pair.signSk;
	var pk: Uint8Array = pair.signPk;
	var keySeed: Uint8Array = sk.subarray(0, 32);

	console.log("Do signing of "+msgKs+"KB message.\n" +
			"Calculations are performed "+numOfRuns+
			" times, to provide an average time.");
	
	pair = nacl.signing.generate_keypair(keySeed);
	assert.ok(nacl.compareVectors(pair.skey, sk),
			"Resulting signing secret key is incompatible with js-nacl");
	assert.ok(nacl.compareVectors(pair.pkey, pk),
			"Resulting signing public key is incompatible with js-nacl");
	
	pair = tweetnacl.sign.keyPair.fromSeed(keySeed);
	assert.ok(nacl.compareVectors(pair.secretKey, sk),
			"Resulting signing secret key is incompatible with tweetnacl");
	assert.ok(nacl.compareVectors(pair.publicKey, pk),
			"Resulting signing public key is incompatible with tweetnacl");
	var msg = getRandom(msgKs*1024);
	var isSigOK: boolean;
	var signature1: Uint8Array;
	var signedMsg2: Uint8Array;

	// ecma-nacl signing
	run(numOfRuns, "\tecma-nacl average for signing: ", () => {
		signature1 = nacl.signing.signature(msg, sk);
	});

	// tweetnacl signing
	run(numOfRuns, "\ttweetnacl average for signing: ", () => {
		signedMsg2 = tweetnacl.sign(msg, sk);
	});
	
	assert.ok(nacl.compareVectors(signature1, signedMsg2.subarray(0, 64)),
			"Signature is incompatible with tweetnacl");
	
	// ecma-nacl signature verification
	run(numOfRuns, "\tecma-nacl average for signature verification: ", () => {
		isSigOK = nacl.signing.verify(signature1, msg, pk);
	});
	if (!isSigOK) { throw new Error("Signature failed verification."); }
	
	// tweetnacl signature verification
	run(numOfRuns, "\ttweetnacl average for signature verification: ", () => {
		isSigOK = !!tweetnacl.sign.open(signedMsg2, pk);
	});
	if (!isSigOK) { throw new Error("Signature failed verification."); }
	
}

function scryptKeyDerivation(logN: number, r: number, p: number): void {
	var passwd = getRandom(32);
	var salt = getRandom(32);
	var resKeyLen = 32;
	var key1: Uint8Array;
	var key2: Uint8Array;

	console.log("Do scrypt key derivation from pass+salt pair.\n" +
			"Calculations are performed for logN=="+logN+
			", r=="+r+", p=="+p+".");

	// ecma-nacl scrypt
	run(1, "\tecma-nacl scrypt: ", () => {
		key1 = nacl.scrypt(passwd, salt, logN, r, p, resKeyLen, (p) => {});
	});
	
	// js-scrypt
	var logR = 0;
	while ((r >>> logR) > 0) { logR += 1; }
	var memSize = Math.max(33554432, 1 << (logN+logR+7+1));
	var scrypt = js_script_factory(memSize);
	run(1, "\tjs-scrypt: ", () => {
		key2 = scrypt.crypto_scrypt(passwd, salt, (1<<logN), r, p, resKeyLen);
	});
	scrypt = null;
	
	assert.ok(nacl.compareVectors(key1, key2),
			"Derived key is incompatible with js-scrypt");
	
}

boxEncryption(10, 4);
boxEncryption(10, 40);
console.log();

secretBoxEncryption(1000, 1);
secretBoxEncryption(3, 1024);
console.log();

sha512Hashing(100, 1);
sha512Hashing(3, 1024);
console.log();

sha256Hashing(100, 1);
sha256Hashing(3, 1024);
console.log();

signing(10, 1/4);
signing(10, 1);
signing(3, 1024);
console.log();

scryptKeyDerivation(14, 8, 1);
scryptKeyDerivation(14, 8, 2);
scryptKeyDerivation(17, 8, 1);
console.log();
