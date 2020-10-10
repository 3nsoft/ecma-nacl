/*
 Copyright(c) 2013 - 2015, 2020 3NSoft Inc.
 This Source Code Form is subject to the terms of the Mozilla Public
 License, v. 2.0. If a copy of the MPL was not distributed with this
 file, you can obtain one at http://mozilla.org/MPL/2.0/.
*/
/**
 * This is a speed comparison between
 * (a) this ecma-nacl,
 * (b) js-nacl (Emscripten compiled C NaCl), and
 * (c) tweetnacl-js (JavaScript re-write of TweetNaCl).
 * Everything run in the same node instance.
 * Make sure to have js-nacl module available to satisfy this script's
 * requirement.
 */

import * as nacl from '../../lib/ecma-nacl';
import { ok } from 'assert';
import { getRandom, runTimingAndLogging as run } from '../libs-for-tests/test-utils';
import * as sha256 from '../../lib/scrypt/sha256';
import { cpus } from 'os';

const js_nacl = require('js-nacl').instantiate();
const tweetnacl = require('tweetnacl');
const js_script_factory = require('../../../src/tests/ext-libs/js-scrypt');

const compareVectors = nacl.compareVectors;

function boxEncryption(numOfRuns: number, msgKs: number): void {
	const js_nacl_gen_keys = js_nacl.crypto_box_keypair();
	const sk1 = js_nacl_gen_keys.boxSk;
	const pk1 = js_nacl_gen_keys.boxPk;
	ok(compareVectors(pk1, nacl.box.generate_pubkey(sk1)),
		"Generation of keys is incompatible with js-nacl.");
	const sk2 = getRandom(32);
	const pk2 = nacl.box.generate_pubkey(sk2);
	const nonce = getRandom(24);
	const msg = getRandom(msgKs*1024);
	let cipher1: Uint8Array;
	let cipher2: Uint8Array;
	let recoveredMsg: Uint8Array;

	console.log(
`Do public key encryption of ${msgKs}KB message.
Calculations are performed ${numOfRuns} times, to provide an average time.`
	);

	// ecma-nacl encryption
	run(numOfRuns, " - ecma-nacl average for packing: ", () => {
		cipher1 = nacl.box.pack(msg, nonce, pk2, sk1);
	});
	
	// js-nacl encryption
	run(numOfRuns, " - js-nacl average for packing: ", () => {
		cipher2 = js_nacl.crypto_box(msg, nonce, pk2, sk1);
	});
	
	ok(compareVectors(cipher1!, cipher2!),
		"Resulting ciphers are incompatible with js-nacl.");
	
	// tweetnacl encryption
	run(numOfRuns, " - tweetnacl average for packing: ", () => {
		cipher2 = tweetnacl.box(msg, nonce, pk2, sk1);
	});
	
	ok(compareVectors(cipher1!, cipher2!),
		"Resulting ciphers are incompatible with tweetnacl.");
	
	// ecma-nacl decryption
	run(numOfRuns, " - ecma-nacl average for opening: ", () => {
		recoveredMsg = nacl.box.open(cipher1!, nonce, pk1, sk2);
	});
	ok(compareVectors(msg, recoveredMsg!),
		"Message was incorrectly decrypted.");
	
	// js-nacl decryption
	run(numOfRuns, " - js-nacl average for opening: ", () => {
		recoveredMsg = js_nacl.crypto_box_open(cipher1!, nonce, pk1, sk2);
	});
	ok(compareVectors(msg, recoveredMsg!),
		"Message was incorrectly decrypted.");
	
	// tweetnacl decryption
	run(numOfRuns, " - tweetnacl average for opening: ", () => {
		recoveredMsg = tweetnacl.box.open(cipher1!, nonce, pk1, sk2);
	});
	ok(compareVectors(msg, recoveredMsg!),
		"Message was incorrectly decrypted.");
}

function secretBoxEncryption(numOfRuns: number, msgKs: number): void {
	const k = getRandom(32);
	const nonce = getRandom(24);
	const msg = getRandom(msgKs*1024);
	let cipher1: Uint8Array;
	let cipher2: Uint8Array;
	let recoveredMsg: Uint8Array;

	console.log(
`Do secret key encryption of ${msgKs}KB message.
Calculations are performed ${numOfRuns} times, to provide an average time.`
	);

	// ecma-nacl encryption
	run(numOfRuns, " - ecma-nacl average for packing: ", () => {
		cipher1 = nacl.secret_box.pack(msg, nonce, k);
	});
	
	// js-nacl encryption
	run(numOfRuns, " - js-nacl average for packing: ", () => {
		cipher2 = js_nacl.crypto_secretbox(msg, nonce, k);
	});
	
	ok(compareVectors(cipher1!, cipher2!),
		"Resulting ciphers are incompatible with js-nacl");
	
	// tweetnacl encryption
	run(numOfRuns, " - tweetnacl average for packing: ", () => {
		cipher2 = tweetnacl.secretbox(msg, nonce, k);
	});
	
	ok(compareVectors(cipher1!, cipher2!),
		"Resulting ciphers are incompatible with tweetnacl");
	
	// ecma-nacl decryption
	run(numOfRuns, " - ecma-nacl average for opening: ", () => {
		recoveredMsg = nacl.secret_box.open(cipher1!, nonce, k);
	});
	ok(compareVectors(msg, recoveredMsg!),
		"Message was incorrectly decrypted.");
	
	// js-nacl decryption
	run(numOfRuns, " - js-nacl average for opening: ", () => {
		recoveredMsg = js_nacl.crypto_secretbox_open(cipher1!, nonce, k);
	});
	ok(compareVectors(msg, recoveredMsg!),
		"Message was incorrectly decrypted.");
	
	// tweetnacl decryption
	run(numOfRuns, " - tweet-nacl average for opening: ", () => {
		recoveredMsg = tweetnacl.secretbox.open(cipher1!, nonce, k);
	});
	ok(compareVectors(msg, recoveredMsg!),
		"Message was incorrectly decrypted.");
}

function sha512Hashing(numOfRuns: number, msgKs: number): void {
	const k = getRandom(32);
	const nonce = getRandom(24);
	const msg = getRandom(msgKs*1024);
	let hash1: Uint8Array;
	let hash2: Uint8Array;

	console.log(
`Do sha512 hashing of ${msgKs}KB message.
Calculations are performed ${numOfRuns} times, to provide an average time.`
	);

	// ecma-nacl
	run(numOfRuns, " - ecma-nacl average for hashing: ", () => {
		hash1 = nacl.hashing.sha512.hash(msg);
	});
	
	// js-nacl
	run(numOfRuns, " - js-nacl average for hashing: ", () => {
		hash2 = js_nacl.crypto_hash(msg);
	});
	
	ok(compareVectors(hash1!, hash2!),
		"Resulting hashes are incompatible with js-nacl");
	
	// tweetnacl
	run(numOfRuns, " - tweetnacl average for hashing: ", () => {
		hash2 = tweetnacl.hash(msg);
	});
	
	ok(compareVectors(hash1!, hash2!),
		"Resulting hashes are incompatible with tweetnacl");
}

function sha256Hashing(numOfRuns: number, msgKs: number): void {
	const k = getRandom(32);
	const nonce = getRandom(24);
	const msg = getRandom(msgKs*1024);
	let hash1: Uint8Array;
	let hash2: Uint8Array;

	console.log(
`Do sha256 hashing of ${msgKs}KB message.
Calculations are performed ${numOfRuns} times, to provide an average time.`
	);

	// ecma-nacl
	const hctx = sha256.makeSha256Ctx(nacl.arrays.makeFactory());
	hash1 = hctx.arrFactory.getUint8Array(32);
	run(numOfRuns, " - ecma-nacl average for hashing: ", () => {
		sha256.SHA256_Init(hctx);
		sha256.SHA256_Update(hctx, msg, 0, msg.length);
		sha256.SHA256_Final(hash1, hctx);
	});
	
	// js-nacl
	run(numOfRuns, " - js-nacl average for hashing: ", () => {
		hash2 = js_nacl.crypto_hash_sha256(msg);
	});
	
	ok(compareVectors(hash1!, hash2!),
		"Resulting hashes are incompatible with js-nacl");
}

function signing(numOfRuns: number, msgKs: number): void {
	let pair = js_nacl.crypto_sign_keypair();
	const sk: Uint8Array = pair.signSk;
	const pk: Uint8Array = pair.signPk;
	const keySeed: Uint8Array = sk.subarray(0, 32);

	console.log(
`Do signing of ${msgKs}KB message.
Calculations are performed ${numOfRuns} times, to provide an average time.`
	);
	
	pair = nacl.signing.generate_keypair(keySeed);
	ok(compareVectors(pair.skey, sk),
		"Resulting signing secret key is incompatible with js-nacl");
	ok(compareVectors(pair.pkey, pk),
		"Resulting signing public key is incompatible with js-nacl");
	
	pair = tweetnacl.sign.keyPair.fromSeed(keySeed);
	ok(compareVectors(pair.secretKey, sk),
		"Resulting signing secret key is incompatible with tweetnacl");
	ok(compareVectors(pair.publicKey, pk),
		"Resulting signing public key is incompatible with tweetnacl");
	const msg = getRandom(msgKs*1024);
	let isSigOK: boolean;
	let signature1: Uint8Array;
	let signedMsg2: Uint8Array;

	// ecma-nacl signing
	run(numOfRuns, " - ecma-nacl average for signing: ", () => {
		signature1 = nacl.signing.signature(msg, sk);
	});

	// tweetnacl signing
	run(numOfRuns, " - tweetnacl average for signing: ", () => {
		signedMsg2 = tweetnacl.sign(msg, sk);
	});
	
	ok(compareVectors(signature1!, signedMsg2!.subarray(0, 64)),
		"Signature is incompatible with tweetnacl");
	
	// ecma-nacl signature verification
	run(numOfRuns, " - ecma-nacl average for signature verification: ", () => {
		isSigOK = nacl.signing.verify(signature1, msg, pk);
	});
	if (!isSigOK!) { throw new Error("Signature failed verification."); }
	
	// tweetnacl signature verification
	run(numOfRuns, " - tweetnacl average for signature verification: ", () => {
		isSigOK = !!tweetnacl.sign.open(signedMsg2, pk);
	});
	if (!isSigOK!) { throw new Error("Signature failed verification."); }
	
}

function scryptKeyDerivation(logN: number, r: number, p: number): void {
	const passwd = getRandom(32);
	const salt = getRandom(32);
	const resKeyLen = 32;
	let key1: Uint8Array;
	let key2: Uint8Array;

	console.log(
`Do scrypt key derivation from pass+salt pair.
Calculations are performed for logN==${logN}, r==${r}, p==${p}.`);

	// ecma-nacl scrypt
	run(1, " - ecma-nacl scrypt: ", () => {
		key1 = nacl.scrypt(passwd, salt, logN, r, p, resKeyLen, (p) => {});
	});
	
	// js-scrypt
	let logR = 0;
	while ((r >>> logR) > 0) { logR += 1; }
	const memSize = Math.max(33554432, 1 << (logN+logR+7+1));
	const scrypt = js_script_factory(memSize);
	run(1, " - js-scrypt: ", () => {
		key2 = scrypt.crypto_scrypt(passwd, salt, (1<<logN), r, p, resKeyLen);
	});
	
	ok(nacl.compareVectors(key1!, key2!),
		"Derived key is incompatible with js-scrypt");
	
}

console.log(`
	*******************
	* Comparison runs *
	*******************
`);

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

console.log(`
Processor: ${cpus()[0].model}
`);
