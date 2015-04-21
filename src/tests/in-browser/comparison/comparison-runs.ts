/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/// <reference path="../../../../lib declarations/ecma-nacl.d.ts" />

// TODO add comparison of signing and scrypt


import ecmaNacl = require('ecma-nacl');
import util = require('../util');

declare var nacl_factory: any;
var js_nacl = nacl_factory.instantiate();

var sbox = ecmaNacl.secret_box
var box = ecmaNacl.box
var compareVectors = ecmaNacl.compareVectors
var log = util.logTestResult;

function runTimingAndLogging(numOfRuns: number, msgPref: string,
		run: () => void): void {
	try {
		var millis = performance.now();
		for (var i=0; i<numOfRuns; i+=1) {
			run();
		}
		millis = (performance.now() - millis)/numOfRuns;
		log((msgPref? msgPref+"" : "")+millis.toFixed(3)+" milliseconds");
	} catch (e) {
		log(e.message, true);
	}
}

export function timeBoxEncryption(numOfRuns: number, msgKs: number): void {
	var js_nacl_gen_keys = js_nacl.crypto_box_keypair();
	var sk1 = js_nacl_gen_keys.boxSk;
	var pk1 = js_nacl_gen_keys.boxPk;
	if(!compareVectors(pk1, box.generate_pubkey(sk1))) {
		log("Generation of keys is incompatible.", true); }
	var sk2 = util.getRandom(32);
	var pk2 = box.generate_pubkey(sk2);
	var nonce = util.getRandom(24);
	var msg = util.getRandom(msgKs * 1024);
	var cipher1: Uint8Array;
	var cipher2: Uint8Array;
	var recoveredMsg: Uint8Array;

	log("Do public key encryption of "+msgKs+"KB of message.\n" +
		"Calculations are performed "+numOfRuns+
		" times, to provide an average time.");

	// ecma-nacl encryption 
	runTimingAndLogging(numOfRuns, "\tecma-nacl average for packing: ", () => {
		cipher1 = box.pack(msg, nonce, pk2, sk1);
	});
		
	// js-nacl encryption
	runTimingAndLogging(numOfRuns, "\tjs-nacl average for packing: ", () => {
		cipher2 = js_nacl.crypto_box(msg, nonce, pk2, sk1);
	});
		
	if (!compareVectors(cipher1, cipher2)) {
		log("Resulting ciphers are incompatible.", true); }
	
	// ecma-nacl decryption 
	runTimingAndLogging(numOfRuns, "\tecma-nacl average for opening: ", () => {
		recoveredMsg = box.open(cipher1, nonce, pk1, sk2);
	});
	if (!compareVectors(msg, recoveredMsg)) {
		log("Message was incorrectly decrypted.", true); }
		
	// js-nacl decryption
	runTimingAndLogging(numOfRuns, "\tjs-nacl average for opening: ", () => {
		recoveredMsg = js_nacl.crypto_box_open(cipher1, nonce, pk1, sk2);
	});
	if (!compareVectors(msg, recoveredMsg)) {
		log("Message was incorrectly decrypted.", true); }
		
}

export function timeSecretBoxEncryption(numOfRuns: number, msgKs: number): void {
	var k = util.getRandom(32);
	var nonce = util.getRandom(24);
	var msg = util.getRandom(msgKs * 1024);
	var cipher1: Uint8Array;
	var cipher2: Uint8Array;
	var recoveredMsg: Uint8Array;
	
	log("Do secret key encryption of "+msgKs+"KB of message.\n" +
		"Calculations are performed "+numOfRuns+
		" times, to provide an average time.");
		
	// ecma-nacl encryption 
	runTimingAndLogging(numOfRuns, "\tecma-nacl average for packing: ", () => {
		cipher1 = sbox.pack(msg, nonce, k);
	});
		
	// js-nacl encryption
	runTimingAndLogging(numOfRuns, "\tjs-nacl average for packing: ", () => {
		cipher2 = js_nacl.crypto_secretbox(msg, nonce, k);
	});
		
	if (!compareVectors(cipher1, cipher2)) {
		log("Resulting ciphers are incompatible.", true); }

	// ecma-nacl decryption 
	runTimingAndLogging(numOfRuns, "\tecma-nacl average for opening: ", () => {
		recoveredMsg = sbox.open(cipher1, nonce, k);
	});
	if (!compareVectors(msg, recoveredMsg)) {
		log("Message was incorrectly decrypted.", true); }
		
	// js-nacl decryption 
	runTimingAndLogging(numOfRuns, "\tjs-nacl average for opening: ", () => {
		recoveredMsg = js_nacl.crypto_secretbox_open(cipher1, nonce, k);
	});
	if (!compareVectors(msg, recoveredMsg)) {
		log("Message was incorrectly decrypted.", true); }

}

export function startBoxEncryption(
		worker: Worker, numOfRuns: number, msgKs: number): void {
	var sk1 = util.getRandom(32);
	var sk2 = util.getRandom(32);
	var nonce = util.getRandom(24);
	var msg = util.getRandom(msgKs*1024);
	worker.postMessage(
			{ cmd: "boxEnc", numOfRuns: numOfRuns,
				sk1: sk1.buffer, sk2: sk2.buffer, nonce: nonce.buffer, msg: msg.buffer },
			[ sk1.buffer, sk2.buffer, nonce.buffer, msg.buffer ]);
}

export function startSecretBoxEncryption(
		worker: Worker, numOfRuns: number, msgKs: number): void {
	var key = util.getRandom(32);
	var nonce = util.getRandom(24);
	var msg = util.getRandom(msgKs*1024);
	worker.postMessage(
			{ cmd: "secretBoxEnc", numOfRuns: numOfRuns,
				key: key.buffer, nonce: nonce.buffer, msg: msg.buffer },
			[ key.buffer, nonce.buffer, msg.buffer ]);
}
