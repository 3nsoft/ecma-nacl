/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
/*
 * This contains code for a page with only Ecma-NaCl runs.
 */
/// <reference path="../../../../lib declarations/ecma-nacl.d.ts" />

// TODO add testing of signing and scrypt

import ecmaNacl = require('ecma-nacl');
import util = require('../util'); 

var sbox = ecmaNacl.secret_box;
var box = ecmaNacl.box;
var compareVectors = ecmaNacl.compareVectors;
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

export function timeBoxPubKeyGeneration(numOfRuns: number): void {
	var sk1 = util.getRandom(32);
	log("Do calculation of a public key for a given secret key.\n"+
		"Calculations are performed "+numOfRuns+
		" times, to provide an average time.");
	runTimingAndLogging(numOfRuns, "\taverage: ", () => {
		box.generate_pubkey(sk1);
	});
}

export function timeBoxEncryption(numOfRuns: number, msgKs: number): void {
	var sk1 = util.getRandom(32);
	var pk1 = box.generate_pubkey(sk1);
	var sk2 = util.getRandom(32);
	var pk2 = box.generate_pubkey(sk2);
	var nonce = util.getRandom(24);
	var msg = util.getRandom(msgKs * 1024);
	var cipher, recoveredMsg;

	log("Do public key encryption of " + msgKs + "KB of message.\n" +
		"Calculations are performed " + numOfRuns +
		" times, to provide an average time.");
	runTimingAndLogging(numOfRuns, "\taverage for packing: ", () => {
		cipher = box.pack(msg, nonce, pk2, sk1);
	});
	runTimingAndLogging(numOfRuns, "\taverage for opening: ", () => {
		recoveredMsg = box.open(cipher, nonce, pk1, sk2);
	});
	if (!compareVectors(msg, recoveredMsg)) {
		log("Message was incorrectly decrypted.", true);
	}
}

export function timeSecretBoxEncryption(numOfRuns: number, msgKs: number): void {
	var k = util.getRandom(32);
	var nonce = util.getRandom(24);
	var msg = util.getRandom(msgKs * 1024);
	var cipher: Uint8Array;
	var recoveredMsg: Uint8Array;

	log("Do secret key encryption of " + msgKs + "KB of message.\n" +
		"Calculations are performed " + numOfRuns +
		" times, to provide an average time.");
	runTimingAndLogging(numOfRuns, "\taverage for packing: ", () => {
		cipher = sbox.pack(msg, nonce, k);
	});
	runTimingAndLogging(numOfRuns, "\taverage for opening: ", () => {
		recoveredMsg = sbox.open(cipher, nonce, k);
	});
	if (!compareVectors(msg, recoveredMsg)) {
		log("Message was incorrectly decrypted.", true);
	}
}

export function startBoxPubKeyGeneration(
		worker: Worker, numOfRuns: number): void {
	var sk1 = util.getRandom(32);
	worker.postMessage(
		{ cmd: "genPubKey", numOfRuns: numOfRuns, skey: sk1.buffer },
		[ sk1.buffer ]);
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
