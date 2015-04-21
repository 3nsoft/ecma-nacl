/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/// <reference path="../../../../lib declarations/ecma-nacl.d.ts" />

if ('undefined' !== typeof window) { throw new Error(
		"This script is for web worker, and should not be loaded directly."); }

importScripts("../ecma-nacl.js");
import ecmaNacl = require('ecma-nacl');

importScripts("../ext-libs/nacl_factory.js");
declare var nacl_factory: any;
var js_nacl = nacl_factory.instantiate()

self.addEventListener('message', function(e) {
	switch (e.data.cmd) {
	case "boxEnc":
		boxEnc(e.data);
		break;
	case "secretBoxEnc":
		secretBoxEnc(e.data);
		break;
	default:
		throw new Error("Command "+e.data.cmd+" is not known to worker.");
	}
});

function log(s: string): void {
	(<any> self).postMessage({ logMsg: s });
}

function logErr(e: Error): void {
	(<any> self).postMessage({ errMsg: e.message });
	console.error(e);
}

function logCompletion(): void {
	(<any> self).postMessage({ done: true });
}

function runTimingAndLogging(numOfRuns: number, msgPref: string,
		run: () => void): void {
	try {
		var millis = Date.now();
		for (var i=0; i<numOfRuns; i+=1) {
			run();
		}
		millis = (Date.now() - millis)/numOfRuns;
		log((msgPref? msgPref+"" : "")+millis.toFixed(3)+" milliseconds");
	} catch (e) {
		logErr(e);
	}
}

function boxEnc(data) {
	var numOfRuns: number = data.numOfRuns;
	var box = ecmaNacl.box;

	var sk1 = new Uint8Array(data.sk1);
	var sk2 = new Uint8Array(data.sk2);
	var pk1 = box.generate_pubkey(sk1);
	var pk2 = box.generate_pubkey(sk2);
	var nonce = new Uint8Array(data.nonce);
	var msg = new Uint8Array(data.msg);
	var cipher1, cipher2, recoveredMsg;

	log("Do public key encryption of "+(msg.length/1024)+"KB of message.\n"+
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
	if(!ecmaNacl.compareVectors(cipher1, cipher2)) {
		logErr(new Error("Resulting ciphers are incompatible.")); }

	// ecma-nacl decryption
	runTimingAndLogging(numOfRuns, "\tecma-nacl average for opening: ", () => {
		recoveredMsg = box.open(cipher1, nonce, pk1, sk2);
	});
	if (!ecmaNacl.compareVectors(msg, recoveredMsg)) {
		logErr(new Error("Message was incorrectly decrypted.")); }

	// js-nacl decryption
	runTimingAndLogging(numOfRuns, "\tjs-nacl average for opening: ", () => {
		recoveredMsg = js_nacl.crypto_box_open(cipher1, nonce, pk1, sk2);
	});
	if (!ecmaNacl.compareVectors(msg, recoveredMsg)) {
		logErr(new Error("Message was incorrectly decrypted.")); }
	
	logCompletion();
}

function secretBoxEnc(data) {
	var numOfRuns: number = data.numOfRuns;
	var sbox = ecmaNacl.secret_box;

	var k = new Uint8Array(data.key)
	var nonce = new Uint8Array(data.nonce)
	var msg = new Uint8Array(data.msg)
	var cipher1, cipher2, recoveredMsg;

	log("Do secret key encryption of "+(msg.length/1024)+"KB of message.\n"+
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
	
	if(!ecmaNacl.compareVectors(cipher1, cipher2)) {
		logErr(new Error("Resulting ciphers are incompatible.")); }
	
	// ecma-nacl decryption
	runTimingAndLogging(numOfRuns, "\tecma-nacl average for opening: ", () => {
		recoveredMsg = sbox.open(cipher1, nonce, k);
	});
	if (!ecmaNacl.compareVectors(msg, recoveredMsg)) {
		logErr(new Error("Message was incorrectly decrypted.")); }
	
	// js-nacl decryption
	runTimingAndLogging(numOfRuns, "\tjs-nacl average for opening: ", () => {
		recoveredMsg = js_nacl.crypto_secretbox_open(cipher1, nonce, k);
	});
	if (!ecmaNacl.compareVectors(msg, recoveredMsg)) {
		logErr(new Error("Message was incorrectly decrypted.")); }
	
	logCompletion();
}
