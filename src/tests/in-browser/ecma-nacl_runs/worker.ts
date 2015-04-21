/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/// <reference path="../../../../lib declarations/ecma-nacl.d.ts" />

if ('undefined' !== typeof window) { throw new Error(
		"This script is for web worker, and should not be loaded directly."); }

importScripts("../ecma-nacl.js");

import ecmaNacl = require('ecma-nacl'); 

var sbox = ecmaNacl.secret_box;
var box = ecmaNacl.box;
var compareVectors = ecmaNacl.compareVectors;

self.addEventListener('message', function(e) {
	switch (e.data.cmd) {
	case "genPubKey":
		genPubKey(e.data);
		break;
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

function genPubKey(data) {
	var numOfRuns: number = data.numOfRuns;
	var skey = new Uint8Array(data.skey);
	log("Do calculation of a public key for a given secret key.\n"+
		"Calculations are performed "+numOfRuns+
		" times, to provide an average time.");
	runTimingAndLogging(numOfRuns, "\taverage: ", () => {
		box.generate_pubkey(skey);
	});
	logCompletion();
}

function boxEnc(data) {
	var numOfRuns: number = data.numOfRuns;

	var sk1 = new Uint8Array(data.sk1);
	var sk2 = new Uint8Array(data.sk2);
	var pk1 = box.generate_pubkey(sk1);
	var pk2 = box.generate_pubkey(sk2);
	var nonce = new Uint8Array(data.nonce);
	var msg = new Uint8Array(data.msg);
	var cipher: Uint8Array;
	var recoveredMsg: Uint8Array;
	
	log("Do public key encryption of "+(msg.length/1024)+"KB of message.\n"+
		"Calculations are performed "+numOfRuns+
		" times, to provide an average time.");
	runTimingAndLogging(numOfRuns, "\taverage for packing: ", () => {
		cipher = box.pack(msg, nonce, pk2, sk1);
	});
	runTimingAndLogging(numOfRuns, "\taverage for opening: ", () => {
		recoveredMsg = box.open(cipher, nonce, pk1, sk2);
	});
	if (!compareVectors(msg, recoveredMsg)) {
		logErr(new Error("Message was incorrectly decrypted."));
	}
	logCompletion();
}

function secretBoxEnc(data) {
	var numOfRuns: number = data.numOfRuns;

	var k = new Uint8Array(data.key);
	var nonce = new Uint8Array(data.nonce);
	var msg = new Uint8Array(data.msg);
	var cipher: Uint8Array;
	var recoveredMsg: Uint8Array;

	log("Do secret key encryption of "+(msg.length/1024)+"KB of message.\n"+
		"Calculations are performed "+numOfRuns+
		" times, to provide an average time.");
	runTimingAndLogging(numOfRuns, "\taverage for packing: ", () => {
		cipher = sbox.pack(msg, nonce, k);
	});
	runTimingAndLogging(numOfRuns, "\taverage for opening: ", () => {
		recoveredMsg = sbox.open(cipher, nonce, k);
	});
	if (!compareVectors(msg, recoveredMsg)) {
		logErr(new Error("Message was incorrectly decrypted."));
	}
	logCompletion();
}

