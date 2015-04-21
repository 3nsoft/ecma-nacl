/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
/**
 * This script makes timed runs in node.
 */

import testUtil = require('../test-utils');
import nacl = require('../../lib/ecma-nacl');
import assert = require('assert');

var sbox = nacl.secret_box;
var box = nacl.box;

var getRandom = testUtil.getRandom;
var run = testUtil.runTimingAndLogging;

function timeBoxPubKeyGeneration(numOfRuns: number): void {
	var sk1 = getRandom(32);
	console.log("Do calculation of a public key for a given secret key.\n" +
		"Calculations are performed "+numOfRuns+
		" times, to provide an average time.");
	run(numOfRuns, "\taverage: ", () => {
		box.generate_pubkey(sk1);
	});
}

function timeBoxEncryption(numOfRuns: number, msgKs: number): void {
	var sk1 = getRandom(32);
	var pk1 = box.generate_pubkey(sk1);
	var sk2 = getRandom(32);
	var pk2 = box.generate_pubkey(sk2);
	var nonce = getRandom(24);
	var msg = getRandom(msgKs*1024);
	var cipher, recoveredMsg;

	console.log("Do public key encryption of "+msgKs+"KB of message.\n" +
			"Calculations are performed "+numOfRuns+" times, to provide an average time.");
	run(numOfRuns, "\taverage for packing: ", () => {
		cipher = box.pack(msg, nonce, pk2, sk1);
	});
	run(numOfRuns, "\taverage for opening: ", () => {
		recoveredMsg = box.open(cipher, nonce, pk1, sk2);
	});
	assert.ok(nacl.compareVectors(msg, recoveredMsg),
			"Message was incorrectly decrypted.");
}

function timeSecretBoxEncryption(numOfRuns: number, msgKs: number): void {
	var k = getRandom(32);
	var nonce = getRandom(24);
	var msg = getRandom(msgKs*1024);
	var cipher, recoveredMsg;

	console.log("Do secret key encryption of "+msgKs+"KB of message.\n" +
			"Calculations are performed "+numOfRuns+" times, to provide an average time.");
	run(numOfRuns, "\taverage for packing: ", () => {
		cipher = sbox.pack(msg, nonce, k);
	});
	run(numOfRuns, "\taverage for opening: ", () => {
		recoveredMsg = sbox.open(cipher, nonce, k);
	});
	assert.ok(nacl.compareVectors(msg, recoveredMsg),
			"Message was incorrectly decrypted.");
}

timeBoxPubKeyGeneration(50);
console.log();

timeBoxEncryption(50, 4);
timeBoxEncryption(50, 40);
console.log();

timeSecretBoxEncryption(1000, 1);
timeSecretBoxEncryption(3, 1024);
console.log();
