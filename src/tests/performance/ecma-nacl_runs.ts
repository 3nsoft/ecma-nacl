/*
 Copyright(c) 2013 - 2015, 2020 3NSoft Inc.
 This Source Code Form is subject to the terms of the Mozilla Public
 License, v. 2.0. If a copy of the MPL was not distributed with this
 file, you can obtain one at http://mozilla.org/MPL/2.0/.
*/
/**
 * This script makes timed runs in node.
 */

import { box, secret_box as sbox, compareVectors } from '../../lib/ecma-nacl';
import { ok } from 'assert';
import { getRandom, runTimingAndLogging as run } from '../libs-for-tests/test-utils';
import { cpus } from 'os';

function timeBoxPubKeyGeneration(numOfRuns: number): void {
	const sk1 = getRandom(32);
	console.log(
`Do calculation of a public key for a given secret key.
Calculations are performed ${numOfRuns} times, to provide an average time.`
	);
	run(numOfRuns, " - average: ", () => {
		box.generate_pubkey(sk1);
	});
}

function timeBoxEncryption(numOfRuns: number, msgKs: number): void {
	const sk1 = getRandom(32);
	const pk1 = box.generate_pubkey(sk1);
	const sk2 = getRandom(32);
	const pk2 = box.generate_pubkey(sk2);
	const nonce = getRandom(24);
	const msg = getRandom(msgKs*1024);
	let cipher: Uint8Array;
	let recoveredMsg: Uint8Array;

	console.log(
`Do public key encryption of ${msgKs}KB of message.
Calculations are performed ${numOfRuns} times, to provide an average time.`
	);
	run(numOfRuns, " - average for packing: ", () => {
		cipher = box.pack(msg, nonce, pk2, sk1);
	});
	run(numOfRuns, " - average for opening: ", () => {
		recoveredMsg = box.open(cipher!, nonce, pk1, sk2);
	});
	ok(compareVectors(msg, recoveredMsg!), "Message was incorrectly decrypted.");
}

function timeSecretBoxEncryption(numOfRuns: number, msgKs: number): void {
	const k = getRandom(32);
	const nonce = getRandom(24);
	const msg = getRandom(msgKs*1024);
	let cipher: Uint8Array;
	let recoveredMsg: Uint8Array;

	console.log(
`Do secret key encryption of ${msgKs}KB of message.
Calculations are performed ${numOfRuns} times, to provide an average time.`
	);
	run(numOfRuns, " - average for packing: ", () => {
		cipher = sbox.pack(msg, nonce, k);
	});
	run(numOfRuns, " - average for opening: ", () => {
		recoveredMsg = sbox.open(cipher!, nonce, k);
	});
	ok(compareVectors(msg, recoveredMsg!), "Message was incorrectly decrypted.");
}

console.log(`
	********************
	* Performance runs *
	********************
`);

timeBoxPubKeyGeneration(50);
console.log();

timeBoxEncryption(50, 4);
timeBoxEncryption(50, 40);
console.log();

timeSecretBoxEncryption(1000, 1);
timeSecretBoxEncryption(3, 1024);
console.log();

console.log(`
Processor: ${cpus()[0].model}
`);
