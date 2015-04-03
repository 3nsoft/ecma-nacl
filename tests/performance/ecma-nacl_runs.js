/**
 * This script makes timed runs in node.
 */
var testUtil = require('../test-utils');
var nacl = require('../../lib/ecma-nacl');
var sbox = nacl.secret_box;
var box = nacl.box;
var getRandom = testUtil.getRandom;
function timeBoxPubKeyGeneration(numOfRuns) {
    var sk1 = getRandom(32);
    console.log("Do calculation of a public key for a given secret key.\n" + "Calculations are performed " + numOfRuns + " times, to provide an average time.");
    var startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        box.generate_pubkey(sk1);
    }
    var hrtimes = process.hrtime(startTime);
    var diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\taverage: " + diff.toFixed(3) + " milliseconds");
}
function timeBoxEncryption(numOfRuns, msgKs) {
    var sk1 = getRandom(32);
    var pk1 = box.generate_pubkey(sk1);
    var sk2 = getRandom(32);
    var pk2 = box.generate_pubkey(sk2);
    var nonce = getRandom(24);
    var msg = getRandom(msgKs * 1024);
    var cipher, recoveredMsg;
    console.log("Do public key encryption of " + msgKs + "KB of message.\n" + "Calculations are performed " + numOfRuns + " times, to provide an average time.");
    var startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        cipher = box.pack(msg, nonce, pk2, sk1);
    }
    var hrtimes = process.hrtime(startTime);
    var diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\taverage for packing: " + diff.toFixed(3) + " milliseconds");
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        recoveredMsg = box.open(cipher, nonce, pk1, sk2);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\taverage for opening: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(msg, recoveredMsg, "Message was incorrectly decrypted.");
}
function timeSecretBoxEncryption(numOfRuns, msgKs) {
    var k = getRandom(32);
    var nonce = getRandom(24);
    var msg = getRandom(msgKs * 1024);
    var cipher, recoveredMsg;
    console.log("Do secret key encryption of " + msgKs + "KB of message.\n" + "Calculations are performed " + numOfRuns + " times, to provide an average time.");
    var startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        cipher = sbox.pack(msg, nonce, k);
    }
    var hrtimes = process.hrtime(startTime);
    var diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\taverage for packing: " + diff.toFixed(3) + " milliseconds");
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        recoveredMsg = sbox.open(cipher, nonce, k);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\taverage for opening: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(msg, recoveredMsg, "Message was incorrectly decrypted.");
}
timeBoxPubKeyGeneration(50);
console.log();
timeBoxEncryption(50, 4);
timeBoxEncryption(50, 40);
console.log();
timeSecretBoxEncryption(1000, 1);
timeSecretBoxEncryption(3, 1024);
console.log();
