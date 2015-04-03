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
}
catch (err) {
    console.log("js-nacl is not accessable with require()" + "for this performance comparison");
}
try {
    var tweetnacl = require('tweetnacl');
}
catch (err) {
    console.log("tweetnacl is not accessable with require()" + "for this performance comparison");
}
try {
    var js_script_factory = require('../in-browser/js-scrypt');
}
catch (err) {
    console.log("js-scrypt is not accessable with require()" + "for this performance comparison");
}
var testUtil = require('../test-utils');
var nacl = require('../../lib/ecma-nacl');
var sha256 = require('../../lib/scrypt/sha256');
var sbox = nacl.secret_box;
var box = nacl.box;
var sha512 = nacl.hashing.sha512;
var getRandom = testUtil.getRandom;
function boxEncryption(numOfRuns, msgKs) {
    var js_nacl_gen_keys = js_nacl.crypto_box_keypair();
    var sk1 = js_nacl_gen_keys.boxSk;
    var pk1 = js_nacl_gen_keys.boxPk;
    testUtil.compare(pk1, box.generate_pubkey(sk1), "Generation of keys is incompatible with js-nacl.");
    var sk2 = getRandom(32);
    var pk2 = box.generate_pubkey(sk2);
    var nonce = getRandom(24);
    var msg = getRandom(msgKs * 1024);
    var cipher1, cipher2, recoveredMsg;
    console.log("Do public key encryption of " + msgKs + "KB message.\n" + "Calculations are performed " + numOfRuns + " times, to provide an average time.");
    // ecma-nacl encryption
    var startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        cipher1 = box.pack(msg, nonce, pk2, sk1);
    }
    var hrtimes = process.hrtime(startTime);
    var diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\tecma-nacl average for packing: " + diff.toFixed(3) + " milliseconds");
    // js-nacl encryption
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        cipher2 = js_nacl.crypto_box(msg, nonce, pk2, sk1);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\tjs-nacl average for packing: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(cipher1, cipher2, "Resulting ciphers are incompatible with js-nacl.");
    // tweetnacl encryption
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        cipher2 = tweetnacl.box(msg, nonce, pk2, sk1);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\ttweetnacl average for packing: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(cipher1, cipher2, "Resulting ciphers are incompatible with tweetnacl.");
    // ecma-nacl decryption
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        recoveredMsg = box.open(cipher1, nonce, pk1, sk2);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\tecma-nacl average for opening: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(msg, recoveredMsg, "Message was incorrectly decrypted.");
    // js-nacl decryption
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        recoveredMsg = js_nacl.crypto_box_open(cipher1, nonce, pk1, sk2);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\tjs-nacl average for opening: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(msg, recoveredMsg, "Message was incorrectly decrypted.");
    // js-nacl decryption
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        recoveredMsg = tweetnacl.box.open(cipher1, nonce, pk1, sk2);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\ttweetnacl average for opening: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(msg, recoveredMsg, "Message was incorrectly decrypted.");
}
function secretBoxEncryption(numOfRuns, msgKs) {
    var k = getRandom(32);
    var nonce = getRandom(24);
    var msg = getRandom(msgKs * 1024);
    var cipher1, cipher2, recoveredMsg;
    console.log("Do secret key encryption of " + msgKs + "KB message.\n" + "Calculations are performed " + numOfRuns + " times, to provide an average time.");
    // ecma-nacl encryption
    var startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        cipher1 = sbox.pack(msg, nonce, k);
    }
    var hrtimes = process.hrtime(startTime);
    var diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\tecma-nacl average for packing: " + diff.toFixed(3) + " milliseconds");
    // js-nacl encryption
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        cipher2 = js_nacl.crypto_secretbox(msg, nonce, k);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\tjs-nacl average for packing: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(cipher1, cipher2, "Resulting ciphers are incompatible with js-nacl");
    // tweetnacl encryption
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        cipher2 = tweetnacl.secretbox(msg, nonce, k);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\ttweetnacl average for packing: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(cipher1, cipher2, "Resulting ciphers are incompatible with tweetnacl");
    // ecma-nacl decryption
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        recoveredMsg = sbox.open(cipher1, nonce, k);
    }
    var hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\tecma-nacl average for opening: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(msg, recoveredMsg, "Message was incorrectly decrypted.");
    // js-nacl decryption
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        recoveredMsg = js_nacl.crypto_secretbox_open(cipher1, nonce, k);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\tjs-nacl average for opening: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(msg, recoveredMsg, "Message was incorrectly decrypted.");
    // tweetnacl decryption
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        recoveredMsg = tweetnacl.secretbox.open(cipher1, nonce, k);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\ttweet-nacl average for opening: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(msg, recoveredMsg, "Message was incorrectly decrypted.");
}
function sha512Hashing(numOfRuns, msgKs) {
    var k = getRandom(32);
    var nonce = getRandom(24);
    var msg = getRandom(msgKs * 1024);
    var hash1, hash2;
    console.log("Do sha512 hashing of " + msgKs + "KB message.\n" + "Calculations are performed " + numOfRuns + " times, to provide an average time.");
    // ecma-nacl
    var startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        hash1 = sha512.hash(msg);
    }
    var hrtimes = process.hrtime(startTime);
    var diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\tecma-nacl average for hashing: " + diff.toFixed(3) + " milliseconds");
    // js-nacl
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        hash2 = js_nacl.crypto_hash(msg);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\tjs-nacl average for hashing: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(hash1, hash2, "Resulting hashes are incompatible with js-nacl");
    // tweetnacl
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        hash2 = tweetnacl.hash(msg);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\ttweetnacl average for hashing: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(hash1, hash2, "Resulting hashes are incompatible with tweetnacl");
}
function sha256Hashing(numOfRuns, msgKs) {
    var k = getRandom(32);
    var nonce = getRandom(24);
    var msg = getRandom(msgKs * 1024);
    var hash1, hash2;
    console.log("Do sha256 hashing of " + msgKs + "KB message.\n" + "Calculations are performed " + numOfRuns + " times, to provide an average time.");
    // ecma-nacl
    var hctx = sha256.makeSha256Ctx(new nacl.TypedArraysFactory());
    hash1 = hctx.arrFactory.getUint8Array(32);
    var startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        sha256.SHA256_Init(hctx);
        sha256.SHA256_Update(hctx, msg, 0, msg.length);
        sha256.SHA256_Final(hash1, hctx);
    }
    var hrtimes = process.hrtime(startTime);
    var diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\tecma-nacl average for hashing: " + diff.toFixed(3) + " milliseconds");
    // js-nacl
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        hash2 = js_nacl.crypto_hash_sha256(msg);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\tjs-nacl average for hashing: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(hash1, hash2, "Resulting hashes are incompatible with js-nacl");
}
function signing(numOfRuns, msgKs) {
    var pair = js_nacl.crypto_sign_keypair();
    var sk = pair.signSk;
    var pk = pair.signPk;
    var keySeed = sk.subarray(0, 32);
    console.log("Do signing of " + msgKs + "KB message.\n" + "Calculations are performed " + numOfRuns + " times, to provide an average time.");
    pair = nacl.signing.generate_keypair(keySeed);
    testUtil.compare(pair.skey, sk, "Resulting signing secret key is incompatible with js-nacl");
    testUtil.compare(pair.pkey, pk, "Resulting signing public key is incompatible with js-nacl");
    pair = tweetnacl.sign.keyPair.fromSeed(keySeed);
    testUtil.compare(pair.secretKey, sk, "Resulting signing secret key is incompatible with tweetnacl");
    testUtil.compare(pair.publicKey, pk, "Resulting signing public key is incompatible with tweetnacl");
    var msg = getRandom(msgKs * 1024);
    var isSigOK;
    var signature1;
    var signedMsg2;
    // ecma-nacl signing
    var startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        signature1 = nacl.signing.signature(msg, sk);
    }
    var hrtimes = process.hrtime(startTime);
    var diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\tecma-nacl average for signing: " + diff.toFixed(3) + " milliseconds");
    // tweetnacl signing
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        signedMsg2 = tweetnacl.sign(msg, sk);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\ttweetnacl average for signing: " + diff.toFixed(3) + " milliseconds");
    testUtil.compare(signature1, signedMsg2.subarray(0, 64), "Signature is incompatible with tweetnacl");
    // ecma-nacl signature verification
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        isSigOK = nacl.signing.verify(signature1, msg, pk);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\tecma-nacl average for signature verification: " + diff.toFixed(3) + " milliseconds");
    if (!isSigOK) {
        throw new Error("Signature failed verification.");
    }
    // tweetnacl signature verification
    startTime = process.hrtime();
    for (var i = 0; i < numOfRuns; i += 1) {
        isSigOK = !!tweetnacl.sign.open(signedMsg2, pk);
    }
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / numOfRuns / 1e6;
    console.log("\ttweetnacl average for signature verification: " + diff.toFixed(3) + " milliseconds");
    if (!isSigOK) {
        throw new Error("Signature failed verification.");
    }
}
function scryptKeyDerivation(logN, r, p) {
    var passwd = getRandom(32);
    var salt = getRandom(32);
    var resKeyLen = 32;
    console.log("Do scrypt key derivation from pass+salt pair.\n" + "Calculations are performed for logN==" + logN + ", r==" + r + ", p==" + p + ".");
    // ecma-nacl scrypt
    var startTime = process.hrtime();
    var key1 = nacl.scrypt(passwd, salt, logN, r, p, resKeyLen, function (p) {
    });
    var hrtimes = process.hrtime(startTime);
    var diff = (hrtimes[0] * 1e9 + hrtimes[1]) / 1e6;
    console.log("\tecma-nacl scrypt: " + diff.toFixed(3) + " milliseconds");
    // js-scrypt
    var logR = 0;
    while ((r >>> logR) > 0) {
        logR += 1;
    }
    var memSize = Math.max(33554432, 1 << (logN + logR + 7 + 1));
    var scrypt = js_script_factory(memSize);
    startTime = process.hrtime();
    var key2 = scrypt.crypto_scrypt(passwd, salt, (1 << logN), r, p, resKeyLen);
    hrtimes = process.hrtime(startTime);
    diff = (hrtimes[0] * 1e9 + hrtimes[1]) / 1e6;
    console.log("\tjs-scrypt: " + diff.toFixed(3) + " milliseconds");
    scrypt = null;
    testUtil.compare(key1, key2, "Derived key is incompatible with js-scrypt");
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
signing(10, 1 / 4);
signing(10, 1);
signing(3, 1024);
console.log();
scryptKeyDerivation(14, 8, 1);
scryptKeyDerivation(14, 8, 2);
scryptKeyDerivation(17, 8, 1);
scryptKeyDerivation(17, 8, 2);
console.log();
