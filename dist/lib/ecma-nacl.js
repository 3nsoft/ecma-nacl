/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
/**
 * This file is an external interface of Ecma-NaCl library.
 */
/// <reference path="../typings/tsd.d.ts" />
exports.secret_box = require('./boxes/secret_box');
exports.box = require('./boxes/box');
exports.nonce = require('./util/nonce');
exports.signing = require('./signing/sign');
exports.fileXSP = require('./file/xsp');
var sha512Mod = require('./hash/sha512');
var hashing;
(function (hashing) {
    var sha512;
    (function (sha512) {
        sha512.hash = sha512Mod.hash;
        sha512.makeHasher = sha512Mod.makeHasher;
    })(sha512 = hashing.sha512 || (hashing.sha512 = {}));
})(hashing = exports.hashing || (exports.hashing = {}));
Object.freeze(hashing);
Object.freeze(hashing.sha512);
var scryptMod = require('./scrypt/scrypt');
exports.scrypt = scryptMod.scrypt;
exports.arrays = require('./util/arrays');
var verify = require('./util/verify');
/**
 * @param x typed array
 * @param y typed array
 * @returns true, if arrays have the same length and their elements are equal;
 * and false, otherwise.
 */
function compareVectors(x, y) {
    if (x.length !== y.length) {
        return false;
    }
    return verify.verify(x, y, x.length);
}
exports.compareVectors = compareVectors;
Object.freeze(exports);
