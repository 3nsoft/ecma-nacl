/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
/**
 * This file is an external interface of Ecma-NaCl library.
 */
exports.secret_box = require('./boxes/secret_box');
exports.box = require('./boxes/box');
exports.nonce = require('./util/nonce');
exports.signing = require('./signing/sign');
exports.fileXSP = require('./file/xsp');
var sha512 = require('./hash/sha512');
exports.hashing = {
    sha512: sha512
};
Object.freeze(exports.hashing);
var scryptMod = require('./scrypt/scrypt');
exports.scrypt = scryptMod.scrypt;
var arrays = require('./util/arrays');
exports.TypedArraysFactory = arrays.Factory;
exports.wipeArrays = arrays.Factory.prototype.wipe;
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
