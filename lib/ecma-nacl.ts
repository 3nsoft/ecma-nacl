/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * This file is an external interface of Ecma-NaCl library.
 */

export import secret_box = require('./boxes/secret_box');
export import box = require('./boxes/box');
export import nonce = require('./util/nonce');
export import signing = require('./signing/sign');
export import fileXSP = require('./file/xsp');

import sha512 = require('./hash/sha512');
export var hashing = {
	sha512: sha512
};
Object.freeze(hashing);

import scryptMod = require('./scrypt/scrypt');
export var scrypt = scryptMod.scrypt;

import arrays = require('./util/arrays');
export var TypedArraysFactory = arrays.Factory;
export var wipeArrays = arrays.Factory.prototype.wipe;

import verify = require('./util/verify');

/**
 * @param x typed array
 * @param y typed array
 * @returns true, if arrays have the same length and their elements are equal;
 * and false, otherwise.
 */
export function compareVectors(x, y) {
	if (x.length !== y.length) { return false; }
	return verify.verify(x, y, x.length);
}

Object.freeze(exports);