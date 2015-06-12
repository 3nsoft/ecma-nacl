/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * This file is an external interface of Ecma-NaCl library.
 */

/// <reference path="../typings/tsd.d.ts" />

export import secret_box = require('./boxes/secret_box');
export import box = require('./boxes/box');
export import nonce = require('./util/nonce');
export import signing = require('./signing/sign');
export import fileXSP = require('./file/xsp');

import sha512Mod = require('./hash/sha512');
export module hashing.sha512 {
	export var hash = sha512Mod.hash;
	export var makeHasher = sha512Mod.makeHasher;
}
Object.freeze(hashing);
Object.freeze(hashing.sha512);

import scryptMod = require('./scrypt/scrypt');
export var scrypt = scryptMod.scrypt;

export import arrays = require('./util/arrays');

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


export interface GetRandom {
	(n: number): Uint8Array;	
}


Object.freeze(exports);