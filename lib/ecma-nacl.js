/* Copyright(c) 2013-2014 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * This file is an external interface of Ecma-NaCl library.
 */

var secret_box = require('./boxes/secret_box')
, box = require('./boxes/box')
, TypedArraysFactory = require('./util/arrays')
, verify = require('./util/verify').verify
, nonceMod = require('./util/nonce')
, fileXSP = require('./file/xsp');

/**
 * @param x typed array
 * @param y typed array
 * @returns true, if arrays have the same length and their elements are equal;
 * and false, otherwise.
 */
function compareVectors(x, y) {
	"use strict";
	if (x.length !== y.length) { return false; }
	return verify(x, y, x.length);
}

module.exports = {
		secret_box: secret_box,
		box: box,
		fileXSP: fileXSP,
		TypedArraysFactory: TypedArraysFactory,
		compareVectors: compareVectors,
		wipeArrays: TypedArraysFactory.prototype.wipe,
		advanceNonceOddly: nonceMod.advanceOddly,
		advanceNonceEvenly: nonceMod.advanceEvenly,
};
Object.freeze(module.exports);
