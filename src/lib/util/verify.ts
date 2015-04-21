/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * @param x is typed array
 * @param y is typed array, of the same length as x
 * @param n is number of element to compare, starting from each arrays head.
 * If this number is greater than length of given arrays, behaviour is undefined.
 * Therefore, users of this function must check lengths of given arrays
 * before calling this function.
 * It also implies that this function cannot be directly expose by the library.
 * @returns true when n first elements of arrays were found to correspond in each array,
 *          and false otherwise.
 *          Notice, that C's crypto_verify 16 and 32 return 0 (falsy value), for same elements,
 *          and -1 (truethy value), for different elements.
 */
export function verify(x, y, len: number) {
	var differentbits = 0;
	for (var i=0; i<len; i+=1) {
		differentbits |= x[i] ^ y[i];
	}
	return (differentbits === 0);
}

/**
 * @param x is typed array
 * @param y is typed array, of the same length as x
 * @returns true when 16 first elements of arrays were found to correspond in each array,
 *          and false otherwise.
 *          Notice, that C's crypto_verify 16 and 32 return 0 (falsy value), for same elements,
 *          and -1 (truethy value), for different elements.
 */
export function v16(x, y) {
	return verify(x, y, 16);
}

/**
 * @param x is typed array
 * @param y is typed array, of the same length as x
 * @returns true when 32 first elements of arrays were found to correspond in each array,
 *          and false otherwise.
 *          Notice, that C's crypto_verify 16 and 32 return 0 (falsy value), for same elements,
 *          and -1 (truethy value), for different elements.
 */
export function v32(x, y) {
	return verify(x, y, 32);
}

Object.freeze(exports);