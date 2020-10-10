/*
 Copyright(c) 2016 3NSoft Inc.
 This Source Code Form is subject to the terms of the Mozilla Public
 License, v. 2.0. If a copy of the MPL was not distributed with this
 file, you can obtain one at http://mozilla.org/MPL/2.0/.
*/

export function bytesEqual(
	a: Uint8Array|Uint32Array, b: Uint8Array|Uint32Array
): boolean {
	if (a.BYTES_PER_ELEMENT !== b.BYTES_PER_ELEMENT) { return false; }
	if (a.length !== b.length) { return false; }
	for (let i=0; i<a.length; i+=1) {
		if (a[i] !== b[i]) { return false; }
	}
	return true;
}