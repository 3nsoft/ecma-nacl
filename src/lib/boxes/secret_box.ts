/*
 Copyright(c) 2013 - 2015, 2020 3NSoft Inc.
 This Source Code Form is subject to the terms of the Mozilla Public
 License, v. 2.0. If a copy of the MPL was not distributed with this
 file, you can obtain one at http://mozilla.org/MPL/2.0/.
*/

import { xsalsa20, xsalsa20_xor } from './stream';
import { poly1305, poly1305_verify } from './onetimeauth';
import { Factory, makeFactory, makeArrayForOutput } from '../util/arrays';
import { advance as advanceNonce } from '../util/nonce';

function checkPackArgs(m: Uint8Array, n: Uint8Array, k: Uint8Array): void {
	if (!(m instanceof Uint8Array)) { throw new TypeError(
		"Message array m must be Uint8Array."); }
	if (m.length === 0) { throw new Error(
		"Message array should have at least one byte."); }
	if (!(n instanceof Uint8Array)) { throw new TypeError(
		"Nonce array n must be Uint8Array."); }
	if (n.length !== 24) { throw new Error(
			"Nonce array n should have 24 elements (bytes) in it, but it is "+
			n.length+" elements long."); }
	if (!(k instanceof Uint8Array)) { throw new TypeError(
		"Key array k must be Uint8Array."); }
	if (k.length !== 32) { throw new Error(
			"Key array k should have 32 elements (bytes) in it, but it is "+
			k.length+" elements long."); }
}

/**
 * Analog of crypto_secretbox in crypto_secretbox/xsalsa20poly1305/ref/box.c
 * with an addition that given message should not be padded with zeros, and all
 * padding happen automagically without copying message array.
 * @param c is Uint8Array for resulting cipher, with length being 32 bytes
 * longer than message.
 * Resulting cipher of incoming message, packaged according to NaCl's
 * xsalsa20+poly1305 secret-box bytes layout, with 16 leading zeros.
 * @param m is Uint8Array of message bytes that need to be encrypted by secret
 * key.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long secret key.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use.
 */
function xsalsa20poly1305_pad_and_pack(
	c: Uint8Array, m: Uint8Array, n: Uint8Array, k: Uint8Array,
	arrFactory: Factory
): void {
	
	if (c.length < 32+m.length) { throw new Error(
			"Given array c is too short for output."); }
	
	xsalsa20_xor(c,m,32,n,k,arrFactory);

	const dataPartOfC = c.subarray(32)
	, polyOut = c.subarray(16,32)
	, polyKey = c.subarray(0,32);
	
	poly1305(polyOut, dataPartOfC, polyKey, arrFactory);
	
	// clear poly key part, which is not overwritten by poly output
	for (let i=0; i<16; i+=1) {
		c[i] = 0;
	}
	
}

/**
 * @param m is Uint8Array of message bytes that need to be encrypted by secret
 * key.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long secret key.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use. It may be undefined, in which case an internally created one is
 * used.
 * @return Uint8Array with resulting cipher of incoming message, packaged
 * according to NaCl's xsalsa20+poly1305 secret-box bytes layout, trimmed of
 * initial zeros, by having a view on array, starting with non-zero part.
 */
export function pack(
	m: Uint8Array, n: Uint8Array, k: Uint8Array, arrFactory?: Factory
): Uint8Array {
	checkPackArgs(m, n, k);
	if (!arrFactory) {
		arrFactory = makeFactory();
	}
	let c = makeArrayForOutput(m.length+32);
	xsalsa20poly1305_pad_and_pack(c, m, n, k, arrFactory);
	c = c.subarray(16);
	arrFactory.wipeRecycled();
	return c;
}

/**
 * Analog of crypto_secretbox_open in
 * crypto_secretbox/xsalsa20poly1305/ref/box.c with an addition that given
 * cipher should not be padded with zeros, and all padding happen automagically
 * without copying cipher array.
 * @param c is Uint8Array of cipher bytes that need to be opened by secret key.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long secret key.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use. It may be undefined, in which case an internally created one is
 * used.
 * @return Uint8Array with opened message.
 * Array is a view of buffer, which has 32 zeros preceding message bytes.
 */
export function open(
	c: Uint8Array, n: Uint8Array, k: Uint8Array, arrFactory?: Factory
): Uint8Array {
	
	if (!(c instanceof Uint8Array)) { throw new TypeError(
		`Cipher array c must be Uint8Array.`); }
	if (c.length < 17) { throw new Error(
		`Cipher array c should have at least 17 elements (bytes) in it, but is only ${
			c.length} elements long.`); }
	if (!(n instanceof Uint8Array)) { throw new TypeError(
		`Nonce array n must be Uint8Array.`); }
	if (n.length !== 24) { throw new Error(
		`Nonce array n should have 24 elements (bytes) in it, but it is ${
			n.length} elements long.`); }
	if (!(k instanceof Uint8Array)) { throw new TypeError(
		`Key array k must be Uint8Array.`); }
	if (k.length !== 32) { throw new Error(
		`Key array k should have 32 elements (bytes) in it, but it is ${
			k.length} elements long.`); }
	if (!arrFactory) { arrFactory = makeFactory(); }
	
	const subkey = arrFactory.getUint8Array(32);
	xsalsa20(subkey,n,k,arrFactory);
	
	const polyPartOfC = c.subarray(0,16);
	const msgPartOfC = c.subarray(16);
	
	if (!poly1305_verify(polyPartOfC,msgPartOfC,subkey,arrFactory)) {
		throw {
			message: `Cipher bytes fail verification.`,
			failedCipherVerification: true
		};
	}
	
	const m = makeArrayForOutput(c.length+16);

	xsalsa20_xor(m,c,16,n,k,arrFactory);

	// first 32 bytes of the opened thing should be cleared
	for (let i=0; i < 32; i+=1) { m[i] = 0; }

	arrFactory.recycle(subkey);
	arrFactory.wipeRecycled();
	
	return m.subarray(32);
}

/**
 * @param c is Uint8Array for packing nonce together with cipher.
 * Its length should be 40 bytes longer than that of a message.
 * @param m is Uint8Array of message bytes that need to be encrypted by secret
 * key.
 * @param n is Uint8Array, 24 bytes long nonce.
 * @param k is Uint8Array, 32 bytes long secret key.
 * @param arrFactory is typed arrays factory, used to allocated/find an array
 * for use. It may be undefined, in which case an internally created one is
 * used.
 */
function packWithNonceInto(
	c: Uint8Array, m: Uint8Array, n: Uint8Array, k: Uint8Array,
	arrFactory?: Factory
): void {
	checkPackArgs(m, n, k);
	if (c.length < 40+m.length) { throw new Error(
		`Array c, for packing nonce and cipher, is too short.`); }
	if (!arrFactory) {
		arrFactory = makeFactory();
	}
	xsalsa20poly1305_pad_and_pack(c.subarray(8), m, n, k, arrFactory);
	c.set(n);	// sets first 24 bytes (length of n) to nonce value
	arrFactory.wipeRecycled();
}

const regularOpen = open;

/**
 * This is an encryptor that packs bytes according to "with-nonce" format.
 */
export interface Encryptor {
	
	/**
	 * This encrypts given bytes using internally held nonce, which is
	 * advanced for every packing operation, ensuring that every call will
	 * have a different nonce.
	 * @param m is a byte array that should be encrypted
	 * @return byte array with cipher formatted with nonce
	 */
	pack(m: Uint8Array): Uint8Array;
	
	/**
	 * This method securely wipes internal key, and drops resources, so that
	 * memory can be GC-ed.
	 */
	destroy(): void;
	
	/**
	 * @return an integer, by which nonce is advanced.
	 */
	getDelta(): number;
	
}

/**
 * This is an dencryptor that unpacks bytes from "with-nonce" format.
 */
export interface Decryptor {
	
	/**
	 * @param c is a byte array with cipher, formatted with nonce.
	 * @return decrypted bytes.
	 */
	open(c: Uint8Array): Uint8Array;
	
	/**
	 * This method securely wipes internal key, and drops resources, so that
	 * memory can be GC-ed.
	 */
	destroy(): void;
	
}

export module formatWN {

	/**
	 * @param m is Uint8Array of message bytes that need to be encrypted by
	 * secret key.
	 * @param n is Uint8Array, 24 bytes long nonce.
	 * @param k is Uint8Array, 32 bytes long secret key.
	 * @param arrFactory is typed arrays factory, used to allocated/find an array
	 * for use. It may be undefined, in which case an internally created one is
	 * used.
	 * @returns Uint8Array, where nonce is packed together with cipher.
	 * Length of the returned array is 40 bytes greater than that of a message.
	 */
	export function pack(
		m: Uint8Array, n: Uint8Array, k: Uint8Array,arrFactory?: Factory
	): Uint8Array {
		if (!arrFactory) { arrFactory = makeFactory(); }
		const c = makeArrayForOutput(40+m.length);
		packWithNonceInto(c, m, n, k, arrFactory);
		arrFactory.wipeRecycled();
		return c;
	}

	/**
	 * @param c is Uint8Array with nonce and cipher bytes that need to be opened
	 * by secret key.
	 * @param k is Uint8Array, 32 bytes long secret key.
	 * @param arrFactory is typed arrays factory, used to allocated/find an
	 * array for use.
	 * It may be undefined, in which case an internally created one is used.
	 * @return Uint8Array with opened message.
	 * Array is a view of buffer, which has 32 zeros preceding message bytes.
	 */
	export function open(
		c: Uint8Array, k: Uint8Array, arrFactory?: Factory
	): Uint8Array {
		if (c.length < 41) { throw new Error(
			`Array c with nonce and cipher should have at least 41 elements (bytes) in it, but is only ${c.length} elements long.`); }
		if (!arrFactory) {
			arrFactory = makeFactory();
		}
		const n = c.subarray(0, 24);
		c = c.subarray(24);
		const m = regularOpen(c, n, k, arrFactory);
		arrFactory.wipeRecycled();
		return m;
	}
	
	/**
	 * @param c is Uint8Array with nonce and cipher bytes
	 * @returns Uint8Array, which is a copy of 24-byte nonce from a given array c
	 */
	export function copyNonceFrom(c: Uint8Array): Uint8Array {
		if (c.length < 41) { throw new Error(
			`Array c with nonce and cipher should have at least 41 elements (bytes) in it, but is only ${c.length} elements long.`); }
		const copy = makeArrayForOutput(24);
		copy.set(c.subarray(0, 24));
		return copy;
	}
	
	/**
	 * @param key for new encryptor.
	 * Note that key will be copied, thus, if given array shall never be used
	 * anywhere, it should be wiped after this call.
	 * @param nextNonce is nonce, which should be used for the very first
	 * packing. All further packing will be done with new nonce, as it is
	 * automatically advanced. Note that nextNonce will be copied.
	 * @param delta is a number between 1 and 255 inclusive, used to advance
	 * nonce. When missing, it defaults to one.
	 * @param arrFactory is typed arrays factory, used to allocated/find an
	 * array for use. It may be undefined, in which case an internally created
	 * one is used.
	 * @return a frozen object with pack & open functions, and destroy.
	 * It is NaCl's secret box for a given key, with automatically advancing
	 * nonce.
	 */
	export function makeEncryptor(
		key: Uint8Array, nextNonce: Uint8Array, delta?: number,
		arrFactory?: Factory
	): Encryptor {
		if (!(nextNonce instanceof Uint8Array)) { throw new TypeError(
			`Nonce array nextNonce must be Uint8Array.`); }
		if (nextNonce.length !== 24) { throw new Error(
			`Nonce array nextNonce should have 24 elements (bytes) in it, but it is ${
				nextNonce.length} elements long.`); }
		if (!(key instanceof Uint8Array)) { throw new TypeError(
			`Key array key must be Uint8Array.`); }
		if (key.length !== 32) { throw new Error(
			`Key array key should have 32 elements (bytes) in it, but it is ${
				key.length} elements long.`); }
		if ('number' !== typeof delta) {
			delta = 1;
		} else if ((delta < 1) || (delta > 255)) {
			throw new Error(`Given delta is out of bounds.`);
		}
		
		// set variable in the closure
		if (!arrFactory) {
			arrFactory = makeFactory();
		}
		key = makeUint8ArrayCopy(key);
		nextNonce = makeUint8ArrayCopy(nextNonce);
		let counter = 0;
		const counterMax = Math.floor(0xfffffffffffff / delta);
		
		// arrange and freeze resulting object
		const encryptor: Encryptor = {
			pack: (m) => {
				if (!key) { throw new Error(
					`This encryptor cannot be used, as it had already been destroyed.`); }
				if (counter > counterMax) { throw new Error(
					`This encryptor has been used too many times. Further use may lead to duplication of nonces.`); }
				const c = pack(m, nextNonce, key, arrFactory);
				advanceNonce(nextNonce, delta!);
				counter += 1;
				return c;
			},
			destroy: () => {
				if (!key) { return; }
				arrFactory!.wipe(key, nextNonce);
				key = undefined as any;
				nextNonce = undefined as any;
				arrFactory = undefined as any;
			},
			getDelta: () => {
				return delta!;
			}
		};
		Object.freeze(encryptor);
		
		return encryptor;
	}
	
	/**
	 * 
	 * @param key for new decryptor.
	 * @param arrFactory is typed arrays factory, used to allocated/find an
	 * array for use. It may be undefined, in which case an internally created
	 * one is used. Note that key will be copied, thus, if given array shall
	 * never be used anywhere, it should be wiped after this call.
	 * @return a frozen object with pack & open and destroy functions.
	 */
	export function makeDecryptor(
		key: Uint8Array, arrFactory?: Factory
	): Decryptor {
		if (!(key instanceof Uint8Array)) { throw new TypeError(
			`Key array key must be Uint8Array.`); }
		if (key.length !== 32) { throw new Error(
			`Key array key should have 32 elements (bytes) in it, but it is ${
				key.length} elements long.`); }
		
		// set variable in the closure
		if (!arrFactory) {
			arrFactory = makeFactory();
		}
		key = makeUint8ArrayCopy(key);
		
		// arrange and freeze resulting object
		const decryptor: Decryptor = {
			open: (c) => {
				if (!key) { throw new Error(
					`This decryptor cannot be used, as it had already been destroyed.`); }
				return open(c, key, arrFactory);
			},
			destroy: () => {
				if (!key) { return; }
				arrFactory!.wipe(key);
				key = undefined as any;
				arrFactory = undefined as any;
			}
		};
		Object.freeze(decryptor);
		
		return decryptor;
	}

}
Object.freeze(formatWN);

function makeUint8ArrayCopy(arr: Uint8Array): Uint8Array {
	const copy = new Uint8Array(arr.length);
	copy.set(arr);
	return copy;
}

export const NONCE_LENGTH = 24;
export const KEY_LENGTH = 32;
export const POLY_LENGTH = 16;
export const JWK_ALG_NAME = 'NaCl-sbox-XSP';

Object.freeze(exports);