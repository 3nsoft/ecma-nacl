/*
 Copyright(c) 2015, 2020 3NSoft Inc.
 This Source Code Form is subject to the terms of the Mozilla Public
 License, v. 2.0. If a copy of the MPL was not distributed with this
 file, you can obtain one at http://mozilla.org/MPL/2.0/.
*/

import * as ge from './ge25519';
import * as sc from './sc25519';
import * as sha512 from '../hash/sha512';
import { Factory, makeFactory, makeArrayForOutput } from '../util/arrays';
import * as vectVerify from '../util/verify';

export interface Keypair {
	
	/**
	 * Secret key of this pair.
	 */
	skey: Uint8Array;
	
	/**
	 * Public key of this pair.
	 */
	pkey: Uint8Array;
}

/**
 * Analog of crypto_sign_keypair in crypto_sign/ed25519/ref/keypair.c
 */
export function generate_keypair(
	seed: Uint8Array, arrFactory?: Factory
): Keypair {
	if (!(seed instanceof Uint8Array)) { throw new TypeError(
		`Seed must be Uint8Array.`); }
	if (seed.length !== 32) { throw new Error(
		`Seed should have 32 elements (bytes) in it, but it is ${
			seed.length} elements long.`); }
	if (!arrFactory) {
		arrFactory = makeFactory();
	}
	
	const scsk = sc.make_sc25519(arrFactory);
	const gepk = ge.make_ge25519(arrFactory);

	const az = sha512.hash(seed, arrFactory);
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;

	sc.from32bytes(scsk,az,arrFactory);
	
	ge.scalarmult_base(gepk, scsk, arrFactory);
	
	const pk = makeArrayForOutput(32);
	ge.pack(pk, gepk, arrFactory);

	const sk = makeArrayForOutput(64);
	for (let i=0; i<32; i+=1) {
		sk[i] = seed[i];
	}
	for (let i=32; i<64; i+=1) {
		sk[i] = pk[i-32];
	}
	
	arrFactory.wipeRecycled();
	
	return {
		skey: sk,
		pkey: pk
	};
}

export function extract_pkey(sk: Uint8Array): Uint8Array {
	if (sk.BYTES_PER_ELEMENT !== 1) { throw new TypeError(
		`Key array sk must be Uint8Array.`); }
	if (sk.length !== 64) { throw new Error(
		`Key array sk should have 64  elements (bytes) in it, but it is ${
			sk.length} elements long.`); }
	const pk = makeArrayForOutput(32);
	for (let i=32; i<64; i+=1) {
		pk[i-32] = sk[i];
	}
	return pk;
}

/**
 * Analog of crypto_sign in crypto_sign/ed25519/ref/sign.c
 */
export function sign(
	m: Uint8Array, sk: Uint8Array, arrFactory?: Factory
): Uint8Array {
	if (!(sk instanceof Uint8Array)) { throw new TypeError(
		`Key array sk must be Uint8Array.`); }
	if (sk.length !== 64) { throw new Error(
		`Key array sk should have 64 elements (bytes) in it, but it is ${
			sk.length} elements long.`); }
	if (!arrFactory) {
		arrFactory = makeFactory();
	}
	
	const sck = sc.make_sc25519(arrFactory);
	const scs = sc.make_sc25519(arrFactory);
	const scsk = sc.make_sc25519(arrFactory);
	const ger = ge.make_ge25519(arrFactory);

	const pk = arrFactory.getUint8Array(32);
	pk.set(sk.subarray(32));
	/* pk: 32-byte public key A */

	const az = sha512.hash(sk.subarray(0, 32), arrFactory);
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;
	/* az: 32-byte scalar a, 32-byte randomizer z */

	const sm = makeArrayForOutput(m.length + 64);
	sm.subarray(64).set(m);
	sm.subarray(32, 64).set(az.subarray(32));
	/* sm: 32-byte uninit, 32-byte z, mlen-byte m */

	const nonce = sha512.hash(sm.subarray(32), arrFactory);
	/* nonce: 64-byte H(z,m) */

	sc.from64bytes(sck, nonce, arrFactory);
	ge.scalarmult_base(ger, sck, arrFactory);
	ge.pack(sm.subarray(0, 32), ger, arrFactory);
	/* sm: 32-byte R, 32-byte z, mlen-byte m */
	
	sm.set(pk, 32);
	/* sm: 32-byte R, 32-byte A, mlen-byte m */

	const hram = sha512.hash(sm, arrFactory);
	/* hram: 64-byte H(R,A,m) */

	sc.from64bytes(scs, hram, arrFactory);
	sc.from32bytes(scsk, az, arrFactory);
	sc.mul(scs, scs, scsk, arrFactory);
	sc.add(scs, scs, sck, arrFactory);
	/* scs: S = nonce + H(R,A,m)a */

	sc.to32bytes(sm.subarray(32, 64), scs);
	/* sm: 32-byte R, 32-byte S, mlen-byte m */

	arrFactory.recycle(az, nonce, hram, sck, scs, scsk, pk);
	arrFactory.wipeRecycled();
	
	return sm;
}

export function signature(
	m: Uint8Array, sk: Uint8Array, arrFactory?: Factory
): Uint8Array {
	if (!(sk instanceof Uint8Array)) { throw new TypeError(
		`Key array sk must be Uint8Array.`); }
	if (sk.length !== 64) { throw new Error(
		`Key array sk should have 64 elements (bytes) in it, but it is ${
			sk.length} elements long.`); }
	if (!arrFactory) {
		arrFactory = makeFactory();
	}
	
	const hasher = sha512.makeHasher(false, arrFactory);
	const sck = sc.make_sc25519(arrFactory);
	const scs = sc.make_sc25519(arrFactory);
	const scsk = sc.make_sc25519(arrFactory);
	const ger = ge.make_ge25519(arrFactory);

	const pk = arrFactory.getUint8Array(32);
	pk.set(sk.subarray(32));
	/* pk: 32-byte public key A */

	hasher.update(sk.subarray(0, 32));
	const az = hasher.digest();
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;
	/* az: 32-byte scalar a, 32-byte randomizer z */

	const sig = arrFactory.getUint8Array(64);
	sig.subarray(32, 64).set(az.subarray(32));
	/* sig: 32-byte uninit, 32-byte z */

	hasher.update(sig.subarray(32));
	hasher.update(m);
	const nonce = hasher.digest();
	/* nonce: 64-byte H(z,m) */

	sc.from64bytes(sck, nonce, arrFactory);
	ge.scalarmult_base(ger, sck, arrFactory);
	ge.pack(sig.subarray(0, 32), ger, arrFactory);
	/* sig: 32-byte R, 32-byte z */

	hasher.update(sig.subarray(0, 32));
	hasher.update(pk);
	hasher.update(m);
	const hram = hasher.digest();
	/* hram: 64-byte H(R,A,m) */

	sc.from64bytes(scs, hram, arrFactory);
	sc.from32bytes(scsk, az, arrFactory);
	sc.mul(scs, scs, scsk, arrFactory);
	sc.add(scs, scs, sck, arrFactory);
	/* scs: S = nonce + H(R,A,m)a */

	sc.to32bytes(sig.subarray(32), scs);
	/* sig: 32-byte R, 32-byte S */

	arrFactory.recycle(az, nonce, hram, sck, scs, scsk, pk);
	hasher.destroy();
	arrFactory.wipeRecycled();
	
	return sig;
}

/**
 * Analog of crypto_sign_open in crypto_sign/ed25519/ref/open.c
 */
export function open(
	sm: Uint8Array, pk: Uint8Array, arrFactory?: Factory
): Uint8Array|undefined {
	if (!(pk instanceof Uint8Array)) { throw new TypeError(
		`Key array pk must be Uint8Array.`); }
	if (pk.length !== 32) { throw new Error(
		`Key array pk should have 32 elements (bytes) in it, but it is ${
			pk.length} elements long.`); }
	if (!arrFactory) {
		arrFactory = makeFactory();
	}
	const rcopy = arrFactory.getUint8Array(32);
	const rcheck = arrFactory.getUint8Array(32);
	const get1 = ge.make_ge25519(arrFactory);
	const get2 = ge.make_ge25519(arrFactory);
	const schram = sc.make_sc25519(arrFactory);
	const scs = sc.make_sc25519(arrFactory);

	if ((sm.length < 64) || (sm[63] & 224) ||
			!ge.unpackneg_vartime(get1,pk,arrFactory)) { return; }

	rcopy.set(sm.subarray(0, 32));

	sc.from32bytes(scs, sm.subarray(32, 64), arrFactory);

	const m = makeArrayForOutput(sm.length);
	m.set(sm);
	m.set(pk, 32);
	const hram = sha512.hash(m,arrFactory);

	sc.from64bytes(schram, hram, arrFactory);

	ge.double_scalarmult_vartime(get2, get1, schram, ge.base, scs, arrFactory);
	ge.pack(rcheck, get2, arrFactory);

	const isOK = vectVerify.v32(rcopy,rcheck);
	
	for (let i=0; i<64; i+=1) { m[i] = 0; }
	arrFactory.recycle(rcopy, rcheck, hram, schram, scs);
	ge.recycle_ge25519(arrFactory, get1, get2);
	arrFactory.wipeRecycled();
	
	return (isOK? m.subarray(64) : undefined);
}

export function verify(
	sig: Uint8Array, m: Uint8Array, pk: Uint8Array, arrFactory?: Factory
): boolean {
	if (!(pk instanceof Uint8Array)) { throw new TypeError(
		`Key array pk must be Uint8Array.`); }
	if (pk.length !== 32) { throw new Error(
		`Key array pk should have 32 elements (bytes) in it, but it is ${
			pk.length} elements long.`); }
	if (!arrFactory) {
		arrFactory = makeFactory();
	}
	const rcopy = arrFactory.getUint8Array(32);
	const rcheck = arrFactory.getUint8Array(32);
	const get1 = ge.make_ge25519(arrFactory);
	const get2 = ge.make_ge25519(arrFactory);
	const schram = sc.make_sc25519(arrFactory);
	const scs = sc.make_sc25519(arrFactory);

	if ((sig.length < 64) || (sig[63] & 224) ||
			!ge.unpackneg_vartime(get1,pk,arrFactory)) { return false; }

	rcopy.set(sig.subarray(0, 32));

	sc.from32bytes(scs, sig.subarray(32, 64), arrFactory);

	const hasher = sha512.makeHasher(true, arrFactory);
	
	hasher.update(sig.subarray(0, 32));
	hasher.update(pk);
	hasher.update(m);
	const hram = hasher.digest();

	sc.from64bytes(schram, hram, arrFactory);

	ge.double_scalarmult_vartime(get2, get1, schram, ge.base, scs, arrFactory);
	ge.pack(rcheck, get2, arrFactory);

	const isOK = vectVerify.v32(rcopy,rcheck);
	
	arrFactory.recycle(rcopy, rcheck, hram, schram, scs);
	ge.recycle_ge25519(arrFactory, get1, get2);
	hasher.destroy();
	arrFactory.wipeRecycled();
	
	return isOK;
}

export const JWK_ALG_NAME = 'NaCl-sign-Ed25519';
export const SEED_LENGTH = 32;
export const PUBLIC_KEY_LENGTH = 32;
export const SECRET_KEY_LENGTH = 64;


Object.freeze(exports);
