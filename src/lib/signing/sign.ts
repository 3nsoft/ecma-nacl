/* Copyright(c) 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

import ge = require('./ge25519');
import sc = require('./sc25519');
import sha512 = require('../hash/sha512');
import arrays = require('../util/arrays');
import vectVerify = require('../util/verify');

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
export function generate_keypair(seed: Uint8Array,
		arrFactory?: arrays.Factory): Keypair {
	if (seed.BYTES_PER_ELEMENT !== 1) { throw new TypeError(
			"Seed must be Uint8Array."); }
	if (seed.length !== 32) { throw new Error("Seed should have 32 "+
			"elements (bytes) in it, but it is "+seed.length+
			" elements long."); }
	if (!arrFactory) {
		arrFactory = arrays.makeFactory();
	}
	
	var scsk = sc.make_sc25519(arrFactory);
	var gepk = ge.make_ge25519(arrFactory);

	var az = sha512.hash(seed, arrFactory);
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;

	sc.from32bytes(scsk,az,arrFactory);
	
	ge.scalarmult_base(gepk, scsk, arrFactory);
	
	var pk = arrFactory.getUint8Array(32);
	ge.pack(pk, gepk, arrFactory);

	var sk = arrFactory.getUint8Array(64);
	for (var i=0; i<32; i+=1) {
		sk[i] = seed[i];
	}
	for (var i=32; i<64; i+=1) {
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
			"Key array sk must be Uint8Array."); }
	if (sk.length !== 64) { throw new Error("Key array sk should have 64 "+
			"elements (bytes) in it, but it is "+sk.length+" elements long."); }
	var pk = new Uint8Array(32);
	for (var i=32; i<64; i+=1) {
		pk[i-32] = sk[i];
	}
	return pk;
}

/**
 * Analog of crypto_sign in crypto_sign/ed25519/ref/sign.c
 */
export function sign(m: Uint8Array, sk: Uint8Array,
		arrFactory?: arrays.Factory): Uint8Array {
	if (sk.BYTES_PER_ELEMENT !== 1) { throw new TypeError(
			"Key array sk must be Uint8Array."); }
	if (sk.length !== 64) { throw new Error("Key array sk should have 64 "+
			"elements (bytes) in it, but it is "+sk.length+" elements long."); }
	if (!arrFactory) {
		arrFactory = arrays.makeFactory();
	}
	
	var sck = sc.make_sc25519(arrFactory);
	var scs = sc.make_sc25519(arrFactory);
	var scsk = sc.make_sc25519(arrFactory);
	var ger = ge.make_ge25519(arrFactory);

	var pk = arrFactory.getUint8Array(32);
	pk.set(sk.subarray(32));
	/* pk: 32-byte public key A */

	var az = sha512.hash(sk.subarray(0, 32), arrFactory);
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;
	/* az: 32-byte scalar a, 32-byte randomizer z */

	var sm = new Uint8Array(m.length + 64);
	sm.subarray(64).set(m);
	sm.subarray(32, 64).set(az.subarray(32));
	/* sm: 32-byte uninit, 32-byte z, mlen-byte m */

	var nonce = sha512.hash(sm.subarray(32), arrFactory);
	/* nonce: 64-byte H(z,m) */

	sc.from64bytes(sck, nonce, arrFactory);
	ge.scalarmult_base(ger, sck, arrFactory);
	ge.pack(sm.subarray(0, 32), ger, arrFactory);
	/* sm: 32-byte R, 32-byte z, mlen-byte m */
	
	sm.subarray(32, 64).set(pk);
	/* sm: 32-byte R, 32-byte A, mlen-byte m */

	var hram = sha512.hash(sm, arrFactory);
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

export function signature(m: Uint8Array, sk: Uint8Array,
		arrFactory?: arrays.Factory): Uint8Array {
	if (sk.BYTES_PER_ELEMENT !== 1) { throw new TypeError(
			"Key array sk must be Uint8Array."); }
	if (sk.length !== 64) { throw new Error("Key array sk should have 64 "+
			"elements (bytes) in it, but it is "+sk.length+" elements long."); }
	if (!arrFactory) {
		arrFactory = arrays.makeFactory();
	}
	
	var hasher = sha512.makeHasher(false, arrFactory);
	var sck = sc.make_sc25519(arrFactory);
	var scs = sc.make_sc25519(arrFactory);
	var scsk = sc.make_sc25519(arrFactory);
	var ger = ge.make_ge25519(arrFactory);

	var pk = arrFactory.getUint8Array(32);
	pk.set(sk.subarray(32));
	/* pk: 32-byte public key A */

	hasher.update(sk.subarray(0, 32));
	var az = hasher.digest();
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;
	/* az: 32-byte scalar a, 32-byte randomizer z */

	var sig = arrFactory.getUint8Array(64);
	sig.subarray(32, 64).set(az.subarray(32));
	/* sig: 32-byte uninit, 32-byte z */

	hasher.update(sig.subarray(32));
	hasher.update(m);
	var nonce = hasher.digest();
	/* nonce: 64-byte H(z,m) */

	sc.from64bytes(sck, nonce, arrFactory);
	ge.scalarmult_base(ger, sck, arrFactory);
	ge.pack(sig.subarray(0, 32), ger, arrFactory);
	/* sig: 32-byte R, 32-byte z */

	hasher.update(sig.subarray(0, 32));
	hasher.update(pk);
	hasher.update(m);
	var hram = hasher.digest();
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
export function open(sm: Uint8Array, pk: Uint8Array,
		arrFactory?: arrays.Factory): Uint8Array {
	if (pk.BYTES_PER_ELEMENT !== 1) { throw new TypeError(
			"Key array pk must be Uint8Array."); }
	if (pk.length !== 32) { throw new Error("Key array pk should have 32 "+
			"elements (bytes) in it, but it is "+pk.length+" elements long."); }
	if (!arrFactory) {
		arrFactory = arrays.makeFactory();
	}
	var rcopy = arrFactory.getUint8Array(32);
	var rcheck = arrFactory.getUint8Array(32);
	var get1 = ge.make_ge25519(arrFactory);
	var get2 = ge.make_ge25519(arrFactory);
	var schram = sc.make_sc25519(arrFactory);
	var scs = sc.make_sc25519(arrFactory);

	if ((sm.length < 64) || (sm[63] & 224) ||
			!ge.unpackneg_vartime(get1,pk,arrFactory)) { return null; }

	rcopy.set(sm.subarray(0, 32));

	sc.from32bytes(scs, sm.subarray(32, 64), arrFactory);

	var m = new Uint8Array(sm.length);
	m.set(sm);
	m.subarray(32, 64).set(pk);
	var hram = sha512.hash(m,arrFactory);

	sc.from64bytes(schram, hram, arrFactory);

	ge.double_scalarmult_vartime(get2, get1, schram, ge.base, scs, arrFactory);
	ge.pack(rcheck, get2, arrFactory);

	var isOK = vectVerify.v32(rcopy,rcheck);
	
	for (var i=0; i<64; i+=1) { m[i] = 0; }
	arrFactory.recycle(rcopy, rcheck, hram, schram, scs);
	ge.recycle_ge25519(arrFactory, get1, get2);
	arrFactory.wipeRecycled();
	
	return (isOK? m.subarray(64) :  null);
}

export function verify(sig: Uint8Array, m: Uint8Array, pk: Uint8Array,
		arrFactory?: arrays.Factory): boolean {
	if (pk.BYTES_PER_ELEMENT !== 1) { throw new TypeError(
			"Key array pk must be Uint8Array."); }
	if (pk.length !== 32) { throw new Error("Key array pk should have 32 "+
			"elements (bytes) in it, but it is "+pk.length+" elements long."); }
	if (!arrFactory) {
		arrFactory = arrays.makeFactory();
	}
	var rcopy = arrFactory.getUint8Array(32);
	var rcheck = arrFactory.getUint8Array(32);
	var get1 = ge.make_ge25519(arrFactory);
	var get2 = ge.make_ge25519(arrFactory);
	var schram = sc.make_sc25519(arrFactory);
	var scs = sc.make_sc25519(arrFactory);

	if ((sig.length < 64) || (sig[63] & 224) ||
			!ge.unpackneg_vartime(get1,pk,arrFactory)) { return false; }

	rcopy.set(sig.subarray(0, 32));

	sc.from32bytes(scs, sig.subarray(32, 64), arrFactory);

	var hasher = sha512.makeHasher(true, arrFactory);
	
	hasher.update(sig.subarray(0, 32));
	hasher.update(pk);
	hasher.update(m);
	var hram = hasher.digest();

	sc.from64bytes(schram, hram, arrFactory);

	ge.double_scalarmult_vartime(get2, get1, schram, ge.base, scs, arrFactory);
	ge.pack(rcheck, get2, arrFactory);

	var isOK = vectVerify.v32(rcopy,rcheck);
	
	arrFactory.recycle(rcopy, rcheck, hram, schram, scs);
	ge.recycle_ge25519(arrFactory, get1, get2);
	hasher.destroy();
	arrFactory.wipeRecycled();
	
	return isOK;
}

export var JWK_ALG_NAME = 'NaCl-sign-Ed25519';
export var PUBLIC_KEY_LENGTH = 32;
export var SECRET_KEY_LENGTH = 64;


Object.freeze(exports);
